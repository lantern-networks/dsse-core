package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/grantstore"
	"github.com/lantern-networks/dsse-core/policy"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func accessIngestGrant(id string, now time.Time) grantstore.Grant {
	return grantstore.Grant{GrantID: id, TenantID: "tenant_lab_001", UserID: "user", IdPID: "idp", IssuedAt: now.Format(time.RFC3339), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339)}
}
func TestAccessGrantReportPreservesDenialAndRejectsUnsavedAdmission(t *testing.T) {
	now := time.Now()
	s := grantstore.NewStore()
	p := &riskAuditPersister{base: blobstore.FilePersister{Path: filepath.Join(t.TempDir(), "grants.json")}}
	if e := s.SetPersister(p); e != nil {
		t.Fatal(e)
	}
	g, _ := s.Mint(accessIngestGrant("private-cookie", now), time.Hour, now)
	s.Revoke(g.GrantID)
	mux := http.NewServeMux()
	registerGrantReportRoute(mux, s, nil, "", true)
	send := func(body []byte, want int) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRecorder()
		mux.ServeHTTP(r, httptest.NewRequest("POST", "/grant-report", bytes.NewReader(body)))
		if r.Code != want {
			t.Fatalf("status %d want %d: %s", r.Code, want, r.Body)
		}
		return r
	}
	report := func(gs []grantstore.Grant, want int) *httptest.ResponseRecorder {
		data, _ := json.Marshal(map[string]any{"grants": gs})
		return send(data, want)
	}
	gen := s.ConfigGeneration()
	report([]grantstore.Grant{g}, 200)
	if s.Valid(g.GrantID, now) || s.ConfigGeneration() != gen {
		t.Fatal("stale report revived grant")
	}
	foreign := g
	foreign.TenantID = "other"
	r := report([]grantstore.Grant{foreign}, 409)
	if strings.Contains(r.Body.String(), g.GrantID) {
		t.Fatal("credential leaked in error")
	}
	for _, raw := range []string{"null", "{}", `{"grants":null}`, `{"grants":[]} {}`, `{"grants":[{}]}`} {
		send([]byte(raw), 400)
	}
	fresh := accessIngestGrant("new", now)
	p.fail.Store(true)
	report([]grantstore.Grant{fresh}, 500)
	if _, ok := s.Get(fresh.GrantID); ok {
		t.Fatal("unsaved admission visible")
	}
	p.fail.Store(false)
	report([]grantstore.Grant{fresh}, 200)
	p.fail.Store(true)
	fresh.Revoked = true
	for _, changed := range []bool{true, false} {
		response := report([]grantstore.Grant{fresh}, 500)
		var outcome map[string]any
		if err := json.Unmarshal(response.Body.Bytes(), &outcome); err != nil {
			t.Fatal(err)
		}
		if outcome["changed"] != changed || outcome["persistence"] != "unconfirmed" {
			t.Fatal("incorrect attempt outcome")
		}
	}
	if s.Valid(fresh.GrantID, now) {
		t.Fatal("unsaved denial dropped")
	}
	p.fail.Store(false)
	report([]grantstore.Grant{fresh}, 200)
	reloaded := grantstore.NewStore()
	if e := reloaded.SetPersister(p); e != nil || reloaded.Valid(fresh.GrantID, now) {
		t.Fatal("retry not persisted")
	}
	secured := http.NewServeMux()
	registerGrantReportRoute(secured, s, nil, "", false)
	w := httptest.NewRecorder()
	secured.ServeHTTP(w, httptest.NewRequest("POST", "/grant-report", strings.NewReader(`{"grants":[]}`)))
	if w.Code != 403 {
		t.Fatal("missing machine identity accepted")
	}
	standby := http.NewServeMux()
	registerGrantReportRoute(standby, s, nil, "https://authority", false)
	w = httptest.NewRecorder()
	standby.ServeHTTP(w, httptest.NewRequest("POST", "/grant-report", nil))
	if w.Code != 404 {
		t.Fatal("standby accepted reporting")
	}
}
func TestAccessGrantBundleRetriesSameGenerationAfterSaveFailure(t *testing.T) {
	now := time.Now()
	s := grantstore.NewStore()
	p := &riskAuditPersister{base: blobstore.FilePersister{Path: filepath.Join(t.TempDir(), "edge.json")}}
	if e := s.SetPersister(p); e != nil {
		t.Fatal(e)
	}
	g, _ := s.Mint(accessIngestGrant("held", now), time.Hour, now)
	g.Revoked = true
	p.fail.Store(true)
	prev := theGrantStore.Load()
	theGrantStore.Store(s)
	defer theGrantStore.Store(prev)
	payload := configBundlePayload{Generation: 17, Epoch: "access-retry", Grants: &grantBundle{Complete: true, Grants: []grantstore.Grant{g, accessIngestGrant("fresh", now)}}}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	var polls atomic.Int32
	status := &configBundleSyncStatus{}
	type observed struct {
		denied     bool
		adopted    bool
		hadError   bool
		applied    bool
		generation uint64
	}
	observations := make(chan observed, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := polls.Add(1)
		if n == 3 {
			status.mu.RLock()
			hadError := strings.Contains(status.lastError, "persistence")
			status.mu.RUnlock()
			_, found := s.Get("fresh")
			observations <- observed{denied: !s.Valid("held", now), adopted: found, hadError: hadError}
			p.fail.Store(false)
		}
		if n == 4 {
			status.mu.RLock()
			o := observed{applied: status.haveApplied, generation: status.lastAppliedGeneration}
			status.mu.RUnlock()
			observations <- o
			cancel()
		}
		json.NewEncoder(w).Encode(payload)
	}))
	defer server.Close()
	src := configBundleSource{tenantID: "tenant_lab_001", url: server.URL, client: server.Client(), interval: 10 * time.Millisecond, status: status}
	src.run(ctx, configApplyTargets{policyStore: policy.NewStore(nil)})
	if polls.Load() < 4 || len(observations) != 2 {
		t.Fatalf("no bounded retry: polls %d", polls.Load())
	}
	failed, success := <-observations, <-observations
	if !failed.denied || failed.adopted || !failed.hadError || !success.applied || success.generation != 17 {
		t.Fatalf("wrong convergence: %+v %+v", failed, success)
	}
	reloaded := grantstore.NewStore()
	if e := reloaded.SetPersister(p); e != nil || reloaded.Valid("held", now) || !reloaded.Valid("fresh", now) {
		t.Fatal("converged state not saved")
	}
	_, _, e := applyGrantBundleSection(nil, payload.Grants, now)
	if e == nil {
		t.Fatal("missing store silently applied")
	}
	_, _, e = applyGrantBundleSection(s, &grantBundle{}, now)
	if e == nil {
		t.Fatal("incomplete section silently applied")
	}
}
func TestAccessGrantInvalidSnapshotRefusesStartup(t *testing.T) {
	if path := os.Getenv("DSSE_ACCESS_STARTUP_CHILD"); path != "" {
		newServerWithConfig(serverConfig{Evaluator: testEvaluator(), GrantStorePath: path})
		os.Exit(9)
	}
	for _, raw := range []string{"", "null", "{bad", `{"wrong":{"grant_id":"right","tenant_id":"tenant","issued_at":"2026-01-01T00:00:00Z","expires_at":"2026-01-02T00:00:00Z"}}`, `{"right":{"grant_id":"right","tenant_id":"tenant","issued_at":"bad","expires_at":"bad"}}`} {
		path := filepath.Join(t.TempDir(), "state.json")
		if e := os.WriteFile(path, []byte(raw), 0600); e != nil {
			t.Fatal(e)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestAccessGrantInvalidSnapshotRefusesStartup$")
		cmd.Env = append(os.Environ(), "DSSE_ACCESS_STARTUP_CHILD="+path)
		output, e := cmd.CombinedOutput()
		cancel()
		var status *exec.ExitError
		if !errors.As(e, &status) || status.ExitCode() != 1 || !bytes.Contains(output, []byte("load grant store: invalid access grant")) {
			t.Fatalf("wrong startup outcome: %v %s", e, output)
		}
		after, e := os.ReadFile(path)
		if e != nil || string(after) != raw {
			t.Fatal("invalid snapshot changed")
		}
	}
}
