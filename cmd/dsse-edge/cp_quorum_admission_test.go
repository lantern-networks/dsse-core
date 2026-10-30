package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/logs"
)

func TestCPQuorumConfigurationRejectsInsecureOrIncompletePeers(t *testing.T) {
	for _, endpoints := range []string{
		`[]`, `["https://a:2379","https://b:2379"]`,
		`["https://a:2379","https://b:2379","https://a:2379"]`,
		`["http://a:2379","https://b:2379","https://c:2379"]`,
		`["https://a:2379","https://b:2379","https://user:secret@c:2379"]`,
		`["https://a:2379","https://b:2379","https://c:2379/path"]`,
	} {
		if _, err := newCPQuorumCheck(endpoints, "", "", ""); err == nil {
			t.Fatal("accepted insecure or incomplete peer list")
		}
	}
}

func TestCPQuorumGateAlsoRefusesEnrollmentAndLeavesReadsAvailable(t *testing.T) {
	e := standbyAuditElection(t)
	e.quorumCheck = func(context.Context) error { return errors.New("lost quorum") }
	called := 0
	handler := cpQuorumAdmissionMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called++; w.WriteHeader(204) }))
	for _, path := range []string{"/devices/register", "/connectors/register", "/enroll", "/tenant-inspection-crl"} {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest("POST", path, nil))
		if rec.Code != 503 || rec.Header().Get("Retry-After") != "1" {
			t.Fatalf("mutation admitted %s", path)
		}
	}
	if called != 0 {
		t.Fatal("registration handler ran")
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest("GET", "/config", nil))
	if rec.Code != 204 || called != 1 {
		t.Fatal("consensus gate blocked a read")
	}
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest("GET", "/tenant-inspection-crl", nil))
	if rec.Code != 204 || called != 2 {
		t.Fatal("consensus gate blocked published CRL read")
	}
}

func TestCPUnavailableResponderNeverReadsCredentialsOrClaimsLeadership(t *testing.T) {
	for _, path := range []string{"/admin/vlan-objects", "/leader", "/healthz"} {
		r := httptest.NewRequest("POST", path, nil)
		r.Body = standbyUnreadBody{}
		r.Header.Set("Authorization", "Bearer private-token")
		rec := httptest.NewRecorder()
		cpUnavailableHandler(rec, r)
		if rec.Code != 503 || rec.Header().Get("Retry-After") != "1" || rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("Connection") != "close" {
			t.Fatal("passive refusal contract changed")
		}
	}
}

func TestCPQuorumRefusalDoesNotSpendAnExistingDownloadToken(t *testing.T) {
	e := standbyAuditElection(t)
	e.isLeader.Store(true)
	p := &transactionalCAFixture{}
	s := newAdminDownloadTokenStore()
	if err := s.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	token, err := s.Create(downloadTestJob("tenant_a"), "test.gz", "review", []byte("private-export"), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	e.quorumCheck = func(context.Context) error { return errors.New("lost quorum") }
	mux := http.NewServeMux()
	registerAdminSessionRoutes(mux, func(_ string, next http.HandlerFunc) http.HandlerFunc { return next }, serverConfig{}, testEvaluator(), nil, nil, newAdminAuthStore(), s, nil, nil, true)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest("GET", "/admin/export-downloads/"+token.Token, nil))
	if rec.Code != 503 || rec.Header().Get("Retry-After") != "1" {
		t.Fatal("download lost quorum refusal contract")
	}
	e.quorumCheck = nil
	got, ok, err := s.ConsumeContext(context.Background(), token.Token, time.Now())
	if err != nil || !ok || string(got.Payload) != "private-export" {
		t.Fatal("refusal spent the link", err)
	}
}

func TestPostgresCPQuorumLossRefusesWaitingAndBackgroundWrites(t *testing.T) {
	p, leader, _ := blobWriterPostgresFixture(t)
	var available atomic.Bool
	available.Store(true)
	leader.quorumCheck = func(context.Context) error {
		if !available.Load() {
			return errors.New("synthetic lost quorum")
		}
		return nil
	}
	ctx := captureCPWriteLease(context.Background())
	leader.mu.Lock()
	done := make(chan error, 1)
	var edited atomic.Bool
	go func() {
		done <- p.UpdateContext(ctx, func([]byte) ([]byte, error) {
			edited.Store(true)
			return []byte(`{"unconfirmed":true}`), nil
		})
	}()
	// Lose consensus while the request waits for the previous writer's session.
	available.Store(false)
	leader.mu.Unlock()
	err := <-done
	if !errors.Is(err, errCPQuorumUnavailable) || !errors.Is(err, blobstore.ErrWriteNotCommitted) || edited.Load() {
		t.Fatalf("waiting write was admitted: edited=%v err=%v", edited.Load(), err)
	}
	if err := p.Save([]byte(`{"background":true}`)); !errors.Is(err, blobstore.ErrWriteNotCommitted) {
		t.Fatalf("background write admitted without consensus: %v", err)
	}
	if data, err := p.Load(); err != nil || len(data) != 0 {
		t.Fatalf("refused marker persisted: %s %v", data, err)
	}
	if !leader.IsLeader() {
		t.Fatal("quorum loss discarded healthy advisory session")
	}
	available.Store(true)
	if err := p.UpdateContext(ctx, func([]byte) ([]byte, error) { return []byte(`{"recovered":true}`), nil }); err != nil {
		t.Fatal("same healthy session did not resume", err)
	}
}

func TestCPQuorumRefusalPrecedesAuthenticationAndHasItsOwnAuditReason(t *testing.T) {
	e := standbyAuditElection(t)
	e.isLeader.Store(true)
	e.quorumCheck = func(context.Context) error { return errors.New("lost quorum") }
	w, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	mw := newAdminEndpointMiddleware(testEvaluator(), w, standbyNoOutboxCalls{}, standbyNoAuthCalls{}, "", false, nil, nil, nil)
	r := httptest.NewRequest("POST", "/admin/private?secret=value", nil)
	r.Body = standbyUnreadBody{}
	r.Header.Set("Authorization", "Bearer private-token")
	rec := httptest.NewRecorder()
	mw("admin.tenant.admin", func(_ http.ResponseWriter, _ *http.Request) { t.Fatal("refused handler ran") })(rec, r)
	if rec.Code != 503 || rec.Header().Get("Retry-After") != "1" {
		t.Fatalf("bad refusal %d", rec.Code)
	}
	rows := readTransportAudits(t, w)
	if len(rows) != 1 || rows[0].EventType != "admin_write_refused_without_quorum" || rows[0].Reason == nil || *rows[0].Reason != "quorum_unavailable" {
		t.Fatal("quorum failure reported as a standby", rows)
	}
}

// The caller owns a disposable real three-member mTLS etcd cluster and controls
// stops/restarts between invocations. No synthetic HTTP health responses here.
func TestCPQuorumLiveAdmissionFromFixture(t *testing.T) {
	path := os.Getenv("DSSE_CP_QUORUM_LIVE_FIXTURE")
	if path == "" {
		t.Skip("disposable live quorum fixture not requested")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Endpoints []string `json:"endpoints"`
		Expected  bool     `json:"expected"`
	}
	if err = json.Unmarshal(b, &fixture); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Dir(path)
	endpoints, _ := json.Marshal(fixture.Endpoints)
	check, err := newCPQuorumCheck(string(endpoints), filepath.Join(dir, "store-ca.pem"), filepath.Join(dir, "cp-quorum.pem"), filepath.Join(dir, "cp-quorum-key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	e := &cpLeaderElector{quorumCheck: check}
	start := time.Now()
	err = e.checkQuorum(context.Background())
	if (err == nil) != fixture.Expected {
		t.Fatalf("quorum admission expected=%v err=%v", fixture.Expected, err)
	}
	if time.Since(start) > cpQuorumTimeout+time.Second {
		t.Fatal("quorum probe exceeded its budget")
	}
	if err != nil {
		rec := httptest.NewRecorder()
		writeError(rec, 500, err)
		if rec.Code != 503 || rec.Header().Get("Retry-After") != "1" {
			t.Fatal("quorum error lost retry contract")
		}
	}
}

func TestCPQuorumLiveFounderBootstrapSealsMarker(t *testing.T) {
	path := os.Getenv("DSSE_CP_QUORUM_BOOTSTRAP_LIVE_FIXTURE")
	if path == "" {
		t.Skip("disposable standalone bootstrap fixture not requested")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Endpoints []string `json:"endpoints"`
	}
	if err = json.Unmarshal(b, &fixture); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Dir(path)
	marker := filepath.Join(t.TempDir(), "admin-bootstrapped")
	endpoints, _ := json.Marshal(fixture.Endpoints)
	check, err := newCPQuorumCheck(string(endpoints), filepath.Join(dir, "store-ca.pem"), filepath.Join(dir, "cp-quorum.pem"), filepath.Join(dir, "cp-quorum-key.pem"), cpQuorumBootstrap{allowed: true, marker: marker, founderEndpoint: fixture.Endpoints[2]})
	if err != nil {
		t.Fatal(err)
	}
	e := &cpLeaderElector{quorumCheck: check}
	if err = e.checkQuorum(context.Background()); err != nil {
		t.Fatal("initial founder bootstrap refused", err)
	}
	if err = os.WriteFile(marker, []byte("named admin created"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = e.checkQuorum(context.Background()); !errors.Is(err, errCPQuorumUnavailable) {
		t.Fatal("named-admin marker did not close standalone admission", err)
	}
	if err = os.Remove(marker); err != nil {
		t.Fatal(err)
	}
	if err = e.checkQuorum(context.Background()); !errors.Is(err, errCPQuorumUnavailable) {
		t.Fatal("removing marker reopened live authority", err)
	}
}

// This combines the real etcd admission probe with the real PostgreSQL writer.
// The external fixture owns faults; no synthetic quorum callback is substituted.
func TestPostgresCPQuorumLiveWriteFenceFromFixture(t *testing.T) {
	path := os.Getenv("DSSE_CP_QUORUM_LIVE_FIXTURE")
	if path == "" {
		t.Skip("disposable live quorum fixture not requested")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Endpoints []string `json:"endpoints"`
		Expected  bool     `json:"expected"`
	}
	if err = json.Unmarshal(b, &fixture); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Dir(path)
	endpoints, _ := json.Marshal(fixture.Endpoints)
	check, err := newCPQuorumCheck(string(endpoints), filepath.Join(dir, "store-ca.pem"), filepath.Join(dir, "cp-quorum.pem"), filepath.Join(dir, "cp-quorum-key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	p, leader, _ := blobWriterPostgresFixture(t)
	leader.quorumCheck = check
	var edited bool
	err = p.UpdateContext(captureCPWriteLease(context.Background()), func([]byte) ([]byte, error) {
		edited = true
		return []byte(`{"committed_with_live_quorum":true}`), nil
	})
	if fixture.Expected {
		if err != nil || !edited {
			t.Fatalf("healthy live quorum refused DB write: %v", err)
		}
		if data, e := p.Load(); e != nil || string(data) != `{"committed_with_live_quorum":true}` {
			t.Fatal("acknowledged write was not persisted", e)
		}
	} else {
		if !errors.Is(err, errCPQuorumUnavailable) || !errors.Is(err, blobstore.ErrWriteNotCommitted) || edited {
			t.Fatalf("unavailable live quorum admitted DB edit: edited=%v err=%v", edited, err)
		}
		if data, e := p.Load(); e != nil || len(data) != 0 {
			t.Fatal("refused DB write changed state", e)
		}
	}
}
