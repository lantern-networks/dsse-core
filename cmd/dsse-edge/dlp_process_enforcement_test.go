package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/agentpolicy"
	"github.com/lantern-networks/dsse-core/appcatalog"
	"github.com/lantern-networks/dsse-core/assetcatalog"
	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/edgeplane"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/policy"
	"github.com/lantern-networks/dsse-core/policyrule"
)

const dlpProcessToken = "synthetic-dlp-process-token"

func dlpProcessServer(t *testing.T, dir string, overrides ...policy.RuntimeStore) (*httptest.Server, string, *recordingAdminAuditOutboxDeadReader) {
	t.Helper()
	tenant := testEvaluator().PolicyBundle.TenantID
	auth := newAdminAuthStore()
	auth.UpsertPrincipal(adminPrincipal{ID: "dlp-admin", TenantID: tenant, Roles: []string{"admin"}, Status: "active"})
	auth.UpsertAPIToken(adminAPIToken{ID: "dlp-admin", TenantID: tenant, TokenHash: adminTokenHash(dlpProcessToken), Roles: []string{"admin"}, Scopes: []string{"admin.policy.read", "admin.dlp.read", "admin.dlp.write"}, CreatedByAdminPrincipalID: "dlp-admin", Status: "active", ExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339)})
	writer, err := logs.NewWriter(filepath.Join(dir, "cp-logs"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { writer.Close() })
	signer, err := agentpolicy.LoadOrGenerateSigner("", true)
	if err != nil {
		t.Fatal(err)
	}
	outbox := &recordingAdminAuditOutboxDeadReader{}
	seed := []model.Policy{{ID: "inspect-upload", TenantID: tenant, Status: "active", Priority: 100, Conditions: map[string]any{"protocol": "tcp"}, Action: model.PolicyAction{Decision: "allow"}, DLP: &model.DLPSpec{PolicyID: "protect"}}}
	policies := policy.RuntimeStore(policy.NewStore(seed))
	if len(overrides) > 0 {
		policies = overrides[0]
	}
	cp := httptest.NewServer(newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Registry: connector.NewRegistry(), AdminAuth: auth, OperatorTenantID: tenant, PolicyStore: policies, AgentPolicySigner: signer, Writer: writer, AdminAuditOutbox: outbox, DLPPolicyObjectStorePath: filepath.Join(dir, "dlp.json")}))
	t.Cleanup(cp.Close)
	return cp, signer.PublicKeyHex(), outbox
}
func dlpProcessRequest(t *testing.T, base, method, body string, want int) []byte {
	t.Helper()
	r, err := http.NewRequest(method, base+"/admin/dlp-policies?id=protect", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Authorization", "Bearer "+dlpProcessToken)
	r.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil || resp.StatusCode != want {
		t.Fatalf("DLP %s status=%d want=%d body=%s error=%v", method, resp.StatusCode, want, raw, err)
	}
	return raw
}
func TestDLPAdminAcknowledgesOnlySavedPolicy(t *testing.T) {
	for _, op := range []string{"create", "edit", "disable", "enable", "delete"} {
		t.Run(op, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "dlp.json")
			tenant := testEvaluator().PolicyBundle.TenantID
			initial := model.DLPPolicyObject{ID: "protect", TenantID: tenant, Name: "Card protection", Identifiers: []string{"credit_card"}, OnMatch: "block", Status: "active"}
			if op == "enable" {
				initial.Status = "disabled"
			}
			store := newDLPPolicyObjectStore()
			if err := store.SetPersister(blobstore.FilePersister{Path: path}); err != nil {
				t.Fatal(err)
			}
			if op != "create" {
				store.Upsert(initial)
				if err := store.PersistIfDirty(); err != nil {
					t.Fatal(err)
				}
			}
			cp, _, outbox := dlpProcessServer(t, dir)
			before := dlpProcessRequest(t, cp.URL, "GET", "", 200)
			if _, err := os.Stat(path); err == nil {
				if err := os.Rename(path, path+".previous"); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Mkdir(path, 0700); err != nil {
				t.Fatal(err)
			}
			next := initial
			next.Name = "Updated card protection"
			if op == "disable" {
				next.Status = "disabled"
			}
			if op == "enable" {
				next.Status = "active"
			}
			raw, _ := json.Marshal(next)
			method := "POST"
			if op == "delete" {
				method = "DELETE"
			}
			dlpProcessRequest(t, cp.URL, method, string(raw), 500)
			if got := dlpProcessRequest(t, cp.URL, "GET", "", 200); !bytes.Equal(got, before) {
				t.Fatal("failed save changed live policy")
			}
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(path + ".previous"); err == nil {
				if err := os.Rename(path+".previous", path); err != nil {
					t.Fatal(err)
				}
			}
			dlpProcessRequest(t, cp.URL, method, string(raw), 200)
			fresh := newDLPPolicyObjectStore()
			if err := fresh.SetPersister(blobstore.FilePersister{Path: path}); err != nil {
				t.Fatal(err)
			}
			got, ok := fresh.Get(tenant, "protect")
			if op == "delete" {
				if ok {
					t.Fatal("deleted policy remained on disk")
				}
			} else if !ok || got.Name != next.Name || got.Status != next.Status {
				t.Fatalf("saved policy mismatch: %+v", got)
			}
			outbox.mu.Lock()
			defer outbox.mu.Unlock()
			if len(outbox.wrapperAudits) != 2 {
				t.Fatalf("mutation audit count=%d", len(outbox.wrapperAudits))
			}
			for i, a := range outbox.wrapperAudits {
				want := "error"
				if i == 1 {
					want = "success"
				}
				if a.Result == nil || *a.Result != want || a.ActorUserID == nil || *a.ActorUserID != "dlp-admin" || a.TenantID != tenant {
					t.Fatalf("audit %d mismatch: %+v", i, a)
				}
			}
		})
	}
}

func TestDLPEnforcementCPChild(t *testing.T) {
	dir := os.Getenv("DSSE_DLP_ENFORCEMENT_CP_CHILD")
	if dir == "" {
		t.Skip("helper process")
	}
	cp, key, outbox := dlpProcessServer(t, dir)
	raw, _ := json.Marshal(map[string]string{"url": cp.URL, "public_key": key})
	if err := os.WriteFile(filepath.Join(dir, "ready.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(40 * time.Second)
	for {
		if _, err := os.Stat(filepath.Join(dir, "stop")); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("parent timeout")
		}
		time.Sleep(10 * time.Millisecond)
	}
	outbox.mu.Lock()
	defer outbox.mu.Unlock()
	if len(outbox.wrapperAudits) != 6 {
		t.Fatalf("DLP mutation audits=%d want6", len(outbox.wrapperAudits))
	}
	for _, a := range outbox.wrapperAudits {
		if a.ActorUserID == nil || *a.ActorUserID != "dlp-admin" || a.Result == nil || *a.Result != "success" || a.TenantID != testEvaluator().PolicyBundle.TenantID {
			t.Fatalf("DLP audit mismatch: %+v", a)
		}
	}
}
func TestDLPPolicyAcrossProcessesControlsUploads(t *testing.T) {
	dir := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestDLPEnforcementCPChild$", "-test.v")
	child.Env = append(os.Environ(), "DSSE_DLP_ENFORCEMENT_CP_CHILD="+dir)
	var output bytes.Buffer
	child.Stdout = &output
	child.Stderr = &output
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if child.ProcessState == nil {
			child.Process.Kill()
			child.Wait()
		}
	}()
	var ready struct {
		URL       string `json:"url"`
		PublicKey string `json:"public_key"`
	}
	for {
		raw, err := os.ReadFile(filepath.Join(dir, "ready.json"))
		if err == nil && json.Unmarshal(raw, &ready) == nil && ready.URL != "" {
			break
		}
		if ctx.Err() != nil {
			t.Fatal("CP startup timeout")
		}
		time.Sleep(10 * time.Millisecond)
	}
	stores := dlpStoresForTest("synthetic-distribution-salt")
	policies := policy.NewStore(nil)
	status := &configBundleSyncStatus{source: ready.URL, interval: 20 * time.Millisecond}
	source := configBundleSource{url: ready.URL, client: http.DefaultClient, token: dlpProcessToken, tenantID: testEvaluator().PolicyBundle.TenantID, verifyPubKeyHex: ready.PublicKey, requireSigned: true, status: status, interval: 20 * time.Millisecond}
	pollCtx, stop := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		source.run(pollCtx, configApplyTargets{applications: appcatalog.NewStore(), assets: assetcatalog.NewStore(), rules: policyrule.NewStore(), policyStore: policies, dlp: stores})
	}()
	defer func() { stop(); <-done }()
	var deliveries atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, err := io.ReadAll(r.Body)
		if err == nil && strings.Contains(string(raw), "4111111111111111") {
			deliveries.Add(1)
		}
		w.WriteHeader(204)
	}))
	defer upstream.Close()
	upURL, _ := url.Parse(upstream.URL)
	cfg, events := newDLPTestConfig(t)
	cfg.Evaluator = testEvaluator()
	cfg.PolicyStore = policies
	cfg.Registry = connector.NewRegistry()
	cfg.DecisionStore = newAccessDecisionStore()
	cfg.DeviceAuthenticatedInProcess = true
	cfg.ProxyClient = &http.Client{Transport: redirectAllToServer{host: upURL.Host, rt: http.DefaultTransport}}
	cfg.DLPPolicies = stores.policies
	cfg.DLPClassifiers = stores.classifiers
	cfg.DLPFingerprints = stores.fingerprints
	edge := httptest.NewServer(newEdgeSWGHTTPEgressHandler(cfg))
	defer edge.Close()
	for _, step := range []struct {
		name, action, status string
		min, statusCode      int
		deleted              bool
	}{{"create", "block", "active", 1, 403, false}, {"observe", "observe", "active", 1, 204, false}, {"disable", "block", "disabled", 1, 204, false}, {"enable", "block", "active", 1, 403, false}, {"threshold", "block", "active", 2, 204, false}, {"delete", "block", "active", 2, 204, true}} {
		t.Run(step.name, func(t *testing.T) {
			obj := model.DLPPolicyObject{ID: "protect", Name: "Card protection", Identifiers: []string{"credit_card"}, OnMatch: step.action, Status: step.status, MinCount: step.min}
			raw, _ := json.Marshal(obj)
			method := "POST"
			if step.deleted {
				method = "DELETE"
			}
			dlpProcessRequest(t, ready.URL, method, string(raw), 200)
			bundle, err := source.fetch(ctx)
			if err != nil || !bundle.signatureVerified {
				t.Fatalf("signed bundle error: %v", err)
			}
			deadline := time.Now().Add(5 * time.Second)
			for {
				s := status.snapshot()
				if s["have_applied"] == true && s["last_applied_generation"].(uint64) >= bundle.Generation {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("DLP distribution timeout")
				}
				time.Sleep(10 * time.Millisecond)
			}
			fresh := newDLPPolicyObjectStore()
			if err := fresh.SetPersister(blobstore.FilePersister{Path: filepath.Join(dir, "dlp.json")}); err != nil {
				t.Fatal(err)
			}
			tenant := testEvaluator().PolicyBundle.TenantID
			for label, store := range map[string]*dlpPolicyObjectStore{"CP disk": fresh, "Edge": stores.policies} {
				got, ok := store.Get(tenant, "protect")
				if step.deleted {
					if ok {
						t.Fatalf("%s retained deleted policy", label)
					}
				} else if !ok || got.OnMatch != step.action || got.Status != step.status || got.MinCount != step.min {
					t.Fatalf("%s policy mismatch %+v", label, got)
				}
			}
			before := deliveries.Load()
			previousEvents := map[string]bool{}
			for _, event := range events.ListByTenant(tenant) {
				previousEvents[event.ID] = true
			}
			r, err := http.NewRequestWithContext(ctx, "POST", edge.URL+edgeplane.EdgeSWGHTTPEgressPath, strings.NewReader(`{"card":"4111111111111111"}`))
			if err != nil {
				t.Fatal(err)
			}
			r.Header.Set(edgeplane.EdgeSWGHTTPEgressTargetURLHeader, "https://upload.example.test/")
			r.Header.Set("Content-Type", "application/json")
			resp, err := http.DefaultClient.Do(r)
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode != step.statusCode {
				t.Fatalf("upload status=%d want%d body=%s", resp.StatusCode, step.statusCode, body)
			}
			want := before
			if step.statusCode == 204 {
				want++
			}
			if deliveries.Load() != want {
				t.Fatalf("upstream deliveries=%d want%d", deliveries.Load(), want)
			}
			matches := 0
			for _, event := range events.ListByTenant(tenant) {
				if previousEvents[event.ID] || event.FindingType == nil || *event.FindingType != "dlp_match" {
					continue
				}
				matches++
				wantAction := "observe"
				if step.statusCode == 403 {
					wantAction = "block"
				}
				if event.Metadata["dlp_action"] != wantAction || event.PayloadStored || !event.Masked {
					t.Fatalf("finding mismatch: %+v", event)
				}
				raw, _ := json.Marshal(event)
				if bytes.Contains(raw, []byte("4111111111111111")) {
					t.Fatal("raw card value in finding")
				}
			}
			// Missing or disabled named policies retain the existing inline
			// observe fallback; they stop blocking, but still record findings.
			wantMatches := 1
			if matches != wantMatches {
				t.Fatalf("new findings=%d want%d", matches, wantMatches)
			}
			diskEvents, err := cfg.Writer.ReadJSONL("inspection_events.log.jsonl")
			if err != nil {
				t.Fatal(err)
			}
			for _, event := range events.ListByTenant(tenant) {
				if previousEvents[event.ID] || event.FindingType == nil || *event.FindingType != "dlp_match" {
					continue
				}
				found := false
				for _, row := range diskEvents {
					if row["inspection_event_id"] == event.ID || row["id"] == event.ID {
						found = true
						break
					}
				}
				if !found {
					t.Fatal("finding missing from durable inspection log")
				}
			}
		})
		if t.Failed() {
			return
		}
	}
	stop()
	<-done
	if err := os.WriteFile(filepath.Join(dir, "stop"), []byte("done"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := child.Wait(); err != nil {
		t.Fatalf("CP audit check: %v %s", err, output.String())
	}
}

// Force an ordinary admin edit to overlap bundle assembly at its generation read.
type dlpEditDuringBundle struct {
	*policy.Store
	calls atomic.Int32
	edit  func()
}

func (s *dlpEditDuringBundle) ConfigGeneration() uint64 {
	if s.calls.Add(1) == 2 && s.edit != nil {
		s.edit()
	}
	return s.Store.ConfigGeneration()
}
func TestConfigBundleRefusesDLPChangedDuringSnapshot(t *testing.T) {
	store := &dlpEditDuringBundle{Store: policy.NewStore(nil)}
	cp, _, _ := dlpProcessServer(t, t.TempDir(), store)
	dlpProcessRequest(t, cp.URL, "POST", `{"id":"protect","name":"Cards","identifiers":["credit_card"],"on_match":"block"}`, 200)
	store.edit = func() {
		dlpProcessRequest(t, cp.URL, "POST", `{"id":"protect","name":"Cards","identifiers":["credit_card"],"on_match":"observe"}`, 200)
	}
	store.calls.Store(0)
	req, _ := http.NewRequest("GET", cp.URL+"/admin/config-bundle", nil)
	req.Header.Set("Authorization", "Bearer "+dlpProcessToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 503 {
		t.Fatalf("bundle status=%d: old DLP snapshot accepted under new generation", resp.StatusCode)
	}
}
