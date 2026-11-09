package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/authrollout"
	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/logs"
)

func TestAuthInstallerStatusRequiresReadableActualMemberCache(t *testing.T) {
	authority, census := rolloutFixture(t)
	if err := authority.authority.Configure(context.Background(), 0, census); err != nil {
		t.Fatal(err)
	}
	completeRollout(t, authority, census)
	distribution, err := authority.distribution(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	p := &countingRolloutPersister{inner: blobstore.FilePersister{Path: filepath.Join(t.TempDir(), "actual-edge-cache.json")}}
	edge := &authRolloutRuntime{cache: authrollout.NewCache(authrollout.NewStore(p)), expected: &census.Members[1], deployment: census.Deployment}
	if edge.statusSnapshot()["state_available"] != false {
		t.Fatal("empty cache reported applied")
	}
	edge.receive(distribution, true, time.Now())
	status := edge.statusSnapshot()
	manifest, _ := json.Marshal(census)
	hash := sha256.Sum256(manifest)
	if status["state_available"] != true || status["node_id"] != "edge" || status["generation"] != census.Generation || status["revision"] != distribution.State.Revision || status["complete"] != true || status["census_sha256"] != hex.EncodeToString(hash[:]) {
		t.Fatalf("incomplete applied status: %+v", status)
	}
	if !edge.featureEnabled(authrollout.SingleRequestFeature) {
		t.Fatal("completed feature unavailable")
	}
	// Availability fallback for authorization is deliberately not proof that
	// the durable cache remains readable during setup verification.
	p.failLoad = true
	if edge.statusSnapshot()["state_available"] != false {
		t.Fatal("unreadable cache used last-known decision state as installation evidence")
	}
	p.failLoad = false
	edge.deployment = "other-deployment"
	if edge.statusSnapshot()["state_available"] != false {
		t.Fatal("wrong deployment reported applied")
	}
	edge.deployment = census.Deployment
	other := *edge.expected
	other.CertificateSHA256 = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	edge.expected = &other
	if edge.statusSnapshot()["state_available"] != false {
		t.Fatal("wrong member identity reported applied")
	}
}

func TestAnonymousHealthDoesNotExposeOrReadDurableAuthenticationState(t *testing.T) {
	authority, census := rolloutFixture(t)
	if err := authority.authority.Configure(context.Background(), 0, census); err != nil {
		t.Fatal(err)
	}
	completeRollout(t, authority, census)
	distribution, err := authority.distribution(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	p := &countingRolloutPersister{inner: blobstore.FilePersister{Path: filepath.Join(t.TempDir(), "edge-cache.json")}}
	edge := &authRolloutRuntime{cache: authrollout.NewCache(authrollout.NewStore(p)), expected: &census.Members[1], deployment: census.Deployment}
	edge.receive(distribution, true, time.Now())
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	syncStatus := &configBundleSyncStatus{source: "https://authority.example.test", interval: time.Second}
	syncStatus.recordApplied(42, "test-epoch", 1, time.Now())
	handler := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Writer: writer, Registry: connector.NewRegistry(), AdminAuth: seedAdminConnectorAPITokenAuth("reader", "read-only-token", []string{"admin.state.read"}), ConfigSyncStatus: syncStatus, OperatorTenantID: "tenant_lab_001"})
	previous := theAuthRollout.Swap(edge)
	defer theAuthRollout.Store(previous)
	before := p.loads
	for i := 0; i < 6; i++ {
		// Anonymous: the status and nothing else (a_node_tells_only_its_operator_what_it_is.go).
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest("GET", "/healthz", nil))
		if rec.Code != 200 {
			t.Fatalf("health: %d", rec.Code)
		}
		var body map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if len(body) != 1 || body["status"] != "ok" {
			t.Fatalf("anonymous health carried more than its status: %s", rec.Body.String())
		}
		// The operator: the sync diagnostic, still without the rollout and still without a durable read.
		req := httptest.NewRequest("GET", "/healthz", nil)
		req.Header.Set("Authorization", "Bearer read-only-token")
		rec = httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		body = nil
		if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &body) != nil {
			t.Fatalf("operator health: %d %s", rec.Code, rec.Body.String())
		}
		pull, _ := body["config_pull"].(map[string]any)
		if pull == nil {
			t.Fatalf("operator health lost the sync diagnostic: %s", rec.Body.String())
		}
		if _, present := pull["auth_rollout"]; present {
			t.Fatal("health exposed rollout")
		}
		if pull["last_applied_generation"] != float64(42) {
			t.Fatal("operator sync diagnostic lost")
		}
	}
	if p.loads != before {
		t.Fatalf("health read durable rollout %d times", p.loads-before)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest("GET", "/admin/config-sync-status", nil))
	if rec.Code != http.StatusUnauthorized || p.loads != before {
		t.Fatal("anonymous admin status disclosed/read rollout")
	}
	req := httptest.NewRequest("GET", "/admin/config-sync-status", nil)
	req.Header.Set("Authorization", "Bearer read-only-token")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	var body map[string]any
	json.Unmarshal(rec.Body.Bytes(), &body)
	if rec.Code != 200 || body["auth_rollout"] == nil || p.loads != before+1 {
		t.Fatalf("authenticated durable evidence missing: %d %s", rec.Code, rec.Body.String())
	}
	for _, path := range []string{"/admin/policies", "/admin/api-tokens"} {
		req := httptest.NewRequest("POST", path, nil)
		req.Header.Set("Authorization", "Bearer read-only-token")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("installation reader could mutate %s: HTTP %d", path, rec.Code)
		}
	}
}
