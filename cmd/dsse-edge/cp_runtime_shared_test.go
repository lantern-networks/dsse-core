package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/policy"
)

type runtimeLeaseGate struct {
	postgresBlobPersister
	before func()
}

func (p *runtimeLeaseGate) UpdateContext(ctx context.Context, edit func([]byte) ([]byte, error)) error {
	if p.before != nil {
		p.before()
	}
	return p.postgresBlobPersister.UpdateContext(ctx, edit)
}

func TestPostgresRuntimeWritersPeerTermReadBundlePromotion(t *testing.T) {
	leader, peerLeader := postgresFailureElectors(t)
	db, err := newCPStateBlobDB(os.Getenv("POSTGRES_QUEUE_E2E_DSN"), "../../migrations", true)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	oldE, oldCP := cpLeaderElectorInstance, edgeIsControlPlane
	cpLeaderElectorInstance = nil
	defer func() { cpLeaderElectorInstance = oldE; edgeIsControlPlane = oldCP }()
	p := postgresBlobPersister{db: db, key: "admin_runtime_state"}
	saved, err := p.Load()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec("DELETE FROM cp_state_blobs WHERE store_key=$1", p.key); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if saved == nil {
			db.Exec("DELETE FROM cp_state_blobs WHERE store_key=$1", p.key)
		} else {
			db.Exec("UPDATE cp_state_blobs SET payload=$2 WHERE store_key=$1", p.key, saved)
		}
	}()
	gate := &runtimeLeaseGate{postgresBlobPersister: p}
	a, b := policy.NewStore(nil), policy.NewStore(nil)
	if err = a.SetRuntimeStatePersister(gate); err != nil {
		t.Fatal(err)
	}
	if err = b.SetRuntimeStatePersister(p); err != nil {
		t.Fatal(err)
	}
	tenant := "tenant_lab_001"
	item := model.Policy{ID: "owned", Name: "owned", Status: "active", Conditions: map[string]any{"sni": "example.invalid"}, Action: model.PolicyAction{Decision: "allow"}}
	if _, err = a.Upsert(context.Background(), item, tenant, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err = a.UpsertLegacyExceptionConfirmed(tenant, model.LegacyException{ID: "owned", TenantID: tenant, Port: 443, SourceServer: "10.0.0.1", Protocol: "tcp", Status: "active", BusinessOwner: "owner", ExpiresAt: time.Now().Add(time.Hour).Format(time.RFC3339)}); err != nil {
		t.Fatal(err)
	}
	yes, ttl := true, 120
	if err = b.ApplyEastWestUpdateConfirmed("peer", nil, &ttl, &yes, nil); err != nil {
		t.Fatal(err)
	}
	if err = b.SetServerInitiatedEnabledConfirmed("peer", true); err != nil {
		t.Fatal(err)
	}
	if err = b.UpsertLegacyExceptionConfirmed("peer", model.LegacyException{ID: "kept", Port: 22}); err != nil {
		t.Fatal(err)
	}
	cpLeaderElectorInstance = leader
	edgeIsControlPlane = true
	leader.tick()
	if !leader.IsLeader() {
		t.Fatal("initial leader")
	}
	auth := newAdminAuthStore()
	auth.UpsertPrincipal(adminPrincipal{ID: "runtime-admin", TenantID: tenant, Roles: []string{"admin"}, Status: "active"})
	auth.UpsertSession(adminSession{ID: "runtime-session", TenantID: tenant, AdminPrincipalID: "runtime-admin", Roles: []string{"admin"}, Status: "active", ExpiresAt: time.Now().Add(time.Hour).Format(time.RFC3339), Metadata: map[string]any{adminCSRFTokenKey: "runtime-csrf"}})
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	evaluator := testEvaluator()
	evaluator.PolicyBundle.SWGTenantRestrictionRules = []model.SWGTenantRestrictionRule{{ID: "legacy-rule", TenantID: tenant, SaaSApplicationID: "legacy-app", Provider: "google_workspace", Status: "active"}}
	h := newServerWithConfig(serverConfig{Writer: writer, Evaluator: evaluator, AdminAuth: auth, PolicyStore: a})
	call := func(method, path, body string, want int) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.AddCookie(&http.Cookie{Name: "admin_session", Value: "runtime-session"})
		r.Header.Set("X-CSRF-Token", "runtime-csrf")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != want {
			t.Fatalf("%s %s got %d want %d: %s", method, path, w.Code, want, w.Body)
		}
		return w
	}
	rotate := func() {
		leader.release()
		peerLeader.tick()
		if !peerLeader.IsLeader() {
			t.Fatal("peer election")
		}
		peerLeader.release()
		leader.tick()
		if !leader.IsLeader() {
			t.Fatal("reelection")
		}
	}
	cases := []struct {
		method, path, body string
		failure            int
	}{
		{"POST", "/admin/east-west", `{"enabled":true,"max_grant_ttl_seconds":90}`, 503},
		{"POST", "/admin/server-initiated", `{"enabled":true}`, 503},
		{"POST", "/admin/legacy-exceptions", `{"id":"owned","business_owner":"review"}`, 503},
		{"DELETE", "/admin/legacy-exceptions/owned", "", 503},
		{"POST", "/admin/policies", `{"id":"new","name":"new","status":"active","conditions":{"sni":"new.invalid"},"action":{"decision":"allow"}}`, 500},
		{"POST", "/admin/policies/owned/status", `{"status":"disabled"}`, 503},
		{"DELETE", "/admin/policies/owned", "", 503},
		{"POST", "/admin/swg/tenant-restriction", `{"provider":"openai_chatgpt","allowed_value":"org-review","enabled":true}`, 503},
		{"POST", "/admin/swg/tenant-restriction", `{"saas_enablement":{"legacy-app":false}}`, 503},
	}
	for _, tc := range cases {
		before, _ := p.Load()
		snap := a.SnapshotTenantConfig(tenant)
		gen := a.ConfigGeneration()
		gate.before = rotate
		call(tc.method, tc.path, tc.body, tc.failure)
		gate.before = nil
		after, _ := p.Load()
		if !bytes.Equal(before, after) || a.ConfigGeneration() != gen || !reflect.DeepEqual(snap, a.SnapshotTenantConfig(tenant)) {
			t.Fatalf("rejected request changed state: %s", tc.path)
		}
		call(tc.method, tc.path, tc.body, 200)
		restored := policy.NewStore(nil)
		if err := restored.SetRuntimeStatePersister(p); err != nil {
			t.Fatal(err)
		}
		if !restored.EastWestIsEnabled("peer") || restored.EastWestMaxGrantTTL("peer") != 120 || !restored.ServerInitiatedEnabledFor("peer") || len(restored.LegacyExceptionsFor("peer")) != 1 {
			t.Fatalf("peer lost: %s", tc.path)
		}
	}
	// Another writer changes the same tenant after the server's last mutation.
	if err = b.SetServerInitiatedEnabledContext(captureCPWriteLease(context.Background()), tenant, false); err != nil {
		t.Fatal(err)
	}
	gen := a.ConfigGeneration()
	call("GET", "/admin/config-bundle", "", 200)
	if a.ServerInitiatedEnabledFor(tenant) || a.ConfigGeneration() <= gen {
		t.Fatal("bundle failed to refresh runtime")
	}
	if err = b.SetServerInitiatedEnabledContext(captureCPWriteLease(context.Background()), tenant, true); err != nil {
		t.Fatal(err)
	}
	call("GET", "/admin/server-initiated", "", 200)
	if !a.ServerInitiatedEnabledFor(tenant) {
		t.Fatal("management read failed to refresh")
	}
	raw, _ := p.Load()
	gen = a.ConfigGeneration()
	snap := a.SnapshotTenantConfig(tenant)
	if _, err = db.Exec("UPDATE cp_state_blobs SET payload=$2 WHERE store_key=$1", p.key, []byte(`null`)); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/admin/east-west", "/admin/server-initiated", "/admin/legacy-exceptions", "/admin/policies", "/admin/policies/new", "/admin/swg/tenant-restriction", "/admin/config-bundle", "/admin/egress-effective-rules", "/admin/effective-policy?destination=example.invalid"} {
		call("GET", path, "", 503)
	}
	call("POST", "/admin/server-initiated", `{"enabled":false}`, 503)
	if a.ConfigGeneration() != gen || !reflect.DeepEqual(snap, a.SnapshotTenantConfig(tenant)) {
		t.Fatal("read/write error changed live")
	}
	configureRuntimePromotion(peerLeader, b)
	leader.release()
	peerLeader.tick()
	if peerLeader.IsLeader() {
		t.Fatal("corrupt runtime promotion advertised")
	}
	if _, err = db.Exec("UPDATE cp_state_blobs SET payload=$2 WHERE store_key=$1", p.key, raw); err != nil {
		t.Fatal(err)
	}
	peerLeader.tick()
	if !peerLeader.IsLeader() {
		t.Fatal("restored promotion failed")
	}
	if !b.ServerInitiatedEnabledFor(tenant) {
		t.Fatal("promotion stale")
	}
	peerLeader.release()
	leader.tick()
	call("POST", "/admin/server-initiated", `{"enabled":false}`, 200)
	// Every rejected mutation must have a failed transport audit, never success.
	outcomes := map[string]int{}
	for _, row := range readTransportAudits(t, writer) {
		if row.EventType == "admin_config_change" && row.Result != nil {
			outcomes[*row.Result]++
		}
	}
	if outcomes["success"] != 10 || outcomes["error"] != 10 {
		rows, _ := json.Marshal(readTransportAudits(t, writer))
		t.Fatalf("transport audit missing: %s", rows)
	}
	t.Logf("transport outcomes: %+v", outcomes)
}
