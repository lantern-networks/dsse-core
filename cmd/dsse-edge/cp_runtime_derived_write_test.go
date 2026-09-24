package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/assetcatalog"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/policy"
	"github.com/lantern-networks/dsse-core/policyrule"
)

func TestPostgresCatalogRecompilePreservesRuntimeAuthority(t *testing.T) {
	if os.Getenv("POSTGRES_QUEUE_E2E_DSN") == "" {
		t.Skip("POSTGRES_QUEUE_E2E_DSN is not set")
	}
	db, err := newCPStateBlobDB(os.Getenv("POSTGRES_QUEUE_E2E_DSN"), "../../migrations", true)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	old := cpLeaderElectorInstance
	cpLeaderElectorInstance = nil
	defer func() { cpLeaderElectorInstance = old }()
	p := postgresBlobPersister{db: db, key: "admin_runtime_state"}
	saved, err := p.Load()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if saved != nil {
			db.Exec("UPDATE cp_state_blobs SET payload=$2 WHERE store_key=$1", p.key, saved)
		} else {
			db.Exec("DELETE FROM cp_state_blobs WHERE store_key=$1", p.key)
		}
	}()
	if _, err = db.Exec("DELETE FROM cp_state_blobs WHERE store_key=$1", p.key); err != nil {
		t.Fatal(err)
	}
	policies := policy.NewStore(nil)
	if err := policies.SetRuntimeStatePersister(p); err != nil {
		t.Fatal(err)
	}
	// Seed after the node has loaded its overlay, as a peer's confirmed changes.
	authority := []byte(`{"schema_version":"admin_policy_runtime_state.v1","east_west_enabled":{"peer":true},"east_west_allow_unmatched":{"peer":false},"east_west_rules":{"peer":[{"id":"legacy","mode":"deny"}]},"east_west_max_grant_ttl":{"peer":90},"server_initiated_enabled":{"peer":true},"legacy_exceptions":{"peer":[{"id":"incoming","tenant_id":"peer","port":443}]},"policy_status_override":{"peer":{"policy":"disabled"}},"tenant_restriction_rule_status":{"legacy-rule":"inactive"},"admin_authored_policies":{"peer":{"policy":{"id":"policy","tenant_id":"peer","status":"disabled"}}},"saas_tenant_restrictions":{}}`)
	if err := p.Save(authority); err != nil {
		t.Fatal(err)
	}
	before, err := p.Load()
	if err != nil {
		t.Fatal(err)
	}
	tenant := "tenant_lab_001"
	auth := newAdminAuthStore()
	auth.UpsertPrincipal(adminPrincipal{ID: "runtime-review", TenantID: tenant, Roles: []string{"admin"}, Status: "active"})
	auth.UpsertSession(adminSession{ID: "runtime-session", TenantID: tenant, AdminPrincipalID: "runtime-review", Roles: []string{"admin"}, Status: "active", ExpiresAt: time.Now().Add(time.Hour).Format(time.RFC3339), Metadata: map[string]any{adminCSRFTokenKey: "runtime-csrf"}})
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	rules := policyrule.NewStore()
	assets := assetcatalog.NewStore()
	h := newServerWithConfig(serverConfig{Writer: writer, Evaluator: testEvaluator(), AdminAuth: auth, PolicyStore: policies, RuleStore: rules, AssetStore: assets})
	assertPreserved := func(phase string) {
		t.Helper()
		after, err := p.Load()
		if err != nil || !bytes.Equal(before, after) {
			t.Fatalf("%s rewrote runtime authority: %s (err=%v)", phase, after, err)
		}
	}
	assertPreserved("startup recompile")
	for _, tc := range []struct{ method, path, body string }{{"POST", "/admin/assets/services", `{"id":"runtime-service","alias":"runtime-service","ports":[{"protocol":"tcp","port":443}]}`}, {"DELETE", "/admin/assets/services/runtime-service", ""}} {
		r := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
		r.AddCookie(&http.Cookie{Name: "admin_session", Value: "runtime-session"})
		r.Header.Set("X-CSRF-Token", "runtime-csrf")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatalf("%s: %d %s", tc.path, w.Code, w.Body)
		}
		assertPreserved(tc.method)
	}
	restored := policy.NewStore(nil)
	if err := restored.SetRuntimeStatePersister(p); err != nil {
		t.Fatal(err)
	}
	if !restored.ServerInitiatedEnabledFor("peer") || !restored.EastWestIsEnabled("peer") || len(restored.LegacyExceptionsFor("peer")) != 1 {
		t.Fatal("security controls lost on restart")
	}
	audits := readTransportAudits(t, writer)
	successes := 0
	for _, row := range audits {
		if row.EventType == "admin_asset_catalog_changed" && row.Result != nil && *row.Result == "saved" {
			successes++
		}
	}
	if successes != 2 {
		t.Fatalf("asset audits=%d; events=%+v", successes, audits)
	}
}
