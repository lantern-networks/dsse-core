package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/agentpolicy"
	"github.com/lantern-networks/dsse-core/appcatalog"
	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/policy"
	"github.com/lantern-networks/dsse-core/policyrule"
)

func TestAdminUpstreamTLSTenantAuthorizationDurabilityAndAudit(t *testing.T) {
	declareOperatorTenantForTest(t, "operator")
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	disk := &managedTRFailingPersister{FilePersister: blobstore.FilePersister{Path: filepath.Join(t.TempDir(), "runtime.json")}}
	store := policy.NewStore(nil)
	if err := store.SetRuntimeStatePersister(disk); err != nil {
		t.Fatal(err)
	}
	auth := newAdminAuthStore()
	now := time.Now()
	for _, seat := range []struct {
		id, tenant    string
		roles, scopes []string
	}{
		{"one", "one", []string{"admin"}, []string{"*"}},
		{"two", "two", []string{"admin"}, []string{"*"}},
		{"reader", "one", []string{"analyst"}, []string{"*"}},
		{"scoped", "one", []string{"admin"}, []string{"admin.policy.read"}},
		{"operator", "operator", []string{"admin", "super_admin"}, []string{"*"}},
	} {
		auth.UpsertPrincipal(adminPrincipal{ID: seat.id, TenantID: seat.tenant, Roles: seat.roles, Status: "active"})
		auth.UpsertAPIToken(adminAPIToken{ID: seat.id, TenantID: seat.tenant, Roles: seat.roles, Scopes: seat.scopes, TokenHash: adminTokenHash("test-" + seat.id), CreatedByAdminPrincipalID: seat.id, Status: "active", ExpiresAt: now.Add(time.Hour).Format(time.RFC3339)})
	}
	config := serverConfig{Evaluator: testEvaluator(), Writer: writer, AdminAuth: auth, PolicyStore: store, OperatorTenantID: "operator", LabMode: boolPtr(false)}
	h := newServerWithConfig(config)
	call := func(method, path, body, actor, operate string, want int) upstreamTLSResponse {
		t.Helper()
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		if actor != "" {
			r.Header.Set("Authorization", "Bearer test-"+actor)
		}
		if operate != "" {
			r.Header.Set("X-Operate-Tenant", operate)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != want {
			t.Fatalf("%s %s %s: %d want %d: %s", method, path, actor, w.Code, want, w.Body)
		}
		if strings.Contains(w.Body.String(), "private-storage-detail") {
			t.Fatal("storage detail exposed")
		}
		var result upstreamTLSResponse
		if want == 200 {
			if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
		}
		return result
	}
	path := "/admin/upstream-tls"
	call("GET", path, "", "", "", 401)
	initial := call("GET", path, "", "one", "", 200)
	if initial.Mode != policy.UpstreamTLSBrowserCompatible || initial.TenantID != "one" || initial.Scope != "tenant" || !initial.Configurable {
		t.Fatal("initial contract", initial)
	}
	for _, actor := range []string{"reader", "scoped"} {
		if call("GET", path, "", actor, "", 200).Configurable {
			t.Fatal("read-only actor marked configurable")
		}
		call("POST", path, `{"mode":"strict"}`, actor, "", 403)
	}
	call("GET", path, "", "one", "two", 403)
	call("POST", path, `{"mode":"strict"}`, "one", "two", 403)
	call("GET", path+"?tenant_id=two", "", "one", "", 403)
	call("GET", path, "", "operator", "", 400)
	for _, body := range []string{`{}`, `{"mode":""}`, `{"mode":"unknown"}`, `{"mode":"browser_compatible","tenant_id":"two"}`, `{"mode":"browser_compatible"}{"mode":"strict"}`} {
		call("POST", path, body, "one", "", 400)
	}
	before := store.ConfigGeneration()
	disk.fail = true
	call("POST", path, `{"mode":"strict"}`, "one", "", 503)
	if store.ConfigGeneration() != before || store.UpstreamTLSModeFor("one") != policy.UpstreamTLSBrowserCompatible {
		t.Fatal("failed save published")
	}
	disk.fail = false
	saved := call("POST", path, `{"mode":"strict"}`, "one", "", 200)
	if saved.Mode != policy.UpstreamTLSStrict || !saved.Configurable || saved.TenantID != "one" {
		t.Fatal("save response", saved)
	}
	if call("GET", path, "", "two", "", 200).Mode != policy.UpstreamTLSBrowserCompatible {
		t.Fatal("cross-tenant mutation")
	}
	fresh := policy.NewStore(nil)
	if err := fresh.SetRuntimeStatePersister(disk); err != nil {
		t.Fatal(err)
	}
	if fresh.UpstreamTLSModeFor("one") != policy.UpstreamTLSStrict {
		t.Fatal("save not durable")
	}
	rows := readTransportAudits(t, writer)
	savedAudits, failedAudits := 0, 0
	for _, row := range rows {
		if row.EventType == "admin_upstream_tls_updated" {
			if row.TenantID != "one" || stringPtrValue(row.ActorUserID) != "one" || row.Metadata["mode"] != "strict" || row.Metadata["scope"] != "tenant" {
				t.Fatal("audit binding")
			}
			if stringPtrValue(row.Result) == "saved" {
				savedAudits++
			} else if stringPtrValue(row.Result) == "persistence_unconfirmed" {
				failedAudits++
			}
		}
	}
	if savedAudits != 1 || failedAudits != 1 {
		t.Fatal("audit coverage", savedAudits, failedAudits)
	}
	// Config followers and standby control planes cannot author their local copy.
	config.ConfigSourceURL = "https://cp.invalid"
	h = newServerWithConfig(config)
	if call("GET", path, "", "one", "", 200).Configurable {
		t.Fatal("follower configurable")
	}
	call("POST", path, `{"mode":"strict"}`, "one", "", 409)
	config.ConfigSourceURL = ""
	old := cpLeaderElectorInstance
	cpLeaderElectorInstance = &cpLeaderElector{}
	t.Cleanup(func() { cpLeaderElectorInstance = old })
	h = newServerWithConfig(config)
	if call("GET", path, "", "one", "", 200).Configurable {
		t.Fatal("standby configurable")
	}
	call("POST", path, `{"mode":"strict"}`, "one", "", 503)
}

func TestUpstreamTLSSignedBundleAllTenantsResetAndInvalid(t *testing.T) {
	cp := policy.NewStore(nil)
	if err := cp.SetRuntimeStatePath(filepath.Join(t.TempDir(), "cp.json")); err != nil {
		t.Fatal(err)
	}
	if err := cp.SetUpstreamTLSModeConfirmed("mode-only", policy.UpstreamTLSBrowserCompatible); err != nil {
		t.Fatal(err)
	}
	signer, err := agentpolicy.LoadOrGenerateSigner("", true)
	if err != nil {
		t.Fatal(err)
	}
	auth := newAdminAuthStore()
	tenant := testEvaluator().PolicyBundle.TenantID
	declareOperatorTenantForTest(t, tenant)
	auth.UpsertPrincipal(adminPrincipal{ID: "fleet", TenantID: tenant, Roles: []string{"admin"}, Status: "active"})
	auth.UpsertAPIToken(adminAPIToken{ID: "fleet", TenantID: tenant, Roles: []string{"admin"}, Scopes: []string{"admin.policy.read"}, TokenHash: adminTokenHash("test-token"), CreatedByAdminPrincipalID: "fleet", Status: "active", ExpiresAt: time.Now().Add(time.Hour).Format(time.RFC3339)})
	h := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), PolicyStore: cp, AdminAuth: auth, OperatorTenantID: tenant, LabMode: boolPtr(false), AgentPolicySigner: signer})
	srv := httptest.NewServer(h)
	defer srv.Close()
	source := configBundleSource{tenantID: testEvaluator().PolicyBundle.TenantID, url: srv.URL, client: srv.Client(), token: "test-token", verifyPubKeyHex: signer.PublicKeyHex(), requireSigned: true}
	payload, err := source.fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, section := range payload.TenantPolicies {
		if section.TenantID == "mode-only" && section.Config != nil && section.Config.UpstreamTLSMode == policy.UpstreamTLSBrowserCompatible {
			found = true
		}
	}
	if !found {
		t.Fatal("mode-only tenant omitted from signed CP bundle")
	}
	edge := policy.NewStore(nil)
	targets := configApplyTargets{policyStore: edge, rules: policyrule.NewStore(), applications: appcatalog.NewStore(), dlp: dlpStoresForTest("upstream-tls")}
	if _, err := source.apply(payload, targets); err != nil {
		t.Fatal(err)
	}
	if edge.UpstreamTLSModeFor("mode-only") != policy.UpstreamTLSBrowserCompatible {
		t.Fatal("signed config not applied")
	}
	strict := policy.TenantConfigBundle{UpstreamTLSMode: policy.UpstreamTLSStrict}
	invalid := policy.TenantConfigBundle{UpstreamTLSMode: "unknown"}
	bad := configBundlePayload{TenantPolicies: []tenantPolicySection{{TenantID: "mode-only", Config: &strict}, {TenantID: "other", Config: &invalid}}}
	before := edge.ConfigGeneration()
	if _, err := source.apply(bad, configApplyTargets{policyStore: edge}); err == nil {
		t.Fatal("unknown mode accepted")
	}
	if edge.ConfigGeneration() != before || edge.UpstreamTLSModeFor("mode-only") != policy.UpstreamTLSBrowserCompatible {
		t.Fatal("invalid bundle partially applied")
	}
	if err := cp.SetUpstreamTLSModeConfirmed("mode-only", policy.UpstreamTLSStrict); err != nil {
		t.Fatal(err)
	}
	payload, err = source.fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := source.apply(payload, targets); err != nil {
		t.Fatal(err)
	}
	if edge.UpstreamTLSModeFor("mode-only") != policy.UpstreamTLSStrict {
		t.Fatal("strict reset not delivered")
	}
}

func TestAdminUpstreamTLSRequiresSessionCSRFAndErasesTenant(t *testing.T) {
	declareOperatorTenantForTest(t, "operator")
	store := policy.NewStore(nil)
	path := filepath.Join(t.TempDir(), "runtime.json")
	if err := store.SetRuntimeStatePath(path); err != nil {
		t.Fatal(err)
	}
	auth := newAdminAuthStore()
	now := time.Now()
	auth.UpsertPrincipal(adminPrincipal{ID: "admin", TenantID: "customer", Roles: []string{"admin"}, Status: "active"})
	auth.UpsertSession(adminSession{ID: "session", TenantID: "customer", AdminPrincipalID: "admin", Roles: []string{"admin"}, Status: "active", ExpiresAt: now.Add(time.Hour).Format(time.RFC3339), MFAState: "fresh", Metadata: map[string]any{adminCSRFTokenKey: "csrf-test"}})
	h := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), PolicyStore: store, AdminAuth: auth, OperatorTenantID: "operator", LabMode: boolPtr(false)})
	for _, tc := range []struct {
		csrf string
		want int
	}{{"", 403}, {"wrong", 403}, {"csrf-test", 200}} {
		r := httptest.NewRequest("POST", "/admin/upstream-tls", strings.NewReader(`{"mode":"strict"}`))
		r.AddCookie(&http.Cookie{Name: "admin_session", Value: "session"})
		r.Header.Set("X-CSRF-Token", tc.csrf)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != tc.want {
			t.Fatalf("csrf %q: %d %s", tc.csrf, w.Code, w.Body)
		}
	}
	if err := store.SetUpstreamTLSModeConfirmed("other", policy.UpstreamTLSStrict); err != nil {
		t.Fatal(err)
	}
	extra := adminTenantExtraStores{UpstreamTLS: store}
	result := adminTenantPurgeResult{TenantID: "customer"}
	extra.erase(&result)
	if len(result.Failures) != 0 {
		t.Fatal(result.Failures)
	}
	fresh := policy.NewStore(nil)
	if err := fresh.SetRuntimeStatePath(path); err != nil {
		t.Fatal(err)
	}
	if fresh.UpstreamTLSModeFor("customer") != policy.UpstreamTLSDefault || fresh.UpstreamTLSModeFor("other") != policy.UpstreamTLSStrict {
		t.Fatal("tenant erasure crossed boundary or was not durable")
	}
}
