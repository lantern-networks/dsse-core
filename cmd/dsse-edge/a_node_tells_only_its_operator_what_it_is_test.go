package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/logs"
)

// operatorAndCustomerTokens is a store holding one API token in the operator's organization and one in a
// customer's, both with every read scope a reader would hold.
func operatorAndCustomerTokens() *adminAuthStore {
	store := seedAdminConnectorAPITokenAuth("operator", "operator-token", []string{"admin.state.read"})
	now := time.Now().UTC()
	store.UpsertPrincipal(adminPrincipal{
		ID: "customer", TenantID: "tenant_customer", Subject: "customer", Email: "customer@example.test",
		Roles: []string{"admin"}, IDPID: "keycloak_lab", Status: "active", CreatedAt: now.Add(-time.Hour).Format(time.RFC3339),
	})
	store.UpsertAPIToken(adminAPIToken{
		ID: "customer_token", TenantID: "tenant_customer", Name: "customer-token", TokenHash: adminTokenHash("customer-token"),
		Roles: []string{"admin"}, Scopes: []string{"admin.state.read"}, CreatedByAdminPrincipalID: "customer",
		CreatedAt: now.Add(-time.Hour).Format(time.RFC3339), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339), Status: "active",
	})
	return store
}

func nodeDetailServer(t *testing.T, drain *atomic.Bool) http.Handler {
	t.Helper()
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("DSSE_NODE_NAME", "edge-a-1")
	return newServerWithConfig(serverConfig{
		Evaluator: testEvaluator(), Writer: writer, Registry: connector.NewRegistry(),
		AdminAuth: operatorAndCustomerTokens(), OperatorTenantID: "tenant_lab_001", DrainState: drain,
	})
}

func askNode(t *testing.T, h http.Handler, path, bearer string) (int, map[string]any, string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	return rec.Code, body, rec.Body.String()
}

// The entrance is open to everybody, and /healthz is reached through it with no name at all. Whoever is not the
// operator learns whether the node takes traffic — the status code and the status word — and nothing else.
func TestHealthTellsOnlyTheOperatorWhatTheNodeIs(t *testing.T) {
	h := nodeDetailServer(t, nil)

	code, operator, raw := askNode(t, h, "/healthz", "operator-token")
	if code != http.StatusOK || operator["role"] == nil || operator["machine"] != "edge-a-1" || operator["build"] == nil {
		// Without this the rest proves nothing: the fields have to exist for their absence to mean anything.
		t.Fatalf("the operator was not told what the node is: %d %s", code, raw)
	}

	for _, who := range []struct{ name, bearer string }{
		{"anonymous", ""},
		{"a customer organization's administrator", "customer-token"},
		{"a credential that resolves to nobody", "not-a-token"},
	} {
		code, body, raw := askNode(t, h, "/healthz", who.bearer)
		if code != http.StatusOK {
			t.Fatalf("%s: the status code must not depend on who asks, got %d", who.name, code)
		}
		if len(body) != 1 || body["status"] != "ok" {
			t.Fatalf("%s was told more than the status: %s", who.name, raw)
		}
		for _, leaked := range []string{"edge-a-1", "control-plane", `"edge"`, "commit"} {
			if strings.Contains(raw, leaked) {
				t.Fatalf("%s was told %q: %s", who.name, leaked, raw)
			}
		}
	}
}

// A balancer drains a node on the status code, so the 503s must stay exactly as they were for everybody.
func TestADrainingNodeSaysSoToEverybody(t *testing.T) {
	drain := &atomic.Bool{}
	drain.Store(true)
	h := nodeDetailServer(t, drain)
	for _, bearer := range []string{"", "customer-token", "operator-token"} {
		code, body, raw := askNode(t, h, "/healthz", bearer)
		if code != http.StatusServiceUnavailable || body["status"] != "draining" {
			t.Fatalf("bearer %q: a draining node must answer 503 draining, got %d %s", bearer, code, raw)
		}
	}
}

// The 503 bodies carry the reason a node cannot sign or reach its broker. Those are for the operator too.
func TestAnUnhealthyNodesReasonIsForTheOperator(t *testing.T) {
	body := map[string]any{"status": "key_custody_unhealthy", "detail": "the signing key at /keys/root is unreadable", "note": "n"}
	rec := httptest.NewRecorder()
	writeNodeHealth(rec, http.StatusServiceUnavailable, body, false)
	if rec.Code != http.StatusServiceUnavailable || strings.TrimSpace(rec.Body.String()) != `{"status":"key_custody_unhealthy"}` {
		t.Fatalf("a caller who is not the operator was told the reason: %d %s", rec.Code, rec.Body.String())
	}
	rec = httptest.NewRecorder()
	writeNodeHealth(rec, http.StatusServiceUnavailable, body, true)
	if !strings.Contains(rec.Body.String(), "unreadable") {
		t.Fatalf("the operator lost the reason: %s", rec.Body.String())
	}
}

// /metrics is on the admin listener, and the admin listener is reached through the public entrance by name.
func TestMetricsAreForTheOperator(t *testing.T) {
	h := nodeDetailServer(t, nil)
	code, _, raw := askNode(t, h, "/metrics", "operator-token")
	if code != http.StatusOK || !strings.Contains(raw, "dsse_access_decisions_total") {
		t.Fatalf("the operator could not read the metrics: %d", code)
	}
	for _, bearer := range []string{"", "customer-token", "not-a-token"} {
		code, _, raw := askNode(t, h, "/metrics", bearer)
		if code != http.StatusUnauthorized || strings.Contains(raw, "dsse_") {
			t.Fatalf("bearer %q read the metrics: %d", bearer, code)
		}
	}
}

// Every answer the /healthz handler writes goes through writeNodeHealth, and /metrics asks first. A new early
// return written with writeJSON would hand its body to anybody, and nothing else would notice.
func TestEveryHealthAnswerGoesThroughTheOperatorGate(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(src)
	start := strings.Index(text, `mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {`)
	if start < 0 {
		t.Fatal("the /healthz handler moved; point this guard at it")
	}
	end := strings.Index(text[start:], "\n\t})\n")
	if end < 0 {
		t.Fatal("could not find the end of the /healthz handler")
	}
	handler := text[start : start+end]
	if strings.Contains(handler, "writeJSON(") || strings.Contains(handler, "w.Write(") {
		t.Fatal("the /healthz handler writes an answer that does not go through writeNodeHealth")
	}
	if !strings.Contains(handler, "detailed := mayReadNodeDetail(r)") || strings.Count(handler, "writeNodeHealth(") < 5 {
		t.Fatal("the /healthz handler no longer asks who the caller is before answering")
	}
	m := strings.Index(text, `mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, r *http.Request) {`)
	if m < 0 || !strings.HasPrefix(strings.TrimSpace(text[m+len(`mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, r *http.Request) {`):]), "if !mayReadNodeDetail(r) {") {
		t.Fatal("/metrics no longer asks for the operator first")
	}
}

// A node started before any organization exists is administered with its own break-glass credential, and that
// is the deployment's owner secret — the operator's by definition, whether or not -operator-tenant-id names an
// organization yet. Unarmed, it is nobody's.
func TestTheArmedBreakGlassCredentialIsTheOperators(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	h := newServerWithConfig(serverConfig{
		Evaluator: testEvaluator(), Writer: writer, Registry: connector.NewRegistry(),
		AdminAuth: operatorAndCustomerTokens(), AdminToken: "a-break-glass-credential-longer-than-32",
	})
	if operatorTenantConfigured() != "" {
		t.Fatal("this case is about a node that names no operator organization")
	}

	previousArmed, previousConfigured := adminBreakGlass.Armed, adminBreakGlass.Configured
	t.Cleanup(func() { adminBreakGlass.Armed, adminBreakGlass.Configured = previousArmed, previousConfigured })

	adminBreakGlass.Armed, adminBreakGlass.Configured = false, true
	if _, body, raw := askNode(t, h, "/healthz", "a-break-glass-credential-longer-than-32"); len(body) != 1 {
		t.Fatalf("an unarmed break-glass credential was treated as the operator: %s", raw)
	}

	adminBreakGlass.Armed = true
	if code, body, raw := askNode(t, h, "/healthz", "a-break-glass-credential-longer-than-32"); code != http.StatusOK || body["role"] == nil {
		t.Fatalf("the armed break-glass credential was not told what the node is: %d %s", code, raw)
	}
	if _, body, raw := askNode(t, h, "/healthz", "operator-token"); len(body) != 1 {
		// With no operator organization named, a named token of some organization is not the operator.
		t.Fatalf("a named token was treated as the operator on a node that names none: %s", raw)
	}
}

// Review HEALTH-R1 (2026-11-09): belonging to the operator's organization was the whole test, so a token of that
// organization scoped to logs alone read everything /admin/state would have refused it. The gate is now the
// one /admin/state applies — the role's permission and the token's scope — on top of the organization.
func TestATokenWithoutTheStatePermissionIsToldOnlyTheStatus(t *testing.T) {
	store := operatorAndCustomerTokens()
	now := time.Now().UTC()
	store.UpsertAPIToken(adminAPIToken{
		ID: "logs_only_token", TenantID: "tenant_lab_001", Name: "logs-only", TokenHash: adminTokenHash("logs-only-token"),
		Roles: []string{"admin"}, Scopes: []string{"admin.logs.read"}, CreatedByAdminPrincipalID: "operator",
		CreatedAt: now.Add(-time.Hour).Format(time.RFC3339), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339), Status: "active",
	})
	// An analyst holds admin.state.read; a role that does not must be refused even with an unscoped session-like identity.
	store.UpsertPrincipal(adminPrincipal{
		ID: "noperm", TenantID: "tenant_lab_001", Subject: "noperm", Email: "noperm@example.test",
		Roles: []string{"no_such_role"}, IDPID: "keycloak_lab", Status: "active", CreatedAt: now.Add(-time.Hour).Format(time.RFC3339),
	})
	store.UpsertAPIToken(adminAPIToken{
		ID: "noperm_token", TenantID: "tenant_lab_001", Name: "noperm", TokenHash: adminTokenHash("noperm-token"),
		Roles: []string{"no_such_role"}, Scopes: []string{"*"}, CreatedByAdminPrincipalID: "noperm",
		CreatedAt: now.Add(-time.Hour).Format(time.RFC3339), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339), Status: "active",
	})
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	h := newServerWithConfig(serverConfig{
		Evaluator: testEvaluator(), Writer: writer, Registry: connector.NewRegistry(),
		AdminAuth: store, OperatorTenantID: "tenant_lab_001",
	})

	// The control: the same token is refused by the route whose permission this borrows.
	if code, _, _ := askNode(t, h, "/admin/state", "logs-only-token"); code != http.StatusForbidden {
		t.Fatalf("/admin/state must refuse a logs-only token with 403, got %d", code)
	}
	for _, bearer := range []string{"logs-only-token", "noperm-token"} {
		code, body, raw := askNode(t, h, "/healthz", bearer)
		if code != http.StatusOK || len(body) != 1 || body["status"] != "ok" {
			t.Fatalf("%s was told more than the status: %d %s", bearer, code, raw)
		}
		if code, _, raw := askNode(t, h, "/metrics", bearer); code != http.StatusUnauthorized || strings.Contains(raw, "dsse_") {
			t.Fatalf("%s read the metrics: %d", bearer, code)
		}
	}
	// And the token that does hold it still reads everything.
	if code, body, raw := askNode(t, h, "/healthz", "operator-token"); code != http.StatusOK || body["role"] == nil {
		t.Fatalf("the state-reading token lost the detail: %d %s", code, raw)
	}
}
