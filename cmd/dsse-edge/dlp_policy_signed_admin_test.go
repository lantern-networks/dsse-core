package main

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/lantern-networks/dsse-core/agentpolicy"
	"github.com/lantern-networks/dsse-core/dlp"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDLPPolicySignedAdminLifecycle(t *testing.T) {
	prev := operatorTenantConfigured()
	t.Cleanup(func() { operatorTenantAuthority.Store(prev) })
	auth := newAdminAuthStore()
	for _, tenant := range []string{"operator", "customer"} {
		auth.UpsertPrincipal(adminPrincipal{ID: tenant, TenantID: tenant, Roles: []string{"admin"}, Status: "active"})
		auth.UpsertAPIToken(adminAPIToken{ID: tenant, TenantID: tenant, TokenHash: adminTokenHash("token-" + tenant), Roles: []string{"admin"}, Scopes: []string{"*"}, CreatedByAdminPrincipalID: tenant, Status: "active", ExpiresAt: time.Now().Add(time.Hour).Format(time.RFC3339)})
	}
	auth.UpsertAPIToken(adminAPIToken{ID: "reader", TenantID: "customer", TokenHash: adminTokenHash("token-reader"), Roles: []string{"admin"}, Scopes: []string{"admin.dlp.read"}, CreatedByAdminPrincipalID: "customer", Status: "active", ExpiresAt: time.Now().Add(time.Hour).Format(time.RFC3339)})
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	signer, err := agentpolicy.LoadOrGenerateSigner("", true)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "policies.json")
	server := httptest.NewServer(newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Writer: writer, AdminAuth: auth, OperatorTenantID: "operator", DLPPolicyObjectStorePath: path, AgentPolicySigner: signer}))
	defer server.Close()
	send := func(token, method, path, body string, want int) string {
		t.Helper()
		req, _ := http.NewRequest(method, server.URL+path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer token-"+token)
		r, err := server.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer r.Body.Close()
		b, _ := io.ReadAll(r.Body)
		if r.StatusCode != want {
			t.Fatalf("%s %s: %d want%d %s", method, path, r.StatusCode, want, b)
		}
		return string(b)
	}
	send("reader", "POST", "/admin/dlp-policies", `{}`, 403)
	send("customer", "POST", "/admin/dlp-policies", `{"expected_tenant_id":"foreign"}`, 409)
	send("customer", "DELETE", "/admin/dlp-policies?id=protect&expected_tenant_id=foreign", "", 409)
	foreign := policyLibraryFixture("operator", "foreign")
	raw, _ := json.Marshal(foreign)
	send("operator", "POST", "/admin/dlp-policies", string(raw), 200)
	src := configBundleSource{url: server.URL, client: server.Client(), token: "token-customer", tenantID: "customer", verifyPubKeyHex: signer.PublicKeyHex(), requireSigned: true}
	before, err := src.fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	edge := dlpStoresForTest("edge")
	cfg, _ := newDLPTestConfig(t)
	cfg.DLPPolicies = edge.policies
	for _, phase := range []string{"create", "observe", "disable", "enable", "delete"} {
		obj := policyLibraryFixture("customer", "protect")
		if phase == "observe" {
			obj.OnMatch = "observe"
			obj.Name = "Edited"
		}
		if phase == "disable" {
			obj.Status = "disabled"
		}
		if phase == "delete" {
			send("customer", "DELETE", "/admin/dlp-policies?id=protect", "", 200)
		} else {
			raw, _ := json.Marshal(obj)
			send("customer", "POST", "/admin/dlp-policies", string(raw), 200)
		}
		got := send("reader", "GET", "/admin/dlp-policies", "", 200)
		if phase != "delete" && !strings.Contains(got, obj.Status) {
			t.Fatal("saved state not returned")
		}
		if strings.Contains(got, "foreign") {
			t.Fatal("foreign policy disclosed")
		}
		bundle, err := src.fetch(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if bundle.Generation <= before.Generation || bundle.DLP == nil {
			t.Fatal("policy edit missing from bundle")
		}
		if _, ok := bundle.DLP.Policies["operator"]; ok {
			t.Fatal("foreign policy in scoped bundle")
		}
		if err := edge.Apply(bundle.DLP); err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest("POST", "https://example.invalid/upload", strings.NewReader("4111111111111111"))
		req.Header.Set("Content-Type", "text/plain")
		installEdgeSWGHTTPEgressDLP(req, cfg, model.AccessDecision{TenantID: "customer", Actions: []model.DecisionAction{{Type: "dlp_inspect", Metadata: map[string]any{"dlp_policy_id": "protect"}}}})
		_, err = io.ReadAll(req.Body)
		block := phase == "create" || phase == "enable"
		if block && !errors.Is(err, dlp.ErrBlocked) || !block && err != nil {
			t.Fatalf("%s upload outcome: %v", phase, err)
		}
		before = bundle
	}
	auditCount := 0
	for _, row := range readConnectorManagementAudits(t, writer) {
		if row.EventType != "admin_config_change" || row.TenantID != "customer" || row.Metadata["path"] != "/admin/dlp-policies" || stringPtrValue(row.Result) != "success" {
			continue
		}
		auditCount++
		if stringPtrValue(row.ActorUserID) != "customer" {
			t.Fatal("missing audit actor")
		}
	}
	if auditCount != 5 {
		t.Fatalf("success audits=%d", auditCount)
	}
}
