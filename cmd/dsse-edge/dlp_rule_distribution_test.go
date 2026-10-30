package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/agentpolicy"
	"github.com/lantern-networks/dsse-core/logs"
)

func TestAdminDLPRulesReachFleetBundle(t *testing.T) {
	previous := operatorTenantConfigured()
	t.Cleanup(func() { operatorTenantAuthority.Store(previous) })
	auth := newAdminAuthStore()
	auth.UpsertPrincipal(adminPrincipal{ID: "operator", TenantID: "operator", Roles: []string{"admin"}, Status: "active"})
	auth.UpsertAPIToken(adminAPIToken{ID: "operator", TenantID: "operator", TokenHash: adminTokenHash("fleet-token"), Roles: []string{"admin"}, Scopes: []string{"admin.policy.read", "admin.dlp.write"}, CreatedByAdminPrincipalID: "operator", Status: "active", ExpiresAt: time.Now().Add(time.Hour).Format(time.RFC3339)})
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	signer, err := agentpolicy.LoadOrGenerateSigner("", true)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Writer: writer, AdminAuth: auth, OperatorTenantID: "operator", AgentPolicySigner: signer}))
	defer server.Close()
	request, err := http.NewRequest(http.MethodPost, server.URL+"/admin/dlp-rules", strings.NewReader(`{"rules":[{"id":"r1","saas_application_id":"saas_openai_chatgpt","identifiers":["credit_card"],"on_match":"block"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer fleet-token")
	request.Header.Set("Content-Type", "application/json")
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("rule write status %d", response.StatusCode)
	}
	src := configBundleSource{url: server.URL, client: server.Client(), token: "fleet-token", tenantID: "operator", verifyPubKeyHex: signer.PublicKeyHex(), requireSigned: true}
	bundle, err := src.fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if bundle.DLP == nil {
		t.Fatal("DLP section absent")
	}
	// Inspect the wire shape here so this regression fails even before the
	// receiver's rule field exists in the product implementation.
	raw, err := json.Marshal(bundle.DLP)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"rules"`) || !strings.Contains(string(raw), `"r1"`) {
		t.Fatal("acknowledged DLP rule missing from signed fleet bundle")
	}
}
