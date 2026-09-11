package main

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/agentpolicy"
	"github.com/lantern-networks/dsse-core/appcatalog"
	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/dlp"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/policy"
)

// Use the installer's actual role/scope shape through authentication, the signed
// publishing route and verified fetch, then enforce on a receiving runtime.
func TestConfigBundleFleetTokenReceivesCustomerDLP(t *testing.T) {
	previous := operatorTenantConfigured()
	t.Cleanup(func() { operatorTenantAuthority.Store(previous) })
	auth := newAdminAuthStore()
	for _, tenant := range []string{"operator", "customer"} {
		auth.UpsertPrincipal(adminPrincipal{ID: tenant, TenantID: tenant, Roles: []string{"admin"}, Status: "active"})
		auth.UpsertAPIToken(adminAPIToken{ID: tenant, TenantID: tenant, TokenHash: adminTokenHash("token-" + tenant), Roles: []string{"admin"}, Scopes: []string{"admin.policy.read"}, CreatedByAdminPrincipalID: tenant, Status: "active", ExpiresAt: time.Now().Add(time.Hour).Format(time.RFC3339)})
	}
	path := filepath.Join(t.TempDir(), "dlp.json")
	store := newDLPPolicyObjectStore()
	if err := store.SetPersister(blobstore.FilePersister{Path: path}); err != nil {
		t.Fatal(err)
	}
	for _, tenant := range []string{"customer", "other"} {
		store.Upsert(model.DLPPolicyObject{ID: "protect", TenantID: tenant, Name: "Protect", Identifiers: []string{"credit_card"}, OnMatch: "block", Status: "active"})
	}
	if err := store.PersistIfDirty(); err != nil {
		t.Fatal(err)
	}
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	signer, err := agentpolicy.LoadOrGenerateSigner("", true)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Writer: writer, AdminAuth: auth, OperatorTenantID: "operator", DLPPolicyObjectStorePath: path, AgentPolicySigner: signer}))
	defer server.Close()
	for _, tenant := range []string{"operator", "customer"} {
		src := configBundleSource{url: server.URL, client: server.Client(), token: "token-" + tenant, tenantID: tenant, verifyPubKeyHex: signer.PublicKeyHex(), requireSigned: true}
		bundle, err := src.fetch(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if bundle.DLP == nil {
			t.Fatal("DLP absent")
		}
		want := 2
		if tenant == "customer" {
			want = 1
		}
		if len(bundle.DLP.Policies) != want {
			t.Fatalf("%s received %d tenant policies, want %d", tenant, len(bundle.DLP.Policies), want)
		}
		if tenant == "customer" {
			if _, ok := bundle.DLP.Policies["other"]; ok {
				t.Fatal("customer received another customer's DLP")
			}
			continue
		}
		receiving := dlpStoresForTest("edge-salt")
		if _, err := src.apply(bundle, configApplyTargets{applications: appcatalog.NewStore(), policyStore: policy.NewStore(nil), dlp: receiving}); err != nil {
			t.Fatal(err)
		}
		cfg, _ := newDLPTestConfig(t)
		cfg.DLPPolicies = receiving.policies
		req := httptest.NewRequest(http.MethodPost, "https://ai.example.test/upload", strings.NewReader(`{"text":"4111111111111111"}`))
		req.Header.Set("Content-Type", "application/json")
		installEdgeSWGHTTPEgressDLP(req, cfg, model.AccessDecision{TenantID: "customer", Actions: []model.DecisionAction{{Type: "dlp_inspect", Metadata: map[string]any{"dlp_policy_id": "protect"}}}})
		if _, err := io.ReadAll(req.Body); !errors.Is(err, dlp.ErrBlocked) {
			t.Fatalf("fleet-delivered policy did not block: %v", err)
		}
	}
}
