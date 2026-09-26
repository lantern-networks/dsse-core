package main

import (
	"context"
	"encoding/json"
	"github.com/lantern-networks/dsse-core/agentpolicy"
	"github.com/lantern-networks/dsse-core/delegatedgrant"
	"github.com/lantern-networks/dsse-core/logs"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDelegatedGrantSignedAdminLifecycle(t *testing.T) {
	prev := operatorTenantConfigured()
	t.Cleanup(func() { operatorTenantAuthority.Store(prev) })
	auth := newAdminAuthStore()
	for _, tenant := range []string{"operator", "own", "foreign"} {
		auth.UpsertPrincipal(adminPrincipal{ID: tenant, TenantID: tenant, Roles: []string{"admin"}, Status: "active"})
		auth.UpsertAPIToken(adminAPIToken{ID: tenant, TenantID: tenant, TokenHash: adminTokenHash("token-" + tenant), Roles: []string{"admin"}, Scopes: []string{"*"}, CreatedByAdminPrincipalID: tenant, Status: "active", ExpiresAt: time.Now().Add(time.Hour).Format(time.RFC3339)})
	}
	auth.UpsertAPIToken(adminAPIToken{ID: "reader", TenantID: "own", TokenHash: adminTokenHash("token-reader"), Roles: []string{"admin"}, Scopes: []string{"admin.delegated_grants.read"}, CreatedByAdminPrincipalID: "own", Status: "active", ExpiresAt: time.Now().Add(time.Hour).Format(time.RFC3339)})
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	signer, err := agentpolicy.LoadOrGenerateSigner("", true)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Writer: writer, AdminAuth: auth, OperatorTenantID: "operator", DelegatedGrantStorePath: filepath.Join(t.TempDir(), "grants.json"), AgentPolicySigner: signer}))
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
			t.Fatalf("%s %s: %d want%d", method, path, r.StatusCode, want)
		}
		return string(b)
	}
	send("reader", "POST", "/admin/delegated-grants", `{}`, 403)
	send("reader", "POST", "/admin/delegated-grants/same/revoke", `{}`, 403)
	send("own", "POST", "/admin/delegated-grants", `{"id":"same","tenant_id":"foreign","subject_user_id":"person","actor_nhi_id":"agent"}`, 400)
	for _, tenant := range []string{"own", "foreign"} {
		g := adminDelegatedAccessGrantFromModel(delegatedFixture(tenant, "same"))
		raw, _ := json.Marshal(g)
		send(tenant, "POST", "/admin/delegated-grants", string(raw), 200)
	}
	src := configBundleSource{url: server.URL, client: server.Client(), token: "token-operator", tenantID: "operator", verifyPubKeyHex: signer.PublicKeyHex(), requireSigned: true}
	before, err := src.fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	edge := delegatedgrant.NewStore(0)
	p := &allowlistSaveFixture{}
	if err := edge.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	receiver := configBundleSource{}
	targets := configApplyTargets{delegatedGrants: edge}
	if _, err := receiver.apply(configBundlePayload{DelegatedGrants: before.DelegatedGrants}, targets); err != nil {
		t.Fatal(err)
	}
	for _, phase := range []string{"edit", "revoke"} {
		if phase == "edit" {
			g := adminDelegatedAccessGrantFromModel(delegatedFixture("own", "same"))
			g.Scopes = []string{"read", "write"}
			raw, _ := json.Marshal(g)
			send("own", "POST", "/admin/delegated-grants", string(raw), 200)
		} else {
			send("own", "POST", "/admin/delegated-grants/same/revoke", `{"revocation_reason_code":"requested"}`, 200)
		}
		state := send("reader", "GET", "/admin/delegated-grants/same", "", 200)
		if strings.Contains(state, `"tenant_id":"foreign"`) {
			t.Fatal("foreign grant disclosed")
		}
		bundle, err := src.fetch(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if bundle.Generation <= before.Generation || bundle.DelegatedGrants == nil {
			t.Fatal("grant edit/revocation not distributed")
		}
		if _, err := receiver.apply(configBundlePayload{DelegatedGrants: bundle.DelegatedGrants}, targets); err != nil {
			t.Fatal(err)
		}
		fresh := delegatedgrant.NewStore(0)
		if err := fresh.SetPersister(p); err != nil {
			t.Fatal(err)
		}
		own, ok := fresh.GetForTenant("own", "same")
		if !ok {
			t.Fatal("own grant absent")
		}
		if phase == "edit" && len(own.Scopes) != 2 || phase == "revoke" && delegatedgrant.IsActive(own, time.Now()) {
			t.Fatal("received own grant incorrect")
		}
		other, ok := fresh.GetForTenant("foreign", "same")
		if !ok || !delegatedgrant.IsActive(other, time.Now()) || len(other.Scopes) != 1 {
			t.Fatal("foreign same-ID grant changed")
		}
		before = bundle
	}
	count := 0
	for _, row := range readConnectorManagementAudits(t, writer) {
		if strings.HasPrefix(row.EventType, "admin_delegated_access_grant_") {
			count++
			if stringPtrValue(row.ActorUserID) != row.TenantID {
				t.Fatal("audit actor or target incorrect")
			}
		}
	}
	if count != 4 {
		t.Fatal("missing successful grant audits", count)
	}
}
