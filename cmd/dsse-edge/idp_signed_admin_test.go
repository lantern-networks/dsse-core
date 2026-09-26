package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/agentpolicy"
	"github.com/lantern-networks/dsse-core/idpregistry"
	"github.com/lantern-networks/dsse-core/logs"
)

func TestIdPSignedAdminLifecycle(t *testing.T) {
	prev := operatorTenantConfigured()
	registry := theIdPRegistry.Load()
	isCP := edgeIsControlPlane
	t.Cleanup(func() { operatorTenantAuthority.Store(prev); theIdPRegistry.Store(registry); edgeIsControlPlane = isCP })
	edgeIsControlPlane = true
	auth := newAdminAuthStore()
	for _, tenant := range []string{"operator", "customer"} {
		role := "admin"
		if tenant == "operator" {
			role = "super_admin"
		}
		auth.UpsertPrincipal(adminPrincipal{ID: tenant, TenantID: tenant, Roles: []string{role, "admin"}, Status: "active"})
		auth.UpsertAPIToken(adminAPIToken{ID: tenant, TenantID: tenant, TokenHash: adminTokenHash("token-" + tenant), Roles: []string{role, "admin"}, Scopes: []string{"*"}, CreatedByAdminPrincipalID: tenant, Status: "active", ExpiresAt: time.Now().Add(time.Hour).Format(time.RFC3339)})
	}
	auth.UpsertAPIToken(adminAPIToken{ID: "reader", TenantID: "customer", TokenHash: adminTokenHash("token-reader"), Roles: []string{"admin"}, Scopes: []string{"admin.idp.read"}, CreatedByAdminPrincipalID: "customer", Status: "active", ExpiresAt: time.Now().Add(time.Hour).Format(time.RFC3339)})
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	signer, err := agentpolicy.LoadOrGenerateSigner("", true)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "idp.json")
	server := httptest.NewServer(newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Writer: writer, AdminAuth: auth, OperatorTenantID: "operator", IdPConnectionStorePath: path, AgentPolicySigner: signer}))
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
			t.Fatalf("%s %s: status=%d want=%d", method, path, r.StatusCode, want)
		}
		if strings.Contains(string(b), "synthetic-idp-secret") {
			t.Fatal("secret in management response")
		}
		return string(b)
	}
	for _, op := range []struct{ method, path string }{{"POST", "/admin/idp-connections"}, {"POST", "/admin/idp-connections/first/default"}, {"DELETE", "/admin/idp-connections/first"}} {
		send("reader", op.method, op.path, `{}`, 403)
	}
	c := idpFixture("foreign", "no")
	raw, _ := json.Marshal(c)
	send("customer", "POST", "/admin/idp-connections", string(raw), 403)
	c = idpFixture("customer", "first")
	c.ClientSecret = "synthetic-idp-secret"
	raw, _ = json.Marshal(c)
	send("operator", "POST", "/admin/idp-connections", string(raw), 200)
	if !strings.Contains(send("reader", "GET", "/admin/idp-connections", "", 200), "first") {
		t.Fatal("operator target tenant incorrect")
	}
	src := configBundleSource{url: server.URL, client: server.Client(), token: "token-operator", tenantID: "operator", verifyPubKeyHex: signer.PublicKeyHex(), requireSigned: true}
	before, err := src.fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	edge := idpregistry.NewStore()
	ep := &allowlistSaveFixture{}
	if err := edge.SetPersister(ep); err != nil {
		t.Fatal(err)
	}
	for _, phase := range []string{"edit", "add", "default", "delete-first", "delete-last"} {
		switch phase {
		case "edit":
			c.ClientSecret = ""
			c.DisplayName = "Edited"
			raw, _ = json.Marshal(c)
			send("customer", "POST", "/admin/idp-connections", string(raw), 200)
		case "add":
			raw, _ = json.Marshal(idpFixture("customer", "second"))
			send("customer", "POST", "/admin/idp-connections", string(raw), 200)
		case "default":
			send("customer", "POST", "/admin/idp-connections/second/default", "", 200)
		case "delete-first":
			send("customer", "DELETE", "/admin/idp-connections/first", "", 200)
		case "delete-last":
			send("customer", "DELETE", "/admin/idp-connections/second", "", 200)
		}
		send("reader", "GET", "/admin/idp-connections", "", 200)
		bundle, err := src.fetch(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if bundle.Generation <= before.Generation || bundle.IdPConnections == nil || !bundle.IdPConnections.Complete {
			t.Fatal("changed IdP absent from signed bundle")
		}
		if _, _, err := applyIdPConnectionBundleSectionChecked(edge, bundle.IdPConnections); err != nil {
			t.Fatal(err)
		}
		fresh := idpregistry.NewStore()
		if err := fresh.SetPersister(ep); err != nil {
			t.Fatal(err)
		}
		switch phase {
		case "edit":
			got, _ := fresh.Get("customer", "first")
			if got.DisplayName != "Edited" || got.ClientSecret != "synthetic-idp-secret" {
				t.Fatal("edit or blank secret retention lost")
			}
		case "default":
			got, ok := fresh.Default("customer")
			if !ok || got.IdPID != "second" {
				t.Fatal("default not carried")
			}
		case "delete-last":
			if len(fresh.ListAll()) != 0 {
				t.Fatal("last deletion not carried")
			}
		}
		before = bundle
	}
	count := 0
	for _, row := range readConnectorManagementAudits(t, writer) {
		if !strings.HasPrefix(row.EventType, "idp_connection_") {
			continue
		}
		count++
		if row.TenantID != "customer" || stringPtrValue(row.Result) != "success" || stringPtrValue(row.ActorUserID) == "" {
			t.Fatal("audit target or actor incorrect")
		}
		raw, _ := json.Marshal(row)
		if strings.Contains(string(raw), "synthetic-idp-secret") || strings.Contains(string(raw), "idp.example.invalid") {
			t.Fatal("audit contains connection credentials or endpoints")
		}
	}
	if count != 6 {
		t.Fatalf("success audits=%d want6", count)
	}
}
