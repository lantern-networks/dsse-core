package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/logs"
)

func TestAdminIdPSaveOutcomesAndAudit(t *testing.T) {
	auth := newAdminAuthStore()
	auth.UpsertPrincipal(adminPrincipal{ID: "idp-admin", TenantID: "tenant_lab_001", Roles: []string{"admin"}, Status: "active"})
	auth.UpsertAPIToken(adminAPIToken{ID: "fixture", TenantID: "tenant_lab_001", TokenHash: adminTokenHash("idp-test-token"), CreatedByAdminPrincipalID: "idp-admin", Roles: []string{"admin"}, Scopes: []string{"*"}, Status: "active", ExpiresAt: time.Now().Add(time.Hour).Format(time.RFC3339)})
	writer, e := logs.NewWriter(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	h := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Writer: writer, AdminAuth: auth})
	store := theIdPRegistry.Load()
	p := &riskAuditPersister{base: blobstore.FilePersister{Path: filepath.Join(t.TempDir(), "idp.json")}}
	if e := store.SetPersister(p); e != nil {
		t.Fatal(e)
	}
	request := func(method, path, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer idp-test-token")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	body := func(id, name string) string {
		b, _ := json.Marshal(map[string]any{"idp_id": id, "display_name": name, "type": "oidc", "issuer": "https://idp.invalid", "authorization_endpoint": "https://idp.invalid/auth", "client_id": "client", "client_secret": "private-client-secret"})
		return string(b)
	}
	if r := request("POST", "/admin/idp-connections", body("a", "a")); r.Code != 200 || strings.Contains(r.Body.String(), "private-client-secret") {
		t.Fatalf("create: %d %s", r.Code, r.Body.String())
	}
	for _, tc := range []struct{ method, path, body string }{{"POST", "/admin/idp-connections", body("b", "b")}, {"POST", "/admin/idp-connections", body("b", "changed")}, {"POST", "/admin/idp-connections/b/default", `{}`}, {"DELETE", "/admin/idp-connections/a", `{}`}} {
		generation := store.ConfigGeneration()
		before, _ := p.Load()
		domain := 0
		for _, r := range readTransportAudits(t, writer) {
			if strings.HasPrefix(r.EventType, "idp_connection_") {
				domain++
			}
		}
		p.fail.Store(true)
		rec := request(tc.method, tc.path, tc.body)
		if rec.Code != 500 || strings.Contains(rec.Body.String(), "private-runtime-location") {
			t.Fatalf("failure: %d %s", rec.Code, rec.Body.String())
		}
		after, _ := p.Load()
		if string(before) != string(after) || store.ConfigGeneration() != generation {
			t.Fatal("failed write changed state")
		}
		rows := readTransportAudits(t, writer)
		n := 0
		for _, r := range rows {
			if strings.HasPrefix(r.EventType, "idp_connection_") {
				n++
			}
		}
		if n != domain {
			t.Fatal("success domain for rejected save")
		}
		p.fail.Store(false)
		rec = request(tc.method, tc.path, tc.body)
		if rec.Code != 200 || strings.Contains(rec.Body.String(), "private-client-secret") {
			t.Fatalf("accepted: %d %s", rec.Code, rec.Body.String())
		}
	}
	if rec := request(http.MethodGet, "/admin/idp-connections", ""); strings.Contains(rec.Body.String(), "private-client-secret") {
		t.Fatal("secret in list")
	}
	rows := readTransportAudits(t, writer)
	domains, errors := 0, 0
	for _, r := range rows {
		b, _ := json.Marshal(r)
		if strings.Contains(string(b), "private-client-secret") || strings.Contains(string(b), "idp-test-token") || strings.Contains(string(b), "https://idp.invalid") {
			t.Fatal("secret/endpoint in audit")
		}
		if strings.HasPrefix(r.EventType, "idp_connection_") {
			domains++
			if stringPtrValue(r.ActorUserID) != "idp-admin" || r.TenantID != "tenant_lab_001" || stringPtrValue(r.TargetID) == "" || stringPtrValue(r.Result) != "success" {
				t.Fatalf("attribution %+v", r)
			}
		}
		if r.EventType == "admin_config_change" && stringPtrValue(r.Result) == "error" {
			errors++
		}
	}
	if domains != 5 || errors != 4 || len(rows) != 14 {
		t.Fatalf("audit totals %d %d %d", domains, errors, len(rows))
	}
}

func TestAdminIdPAuditAttributionAndPrivacyInvariant(t *testing.T) {
	now := time.Now().UTC()
	for _, tenant := range []string{"tenant_lab_001", "customer"} {
		for _, action := range []string{"upserted", "default_set", "deleted"} {
			req := httptest.NewRequest(http.MethodPost, "/admin/idp-connections", strings.NewReader(`{"client_secret":"private-idp-body","ca_pem":"private-idp-ca"}`))
			req.Header.Set("Authorization", "Bearer private-idp-header")
			req.Header.Set("Cookie", "admin_session=private-idp-cookie")
			req.Header.Set("X-CSRF-Token", "private-idp-csrf")
			req = requestWithAdminIdentity(req, adminIdentity{PrincipalID: "idp-admin", TenantID: "tenant_lab_001"})
			audit := adminIdPChangeAuditLog(req, tenant, "idp_a", action, testEvaluator(), now)
			if stringPtrValue(audit.ActorUserID) != "idp-admin" || audit.TenantID != tenant || stringPtrValue(audit.TargetID) != "idp_a" || stringPtrValue(audit.Result) != "success" {
				t.Fatalf("missing attribution: %+v", audit)
			}
			if tenant != "tenant_lab_001" && (audit.Metadata["operator_principal_id"] != "idp-admin" || audit.Metadata["operator_tenant_id"] != "tenant_lab_001") {
				t.Fatal("missing operator provenance")
			}
			// The administrator's ID is intentional. Keep the shared invariant unchanged for all other fields.
			audit.ActorUserID = nil
			assertAuditLogNonSecretInvariant(t, audit, []string{"private-idp-body", "private-idp-ca", "private-idp-header", "private-idp-cookie", "private-idp-csrf"})
		}
	}
}
