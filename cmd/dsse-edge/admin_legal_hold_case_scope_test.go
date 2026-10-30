package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/logs"
)

func TestLegalHoldListDoesNotMergeCaseDistinctTenants(t *testing.T) {
	now := time.Now().UTC()
	holds := newLegalHoldStore(nil)
	for _, entry := range []struct{ tenant, actor, reason string }{
		{"Acme", "upper-admin", "upper-case-matter"},
		{"acme", "lower-admin", "lower-case-matter"},
	} {
		if err := holds.Set(entry.tenant, entry.actor, entry.reason, true, now); err != nil {
			t.Fatal(err)
		}
	}
	auth := newAdminAuthStore()
	for _, tenant := range []string{"Acme", "acme"} {
		auth.UpsertPrincipal(adminPrincipal{ID: tenant + "-admin", TenantID: tenant, Roles: []string{"admin"}, Status: "active"})
		auth.UpsertAPIToken(adminAPIToken{ID: tenant + "-token", TokenHash: adminTokenHash(tenant + "-secret"), TenantID: tenant,
			CreatedByAdminPrincipalID: tenant + "-admin", Roles: []string{"admin"}, Scopes: []string{"admin.retention.read"},
			Status: "active", ExpiresAt: now.Add(time.Hour).Format(time.RFC3339)})
	}
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	handler := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Writer: writer, AdminAuth: auth, LegalHold: holds, OperatorTenantID: "operator"})
	for _, tenant := range []string{"Acme", "acme"} {
		t.Run(tenant, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/admin/legal-hold", nil)
			req.Header.Set("Authorization", "Bearer "+tenant+"-secret")
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("GET legal hold returned HTTP %d", rec.Code)
			}
			var body struct {
				Holds []legalHoldRecord `json:"holds"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if len(body.Holds) != 1 || body.Holds[0].TenantID != tenant {
				t.Fatalf("tenant %q received %d hold rows, first tenant %q", tenant, len(body.Holds), func() string {
					if len(body.Holds) == 0 {
						return ""
					}
					return body.Holds[0].TenantID
				}())
			}
		})
	}
}
