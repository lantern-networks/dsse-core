package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/model"
)

// ★★★ A DELETED ORGANIZATION WENT ON SIGNING (2026-08-21, measured on the reference lab). Deletion
// deliberately leaves what an organization PRODUCED for the purge to erase — its audit partition, its outbox
// rows. Its certificate authorities were in that same bucket, and an authority is not a record: an
// organization deleted at 05:2x still held a transport CA at 05:44 that had just minted a fresh twelve-hour
// certificate, and every Edge in the fleet was still presenting its name on the transport port. An SNI probe
// for a customer that no longer exists still answered "yes, here".
func TestDeletingAnOrganizationStopsItSigning(t *testing.T) {
	declareOperatorTenantForTest(t, "tenant_operator_001")
	now := time.Now().UTC()

	auth := newAdminAuthStore()
	const bearer = "raw-operator-deleting"
	auth.UpsertPrincipal(adminPrincipal{ID: "adm_del", TenantID: "tenant_operator_001", Subject: "sub_del",
		Email: "operator@example.invalid", Roles: []string{"admin", "super_admin"}, IDPID: "keycloak_lab",
		Status: "active", CreatedAt: now.Add(-time.Hour).Format(time.RFC3339)})
	auth.UpsertAPIToken(adminAPIToken{ID: "tok_del", TenantID: "tenant_operator_001", Name: "operator",
		TokenHash: adminTokenHash(bearer), Roles: []string{"admin", "super_admin"}, Scopes: []string{"*"},
		CreatedByAdminPrincipalID: "adm_del", CreatedAt: now.Add(-time.Hour).Format(time.RFC3339),
		ExpiresAt: now.Add(time.Hour).Format(time.RFC3339), Status: "active"})

	tenants := newOperatorAwareAdminTenantModelStore(model.PolicyBundle{}, now, "", "tenant_operator_001")
	const doomed = "tenant_qq4wsvnvxk2cgqjq4bqxq5t3aa"
	for _, id := range []string{"tenant_operator_001", doomed} {
		if _, err := tenants.Put(context.Background(),
			adminTenantModel{TenantID: id, DisplayName: id, Status: "active"}, now); err != nil {
			t.Fatalf("seed %s: %v", id, err)
		}
	}

	authority := newTenantTransportAuthority(nil, func([]byte) error { return nil }, time.Now)
	if _, err := authority.EnsureCA(doomed, "qq4wsvnvxk2cgqjq4bqxq5t3aa.example.invalid"); err != nil {
		t.Fatalf("create the authority: %v", err)
	}
	if _, _, _, _, known := authority.StateFor(doomed); !known {
		t.Fatal("the control before the act failed: the organization has no authority to lose")
	}

	handler := newServerWithConfig(serverConfig{
		Evaluator: testEvaluator(), AdminAuth: auth, TenantModelStore: tenants,
		OperatorTenantID: "tenant_operator_001", TenantTransportAuthority: authority,
	})

	req := httptest.NewRequest(http.MethodDelete, "/admin/tenants/"+doomed, nil)
	req.Header.Set("authorization", "Bearer "+bearer)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("delete: HTTP %d %s", rec.Code, rec.Body.String())
	}

	if _, _, _, _, known := authority.StateFor(doomed); known {
		t.Fatal("★ the organization is deleted and its transport authority is still here. It goes on minting " +
			"certificates, and every Edge goes on serving its name — so a stranger probing that name by SNI " +
			"is still told the organization exists.")
	}

	// ★ AND THE ANSWER SAYS SO. Stopping the signing silently would leave an operator unable to tell this
	// deployment from one where the authority is still live.
	var body struct {
		Removed map[string]any `json:"removed"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, ok := body.Removed["certificate_authorities_withdrawn"]; !ok {
		t.Fatalf("the answer does not report that the signing stopped: %s", rec.Body.String())
	}
}
