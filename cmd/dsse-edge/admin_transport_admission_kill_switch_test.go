package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/revocation"

	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/enrolledinventory"
	"github.com/lantern-networks/dsse-core/logs"
)

// W-7: the admin (T) transport-admission kill-switch handlers drive the shared revocation.AdmissionRevocations overlay,
// so an operator can revoke a device identity from the transport NOW and restore it after re-enrolment.
func TestAdminTransportAdmissionKillSwitch(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	overlay := revocation.NewAdmissionRevocations()
	// The list is scoped to the caller's tenant now (2026-08-16), and attribution comes from the enrolled
	// ledger — so the ledger is part of this handler's world, not scenery. Without one, a kill-switch list on a
	// multi-tenant node would have to choose between naming other customers' devices and naming none, and it
	// chooses none.
	ledger := enrolledinventory.NewLedger()
	stamp := time.Now().UTC().Format(time.RFC3339)
	if _, err := ledger.Enroll("win-dev-1", "tenant_lab_001", "", stamp); err != nil {
		t.Fatalf("enroll: %v", err)
	}
	if _, err := ledger.Enroll("other-tenant-dev-1", "tenant_someone_else", "", stamp); err != nil {
		t.Fatalf("enroll: %v", err)
	}
	// ★ A REAL CREDENTIAL, because the middleware REPLACES whatever identity a test puts in the request
	// context with the one it resolves. Injecting adminIdentity directly here proves nothing: the handler sees
	// the synthesised unscoped caller, for whom everything is theirs, which is exactly the state in which this
	// boundary cannot be observed.
	auth := newAdminAuthStore()
	auth.UpsertPrincipal(adminPrincipal{
		ID: "adm_lab", TenantID: "tenant_lab_001", Subject: "sub_lab", Email: "admin@lab.invalid",
		Roles: []string{"admin"}, IDPID: "keycloak_lab", Status: "active",
		CreatedAt: time.Now().Add(-time.Hour).UTC().Format(time.RFC3339),
	})
	auth.UpsertAPIToken(adminAPIToken{
		ID: "tok_lab", TenantID: "tenant_lab_001", Name: "lab admin",
		TokenHash: adminTokenHash(testKillSwitchCustomerBearer), Roles: []string{"admin"}, Scopes: []string{"*"},
		CreatedByAdminPrincipalID: "adm_lab",
		CreatedAt:                 time.Now().Add(-time.Hour).UTC().Format(time.RFC3339),
		ExpiresAt:                 time.Now().Add(time.Hour).UTC().Format(time.RFC3339), Status: "active",
	})
	// ★ AND A CUSTOMER IN A DIFFERENT ORGANIZATION FROM THE NODE'S. testEvaluator's bundle is
	// tenant_lab_001, so the credential above IS the node's own organization — which is what a pulling Edge
	// presents. A test whose "customer" is the node cannot see the boundary between them, and the first
	// version of this test could not.
	auth.UpsertPrincipal(adminPrincipal{
		ID: "adm_other", TenantID: "tenant_someone_else", Subject: "sub_other", Email: "admin@other.invalid",
		Roles: []string{"admin"}, IDPID: "keycloak_lab", Status: "active",
		CreatedAt: time.Now().Add(-time.Hour).UTC().Format(time.RFC3339),
	})
	auth.UpsertAPIToken(adminAPIToken{
		ID: "tok_other", TenantID: "tenant_someone_else", Name: "other admin",
		TokenHash: adminTokenHash(testKillSwitchOtherTenantBearer), Roles: []string{"admin"}, Scopes: []string{"*"},
		CreatedByAdminPrincipalID: "adm_other",
		CreatedAt:                 time.Now().Add(-time.Hour).UTC().Format(time.RFC3339),
		ExpiresAt:                 time.Now().Add(time.Hour).UTC().Format(time.RFC3339), Status: "active",
	})
	handler := newServerWithConfig(serverConfig{
		Evaluator:            testEvaluator(),
		AdmissionRevocations: overlay,
		EnrolledLedger:       ledger,
		Writer:               writer,
		Registry:             connector.NewRegistry(),
		AdminAuth:            auth,
	})
	// Every call carries the customer's credential now. It used to carry none, which the middleware resolves
	// to an UNSCOPED caller — everything is theirs — and that is precisely the state in which the boundary
	// below cannot be observed. win-dev-1 belongs to this customer, so the cases here are unchanged.
	do := func(method, path, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("content-type", "application/json")
		req.Header.Set("authorization", "Bearer "+testKillSwitchCustomerBearer)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}

	// Revoke -> overlay reflects it (the (T) handshake would now deny this identity).
	if rec := do(http.MethodPost, "/admin/transport-admission/revoke", `{"identity":"win-dev-1","reason":"admin_test"}`); rec.Code != http.StatusOK {
		t.Fatalf("revoke status=%d body=%s", rec.Code, rec.Body.String())
	}
	if reason, ok := overlay.IsRevoked("win-dev-1"); !ok || reason != "admin_test" {
		t.Fatalf("overlay must reflect admin revoke; ok=%v reason=%q", ok, reason)
	}

	// List -> includes the revoked identity.
	if rec := do(http.MethodGet, "/admin/transport-admission", ""); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "win-dev-1") {
		t.Fatalf("list must include revoked identity; code=%d body=%s", rec.Code, rec.Body.String())
	}

	// Restore (re-enrol/re-attest) -> cleared.
	if rec := do(http.MethodPost, "/admin/transport-admission/restore", `{"identity":"win-dev-1"}`); rec.Code != http.StatusOK {
		t.Fatalf("restore status=%d body=%s", rec.Code, rec.Body.String())
	}
	if _, ok := overlay.IsRevoked("win-dev-1"); ok {
		t.Fatal("restore must clear the revocation")
	}

	// ★★★ AND A CUSTOMER MAY ONLY THROW IT AT ITS OWN DEVICES (2026-08-17, measured with tenant_northwind's
	// own administrator on the lab: POST /admin/transport-admission/revoke reached the handler and returned
	// 400 only because the body was empty — the permission check passed).
	//
	// This is the ONE path allowed to tear down ESTABLISHED (T) sessions. It took an identity string with no
	// tenant check at all, so naming another organization's device cut it off immediately, from an account
	// with no relationship to it. The LIST beside it was scoped in the August sweep; the act was not — the
	// read was the disclosure and this is the consequence.
	//
	// The cases above run with no identity in the request context, which is an UNSCOPED caller — everything is
	// theirs — so they never asked this question. That is why this test passed while the hole was open.
	asCustomer := func(method, path, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("content-type", "application/json")
		req.Header.Set("authorization", "Bearer "+testKillSwitchCustomerBearer)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}
	// Somebody else's device: refused, and nothing happens to it.
	if rec := asCustomer(http.MethodPost, "/admin/transport-admission/revoke",
		`{"identity":"other-tenant-dev-1","reason":"not_mine"}`); rec.Code != http.StatusNotFound {
		t.Fatalf("a customer must not cut off another organization's device, got %d %s", rec.Code, rec.Body.String())
	}
	if _, ok := overlay.IsRevoked("other-tenant-dev-1"); ok {
		t.Fatal("the other organization's device was revoked anyway — a refusal that still acts is not a refusal")
	}
	// Its own device: still works, or this is a lockout rather than a boundary.
	if rec := asCustomer(http.MethodPost, "/admin/transport-admission/revoke",
		`{"identity":"win-dev-1","reason":"mine"}`); rec.Code != http.StatusOK {
		t.Fatalf("a customer must still be able to block its OWN device, got %d %s", rec.Code, rec.Body.String())
	}
	// Restoring somebody else's block is the same act in the other direction: a block anyone can lift is not
	// a block.
	overlay.Revoke("other-tenant-dev-1", "theirs")
	if rec := asCustomer(http.MethodPost, "/admin/transport-admission/restore",
		`{"identity":"other-tenant-dev-1"}`); rec.Code != http.StatusNotFound {
		t.Fatalf("a customer must not lift another organization's block, got %d", rec.Code)
	}
	if _, ok := overlay.IsRevoked("other-tenant-dev-1"); !ok {
		t.Fatal("the other organization's block was lifted anyway")
	}
	overlay.Restore("other-tenant-dev-1")
	overlay.Restore("win-dev-1")

	// ★★ AND THE FEED A NODE PULLS IS NOT A CUSTOMER'S READ (2026-08-17). GET /admin/revocations answered a
	// customer administrator with the whole deployment's revoked identities — every organization's blocked
	// devices, named. It is deliberately unfiltered, because filtering it by a human's tenant would stop
	// propagating other tenants' kill-switches to a pulling Edge; the resolution is that the puller presents a
	// MACHINE credential and no screen in the Console calls this route at all.
	asOtherTenant := func(method, path, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("content-type", "application/json")
		req.Header.Set("authorization", "Bearer "+testKillSwitchOtherTenantBearer)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}
	overlay.Revoke("other-tenant-dev-1", "theirs")
	if rec := asOtherTenant(http.MethodGet, "/admin/revocations", ""); rec.Code != http.StatusForbidden {
		t.Fatalf("a customer session must not read the deployment's revocation feed, got %d %s", rec.Code, rec.Body.String())
	}
	// The control: a machine credential — which is what a pulling Edge presents — still gets the whole feed,
	// including the other organization's entry. Filtering this is the enforcement failure the note warns about.
	if rec := do(http.MethodGet, "/admin/revocations", ""); rec.Code != http.StatusOK ||
		!strings.Contains(rec.Body.String(), "other-tenant-dev-1") {
		t.Fatalf("the pulling node must still receive every organization's revocations, got %d %s",
			rec.Code, rec.Body.String())
	}
	overlay.Restore("other-tenant-dev-1")

	// Missing identity -> 400.
	if rec := do(http.MethodPost, "/admin/transport-admission/revoke", `{}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("missing identity must be 400; got %d", rec.Code)
	}

	// ★ AND THE LIST IS ONE CUSTOMER'S. A kill-switch entry names a device and says it was cut off — another
	// customer's incident, when it is not the caller's. Both are revoked here, so the check cannot pass by the
	// list simply being empty: the caller's own must be present in the same response that omits the other's.
	if rec := do(http.MethodPost, "/admin/transport-admission/revoke", `{"identity":"win-dev-1","reason":"admin_test"}`); rec.Code != http.StatusOK {
		t.Fatalf("re-revoke status=%d body=%s", rec.Code, rec.Body.String())
	}
	overlay.Revoke("other-tenant-dev-1", "another_tenants_incident")
	rec := do(http.MethodGet, "/admin/transport-admission", "")
	if body := rec.Body.String(); strings.Contains(body, "other-tenant-dev-1") {
		t.Fatalf("another tenant's revoked device is named to this caller: %s", body)
	} else if !strings.Contains(body, "win-dev-1") {
		t.Fatalf("the caller lost its OWN revoked device — a fix that empties the screen is not a fix: %s", body)
	}
}

// testKillSwitchCustomerBearer is an ORDINARY admin of tenant_lab_001 — no super_admin, no cross-tenant
// permission. The whole point is that this is what a customer holds.
const testKillSwitchCustomerBearer = "raw-kill-switch-customer-admin"

// testKillSwitchOtherTenantBearer is an admin of an organization that is NOT the node's own — the only
// position from which the revocation feed's boundary is visible.
const testKillSwitchOtherTenantBearer = "raw-kill-switch-other-tenant-admin"
