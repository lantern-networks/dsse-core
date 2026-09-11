package main

import (
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// asNorthwindAdmin issues a request as an ORDINARY admin of tenant_northwind — the customer, not the operator.
func asNorthwindAdmin(t *testing.T, handler http.Handler, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	payload := ""
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		payload = string(raw)
	}
	req := httptest.NewRequest(method, path, strings.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("authorization", "Bearer "+testTenantCANorthwindBearer)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

// ★ THE ONE PKI DOMAIN ALREADY SHAPED CORRECTLY COULD NOT BE OPERATED BY ITS OWNER (2026-08-16). The device
// CA is the good shape: the customer holds the key, the operator only verifies. But all three routes required
// admin.tenant.admin — operator-only — so registering, rotating or withdrawing it was a support ticket. A CA
// rotation nobody can perform is a CA nobody rotates, and it expires on a day of its own choosing (the lab's
// second tenant holds a 30-day one).
//
// The capability, not the refusal, is the point of this test: a customer admin registers its OWN device CA and
// the handshake will accept devices under it.
func TestATenantAdminCanRegisterItsOwnDeviceCA(t *testing.T) {
	handler, registry, trust, _ := tenantCARoutesForTest(t)
	caCert, caPEM := tenantCATestCA(t, "Northwind Device Issuing CA")

	res := asNorthwindAdmin(t, handler, http.MethodPost, "/admin/tenant-cas",
		map[string]string{"tenant_id": "tenant_northwind", "ca_pem": string(caPEM)})

	if res.Code != http.StatusCreated {
		t.Fatalf("a tenant admin could not register its OWN device CA: HTTP %d — %s", res.Code, res.Body.String())
	}
	// Both halves, as the route itself insists: trusted at the handshake AND attributed to the tenant.
	tenant, ok := registry.TenantForVerifiedChains([][]*x509.Certificate{{caCert}})
	if !ok || tenant != "tenant_northwind" {
		t.Fatalf("the CA resolves to %q/%v — those devices would belong to nobody", tenant, ok)
	}
	if !trustStoreHolds(t, trust, caCert) {
		t.Fatal("attributed but not trusted: the organization's devices still cannot connect")
	}
}

// ★★ AND IT WORKS WHEN THE ORGANIZATION DOES NOT NAME ITSELF, WHICH IS WHAT THE SCREEN SENDS (2026-08-17,
// measured signed in as the first administrator of a self-run organization).
//
// The test above passes tenant_id explicitly, so it proved the route and not the path a person takes. The
// Console sends `operateTenant || ""` — set for an operator, never for a customer — so the customer's own
// "Register this organization's device CA" button posted an EMPTY tenant and the route answered 400
// "tenant_id and ca_pem are both required": a field the person pressing the button never filled in, on the
// one control that clears their blocking setup item. Cleared for the operator, still blocking for the
// customer, and the screen's own comment recorded it as fixed.
//
// A write's organization comes from the caller. Naming another one stays an operator act — the test below
// this one is unchanged and still refuses it.
func TestAnOrganizationRegistersItsDeviceCAWithoutNamingItself(t *testing.T) {
	handler, registry, trust, _ := tenantCARoutesForTest(t)
	caCert, caPEM := tenantCATestCA(t, "Northwind Device Issuing CA")

	// Exactly the body the Console posts for a customer: no tenant_id at all.
	res := asNorthwindAdmin(t, handler, http.MethodPost, "/admin/tenant-cas",
		map[string]string{"ca_pem": string(caPEM)})

	if res.Code != http.StatusCreated {
		t.Fatalf("an organization could not register its own device CA without naming itself: HTTP %d — %s",
			res.Code, res.Body.String())
	}
	tenant, ok := registry.TenantForVerifiedChains([][]*x509.Certificate{{caCert}})
	if !ok || tenant != "tenant_northwind" {
		t.Fatalf("the CA was attributed to %q/%v — an unnamed organization must resolve to the CALLER'S, or the "+
			"devices belong to nobody", tenant, ok)
	}
	if !trustStoreHolds(t, trust, caCert) {
		t.Fatal("attributed but not trusted: the organization's devices still cannot connect")
	}

	// A body with neither the CA nor anything else still fails, and says which part is missing — the old
	// message named tenant_id, which is never the caller's to supply.
	empty := asNorthwindAdmin(t, handler, http.MethodPost, "/admin/tenant-cas", map[string]string{})
	if empty.Code != http.StatusBadRequest {
		t.Fatalf("a request with no CA must be refused, got HTTP %d", empty.Code)
	}
	if strings.Contains(empty.Body.String(), "tenant_id") {
		t.Fatalf("the refusal still asks for tenant_id, which the caller does not supply: %s", empty.Body.String())
	}
}

// And it stops exactly there. Registering a CA FOR ANOTHER ORGANIZATION means every device that CA issues is
// admitted as that organization's — a fleet-sized act on somebody else's tenant.
func TestATenantAdminCannotRegisterAnotherOrganizationsDeviceCA(t *testing.T) {
	handler, registry, trust, _ := tenantCARoutesForTest(t)
	caCert, caPEM := tenantCATestCA(t, "Acme Device Issuing CA")

	res := asNorthwindAdmin(t, handler, http.MethodPost, "/admin/tenant-cas",
		map[string]string{"tenant_id": "tenant_acme", "ca_pem": string(caPEM)})

	if res.Code != http.StatusForbidden {
		t.Fatalf("registering another organization's device CA returned HTTP %d — %s", res.Code, res.Body.String())
	}
	// ★ AND NOTHING LANDED. This route applies TRUST before attribution on purpose, so a refusal that arrives
	// after the trust half would leave the node trusting a CA it refused to register — the exact "half a
	// registration" state the route's own comment calls worse than none. The guard runs before either half.
	if _, ok := registry.TenantForVerifiedChains([][]*x509.Certificate{{caCert}}); ok {
		t.Fatal("the refused CA was attributed anyway")
	}
	if trustStoreHolds(t, trust, caCert) {
		t.Fatal("the refused CA entered the device trust set — a 403 that changed the node's trust")
	}
}

// Withdrawing your own is a real thing to want: it is how a rotation ends. Withdrawing somebody else's stops
// admitting their entire fleet.
func TestATenantAdminCannotWithdrawAnotherOrganizationsDeviceCA(t *testing.T) {
	handler, registry, _, _ := tenantCARoutesForTest(t)
	acmeCert, acmePEM := tenantCATestCA(t, "Acme Device Issuing CA")
	if res := doTenantCARequest(t, handler, http.MethodPost, "/admin/tenant-cas",
		map[string]string{"tenant_id": "tenant_acme", "ca_pem": string(acmePEM)}); res.Code != http.StatusCreated {
		t.Fatalf("operator seed: HTTP %d — %s", res.Code, res.Body.String())
	}

	res := asNorthwindAdmin(t, handler, http.MethodDelete, "/admin/tenant-cas/tenant_acme", nil)

	if res.Code != http.StatusForbidden {
		t.Fatalf("withdrawing another organization's CA returned HTTP %d — %s", res.Code, res.Body.String())
	}
	// The refusal has to be real: a 403 that withdrew it anyway would cut off that customer's whole fleet.
	if tenant, ok := registry.TenantForVerifiedChains([][]*x509.Certificate{{acmeCert}}); !ok || tenant != "tenant_acme" {
		t.Fatal("the other organization's CA was withdrawn despite the refusal — its devices are now unadmittable")
	}
}

// The list is the caller's own organization. On this surface a withheld COUNT is deliberately not reported:
// on the device screens a count exists so a tenant is never shown a smaller version of its own fleet, but
// another organization's CA is not a diminished view of this caller's world — and the number of them is the
// membership figure this list should not publish either.
func TestTheTenantCAListShowsATenantOnlyItsOwn(t *testing.T) {
	handler, _, _, _ := tenantCARoutesForTest(t)
	_, acmePEM := tenantCATestCA(t, "Acme Device Issuing CA")
	_, nwPEM := tenantCATestCA(t, "Northwind Device Issuing CA")
	for tenant, pem := range map[string]string{"tenant_acme": string(acmePEM), "tenant_northwind": string(nwPEM)} {
		if res := doTenantCARequest(t, handler, http.MethodPost, "/admin/tenant-cas",
			map[string]string{"tenant_id": tenant, "ca_pem": pem}); res.Code != http.StatusCreated {
			t.Fatalf("operator seed %s: HTTP %d — %s", tenant, res.Code, res.Body.String())
		}
	}

	res := asNorthwindAdmin(t, handler, http.MethodGet, "/admin/tenant-cas", nil)
	if res.Code != http.StatusOK {
		t.Fatalf("HTTP %d — %s", res.Code, res.Body.String())
	}
	body := res.Body.String()
	if strings.Contains(body, "tenant_acme") {
		t.Fatalf("another organization is named to this caller: %s", body)
	}
	// The guard: its own is there in the same response, or this passes on an empty list.
	if !strings.Contains(body, "tenant_northwind") {
		t.Fatalf("the caller cannot see its OWN device CA: %s", body)
	}

	// The operator still sees both — somebody has to be able to survey the deployment.
	if got := doTenantCARequest(t, handler, http.MethodGet, "/admin/tenant-cas", nil).Body.String(); !strings.Contains(got, "tenant_acme") {
		t.Fatalf("the operator lost the fleet view: %s", got)
	}
}
