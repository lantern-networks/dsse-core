package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// ★★★ AN ORGANIZATION WITH ITS OWN INTERCEPTION ROOT WAS INVISIBLE TO THE FETCH THAT WOULD HAVE ENFORCED IT
// (2026-08-27, measured after walking a customer's whole PKI through the Console).
//
// The route hands an Edge three tiers in one answer — transport, interception, device identity — and when the
// Edge asks for "everything you hold for me", which is the normal case in a shared fleet, the list it gets
// back was
//
//	wanted = authority.Organizations()      // the TRANSPORT authority's, only
//
// so an organization that had been given an interception authority and no transport one was in nobody's list.
// The Edge fetched successfully, was handed nothing, and went on signing that customer's traffic under the
// deployment's shared root — while the control plane and the Console both showed the customer's own root in
// force. The three tiers are set up on three separate screens and a customer is under no obligation to do all
// three, so this is the ordinary path, not a corner.
//
// The list is the UNION. Each tier still refuses on its own for an organization it has nothing for, which is
// how "this organization runs its own PKI" stays distinguishable from "this organization was not asked about".
func TestTheMaterialFetchSeesAnOrganizationThatHasOnlyAnInterceptionAuthority(t *testing.T) {
	const bearer = "material-union-probe"
	now := func() time.Time { return time.Date(2026, 8, 27, 9, 0, 0, 0, time.UTC) }

	transport := newTenantTransportAuthority(nil, func([]byte) error { return nil }, now)
	if _, err := transport.EnsureCA("tenant_with_transport", "a.dsse.invalid"); err != nil {
		t.Fatalf("transport authority: %v", err)
	}
	interception := newTenantInterceptionAuthority(nil, func([]byte) error { return nil }, now)
	stamp := now()
	rootCert, rootKey := interceptionTestCA(t, "Kaede Logistics Interception Root", nil, nil, stamp)
	issuingCert, issuingKey := interceptionTestCA(t, "Kaede Logistics Interception Issuing CA", rootCert, rootKey, stamp)
	root, issuing, key := certPEMForTest(rootCert), certPEMForTest(issuingCert), ecKeyPEMForTest(t, issuingKey)
	if _, err := interception.Import("tenant_kaede", root, issuing, key); err != nil {
		t.Fatalf("import the organization's interception authority: %v", err)
	}
	device := newTenantDeviceAuthority(nil, func([]byte) error { return nil }, now)
	if _, err := device.EnsureCA("tenant_kaede", "Kaede Logistics"); err != nil {
		t.Fatalf("device authority: %v", err)
	}

	mux := http.NewServeMux()
	registerTenantTransportMaterialRoute(mux, transport, interception, device, bearer, time.Hour, nil, true)

	req := httptest.NewRequest(http.MethodPost, "/tenant-edge-material", strings.NewReader(`{}`))
	req.Header.Set("authorization", "Bearer "+bearer)
	req.Header.Set("content-type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("the fetch was refused: %d %s", rec.Code, rec.Body.String())
	}
	var answer struct {
		Interception []struct {
			TenantID string `json:"tenant_id"`
		} `json:"interception"`
		DeviceIdentity []struct {
			TenantID string `json:"tenant_id"`
		} `json:"device_identity"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &answer); err != nil {
		t.Fatalf("the answer could not be read: %v", err)
	}
	named := func(rows []struct {
		TenantID string `json:"tenant_id"`
	}, want string) bool {
		for _, r := range rows {
			if r.TenantID == want {
				return true
			}
		}
		return false
	}
	if !named(answer.Interception, "tenant_kaede") {
		t.Errorf("an organization with its own INTERCEPTION authority was handed none, so every Edge goes on "+
			"signing its traffic under the deployment's shared root: %s", rec.Body.String())
	}
	if !named(answer.DeviceIdentity, "tenant_kaede") {
		t.Errorf("an organization with its own DEVICE-IDENTITY authority was handed none, so no Edge can admit "+
			"a device enrolling with the token its administrator issued: %s", rec.Body.String())
	}
}

// ★ THE CONTROL: an organization the deployment holds nothing for is still not in the answer. The union must
// widen the list, not the issuing — otherwise every organization would look served.
func TestAnOrganizationWithNoAuthorityAtAllIsStillNotServed(t *testing.T) {
	const bearer = "material-union-control"
	now := func() time.Time { return time.Date(2026, 8, 27, 9, 0, 0, 0, time.UTC) }
	transport := newTenantTransportAuthority(nil, func([]byte) error { return nil }, now)
	if _, err := transport.EnsureCA("tenant_with_transport", "a.dsse.invalid"); err != nil {
		t.Fatalf("transport authority: %v", err)
	}
	mux := http.NewServeMux()
	registerTenantTransportMaterialRoute(mux, transport,
		newTenantInterceptionAuthority(nil, func([]byte) error { return nil }, now),
		newTenantDeviceAuthority(nil, func([]byte) error { return nil }, now),
		bearer, time.Hour, nil, true)

	req := httptest.NewRequest(http.MethodPost, "/tenant-edge-material", strings.NewReader(`{}`))
	req.Header.Set("authorization", "Bearer "+bearer)
	req.Header.Set("content-type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if strings.Contains(rec.Body.String(), "tenant_never_heard_of") {
		t.Errorf("an organization nothing holds an authority for appears in the answer: %s", rec.Body.String())
	}
}
