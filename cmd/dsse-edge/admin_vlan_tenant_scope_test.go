package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/vlan"
)

func vlanScopeCall(t *testing.T, mux *http.ServeMux, method, path, body string, identity adminIdentity) (int, string) {
	t.Helper()
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, path, nil)
	} else {
		r = httptest.NewRequest(method, path, strings.NewReader(body))
	}
	r = r.WithContext(context.WithValue(r.Context(), adminIdentityContextKey{}, identity))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, r)
	return rec.Code, rec.Body.String()
}

// ★★★ A CUSTOMER DELETED ANOTHER CUSTOMER'S NETWORK OBJECT, ON THE LIVE LAB, WITH A 200 (2026-08-16).
// Signed in to the Console as Northwind's administrator — roles ["admin"], no cross-tenant permission — the
// Networks screen listed tenant_reference_lab's object and DELETE removed it from the control plane.
//
// Every property here is one half of that: what a customer may SEE, what a customer may DELETE, what a
// customer may CLAIM by writing a tenant_id into the body, and what the firewall export carries. The operator
// control is asserted in the same run, so a fix that blinded everybody would fail rather than pass.
func TestVLANObjectsAreScopedToTheOrganizationAsking(t *testing.T) {
	declareOperatorTenantForTest(t, "tenant_operator_001")
	store := vlan.NewStore()
	if _, err := store.UpsertObject(model.VLANObject{ID: "vlan_lab", TenantID: "tenant_reference_lab", Name: "Lab subnet", Class: "server", CIDRs: []string{"10.99.0.0/24"}}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := store.UpsertObject(model.VLANObject{ID: "vlan_nw", TenantID: "tenant_northwind", Name: "Northwind subnet", Class: "server", CIDRs: []string{"10.5.0.0/24"}}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := store.UpsertPolicy(model.VLANBoundaryPolicy{ID: "pol_lab", TenantID: "tenant_reference_lab", SourceClass: "managed_endpoint", DestClass: "server", ServiceFamily: "ssh", Ports: []int{22}, Mode: "deny"}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	mux := http.NewServeMux()
	registerVLANRoutes(mux, func(_ string, h http.HandlerFunc) http.HandlerFunc { return h }, store, "")

	customer := adminIdentity{PrincipalID: "adm_nw", TenantID: "tenant_northwind", Roles: []string{"admin"}, AuthMethod: "admin_session"}
	operator := adminIdentity{PrincipalID: "adm_op", TenantID: "tenant_operator_001", Roles: []string{"owner"}, AuthMethod: "admin_session"}

	// 1. The list shows their own and not another organization's.
	code, body := vlanScopeCall(t, mux, http.MethodGet, "/admin/vlan-objects", "", customer)
	if code != http.StatusOK || strings.Contains(body, "vlan_lab") || !strings.Contains(body, "vlan_nw") {
		t.Fatalf("a customer must see their own objects and no others: %d %s", code, body)
	}

	// 2. The boundary policies too.
	code, body = vlanScopeCall(t, mux, http.MethodGet, "/admin/vlan-boundary-policies", "", customer)
	if code != http.StatusOK || strings.Contains(body, "pol_lab") {
		t.Fatalf("a customer must not see another organization's boundary policies: %d %s", code, body)
	}

	// 3. The firewall export is built from what the caller may see. An export carrying somebody else's subnets
	//    is that organization's network map leaving with the wrong party.
	code, body = vlanScopeCall(t, mux, http.MethodGet, "/admin/vlan-boundary-policies/export", "", customer)
	if code != http.StatusOK || strings.Contains(body, "10.99.0.0/24") {
		t.Fatalf("the export must not carry another organization's subnets: %d %s", code, body)
	}

	// 4. THE ONE THAT HAPPENED: deleting by id alone. Answered as absent, and the object survives.
	code, _ = vlanScopeCall(t, mux, http.MethodDelete, "/admin/vlan-objects/vlan_lab", "", customer)
	if code != http.StatusNotFound {
		t.Fatalf("deleting another organization's object must read as absent, got %d", code)
	}
	if _, ok := store.GetObject("vlan_lab"); !ok {
		t.Fatalf("another organization's object was DELETED by a customer")
	}

	// 5. A tenant_id in the BODY must not let a customer file an object under another organization.
	//
	// ★★ AND IT IS NOW REFUSED RATHER THAN REDIRECTED (2026-08-17). This asserted that the write SUCCEEDS and
	// lands in the caller's own organization — which is safe, and is a lie to the caller: they named an
	// organization, got HTTP 200, and the object is somewhere else. Measured on the lab as a customer posting
	// a device group naming another organization: 200, filed in their own.
	//
	// The tree had already decided this for the two other forms of the same request — the middleware makes
	// X-Operate-Tenant a 403 ("it would otherwise have been carried out in your own organization, which is not
	// what you asked for") and /admin/policies makes the body form a 400 — so what existed was one rule with
	// three answers depending on which route you reached. The refusal now lives in adminTenantForWrite, which
	// is the one place all of these resolve through.
	//
	// The security property is unchanged: no cross-tenant write happens either way. What changes is that the
	// caller is told.
	code, body = vlanScopeCall(t, mux, http.MethodPost, "/admin/vlan-objects",
		`{"id":"vlan_claimed","tenant_id":"tenant_reference_lab","class":"server","cidrs":["10.7.0.0/24"]}`, customer)
	if code != http.StatusForbidden {
		t.Fatalf("naming another organization in the body must be refused, got %d %s", code, body)
	}
	if !strings.Contains(body, "tenant_reference_lab") || !strings.Contains(body, "tenant_northwind") {
		t.Fatalf("the refusal must name both organizations, or it is not actionable: %s", body)
	}
	if _, ok := store.GetObject("vlan_claimed"); ok {
		t.Fatal("the object was written anyway — a refusal that still writes is worse than the redirect it replaced")
	}

	// And the ordinary shape still works: no tenant named, filed under the caller's own organization.
	code, body = vlanScopeCall(t, mux, http.MethodPost, "/admin/vlan-objects",
		`{"id":"vlan_own","class":"server","cidrs":["10.7.0.0/24"]}`, customer)
	if code != http.StatusOK {
		t.Fatalf("a customer writing into its own organization must still work: %d %s", code, body)
	}
	own, ok := store.GetObject("vlan_own")
	if !ok || own.TenantID != "tenant_northwind" {
		t.Fatalf("the object must be filed under the CALLER's organization, got %+v", own)
	}

	// 6. The control: the operator still sees and may remove everything, or this was blinded rather than scoped.
	code, body = vlanScopeCall(t, mux, http.MethodGet, "/admin/vlan-objects", "", operator)
	if code != http.StatusOK || !strings.Contains(body, "vlan_lab") || !strings.Contains(body, "vlan_nw") {
		t.Fatalf("the operator must still see the whole deployment: %d %s", code, body)
	}
	var listed map[string]any
	_ = json.Unmarshal([]byte(body), &listed)
	if objs, _ := listed["objects"].([]any); len(objs) != 3 {
		t.Fatalf("the operator must see all three objects, got %d", len(objs))
	}
	if code, _ = vlanScopeCall(t, mux, http.MethodDelete, "/admin/vlan-objects/vlan_lab", "", operator); code != http.StatusOK {
		t.Fatalf("the operator must still be able to remove an object, got %d", code)
	}
}
