package main

import (
	"net/http"
	"strings"
	"testing"

	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/vlan"
)

// A definition with no organization is listed to every customer. Changing it was
// refused by the store's ownership callback as ErrNotFound, so the Console
// answered "absent" about the row it had just shown. The customer must get the
// truth (it exists; only the operator can change it), and nothing may change.
func TestLegacyUnownedNetworkIsRefusedAsOperatorOnlyNotAbsent(t *testing.T) {
	declareOperatorTenantForTest(t, "tenant_operator_001")
	store := vlan.NewStore()
	if _, err := store.UpsertObject(model.VLANObject{ID: "net_legacy", Name: "Legacy", Class: "server", CIDRs: []string{"10.77.0.0/24"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.UpsertPolicy(model.VLANBoundaryPolicy{ID: "pol_legacy", SourceClass: "server", DestClass: "server", Mode: "observe"}); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	registerVLANRoutes(mux, func(_ string, h http.HandlerFunc) http.HandlerFunc { return h }, store, "")
	customer := adminIdentity{PrincipalID: "adm_nw", TenantID: "tenant_northwind", Roles: []string{"admin"}, AuthMethod: "admin_session"}
	operator := adminIdentity{PrincipalID: "adm_op", TenantID: "tenant_operator_001", Roles: []string{"owner"}, AuthMethod: "admin_session"}

	if code, body := vlanScopeCall(t, mux, http.MethodGet, "/admin/vlan-objects", "", customer); code != http.StatusOK || !strings.Contains(body, "net_legacy") {
		t.Fatalf("precondition: the customer sees the legacy definition: %d %s", code, body)
	}
	for _, c := range []struct{ method, path, body string }{
		{http.MethodDelete, "/admin/vlan-objects/net_legacy", ""},
		{http.MethodPost, "/admin/vlan-objects", `{"id":"net_legacy","name":"Mine now","class":"server","cidrs":["10.77.0.0/24"]}`},
		{http.MethodPost, "/admin/vlan-boundary-policies", `{"id":"pol_legacy","source_class":"server","dest_class":"server","mode":"deny"}`},
	} {
		code, body := vlanScopeCall(t, mux, c.method, c.path, c.body, customer)
		if code != http.StatusForbidden || strings.Contains(strings.ToLower(body), "absent") || !strings.Contains(body, "operator") {
			t.Fatalf("%s %s: %d %s", c.method, c.path, code, body)
		}
	}
	if o, ok := store.GetObject("net_legacy"); !ok || o.TenantID != "" || o.Name != "Legacy" {
		t.Fatalf("refused change altered the definition: %+v %v", o, ok)
	}
	if code, body := vlanScopeCall(t, mux, http.MethodDelete, "/admin/vlan-objects/net_legacy", "", operator); code != http.StatusOK {
		t.Fatalf("the operator must still be able to remove it: %d %s", code, body)
	}
}
