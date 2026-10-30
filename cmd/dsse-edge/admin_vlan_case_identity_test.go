package main

import (
	"net/http"
	"strings"
	"testing"

	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/vlan"
)

func TestVLANCaseDistinctTenantIsolation(t *testing.T) {
	declareOperatorTenantForTest(t, "operator")
	for _, operation := range []string{"objects", "policies", "export", "delete", "overwrite-object", "overwrite-policy"} {
		t.Run(operation, func(t *testing.T) {
			store := vlan.NewStore()
			for _, tenant := range []string{"Acme", "acme"} {
				if _, err := store.UpsertObject(model.VLANObject{ID: tenant, TenantID: tenant, Class: "server", CIDRs: []string{"10.0.0.0/24"}}); err != nil {
					t.Fatal(err)
				}
				if _, err := store.UpsertPolicy(model.VLANBoundaryPolicy{ID: tenant, TenantID: tenant, SourceClass: "server", DestClass: "server", Mode: "deny"}); err != nil {
					t.Fatal(err)
				}
			}
			mux := http.NewServeMux()
			registerVLANRoutes(mux, func(_ string, h http.HandlerFunc) http.HandlerFunc { return h }, store, "")
			customer := adminIdentity{PrincipalID: "admin", TenantID: "Acme", Roles: []string{"admin"}, AuthMethod: "admin_session"}
			method, path, body, want := http.MethodGet, "/admin/vlan-objects", "", http.StatusOK
			switch operation {
			case "policies":
				path = "/admin/vlan-boundary-policies"
			case "export":
				path = "/admin/vlan-boundary-policies/export"
			case "delete":
				method, path, want = http.MethodDelete, "/admin/vlan-objects/acme", http.StatusNotFound
			case "overwrite-object":
				method, want, body = http.MethodPost, http.StatusNotFound, `{"id":"acme","class":"server","cidrs":["10.99.0.0/24"]}`
			case "overwrite-policy":
				method, path, want, body = http.MethodPost, "/admin/vlan-boundary-policies", http.StatusNotFound, `{"id":"acme","source_class":"server","dest_class":"server","mode":"observe"}`
			}
			code, result := vlanScopeCall(t, mux, method, path, body, customer)
			if code != want {
				t.Fatalf("status = %d, want %d", code, want)
			}
			if method == http.MethodGet && (strings.Contains(result, `"acme"`) || !strings.Contains(result, `"Acme"`)) {
				t.Fatalf("list/export crossed case-distinct tenant boundary: %s", result)
			}
			if other, ok := store.GetObject("acme"); !ok || other.TenantID != "acme" || other.CIDRs[0] != "10.0.0.0/24" {
				t.Fatal("another tenant's object changed")
			}
			for _, p := range store.ListPolicies() {
				if p.ID == "acme" && (p.TenantID != "acme" || p.Mode != "deny") {
					t.Fatal("another tenant's policy changed")
				}
			}
		})
	}
}
