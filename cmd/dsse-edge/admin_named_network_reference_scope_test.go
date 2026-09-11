package main

import (
	"testing"

	"github.com/lantern-networks/dsse-core/model"
)

// ★★ A REFERENCE TO ANOTHER ORGANIZATION'S NAMED NETWORK (2026-08-17, found by reading the by-id write routes
// one at a time — the layer the "what can a customer write" sweep could not see, because these handlers DO
// mention a tenant and use it correctly for the write itself).
//
// Both binding routes — POST /admin/sites/{site_id}/networks and POST /admin/connectors/{id}/routes — checked
// that the referenced network exists with vlanBoundary.GetObject(id), which is deployment-wide, and then
// authored the binding under the caller's own tenant. The RESOLVER that later expands that reference to CIDRs
// has always refused a foreign one. The two halves disagreed, silently, in both directions:
//
//   - an existence oracle: 200 for a network id that exists in another organization, 400 for one that exists
//     nowhere, so a customer could confirm another organization's network names one guess at a time;
//   - a binding that can never work: accepted, stored, and resolving to nothing forever, with the site showing
//     a route that does not route and nothing saying why.
//
// The CIDRs never leaked — the resolver held — so what this closes is the reference and the dead write.
func TestANamedNetworkMayOnlyBeReferencedByItsOwner(t *testing.T) {
	mine := model.VLANObject{ID: "vlan_mine", TenantID: "tenant_northwind"}
	theirs := model.VLANObject{ID: "vlan_theirs", TenantID: "tenant_reference_lab"}
	// An object carrying no tenant is the deployment's, and stays visible — the rule
	// deviceGroupVisibleToTenant settled for every other object, applied here in the same words.
	shared := model.VLANObject{ID: "vlan_shared"}

	if !namedNetworkVisibleToTenant(mine, true, "tenant_northwind") {
		t.Fatal("an organization must be able to bind its OWN Named Network — this is a boundary, not a lockout")
	}
	if namedNetworkVisibleToTenant(theirs, true, "tenant_northwind") {
		t.Fatal("another organization's Named Network must not be referenceable: it answers 200 for an id that " +
			"exists elsewhere and 400 for one that exists nowhere, which is an oracle for their network names")
	}
	if !namedNetworkVisibleToTenant(shared, true, "tenant_northwind") {
		t.Fatal("a deployment-owned network (no tenant) must stay bindable, or this scoping is a lockout")
	}
	// An unscoped caller — a deployment with no tenant model — sees everything, the same answer every other
	// boundary in this tree gives.
	if !namedNetworkVisibleToTenant(theirs, true, "") {
		t.Fatal("an unscoped caller must not be blinded by a rule about tenants")
	}
	// And an id that exists nowhere is refused whatever the caller is, or the refusal above says nothing.
	if namedNetworkVisibleToTenant(model.VLANObject{}, false, "tenant_northwind") {
		t.Fatal("a network that does not exist must be refused")
	}
	if namedNetworkVisibleToTenant(model.VLANObject{}, false, "") {
		t.Fatal("a network that does not exist must be refused even for an unscoped caller")
	}
}
