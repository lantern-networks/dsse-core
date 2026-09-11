package main

import "testing"

// ★★ THE SCREEN GUESSED THE OWNER FROM THE CERTIFICATE'S NAME (2026-08-18, measured as Northwind's
// administrator on the reference deployment).
//
// Ownership was read by looking for the literal "tenant_" inside the Subject or Issuer. A device-trust CA a
// customer registered as "CN=Probe3 Device CA, O=Bootstrap Probe 3" therefore had no owner, counted as
// DEPLOYMENT material, and was listed to every organization on the node — by name, organization, fingerprint
// and expiry. The customer chooses that name, so whether their own CA leaked to the others depended on how
// they had happened to write it.
//
// The registry knows the answer exactly: a certificate is admitted AS the tenant whose CA issued it, and
// re-pointing a CA at another tenant is refused. That fact is now carried onto the screen.
func TestADeviceCAsOwnerComesFromTheRegistryNotItsName(t *testing.T) {
	items := []pkiCertificateItem{
		// Named WITHOUT the convention, owned by somebody else. This is the one that leaked.
		{SHA256: "aaa", Role: "device_client_ca", Subject: "CN=Probe3 Device CA,O=Bootstrap Probe 3", TenantID: "tenant_probe3"},
		// Named WITHOUT the convention, owned by the caller.
		{SHA256: "bbb", Role: "device_client_ca", Subject: "CN=Acme Device CA,O=Acme", TenantID: "tenant_northwind"},
		// The deployment's own material: no owner, and it must stay visible to everybody.
		{SHA256: "ccc", Role: "transport_anchor", Subject: "CN=Lantern DSSE Transport CA (MSSP) v2,O=Lantern DSSE"},
		// A device CA the registry cannot place. Fails CLOSED rather than being shown to all.
		{SHA256: "ddd", Role: "device_client_ca", Subject: "CN=Orphan Device CA,O=Nobody"},
	}
	kept := pkiCertificateItemsForTenant(items, "tenant_northwind", nil)

	got := map[string]bool{}
	for _, item := range kept {
		got[item.SHA256] = true
	}
	if got["aaa"] {
		t.Fatal("another organization's device CA is still listed — the owner is being read from the name again")
	}
	if !got["bbb"] {
		t.Fatal("the caller's OWN device CA was dropped: scoping turned into a blinding")
	}
	if !got["ccc"] {
		t.Fatal("the deployment's own transport anchor was dropped — an unowned item is not automatically somebody's")
	}
	if got["ddd"] {
		t.Fatal("a device CA the registry cannot place was shown to a customer: 'no owner' must not read as 'everybody's' for a CA that always belongs to somebody")
	}

	// ★ THE CONTROL: the boundary is OWNERSHIP, not a fixed list. The other organization must see its own and
	// not this one's — otherwise the assertions above would pass just as well for a filter that always drops
	// the same two certificates.
	//
	// (The operator is not tested here because the operator never reaches this function: answering for the
	// deployment skips the filter entirely at the handler, which is what keeps the orphan visible to the one
	// caller who can act on it.)
	theirs := pkiCertificateItemsForTenant(items, "tenant_probe3", nil)
	other := map[string]bool{}
	for _, item := range theirs {
		other[item.SHA256] = true
	}
	if !other["aaa"] {
		t.Fatal("the other organization lost its OWN device CA")
	}
	if other["bbb"] {
		t.Fatal("the boundary leaks the other way too")
	}
	if !other["ccc"] {
		t.Fatal("the deployment's own material vanished for the other organization")
	}
}

// ★ AND THE OPERATOR IS TOLD, RATHER THAN LEFT WITH A BLANK COLUMN (2026-08-18).
//
// The route that could create an ownerless device-trust CA is retired, but the ones already registered still
// admit devices — and a device admitted through a CA belonging to nobody resolves to no tenant at all. The
// operator is the only caller who can see it (a tenant's view withholds it entirely) and the only one who can
// place it or withdraw it, so the answer says which ones they are.
func TestAnOwnerlessDeviceCAIsNamedToTheOperator(t *testing.T) {
	items := []pkiCertificateItem{
		{SHA256: "aaa", Role: "device_client_ca", Subject: "CN=Owned,O=X", TenantID: "tenant_a"},
		{SHA256: "bbb", Role: "device_client_ca", Subject: "CN=Orphan,O=Nobody"},
	}
	// The builder sets OwnerUnknown; here the assertion is on what the FILTER does with it, which is the part
	// that decides who sees the problem.
	items[1].OwnerUnknown = true

	// A tenant sees neither the other tenant's nor the orphan.
	forTenant := pkiCertificateItemsForTenant(items, "tenant_b", nil)
	if len(forTenant) != 0 {
		t.Fatalf("a tenant was shown a CA that is not theirs: %+v", forTenant)
	}

	// The owner sees its own and still not the orphan — an unplaceable CA is not silently attributed to
	// whoever happens to be asking.
	forOwner := pkiCertificateItemsForTenant(items, "tenant_a", nil)
	if len(forOwner) != 1 || forOwner[0].SHA256 != "aaa" {
		t.Fatalf("the owner's view is wrong: %+v", forOwner)
	}
	if forOwner[0].OwnerUnknown {
		t.Fatal("an owned CA was marked unplaceable")
	}
}
