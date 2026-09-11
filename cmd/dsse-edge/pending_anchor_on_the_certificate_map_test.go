package main

import "testing"

// ★★★ THE ROTATION'S FAR END WAS NOT ON THE CUSTOMER'S OWN CERTIFICATE MAP (2026-08-20).
//
// During an overlap an organization's devices are told to trust TWO of its authorities: the one this node
// serves and the one it is moving onto. The map drew only the first. So the customer could see the end they
// are leaving and not the end they are arriving at — while the question the overlap exists to answer is "have
// my machines picked up the new one yet", which cannot be asked about a row that is not there.
func TestTheFarEndOfARotationIsOnTheCertificateMap(t *testing.T) {
	dir := t.TempDir()
	writeTenantCACert(t, dir, "tenant_northwind", "northwind.dsse.invalid")
	useEmptyTenantCertificateIndex(t)
	if _, err := loadTransportTenantCertificates(dir); err != nil {
		t.Fatal(err)
	}
	served, _ := transportTenantCertificates.AnchorFor("tenant_northwind")

	inventory := buildPKICertificateInventory(pkiCertInventoryInput{
		PerTenantTransportAnchors:        map[string]string{"tenant_northwind": served},
		PerTenantPendingTransportAnchors: map[string]string{"tenant_northwind": served},
	})
	anchors := 0
	for _, item := range inventory.Items {
		if item.Role == "transport_anchor" && item.TenantID == "tenant_northwind" {
			anchors++
		}
	}
	if anchors != 2 {
		t.Fatalf("the map drew %d anchor(s) for an organization mid-overlap; its devices are told two, and the "+
			"one it is moving ONTO is the one it needs to watch", anchors)
	}
	inactive := 0
	for _, item := range inventory.Items {
		if item.Role == "transport_anchor" && item.TenantID == "tenant_northwind" && !item.Active {
			inactive++
		}
	}
	if inactive != 1 {
		t.Fatalf("the announced-but-not-served anchor is not marked inactive (%d inactive) — nothing is "+
			"presented under it today and the map must not say otherwise", inactive)
	}
}
