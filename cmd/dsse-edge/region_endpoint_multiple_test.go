package main

import "testing"

func TestCatalogRetainsThreeDoorsWithinOneAllowedRegion(t *testing.T) {
	c, err := parseRegionEndpoints("kiri=https://a.example;kiri=https://b.example;kiri=https://c.example;osaka=https://o.example")
	if err != nil {
		t.Fatal(err)
	}
	got := c.allowedRegionEndpoints([]string{"kiri"}, "kiri")
	if len(got) != 3 || got[0].Endpoint != "https://a.example" || got[1].Endpoint != "https://b.example" || got[2].Endpoint != "https://c.example" {
		t.Fatalf("residency-filtered doors=%v", got)
	}
	if len(c.regionIDs()) != 2 {
		t.Fatalf("region IDs=%v", c.regionIDs())
	}
	reordered, err := parseRegionEndpoints("osaka=https://o.example;kiri=https://c.example;kiri=https://a.example;kiri=https://b.example")
	if err != nil || c.digest() != reordered.digest() {
		t.Fatalf("same doors produced different digest: %s / %s (%v)", c.digest(), reordered.digest(), err)
	}
	section := regionEndpointBundleSection(true, c)
	if len(section.Endpoints) != 4 {
		t.Fatalf("bundle=%v", section.Endpoints)
	}
}
