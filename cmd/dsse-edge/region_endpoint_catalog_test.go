package main

import (
	"testing"
)

func mustCatalog(t *testing.T, raw string) *regionEndpointCatalog {
	t.Helper()
	c, err := parseRegionEndpoints(raw)
	if err != nil {
		t.Fatalf("parseRegionEndpoints(%q): %v", raw, err)
	}
	return c
}

func regionsOf(eps []regionEndpoint) []string {
	out := make([]string, 0, len(eps))
	for _, e := range eps {
		out = append(out, e.Region)
	}
	return out
}

func eq(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

const threeRegionCatalog = "jp-tokyo=https://tok.edge:443;jp-osaka=https://osa.edge:443;jp-ishikari=https://ish.edge:443"

// TestGeoSteeringResidencyFilteringNeverEmitsOutOfBoundary is the structural residency guarantee: a
// residency-pinned tenant's agent is NEVER offered a region outside its allowed set, so it cannot land out of
// boundary no matter how it measures latency.
func TestGeoSteeringResidencyFilteringNeverEmitsOutOfBoundary(t *testing.T) {
	cat := mustCatalog(t, threeRegionCatalog)

	// Pinned to a single region: only that region is offered.
	got := regionsOf(cat.allowedRegionEndpoints([]string{"jp-tokyo"}, ""))
	if !eq(got, []string{"jp-tokyo"}) {
		t.Fatalf("single-region pinned = %v, want [jp-tokyo] (no osaka/ishikari)", got)
	}

	// Pinned to two of three: the third is never emitted; home anchors first.
	got = regionsOf(cat.allowedRegionEndpoints([]string{"jp-osaka", "jp-tokyo"}, "jp-osaka"))
	if !eq(got, []string{"jp-osaka", "jp-tokyo"}) {
		t.Fatalf("two-region pinned (home osaka) = %v, want [jp-osaka jp-tokyo] (ishikari excluded, home first)", got)
	}
}

// TestGeoSteeringHomeRegionAnchoredFirst proves: home_region is the tiebreak/preferred-failover anchor, placed
// first; the rest follow in catalog order.
func TestGeoSteeringHomeRegionAnchoredFirst(t *testing.T) {
	cat := mustCatalog(t, threeRegionCatalog)
	got := regionsOf(cat.allowedRegionEndpoints(nil, "jp-ishikari")) // unpinned, home ishikari
	if !eq(got, []string{"jp-ishikari", "jp-tokyo", "jp-osaka"}) {
		t.Fatalf("unpinned home=ishikari = %v, want [jp-ishikari jp-tokyo jp-osaka] (home first, then catalog order)", got)
	}
}

// TestGeoSteeringUnpinnedGetsAllRegions proves an unpinned tenant ranges over every region (global nearest).
func TestGeoSteeringUnpinnedGetsAllRegions(t *testing.T) {
	cat := mustCatalog(t, threeRegionCatalog)
	got := regionsOf(cat.allowedRegionEndpoints(nil, ""))
	if !eq(got, []string{"jp-tokyo", "jp-osaka", "jp-ishikari"}) {
		t.Fatalf("unpinned = %v, want all three in catalog order", got)
	}
}

// TestGeoSteeringHomeOutsideBoundaryStillFilteredOut proves residency beats a misconfigured home: if home is not
// in allowed_regions, it is NOT emitted (the boundary wins).
func TestGeoSteeringHomeOutsideBoundaryStillFilteredOut(t *testing.T) {
	cat := mustCatalog(t, threeRegionCatalog)
	got := regionsOf(cat.allowedRegionEndpoints([]string{"jp-tokyo"}, "jp-osaka")) // home osaka NOT allowed
	if !eq(got, []string{"jp-tokyo"}) {
		t.Fatalf("home outside boundary = %v, want [jp-tokyo] (osaka home filtered out by residency)", got)
	}
}

// TestGeoSteeringUnknownAllowedRegionIsIgnored proves a residency entry with no catalog endpoint yields nothing
// for that region (fail-closed: never a phantom endpoint).
func TestGeoSteeringUnknownAllowedRegionIsIgnored(t *testing.T) {
	cat := mustCatalog(t, threeRegionCatalog)
	got := regionsOf(cat.allowedRegionEndpoints([]string{"eu-frankfurt"}, "eu-frankfurt")) // not in catalog
	if len(got) != 0 {
		t.Fatalf("unknown allowed region = %v, want [] (no phantom endpoint)", got)
	}
}

// TestParseRegionEndpointsRejectsBadInput guards the config contract.
func TestParseRegionEndpointsRejectsBadInput(t *testing.T) {
	for _, bad := range []string{"jp-tokyo", "jp-tokyo=http://insecure", "=https://x", "jp-tokyo=https://a;jp-tokyo=https://b"} {
		if _, err := parseRegionEndpoints(bad); err == nil {
			t.Fatalf("parseRegionEndpoints(%q) = nil error, want rejection", bad)
		}
	}
	if c, err := parseRegionEndpoints(""); err != nil || c != nil {
		t.Fatalf("empty = (%v,%v), want (nil,nil) = geo-steering disabled", c, err)
	}
}

// TestRegionIDsAndDigestMakeAFleetComparable — the region map is per-node configuration with no control-plane
// authorship, so the only way to find an Edge that was missed when a region was added is to ask every node
// what it knows and compare. These two are what makes that possible.
func TestRegionIDsAndDigestMakeAFleetComparable(t *testing.T) {
	a, err := parseRegionEndpoints("region-a=https://a.example;region-b=https://b.example")
	if err != nil {
		t.Fatal(err)
	}
	// Same regions, other order: configured the same, and reporting them as divergent is the false alarm
	// that gets a check ignored.
	b, err := parseRegionEndpoints("region-b=https://b.example;region-a=https://a.example")
	if err != nil {
		t.Fatal(err)
	}
	if a.digest() != b.digest() {
		t.Errorf("two Edges given the same regions in a different order disagree: %s vs %s", a.digest(), b.digest())
	}
	if got := len(a.regionIDs()); got != 2 {
		t.Errorf("regionIDs reported %d regions, want 2", got)
	}

	// An Edge that was MISSED when region-b was added. This is the whole point.
	missed, err := parseRegionEndpoints("region-a=https://a.example")
	if err != nil {
		t.Fatal(err)
	}
	if missed.digest() == a.digest() {
		t.Error("an Edge holding only region-a reports the same digest as one holding both — a region that " +
			"reached only part of the fleet would be invisible")
	}

	// A matching id pointing somewhere else is a divergence too: the devices that Edge serves fail over to a
	// different address than the rest of the fleet sends them to.
	moved, err := parseRegionEndpoints("region-a=https://a.example;region-b=https://elsewhere.example")
	if err != nil {
		t.Fatal(err)
	}
	if moved.digest() == a.digest() {
		t.Error("the same region ids pointing at different endpoints report the same digest")
	}

	// A single-region Edge holds no map at all, and must say so rather than looking like an empty fleet answer.
	var none *regionEndpointCatalog
	if none.digest() != "" || len(none.regionIDs()) != 0 {
		t.Error("a single-region Edge should report no map")
	}
}
