//go:build windows

package main

import (
	"sync/atomic"
	"testing"
)

// ★ The defect: the probe announced the region's own hostname while every real dial announced the
// organization's. The SNI selects the certificate, so the probe asked for a different one and then failed to
// verify it against this organization's anchors — reporting a healthy region as unreachable.
func TestTheProbeAnnouncesTheNameTheRealDialAnnounces(t *testing.T) {
	org := "jduwy24uvp46y23krq7v2slioi.tsubaki.lab"
	tc := transportConfig{
		configuredServerName: org,
		announcedServerName:  &atomic.Pointer[string]{},
		fleetServerName:      &atomic.Pointer[string]{},
	}
	if got := probeSNI(tc, "agents.nagoya.tsubaki.lab"); got != org {
		t.Fatalf("the probe would ask for a different certificate than the tunnel: got %q want %q", got, org)
	}
	if got := tc.activeServerName(); got != probeSNI(tc, "agents.nagoya.tsubaki.lab") {
		t.Fatalf("probe and dial disagree: %q vs %q", got, probeSNI(tc, "agents.nagoya.tsubaki.lab"))
	}
}

// A deployment that announces no name at all keeps the old behaviour: the region's own host name. Absence is
// not permission to invent one.
func TestWithNoAnnouncedNameTheRegionHostStands(t *testing.T) {
	tc := transportConfig{
		announcedServerName: &atomic.Pointer[string]{},
		fleetServerName:     &atomic.Pointer[string]{},
	}
	if got := probeSNI(tc, "agents.nagoya.tsubaki.lab"); got != "agents.nagoya.tsubaki.lab" {
		t.Fatalf("got %q", got)
	}
}

// An announced name adopted at runtime has to reach the probe too — it is shared by pointer for exactly this.
func TestAnAdoptedNameReachesTheProbe(t *testing.T) {
	tc := transportConfig{
		configuredServerName: "installed.example",
		announcedServerName:  &atomic.Pointer[string]{},
		fleetServerName:      &atomic.Pointer[string]{},
	}
	adopted := "announced.example"
	tc.announcedServerName.Store(&adopted)
	if got := probeSNI(tc, "agents.nagoya.tsubaki.lab"); got != adopted {
		t.Fatalf("the probe kept a stale name: %q", got)
	}
}
