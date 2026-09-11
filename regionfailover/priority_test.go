package regionfailover

import "testing"

// Operator priority OUTRANKS measured latency.
//
// The requirement, stated by the operator on 2026-08-10: multi-region must have a configurable order, and a
// tolerance band is not a substitute because tens of milliseconds is not noise — it is several TLS round trips
// and every serialized request after them. So a preferred region that is MEASURABLY SLOWER still wins.
//
// Deliberately asserted against a large, unambiguous latency gap (10 ms vs 80 ms) so this test cannot pass by
// the ranking accidentally tying: if priority were still secondary to RTT, osaka would win by 70 ms.
func TestOperatorPriorityBeatsAFasterRegion(t *testing.T) {
	tokP1 := RegionEndpoint{Region: "jp-tokyo", Endpoint: "https://tok:443", Priority: 1}
	osaP2 := RegionEndpoint{Region: "jp-osaka", Endpoint: "https://osa:443", Priority: 2}

	s := New([]RegionEndpoint{tokP1, osaP2}, "")
	d := s.Evaluate(probeFrom(map[string]Health{"jp-tokyo": up(80), "jp-osaka": up(10)}))
	if d.Current.Region != "jp-tokyo" {
		t.Fatalf("current=%s, want jp-tokyo: priority 1 must win over a region 70ms nearer", d.Current.Region)
	}
	if len(d.FailoverSet) != 1 || d.FailoverSet[0].Region != "jp-osaka" {
		t.Fatalf("failover set = %v, want [jp-osaka] as the next tier", d.FailoverSet)
	}
}

// Within ONE tier, RTT still decides — which is the whole point of tiers. "Pick the nearest PoP" is correct
// among endpoints the operator called equally preferred, and wrong across preferences.
func TestNearestStillDecidesWithinOnePriorityTier(t *testing.T) {
	a := RegionEndpoint{Region: "jp-tokyo", Endpoint: "https://tok:443", Priority: 1}
	b := RegionEndpoint{Region: "jp-osaka", Endpoint: "https://osa:443", Priority: 1}

	s := New([]RegionEndpoint{a, b}, "jp-tokyo")
	d := s.Evaluate(probeFrom(map[string]Health{"jp-tokyo": up(50), "jp-osaka": up(10)}))
	if d.Current.Region != "jp-osaka" {
		t.Fatalf("current=%s, want jp-osaka: inside one tier the nearest wins even over the home anchor", d.Current.Region)
	}
}

// Priority is for PREFERENCE, never for reachability: an unhealthy first choice must fail over to the next tier
// rather than pin the device to a region that cannot serve it.
func TestPriorityFailsOverToTheNextTierWhenThePreferredIsDown(t *testing.T) {
	p1 := RegionEndpoint{Region: "jp-tokyo", Endpoint: "https://tok:443", Priority: 1}
	p2 := RegionEndpoint{Region: "jp-osaka", Endpoint: "https://osa:443", Priority: 2}
	p3 := RegionEndpoint{Region: "jp-ishikari", Endpoint: "https://ish:443", Priority: 3}

	s := New([]RegionEndpoint{p1, p2, p3}, "")
	d := s.Evaluate(probeFrom(map[string]Health{"jp-tokyo": down(), "jp-osaka": up(90), "jp-ishikari": up(5)}))
	if d.Current.Region != "jp-osaka" {
		t.Fatalf("current=%s, want jp-osaka: the next PRIORITY tier, not the fastest survivor", d.Current.Region)
	}
}

// An unspecified priority ranks LAST, so an explicitly-preferred region always beats one nobody ranked...
func TestUnspecifiedPriorityRanksLast(t *testing.T) {
	ranked := RegionEndpoint{Region: "jp-osaka", Endpoint: "https://osa:443", Priority: 5}
	unranked := RegionEndpoint{Region: "jp-tokyo", Endpoint: "https://tok:443"}

	s := New([]RegionEndpoint{unranked, ranked}, "jp-tokyo")
	d := s.Evaluate(probeFrom(map[string]Health{"jp-tokyo": up(1), "jp-osaka": up(100)}))
	if d.Current.Region != "jp-osaka" {
		t.Fatalf("current=%s, want jp-osaka: an explicit priority outranks an unspecified one", d.Current.Region)
	}
}

// ...and when NOTHING is ranked, every region ties and nearest-RTT decides exactly as before. This is the
// backward-compatibility guarantee for an Edge that does not yet send priorities: the change must not silently
// re-home existing fleets.
func TestNoPrioritiesAnywhereKeepsNearestRTTBehaviour(t *testing.T) {
	s := New([]RegionEndpoint{tok, osa, ish}, "jp-tokyo")
	d := s.Evaluate(probeFrom(map[string]Health{"jp-tokyo": up(50), "jp-osaka": up(10), "jp-ishikari": down()}))
	if d.Current.Region != "jp-osaka" {
		t.Fatalf("current=%s, want jp-osaka: with no priorities configured the nearest healthy region still wins", d.Current.Region)
	}
}
