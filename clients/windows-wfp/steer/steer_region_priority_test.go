package main

import (
	"testing"

	"github.com/lantern-networks/dsse-core/regionfailover"
)

// TestTheSeedIsRankedToo is the ordering fact this driver depends on, asserted through newRegionFailover
// because that is where the guarantee lives.
//
// The macOS agent applies the preference only to each list its poller serves, and does not need more: its
// bootstrap seed is a single synthetic endpoint, so there is nothing to order. Here the seed is
// --region-endpoints-seed, a real multi-region MDM bootstrap list; it is what the device steers by until a
// fetch succeeds, and what it KEEPS while the Edge is unreachable, which can be indefinite. Ranking only
// refreshed lists would leave the bootstrap window — and every offline device — decided by jitter, which is
// the defect this feature exists to remove.
func TestTheSeedIsRankedToo(t *testing.T) {
	seed := []regionfailover.RegionEndpoint{
		{Region: "jp-tokyo", Endpoint: "https://tok:443"},
		{Region: "jp-osaka", Endpoint: "https://osa:443"},
	}
	rf := newRegionFailover(seed, "jp-tokyo", nil, regionFailoverActions{}, regionFailoverOptions{
		regionPriority: map[string]int{"jp-osaka": 1, "jp-tokyo": 2},
	})

	got := map[string]int{}
	for _, ep := range rf.allowed {
		got[ep.Region] = ep.Priority
	}
	if got["jp-osaka"] != 1 || got["jp-tokyo"] != 2 {
		t.Fatalf("the seed reached the driver unranked: %v — the bootstrap window would be decided by jitter", got)
	}
	// The caller's slice must not have been rewritten underneath it.
	if seed[0].Priority != 0 || seed[1].Priority != 0 {
		t.Fatalf("newRegionFailover mutated the caller's seed: %+v", seed)
	}
}
