package main

import (
	"strings"
	"testing"

	"github.com/lantern-networks/dsse-core/regionfailover"
)

// the_home_region_is_a_preference_test.go — an organization's home region decides where its devices steer.
//
// ★★★ IT DECIDED NOTHING (2026-08-30, the operator asked whether region priority is verified to work).
// allowedRegionEndpoints puts the home region first, so the preference reached the profile as an ORDER — and
// both agents discard order and rank by RegionPriority, where 0 means UNSPECIFIED and sorts LAST. An empty
// map ties every region and nearest-RTT decides everything. Nothing in this product could fill that map: no
// field in the request body, no control on any screen, and the issuing route never set it. Measured on the
// lab the same day, an organization homed in fukuoka had its device steering through nagoya.

func TestTheOfferedOrderBecomesTheRank(t *testing.T) {
	got := agentProfileRegionPriority([]string{
		"nagoya=https://agents.nagoya.example",
		"fukuoka=https://agents.fukuoka.example",
	})
	if got["nagoya"] != 1 || got["fukuoka"] != 2 || len(got) != 2 {
		t.Fatalf("ranks are %v, want nagoya=1 fukuoka=2", got)
	}
	// ★ 1, not 0: zero is the wire's "unspecified" and sorts LAST, which is the exact silence being fixed —
	// a profile that said "prefer nagoya" as rank 0 would prefer it last.
	for region, rank := range got {
		if rank == 0 {
			t.Errorf("%s was given rank 0, which the agents read as unspecified", region)
		}
	}
	// And the deployment's own validator must accept what this produces, or an operator meets an error from a
	// document nobody typed.
	if errs := regionfailover.ValidatePriority(got); len(errs) > 0 {
		t.Errorf("the derived ranks do not validate: %v", errs)
	}
}

// ★ THE TWO CANNOT DISAGREE, because one is derived from the other. A profile whose endpoint order says one
// thing and whose ranks say another is worse than either alone: the agent follows the ranks and the operator
// reads the order.
func TestTheRankAndTheOrderAreTheSameFact(t *testing.T) {
	endpoints := []string{
		"fukuoka=https://agents.fukuoka.example",
		"nagoya=https://agents.nagoya.example",
		"osaka=https://agents.osaka.example",
	}
	ranks := agentProfileRegionPriority(endpoints)
	for i, e := range endpoints {
		region := strings.TrimSpace(strings.Split(e, "=")[0])
		if ranks[region] != i+1 {
			t.Errorf("%s is offered %d%s but ranked %d", region, i+1, "th", ranks[region])
		}
	}
}

func TestOneRegionIsNotAPreference(t *testing.T) {
	// A single region cannot be reordered, and putting a rank on the wire for it is a value an operator would
	// later have to reason about for nothing.
	if got := agentProfileRegionPriority([]string{"nagoya=https://agents.nagoya.example"}); got != nil {
		t.Errorf("a single region produced ranks %v", got)
	}
	// The single-region fallback address carries no region tag at all and expresses no preference.
	if got := agentProfileRegionPriority([]string{"https://agents.example"}); got != nil {
		t.Errorf("an untagged address produced ranks %v", got)
	}
	if got := agentProfileRegionPriority(nil); got != nil {
		t.Errorf("no endpoints produced ranks %v", got)
	}
}

// ★ AND THE ROUTE THAT ISSUES PROFILES ACTUALLY CARRIES IT. The helper is where the rank is computed; the
// call site is where it reaches a device. A helper with no caller is the failure this repository has hit in
// Go and in Swift, and it passes every test of the helper — which is precisely how this field spent its
// whole life inert.
func TestTheProfileRouteCarriesTheRank(t *testing.T) {
	source := readSourceFile(t, "admin_agent_profile_routes.go")
	// Matched on the CALL, not on its spacing: an assertion that pins gofmt's column alignment fails
	// the day the file is reformatted and says the feature was removed.
	if !strings.Contains(source, "agentProfileRegionPriority(endpoints)") {
		t.Error("the profile-issuing route does not carry the region rank, so every device it configures " +
			"ranks its regions by measured latency alone and the home region decides nothing")
	}
	build := readSourceFile(t, "../../installprofile/build.go")
	if !strings.Contains(build, "o.RegionPriority") {
		t.Error("installprofile.Build drops the rank, so the route can set it and the profile will not carry it")
	}
}
