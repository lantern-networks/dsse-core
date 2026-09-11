package main

import (
	"sort"
	"strings"
	"sync/atomic"
)

// mesh_state_report.go — whether this Edge can reach a connector that lives in another region, said out loud.
//
// ★★★ THE MESH IS FAIL-CLOSED BY DEFAULT, AND THAT MUST BE VISIBLE RATHER THAN INFERRED (2026-08-25).
//
// With no peers configured there is no path to another region's connector: the flow is refused by name. That
// is the right default and the architecture's, but it is indistinguishable from a mesh that IS configured and
// whose links are all down — both refuse the same flow the same way. One is a decision and the other is an
// outage, and an operator staring at a refused connection has no way to tell which.
//
// So the Edge reports three things it alone knows: whether a mesh is configured at all, which regions it is
// meant to reach, and which of those links are LIVE right now. Reported rather than asked for, like every
// other node fact — the control plane serves no data plane, so it cannot answer this about anybody.
//
// ★ AND WHETHER ANYTHING IS ELIGIBLE TO USE IT. A link that is up relays nothing unless a destination opts in
// (-mesh-eligible-hosts, also empty by default). A deployment with healthy links and an empty eligibility list
// behaves exactly like one with no links, which is the second way this can look like a network fault.
var (
	meshConfiguredPeers atomic.Pointer[[]string]
	meshEligibleCount   atomic.Int64
	meshLiveLookup      atomic.Pointer[func(string) bool]
)

// setMeshState records what this node was configured with. Called once at start-up, including with an empty
// list — "none" is the answer that has to be sayable.
func setMeshState(peerRegions []string, eligibleHosts int, live func(region string) bool) {
	regions := make([]string, 0, len(peerRegions))
	for _, r := range peerRegions {
		if r = strings.ToLower(strings.TrimSpace(r)); r != "" {
			regions = append(regions, r)
		}
	}
	sort.Strings(regions)
	meshConfiguredPeers.Store(&regions)
	meshEligibleCount.Store(int64(eligibleHosts))
	if live != nil {
		meshLiveLookup.Store(&live)
	}
}

// meshStateForReport is what this node says about its mesh, for the health answer it already serves.
func meshStateForReport() map[string]any {
	regions := []string{}
	if p := meshConfiguredPeers.Load(); p != nil {
		regions = *p
	}
	out := map[string]any{
		"configured":      len(regions) > 0,
		"peer_regions":    regions,
		"eligible_hosts":  meshEligibleCount.Load(),
		"live_to_regions": []string{},
	}
	if len(regions) == 0 {
		return out
	}
	live := []string{}
	if fn := meshLiveLookup.Load(); fn != nil {
		for _, r := range regions {
			if (*fn)(r) {
				live = append(live, r)
			}
		}
	}
	out["live_to_regions"] = live
	return out
}
