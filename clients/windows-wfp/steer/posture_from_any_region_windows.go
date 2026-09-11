package main

// posture_from_any_region_windows.go -- the half of the walk that dials, split from the half that plans.
//
// The planning side (posture_from_any_region.go) is deliberately platform-neutral so it is tested on the Linux
// CI runner like everything else. This side touches transportHTTPClient, which exists only in the Windows
// build, and a shared symbol reached from an untagged file is how this box goes red alone (2026-08-14).

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/agentpolicy"
)

// fetchPostureFromAnyRegion asks each address in the plan, in order, and returns the first VERIFIED answer.
//
// ★ THE WALK LIVES HERE BECAUSE BOTH CALLERS NEED IT. The start-up fetch is the obvious one; the retry loop is
// the one that matters more, because the retry only exists when the first fetch failed — which on this
// deployment means the home region is down, which is exactly the case a single-address retry cannot escape.
// Two spellings of the walk would have drifted, and the second one would have been the one still asking a dead
// address every minute.
//
// ★ IT DOES NOT WEAKEN THE VERIFICATION. Every answer is checked against the same pinned key by the same
// function; a region that answers with a forgery is refused exactly as the home region would be, and the walk
// simply moves on. Reaching a different node is not the same as trusting one.
func fetchPostureFromAnyRegion(tc transportConfig, plan []posturedEndpoint, keys []string,
	timeout time.Duration) (agentpolicy.SteeringPosturePayload, posturedEndpoint, int, error) {
	var (
		posture agentpolicy.SteeringPosturePayload
		err     = errors.New("no address to ask for the steering posture")
		last    posturedEndpoint
	)
	for i, cand := range plan {
		last = cand
		// Dial THIS candidate. transportHTTPClient follows the config's own target, so asking a second region
		// needs a copy pointed at it: `active` and `pins` are cleared because both OVERRIDE host, and both hold
		// the home region's address. Trust material, the client certificate and the organization's announced
		// name are shared by pointer and deliberately kept — the same organization is being asked, at a
		// different door.
		ask := tc
		ask.host, ask.serverName, ask.active, ask.pins = cand.HostPort, cand.ServerName, nil, nil
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		posture, err = agentpolicy.FetchVerifiedSteeringPostureWithKeys(ctx, transportHTTPClient(ask),
			strings.TrimRight(cand.BaseURL, "/"), keys)
		cancel()
		if err == nil {
			return posture, cand, i, nil
		}
	}
	return posture, last, -1, err
}
