// steer_posture_resolve.go — portable (no OS build tag) so the CP-posture override logic unit-tests on any
// host. The Windows entrypoint fetches the signed posture and calls applyCPPosture to fold it over the
// bootstrap flags. Phase 3c of docs/2026-07-24_cp_controlled_steering_posture_and_device_state.ja.md,
// amended 2026-08-06: the fail-open PERMISSION is no longer CP-authoritative (see applyCPPosture).
package main

import (
	"time"

	"github.com/lantern-networks/dsse-core/agentpolicy"
)

// resolvedPosture is the effective steering posture after the CP signed policy is folded over the bootstrap
// flags. FailOpen (the plain per-flow fail-open) and RegionFailover stay mutually exclusive; TerminalFailOpen
// is the THIRD mode — fail-open as the terminal fallback that coexists WITH region-failover and fires only on
// region exhaustion (Phase 4).
type resolvedPosture struct {
	FailOpen         bool // plain per-flow fail-open (trips on the first Edge outage); only when NOT region-failover
	RegionFailover   bool // in-boundary region selection: operator priority first, RTT only within a tier (see RegionEndpoint.Priority)
	TerminalFailOpen bool // fail-open ONLY after ALL regions are exhausted; only alongside RegionFailover
	Cooldown         time.Duration
}

// applyCPPosture computes the effective posture. Authority is split by axis, deliberately:
//
//   - fail-open PERMISSION is decided at INSTALL TIME (--fail-open --acknowledge-fail-open, or the signed
//     install profile) and the CP cannot grant or revoke it. Fail-open is a machine-local safety trade
//     acknowledged by whoever installed the agent on that box; a CP value silently flipping it defeats the
//     acknowledgment ceremony in one direction (2026-08-06: the lab box ran fail-closed for a period no one
//     chose, because the Edge served the default "off") and would let a compromised CP turn the fleet
//     fail-open in the other. The CP's fail_open_mode is therefore ignored here.
//   - region-failover IS CP-authoritative: it is a residency-boundary property of the tenant, not of one
//     machine, and it stays fail-CLOSED by construction.
//   - the MODE of an install-permitted fail-open follows region-failover: with region-failover OFF it is the
//     plain per-flow fail-open; with region-failover ON it becomes TERMINAL — firing only after ALL
//     in-boundary regions are exhausted, never on a single-region blip — because per-flow fail-open under
//     region-failover would bypass the boundary while healthy in-boundary regions remain.
//   - cooldown is operational tuning, not a safety decision: a positive CP value overrides the flag.
func applyCPPosture(bootFailOpen, bootRegion bool, bootCooldown time.Duration, p agentpolicy.SteeringPosturePayload) resolvedPosture {
	region := p.RegionFailover
	cooldown := bootCooldown
	if p.FailOpenCooldownMS > 0 {
		cooldown = time.Duration(p.FailOpenCooldownMS) * time.Millisecond
	}
	return resolvedPosture{
		FailOpen:         bootFailOpen && !region,
		RegionFailover:   region,
		TerminalFailOpen: bootFailOpen && region,
		Cooldown:         cooldown,
	}
}
