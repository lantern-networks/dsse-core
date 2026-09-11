package main

import "github.com/lantern-networks/dsse-core/agentpolicy"

// steerPostureConfig is the edge-authored (CP-controlled) steering posture served SIGNED to each device at
// GET /steer/agent-policy/posture. It is the central replacement for the agent's --fail-open /
// --region-failover / --fail-open-cooldown startup flags: change it on the edge and every device picks up the
// new posture on its next fetch — no agent re-registration. See
// docs/2026-07-24_cp_controlled_steering_posture_and_device_state.ja.md.
type steerPostureConfig struct {
	FailOpenMode       string // agentpolicy.FailOpenOff | agentpolicy.FailOpenTerminal
	FailOpenCooldownMS int
	RegionFailover     bool
}

// normalized clamps the fail-open mode to the known enum (anything other than the exact "terminal" becomes the
// fail-CLOSED "off"), so a misconfigured edge flag can never widen the boundary. A negative cooldown is zeroed.
func (c steerPostureConfig) normalized() steerPostureConfig {
	if c.FailOpenMode != agentpolicy.FailOpenTerminal {
		c.FailOpenMode = agentpolicy.FailOpenOff
	}
	if c.FailOpenCooldownMS < 0 {
		c.FailOpenCooldownMS = 0
	}
	return c
}
