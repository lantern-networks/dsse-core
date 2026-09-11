package main

import (
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/agentpolicy"
)

func TestApplyCPPosture(t *testing.T) {
	boot := 10 * time.Second
	cases := []struct {
		name         string
		bootFailOpen bool
		p            agentpolicy.SteeringPosturePayload
		wantFailOpen bool
		wantRegion   bool
		wantTerminal bool
		wantCooldown time.Duration
	}{
		{
			// The 2026-08-06 incident, inverted: the install said fail-open (acknowledged), the Edge served its
			// default "off" — and the box silently ran fail-closed. The install decision must survive the CP.
			name:         "CP 'off' cannot revoke an install-time fail-open",
			bootFailOpen: true,
			p:            agentpolicy.SteeringPosturePayload{FailOpenMode: agentpolicy.FailOpenOff},
			wantFailOpen: true, wantRegion: false, wantTerminal: false, wantCooldown: boot,
		},
		{
			// The other direction of the same principle: a CP (compromised or misconfigured) must not be able
			// to turn a fleet fail-open when no human acknowledged it at install.
			name:         "CP 'terminal' cannot grant fail-open the install never acknowledged",
			bootFailOpen: false,
			p:            agentpolicy.SteeringPosturePayload{FailOpenMode: agentpolicy.FailOpenTerminal},
			wantFailOpen: false, wantRegion: false, wantTerminal: false, wantCooldown: boot,
		},
		{
			name:         "install fail-open + CP region-failover => TERMINAL fail-open, per-flow OFF",
			bootFailOpen: true,
			p:            agentpolicy.SteeringPosturePayload{FailOpenMode: agentpolicy.FailOpenOff, RegionFailover: true},
			wantFailOpen: false, wantRegion: true, wantTerminal: true, wantCooldown: boot,
		},
		{
			name:         "no install fail-open + CP region-failover => region only, no fail-open of any kind",
			bootFailOpen: false,
			p:            agentpolicy.SteeringPosturePayload{FailOpenMode: agentpolicy.FailOpenTerminal, RegionFailover: true},
			wantFailOpen: false, wantRegion: true, wantTerminal: false, wantCooldown: boot,
		},
		{
			name:         "strict install stays strict when the CP says nothing",
			bootFailOpen: false,
			p:            agentpolicy.SteeringPosturePayload{},
			wantFailOpen: false, wantRegion: false, wantTerminal: false, wantCooldown: boot,
		},
		{
			name:         "CP cooldown overrides boot (operational tuning stays CP-adjustable)",
			bootFailOpen: true,
			p:            agentpolicy.SteeringPosturePayload{FailOpenCooldownMS: 3000},
			wantFailOpen: true, wantRegion: false, wantTerminal: false, wantCooldown: 3 * time.Second,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := applyCPPosture(c.bootFailOpen, false, boot, c.p)
			if got.FailOpen != c.wantFailOpen || got.RegionFailover != c.wantRegion || got.TerminalFailOpen != c.wantTerminal || got.Cooldown != c.wantCooldown {
				t.Fatalf("applyCPPosture = %+v, want failOpen=%v region=%v terminal=%v cooldown=%s", got, c.wantFailOpen, c.wantRegion, c.wantTerminal, c.wantCooldown)
			}
			// Invariant: per-flow fail-open and region-failover are never both on.
			if got.FailOpen && got.RegionFailover {
				t.Fatalf("per-flow fail-open and region-failover must be mutually exclusive: %+v", got)
			}
			// Invariant: terminal fail-open only ever alongside region-failover.
			if got.TerminalFailOpen && !got.RegionFailover {
				t.Fatalf("terminal fail-open must only appear with region-failover: %+v", got)
			}
			// Invariant: no form of fail-open exists that the install did not acknowledge.
			if (got.FailOpen || got.TerminalFailOpen) && !c.bootFailOpen {
				t.Fatalf("fail-open appeared without an install-time acknowledgment: %+v", got)
			}
		})
	}
}
