package policyrule

import "github.com/lantern-networks/dsse-core/decision"

// sourceNoMatchSentinel is emitted as the device selector when an authored rule's source resolves to ZERO
// device identities (e.g. its source devices are not enrolled yet). It can never equal a real device id, so
// the rule matches nothing — fail-closed — instead of degrading to a wildcard source. The NUL byte keeps it
// distinct from any legitimate identifier.
const sourceNoMatchSentinel = "\x00no-such-source-device"

// destinationNoMatchSentinel is the destination-side analogue: emitted when an authored rule's NON-Any
// destination resolves to ZERO tokens (e.g. its endpoint was removed from the catalog). An empty Destinations
// slice matches ANY destination, so without this an unresolved destination would silently widen the rule to the
// whole lateral plane (fail-open); the sentinel can never equal a real destination token, so the rule matches
// nothing instead — symmetric with the source path.
const destinationNoMatchSentinel = "\x00no-such-destination"

// EastWestResolver resolves authored subject/service references to the match tokens the enforcement
// primitive (decision.EastWestRule) compares against the decision request. The asset catalog implements it.
type EastWestResolver interface {
	// SourceDeviceTokens returns the device identities of the steered endpoints denoted by the source subject
	// ids (groups expand to members), compared against req.DeviceID.
	SourceDeviceTokens(tenant string, ids []string) []string
	// DestinationTokens returns the match tokens (FQDN/IP address, else alias) for the destination subject
	// ids, compared against req.Destination / req.FQDN / req.ApplicationID.
	DestinationTokens(tenant string, ids []string) []string
	// ServiceProtocols returns the east-west protocol families a service denotes (e.g. ["smb"]); empty means
	// any east-west protocol.
	ServiceProtocols(tenant string, serviceID string) []string
}

// CompileEastWest compiles authored OUTBOUND east-west rules into the live enforcement primitive. All axes
// map faithfully: mode ← access, destination ← destination tokens, protocol ← service, and SOURCE is
// RESTRICTED to the authored source's device identities (matched against req.DeviceID) — so a rule really
// segments WHICH devices may reach a destination. If the authored source resolves to no enrolled device, the
// rule is compiled fail-closed (a never-matching sentinel) rather than degrading to wildcard. Inbound rules
// are NOT compiled here — inbound enforces on Windows WFP at the receiver. See
// docs/east_west_rule_enforcement_mapping.md.
func CompileEastWest(tenant string, rules []Rule, resolver EastWestResolver) []decision.EastWestRule {
	out := make([]decision.EastWestRule, 0, len(rules))
	for _, r := range rules {
		if r.Plane != PlaneEastWest || r.Status != StatusActive || r.Direction != DirectionOutbound {
			continue
		}
		// Source: explicit Any => wildcard (no device selector); otherwise the authored devices, with a
		// fail-closed sentinel if they don't resolve (so an unresolved non-Any source never becomes wildcard).
		var sourceDevices []string
		if !IsAnySubject(r.Source) {
			sourceDevices = resolver.SourceDeviceTokens(tenant, r.Source)
			if len(sourceDevices) == 0 {
				sourceDevices = []string{sourceNoMatchSentinel}
			}
		}
		// Destination: explicit Any => wildcard (empty Destinations matches any). A non-Any destination that
		// resolves to ZERO tokens must NOT collapse to that wildcard (fail-open review #10) — emit the no-match
		// sentinel so the rule matches nothing, symmetric with the source path.
		var destinations []string
		if !IsAnySubject(r.Destination) {
			destinations = resolver.DestinationTokens(tenant, r.Destination)
			if len(destinations) == 0 {
				destinations = []string{destinationNoMatchSentinel}
			}
		}
		ew := decision.EastWestRule{
			ID:            r.ID,
			Priority:      r.Priority,
			SourceDevices: sourceDevices,
			Destinations:  destinations,
			Protocols:     resolver.ServiceProtocols(tenant, r.ServiceID),
			Mode:          r.Action.Access,
			// Learning-lifecycle Warn stage: soften authenticate/deny to allow-with-notice (non-holding).
			Warn: r.Stage == StageWarn,
			// Carry the authored step-up assurance to the enforcement primitive (consumed when the authenticate
			// ceremony demands the phishing-resistant token; see docs/lateral_movement_per_hop_authentication.md).
			RequiredIdPID: r.Action.RequiredIdPID,
			MinACR:        r.Action.MinACR,
			RequiredAMR:   append([]string(nil), r.Action.RequiredAMR...),
			MaxAgeSeconds: r.Action.MaxAgeSeconds,
			// "Sensitivity decides the mechanism": carry the machine/non-interactive opt-in so a device-attested
			// (verified mTLS + trusted posture) flow can release a low-sensitivity hop without a human ceremony.
			DeviceAttestedAuto: r.Action.DeviceAttestedAuto,
			// Risk gate, expanded to "threshold or higher" — the SAME helper the egress compiler uses
			// (compile_egress.go), so both planes read one authored RiskAtLeast identically. Previously dropped
			// here, which silently turned an authored risk-gated east-west rule into an ungated one.
			RiskSeverities: RiskSeveritiesAtLeast(r.RiskAtLeast),
		}
		if r.Action.GrantTTLSeconds > 0 {
			ew.MaxTTLSeconds = r.Action.GrantTTLSeconds
		}
		out = append(out, ew)
	}
	return out
}
