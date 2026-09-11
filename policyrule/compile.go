package policyrule

import "sort"

// AddressResolver resolves subject ids (endpoints or groups) to the FQDN/IP addresses of the network
// endpoints they denote. The asset catalog implements this; it lets the rule layer stay address-agnostic
// while compilation maps authored rules down to host-keyed enforcement primitives.
type AddressResolver interface {
	EndpointAddresses(tenant string, ids []string) []string
}

// EgressBypassFQDNs compiles the authored egress rules into the set of destination FQDNs/IPs that must be
// raw-forwarded (TLS-bypassed). Only ACTIVE egress rules whose inspection axis is bypass contribute, and
// only their destinations that resolve to a network endpoint address. Bypass is inherently destination-
// keyed (the interception engine bypasses a host regardless of source), so this compilation is lossless —
// unlike access (allow/deny/authenticate), which is identity/source-scoped and compiled separately.
//
// The caller unions the result with other bypass sources (materialized cert-pin candidates, static bypass)
// and applies the whole set with Engine.SetBypassHosts (a full replace), so recomputing from scratch on
// every rule change is correct and needs no reconciliation.
func EgressBypassFQDNs(tenant string, rules []Rule, resolver AddressResolver) []string {
	set := map[string]bool{}
	for _, r := range rules {
		if r.Plane != PlaneEgress || r.Status != StatusActive || r.Action.Inspection != InspectionBypass {
			continue
		}
		for _, addr := range resolver.EndpointAddresses(tenant, r.Destination) {
			set[addr] = true
		}
	}
	out := make([]string, 0, len(set))
	for a := range set {
		out = append(out, a)
	}
	sort.Strings(out)
	return out
}

// EgressInspectFQDNs compiles the authored egress rules into the set of destination FQDNs/IPs that must be
// DECRYPTED (TLS-inspected). Only ACTIVE egress rules whose inspection axis is inspect and whose access is not
// deny contribute (a denied flow is blocked, never decrypted), and only destinations that resolve to a network
// endpoint address. This is the inspect counterpart of EgressBypassFQDNs: under the bypass-default posture the
// intercept set is an explicit allowlist, so an authored `inspect` rule is how an operator says "decrypt these"
// in the unified model — the caller unions the result into the engine's intercept set under bypass-default.
// Under decrypt-all the intercept set is already "*", so this is a no-op there and need not be applied.
func EgressInspectFQDNs(tenant string, rules []Rule, resolver AddressResolver) []string {
	set := map[string]bool{}
	for _, r := range rules {
		if r.Plane != PlaneEgress || r.Status != StatusActive {
			continue
		}
		if r.Action.Inspection != InspectionInspect || r.Action.Access == AccessDeny {
			continue
		}
		for _, addr := range resolver.EndpointAddresses(tenant, r.Destination) {
			set[addr] = true
		}
	}
	out := make([]string, 0, len(set))
	for a := range set {
		out = append(out, a)
	}
	sort.Strings(out)
	return out
}
