package main

import (
	"net/netip"
	"sync/atomic"
)

// deployment_carries_family.go — do not send a flow into a family this deployment cannot carry.
//
// ★★★ MEASURED ON A REAL BOX, THEN DECIDED (2026-08-25). This agent captures ALL outbound TCP, IPv6
// included, which is the right default. The deployment's Edges may have no IPv6 leg at all — and then every
// one of those flows travelled to an Edge, could not be egressed, and came back closed with no bytes. Over
// seventeen minutes: 572 IPv4 flows carried bytes and none were empty; of 342 IPv6 flows, 185 carried
// nothing. From the operator's chair it read as "somehow slow", which is how it was reported.
//
// The deployment now measures what it can egress and says so in the signed posture document. The decision:
// if it cannot carry a family, this agent must not make requests in it.
//
// ★★ AND "DO NOT CAPTURE IT" WOULD BE THE WRONG READING. The driver redirects every outbound TCP connection;
// not capturing a family means those flows leave the machine UNMEDIATED, which is a bypass, not a fix. So the
// flow is captured as always and CLOSED HERE, immediately, without travelling to an Edge that cannot serve
// it. The application then falls back to IPv4 (Happy Eyeballs) and that flow is steered normally — the same
// destination, reached the same way, without the wasted round trip.
//
// ★ SILENCE MEANS UNCHANGED. Until a signed posture document says otherwise — an older Edge, one that has
// not finished measuring, or no document at all — every family is carried, exactly as before. A deployment
// that cannot tell us must not be able to stop this agent steering.
var carriedFamilies atomic.Pointer[carriedFamilySet]

type carriedFamilySet struct {
	IPv4 bool
	IPv6 bool
}

// setCarriedFamilies records what the deployment said it can egress. An empty or absent list is ignored: see
// the note above — absent is "unchanged", never "none".
func setCarriedFamilies(families []string) {
	if len(families) == 0 {
		return
	}
	set := carriedFamilySet{}
	for _, f := range families {
		switch f {
		case "ipv4":
			set.IPv4 = true
		case "ipv6":
			set.IPv6 = true
		}
	}
	if !set.IPv4 && !set.IPv6 {
		// A list that names neither is a document we do not understand, not an instruction to stop.
		return
	}
	carriedFamilies.Store(&set)
}

// deploymentCarries reports whether a destination's family is one the deployment says it can egress.
func deploymentCarries(dst netip.AddrPort) bool {
	set := carriedFamilies.Load()
	if set == nil {
		return true // nothing has told us; carry everything, as before
	}
	if dst.Addr().Is4() || dst.Addr().Is4In6() {
		return set.IPv4
	}
	return set.IPv6
}
