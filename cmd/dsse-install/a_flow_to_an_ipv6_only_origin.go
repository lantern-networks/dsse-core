package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// a_flow_to_an_ipv6_only_origin.go — does a flow to an IPv6-ONLY destination actually leave over IPv6?
//
// ★★★ THE DEPLOYMENT DECLARED IPv6 AND THEN REFUSED TO USE IT (2026-08-30, measured on a running lab, and
// invisible to every check that existed).
//
// The Edge measures its own egress by dialling, and logged `egress_address_family ipv4=true ipv6=true`.
// verifyEgressAddressFamily read exactly that and passed. Ninety seconds later the same Edge logged, once per
// flow, `this node has no egress in that address family` and re-fetched every IPv6 destination by name over
// IPv4 — because the code that decides what happens to a flow answered the same question for itself, by
// listing interface addresses, and would not count the ULA a NAT66 container holds.
//
// So the health answer and the flow decision disagreed, and the check was reading the one that does not move
// packets. That is now one measurement (see edgeplane.SetMeasuredIPv6Egress), and this is the check that
// would have caught it anyway: it does not ask the Edge what it can do, it CARRIES A FLOW to a destination
// that has no A record and cannot be reached any other way.
//
// ★ IT DOES NOT REQUIRE IPv6. A deployment whose Edges declare IPv4 only is a decision, and this says so
// without failing — the same position verifyEgressAddressFamily takes. What it refuses to let pass is a
// deployment that DECLARES IPv6 and cannot carry it, because that combination is the one an operator cannot
// see from anywhere else: applications fall back, devices see 200, and every IPv6 round trip is wasted.

// verifyIPv6OnlyDestination is the origin this flow is aimed at. It has AAAA records and no A record, so a
// flow that completes to it could not have been carried over IPv4 by any path, including a re-fetch by name.
const verifyIPv6OnlyDestination = "ipv6.google.com:443"

// verifyAFlowReachesAnIPv6OnlyOrigin carries one real flow, through the same steer mux a device uses, to a
// destination that exists only in IPv6. declaresIPv6 is what the Edges said about themselves.
func verifyAFlowReachesAnIPv6OnlyOrigin(dir, door string, certPEM, keyPEM []byte, declaresIPv6 bool) []verifyResult {
	const name = "a flow to an IPv6-only destination is carried over IPv6"
	_, _, err := oneFlowThrough(dir, door, verifyIPv6OnlyDestination, certPEM, keyPEM)
	switch {
	case err == nil && declaresIPv6:
		return []verifyResult{{name: name, ok: true,
			note: fmt.Sprintf("%s has no A record, so this flow could not have been carried over IPv4 by any "+
				"path — including a re-fetch by name. What the Edges declare and what they do agree",
				verifyIPv6OnlyDestination)}}
	case err == nil && !declaresIPv6:
		// Harmless, but it means the posture the agents are given is wrong in the safe direction: devices are
		// closing IPv6 flows this deployment could in fact have carried.
		return []verifyResult{{name: name, ok: true,
			note: fmt.Sprintf("the flow to %s completed, so this deployment CAN carry IPv6 — but its Edges "+
				"declare IPv4 only, so agents are closing IPv6 flows it could have carried. The declaration "+
				"is what devices act on; it should say what this measurement says", verifyIPv6OnlyDestination)}}
	case declaresIPv6:
		return []verifyResult{{name: name, ok: false,
			note: fmt.Sprintf("the Edges DECLARE IPv6 egress and a flow to %s did not complete: %v. Devices "+
				"are told this deployment carries IPv6 and it does not, so every IPv6 destination costs a "+
				"round trip and an IPv6-only one is simply unreachable — while applications fall back to IPv4 "+
				"and nothing looks broken from a device", verifyIPv6OnlyDestination, shortEgressError(err))}}
	default:
		return []verifyResult{{name: name, ok: true,
			note: fmt.Sprintf("this deployment's Edges declare IPv4 only and a flow to %s did not complete, "+
				"which is consistent. ★ An IPv6-ONLY destination is unreachable through this deployment; give "+
				"the Edges IPv6 egress if that matters here", verifyIPv6OnlyDestination)}}
	}
}

// shortEgressError keeps the note readable: the transport errors here are long and the first clause is the
// one that names what happened.
func shortEgressError(err error) string {
	s := strings.TrimSpace(err.Error())
	if i := strings.Index(s, ": "); i > 0 && len(s) > 120 {
		return s[:i] + " (…)"
	}
	if len(s) > 160 {
		return s[:160] + "…"
	}
	return s
}

// edgesDeclareIPv6Egress reports whether EVERY Edge that answers says it can egress IPv6. Every, not any:
// a fleet where it depends on which node a device lands on is already reported by verifyEgressAddressFamily,
// and this check only needs to know what a device is being told.
func edgesDeclareIPv6Egress(client *http.Client, edgeAdmins []string) bool {
	answered, withV6 := 0, 0
	for _, admin := range edgeAdmins {
		admin = strings.TrimRight(strings.TrimSpace(admin), "/")
		if admin == "" {
			continue
		}
		code, raw, err := get(client, admin+"/healthz", "")
		if err != nil || code != 200 {
			continue
		}
		var health struct {
			Role   string `json:"role"`
			Egress *struct {
				IPv6 bool `json:"ipv6"`
			} `json:"egress_address_family"`
		}
		if json.Unmarshal(raw, &health) != nil || health.Role != "edge" {
			continue
		}
		answered++
		if health.Egress != nil && health.Egress.IPv6 {
			withV6++
		}
	}
	return answered > 0 && withV6 == answered
}
