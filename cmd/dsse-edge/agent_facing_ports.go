package main

import (
	"fmt"
	"net"
	"sort"
	"strings"
)

// ★★ AN AGENT REACHES THE EDGE ON ONE PORT, AND THIS EDGE PUBLISHES TWO (2026-08-18, measured).
//
// The requirement is not "the deployment uses one port number". Regions are separate addresses — in the
// reference lab they share a host and are told apart by port only because one machine cannot bind :443 twice,
// which is an artefact of the lab and not of the product. The requirement is per Edge: everything an AGENT
// dials on a given Edge is the same port, so that in a real deployment it is 443 and nothing else.
//
// Measured on the reference deployment: region-a's Edge publishes the (T) transport on :18543 AND the
// expired-certificate recovery listener on :18545, and the second is handed to devices in the signed trust
// bundle (renewal_recovery_endpoint). In production both would be 443 on the same address, so they collide —
// which means the recovery path as built cannot ship. region-b publishes one, having no recovery listener.
//
// Folding them is a cross-platform change (Edge, the macOS network extension, the Windows agent) and is
// designed in docs/pki_who_owns_which_certificate.ja.md the enrolment fold. What lands here is the measurement: the Edge
// says, at start-up and on its own posture, how many ports it expects an agent to dial. A deployment that
// grows a third one says so on the day it is configured rather than on the day somebody tries to run it on 443.
type agentFacingPort struct {
	Port string // the port an agent dials
	What string // what the agent dials it for, in the reader's terms
}

// agentFacingAddresses is every address on this Edge that an agent is told to dial, and the address it is
// TOLD to dial where that can differ from what is bound (a container port mapping, a load balancer).
type agentFacingAddresses struct {
	// MainListen serves /enroll, /bootstrap/trust-bundle and the steering documents.
	MainListen string
	// PublishedEdgeURL is the same listener as an agent is told to reach it (-network-extension-runtime-copy-edge-url).
	PublishedEdgeURL string
	// TransportListen is the encrypted transport (T).
	TransportListen string
	// RecoveryListen and PublishedRecoveryEndpoint are the expired-certificate recovery path.
	RecoveryListen            string
	PublishedRecoveryEndpoint string
}

// agentFacingPorts lists the ports THIS Edge expects an agent to dial, deduplicated by port.
//
// Deliberately not "every listener": the admin API is not on an agent's path, and counting it would report a
// violation that is not one — the kind of noisy gate that gets switched off. Only what an agent is told to
// dial belongs here.
//
// ★★ AND THE MAIN LISTENER IS ON AN AGENT'S PATH, WHICH THIS MISSED (2026-08-19). The first version counted
// the transport and the recovery listener and excluded the main one as "the clientless/browser data
// listener". That is one of its roles and not the only one: the same port serves /enroll and
// /bootstrap/trust-bundle — measured, 200 unauthenticated on :8443 — and the configuration handed to every
// agent names it as edge_url. So the count said 2 while the document an agent is installed with named three
// addresses, and the enrolment fold was one step further away than the gate reported.
//
// Counting it does not make the deployment worse; it makes the number true. A gate that under-reports the
// distance to a target is worse than no gate, because the work looks nearly done.
func agentFacingPorts(in agentFacingAddresses) []agentFacingPort {
	seen := map[string]agentFacingPort{}
	add := func(addr, what string) {
		port := portOfAddress(addr)
		if port == "" {
			return
		}
		if prev, ok := seen[port]; ok {
			// One port serving two purposes is the goal, not a collision. Say both.
			seen[port] = agentFacingPort{Port: port, What: prev.What + " + " + what}
			return
		}
		seen[port] = agentFacingPort{Port: port, What: what}
	}
	add(in.MainListen, "enrolment, the signed trust bundle and the steering documents")
	add(in.PublishedEdgeURL, "enrolment and trust bundle, as published to devices")
	add(in.TransportListen, "the encrypted transport (T)")
	// The listener and the address published to devices can differ (a container port mapping, a load
	// balancer). What matters for the agent is the published one; the listener is included because a
	// deployment that binds a second port without publishing it has still opened it.
	add(in.RecoveryListen, "recovery for an expired certificate")
	add(in.PublishedRecoveryEndpoint, "recovery for an expired certificate, as published to devices")

	out := make([]agentFacingPort, 0, len(seen))
	for _, v := range seen {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Port < out[j].Port })
	return out
}

// portOfAddress accepts "host:port", ":port", "https://host:port" and a bare port.
func portOfAddress(addr string) string {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return ""
	}
	if i := strings.Index(addr, "://"); i >= 0 {
		addr = addr[i+3:]
		if j := strings.IndexAny(addr, "/?#"); j >= 0 {
			addr = addr[:j]
		}
	}
	if _, port, err := net.SplitHostPort(addr); err == nil {
		return strings.TrimSpace(port)
	}
	// A bare port, which is how the trust bundle may carry the recovery endpoint (the device resolves the
	// host from the transport it already has).
	if addr != "" && strings.IndexFunc(addr, func(r rune) bool { return r < '0' || r > '9' }) < 0 {
		return addr
	}
	return ""
}

// describeAgentFacingPorts renders the posture line. Empty when interception-only/no transport is configured.
func describeAgentFacingPorts(ports []agentFacingPort) string {
	if len(ports) == 0 {
		return ""
	}
	parts := make([]string, 0, len(ports))
	for _, p := range ports {
		parts = append(parts, fmt.Sprintf(":%s (%s)", p.Port, p.What))
	}
	if len(ports) == 1 {
		return fmt.Sprintf("agent-facing ports: 1 — %s", parts[0])
	}
	return fmt.Sprintf("agent-facing ports: %d — %s. ★ An agent must reach this Edge on ONE port; on a real "+
		"deployment these would all be 443 on the same address and collide. See docs/pki_who_owns_which_certificate.ja.md the enrolment fold",
		len(ports), strings.Join(parts, ", "))
}
