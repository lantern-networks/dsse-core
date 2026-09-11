package main

import (
	"net"
	"net/url"
	"strings"
)

// agent_profile_address_reaches_a_device.go — an address a device cannot reach is not an address.
//
// ★★★ REPORTED FROM REAL HARDWARE (win-dev-1, letter 101, 2026-08-26). The Device configuration screen issued
// a profile whose default addresses were the deployment's own, and on that deployment they are
// "agents.localhost". On a laptop that resolves to 127.0.0.1. Combined with the default posture — fail-closed,
// which is the right default — a device applying that profile dials ITSELF, cannot reach an Edge, and stops
// carrying traffic. The whole machine loses the network. It was not applied; the address was corrected by
// hand first.
//
// ★ THE LAB ADDRESS IS NOT THE DEFECT. A deployment brought up on localhost is a legitimate thing to have.
// The defect is that the SCREEN offers it as a default, and an operator has no reason to doubt an address the
// deployment itself produced.
//
// So a loopback address is treated as what it is: an address this deployment has not been told. The route
// already refuses to issue a profile for a deployment that knows no address at all, with a sentence saying so;
// this makes "knows only an address no device can use" the same case, because for a device it IS the same case.

// addressReachesADevice reports whether an endpoint is one an endpoint agent could dial.
//
// It answers about the HOST as written, not about what the Edge can reach: the Edge resolving it proves
// nothing, since the Edge is where the loopback points. A name that is not obviously loopback is accepted —
// this refuses what is certainly wrong rather than guessing at what might be.
func addressReachesADevice(endpoint string) bool {
	host := endpointHostOnly(endpoint)
	if host == "" {
		return false
	}
	lower := strings.ToLower(host)
	switch lower {
	case "localhost", "ip6-localhost", "ip6-loopback":
		return false
	}
	// "agents.localhost", "admin.localhost" — the whole .localhost TLD is loopback by definition (RFC 6761),
	// and it is exactly what a deployment brought up on one machine generates.
	if strings.HasSuffix(lower, ".localhost") {
		return false
	}
	if ip := net.ParseIP(host); ip != nil {
		return !ip.IsLoopback() && !ip.IsUnspecified()
	}
	return true
}

// endpointHostOnly extracts the host from "region=https://host:port", "https://host:port" or "host:port".
func endpointHostOnly(endpoint string) string {
	endpoint = strings.TrimSpace(endpoint)
	if i := strings.Index(endpoint, "="); i > 0 && !strings.Contains(endpoint[:i], "/") {
		endpoint = strings.TrimSpace(endpoint[i+1:])
	}
	if endpoint == "" {
		return ""
	}
	if !strings.Contains(endpoint, "://") {
		endpoint = "https://" + endpoint
	}
	u, err := url.Parse(endpoint)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

// endpointsADeviceCanReach splits the addresses into the ones a device could dial and the ones it could not.
func endpointsADeviceCanReach(endpoints []string) (reachable, loopback []string) {
	for _, e := range endpoints {
		if strings.TrimSpace(e) == "" {
			continue
		}
		if addressReachesADevice(e) {
			reachable = append(reachable, e)
		} else {
			loopback = append(loopback, e)
		}
	}
	return reachable, loopback
}
