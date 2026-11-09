package main

import (
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/edgeplane"
	"github.com/lantern-networks/dsse-core/interception"
	"github.com/lantern-networks/dsse-core/model"
)

// steerRefusalPageWait bounds how long a refused flow is held open for the client to ask for the page. A client
// that sends nothing in that time is not a browser waiting for an answer, and its flow is closed as before.
const steerRefusalPageWait = 10 * time.Second

// serveSteerRefusalPage answers a steered flow that policy refused at its OPEN with the refusal page the
// decrypted path shows, when the flow is web traffic this Edge can answer, and reports whether it did.
//
// ★★ A DENIED SITE SHOWED A PAGE OR A DEAD CONNECTION DEPENDING ON WHICH EDGE THE FLOW LANDED ON (acceptance C,
// fourth walk, 2026-11-08). Chrome reached a denied site over IPv6 and got ERR_CONNECTION_CLOSED; PowerShell,
// over IPv4, got the refusal page. Both were refused by the same rule. The difference was where the refusal was
// decided: the IPv6 flow landed on the Edge that had answered the name lookup, recovered the site's name from
// the address at the flow's OPEN, and was refused there — and a refusal at the OPEN closed the flow with no bytes.
// The IPv4 flow landed on an Edge that could not name it yet, was opened, decrypted, and refused at the request,
// where the page is written. The same person, the same site, the same rule: a page or a network failure.
//
// So a refusal at the OPEN is answered the way a refusal at the request is. Nothing is dialled: this Edge writes
// the page itself, under the interception leaf the device already trusts for that name, and the flow ends. A
// destination this organization does not decrypt — a bypass, or a host learned to pin — is not answered under a
// leaf it would never otherwise be shown; it is closed as before, and so is anything that is not web traffic.
func serveSteerRefusalPage(conn net.Conn, route edgeplane.NetworkExtensionRuntimeCopyTCPRoute, family string,
	engine *edgeplane.NetworkExtensionLabTLSInterception, dec model.AccessDecision) bool {
	if conn == nil || dec.Decision == "allow" {
		return false
	}
	// The flow's own wait is the bound: a mux flow's deadlines are not enforced, so closing it is what ends a
	// read that is still waiting.
	timer := time.AfterFunc(steerRefusalPageWait, func() { _ = conn.Close() })
	defer timer.Stop()
	page := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeSWGPolicyRefusal(w, r, steerRefusalPageHost(r, route), dec)
	})
	switch {
	case route.Port == 443 && engine != nil:
		sni, hello, err := interception.PeekClientHelloSNI(conn)
		if err != nil || strings.TrimSpace(sni) == "" {
			return false
		}
		route.SNI = sni
		if !engine.Matches(route) {
			return false
		}
		return engine.ServeLocalHTTPS(&edgeplane.NetworkExtensionLabTLSPrefixedConn{Conn: conn, Prefix: hello}, route, page) == nil
	case family == "http":
		return edgeplane.ServeOneLocalHTTPRequest(conn, page) == nil
	}
	return false
}

// steerRefusalPageHost is the site the page names: the one the browser asked for, else the name the flow was
// opened for, else its address.
func steerRefusalPageHost(r *http.Request, route edgeplane.NetworkExtensionRuntimeCopyTCPRoute) string {
	if r != nil {
		if host := strings.TrimSpace(r.Host); host != "" {
			if h, _, err := net.SplitHostPort(host); err == nil {
				return h
			}
			return host
		}
	}
	if sni := strings.TrimSpace(route.SNI); sni != "" {
		return sni
	}
	return route.Host
}
