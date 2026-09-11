package main

import (
	"log"
	"net/url"
	"strings"
)

// the_configuration_handed_to_an_agent_names_one_port.go — the enrolment fold's rule, checked against the document this
// deployment actually publishes.
//
// ★★★ THE SECTION SAYS IT AND THE DEPLOYMENT DOES THE OPPOSITE (2026-08-21, measured). the enrolment fold: "an agent
// touches ONE port, enrolment included; in production, 443 only", and "a port like 8443 appearing in the
// configuration handed to an agent must not happen at all". The published agent configuration carries
//
//	"edge_url": "https://203.0.113.10:8443"
//
// which is the forbidden thing, in the one document that decides where every new device goes. It had been
// recorded in a comment for a day and nothing said it at run time, so nothing would ever notice it drifting
// further.
//
// ★ AND EVERY PATH AN AGENT NEEDS IS ALREADY ON THE TRANSPORT PORT. Measured on the reference deployment with
// a real device certificate:
//
//	/network-extension/runtime-copy/round-trip   8443 405   transport 405   (same route, both ports)
//	/network-extension/runtime-copy/session      8443 405   transport 405
//	/steer/region-endpoints                      8443 401   transport 200   (mTLS identifies the device)
//	/enroll, /bootstrap/trust-bundle, /healthz, /steer/agent-policy/pubkey   answered by the enrolment fold
//
// So the fold is not blocked on the Edge. It is blocked on the agents dialling the transport port, which is
// win-dev-1's half as much as this side's — and on nothing noticing when the configuration says otherwise,
// which is what this file is.
//
// ★ IT SAYS, IT DOES NOT REFUSE. Refusing to publish would take a working deployment off the air over a
// port number, and a deployment mid-migration legitimately names the old one. What must not happen is
// SILENCE: the gap was true for a day and only a code comment knew.
func warnIfTheAgentConfigurationNamesAnotherPort(publishedEdgeURL, transportListen string) {
	published := strings.TrimSpace(publishedEdgeURL)
	listen := strings.TrimSpace(transportListen)
	if published == "" || listen == "" {
		return
	}
	parsed, err := url.Parse(published)
	if err != nil {
		log.Printf("★ agent configuration: edge_url %q could not be read as a URL, so this node cannot check "+
			"the enrolment fold's rule that the configuration handed to an agent names one port", published)
		return
	}
	publishedPort := strings.TrimSpace(parsed.Port())
	transportPort := transportListen
	if i := strings.LastIndex(listen, ":"); i >= 0 {
		transportPort = listen[i+1:]
	}
	if publishedPort == "" || transportPort == "" || publishedPort == transportPort {
		return
	}
	log.Printf("★★ the enrolment fold: the configuration handed to every new device names port %s, and this node's agent "+
		"transport is on %s. The section says a second agent-facing port must not appear in that document at "+
		"all — every path an agent needs (enrolment, the trust bundle, the policy key, the runtime copy, the "+
		"region list) is answered on the transport port, and the region list is answered BETTER there because "+
		"mTLS identifies the device. What is left is the agents dialling it. Until they do, this deployment "+
		"has two agent-facing ports and the document says so out loud rather than only in a comment: "+
		"-network-extension-runtime-copy-edge-url=%s", publishedPort, transportPort, published)
}
