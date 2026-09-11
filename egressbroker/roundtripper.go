// Package egressbroker is the edge-side client for the browser-faithful egress broker: the transport that
// re-originates a decrypt-all flow's upstream leg through a real Chrome network stack (curl-impersonate),
// instead of a Go TLS/HTTP2 emulation that bot management detects.
//
// The engine itself is cgo over libcurl-impersonate and lives in the egress-broker directory. This package
// selects HOW the edge reaches it, at build time:
//
//   - default: the engine runs as a sidecar service and this package speaks HTTP to it (transport_sidecar.go).
//   - -tags embedbroker: the engine runs inside this process and this package calls it directly
//     (transport_embedded.go). The edge binary then requires cgo and the engine library.
//
// Both variants export the same constructors, so nothing upstream — the connector-or-broker selector, the SWG
// egress path, the composition root — knows or cares which one it got. That is the point: the edge and the
// broker are one deployable unit, and whether they are one process is a build decision, not an architecture.
package egressbroker

import (
	"errors"
	"net/http"
	"os"
	"strings"
)

// URLFromEnv is the single reading of EGRESS_BROKER_URL, shared by the transport and the health
// monitor so the URL they probe and the URL they send traffic to can never be two different interpretations.
func URLFromEnv() (string, error) {
	brokerURL := strings.TrimRight(strings.TrimSpace(os.Getenv("EGRESS_BROKER_URL")), "/")
	if brokerURL == "" {
		return "", errors.New("browser-mimic egress is enabled but EGRESS_BROKER_URL is unset: the egress broker is a required component (no in-process fallback engine exists)")
	}
	return brokerURL, nil
}

// IsWSUpgrade reports whether the decided request is a WebSocket upgrade, which takes the raw frame-tunnel
// path rather than request/response re-origination.
func IsWSUpgrade(req *http.Request) bool {
	return strings.Contains(strings.ToLower(req.Header.Get("Connection")), "upgrade") &&
		strings.EqualFold(strings.TrimSpace(req.Header.Get("Upgrade")), "websocket")
}

// reorigHeaderLines flattens the decided request's headers into the raw "Name: value" lines the engine wants.
// Order carries no obligation: curl_easy_impersonate installs the Chrome profile's header set and order, and a
// supplied line whose name is already in the profile replaces it IN PLACE (measured 2026-08-05). The engine,
// not this list, is what makes the wire order Chrome-shaped.
func reorigHeaderLines(src http.Header) []string {
	lines := make([]string, 0, len(src))
	for name, vals := range src {
		for _, v := range vals {
			lines = append(lines, name+": "+v)
		}
	}
	return lines
}
