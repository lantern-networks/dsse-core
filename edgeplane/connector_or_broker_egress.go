package edgeplane

import (
	"log"
	"net/http"
)

// connectorOrBrokerRoundTripper picks the egress path per destination on the decrypt-all browser leg.
//
// Why a selector is needed at all: the browser-faithful broker re-originates from ANOTHER PROCESS, which knows
// nothing about the connector route layer and direct-dials whatever it is given. Sending a connector-fronted
// destination there is wrong twice over — the tunnel that makes an internal app reachable is bypassed, and the
// broker's dial lands in internal address space, which the SSRF pre-flight then (correctly) refuses. The result
// is that private apps are unreachable through decrypt-all browsing.
//
// The fix is NOT a second impersonation engine. There is no bot management in front of an internal app, so
// connector-fronted traffic needs no Chrome fingerprint at all — it needs the tunnel. The choice is "broker or
// connector", not "which engine".
//
// Composition note, because the obvious shortcut is a trap: ConnectorAwareProxyClient cannot be layered on top
// of the broker. It works by replacing a transport's DialContext and requires an *http.Transport; handed a
// custom RoundTripper it silently falls back to http.DefaultTransport — which would discard the broker and dial
// every origin with a bare Go fingerprint, the exact detectability the broker exists to remove, with no error
// anywhere. The selection therefore has to happen at RoundTripper level, explicitly.
type connectorOrBrokerRoundTripper struct {
	resolve   ConnectorResolveFunc
	tenantID  string
	connector http.RoundTripper // connector-aware transport: tunnels to the connector fronting the destination
	broker    http.RoundTripper // browser-faithful re-origination for the public web
}

// NewConnectorOrBrokerRoundTripper routes connector-fronted destinations through connectorTransport and
// everything else through brokerTransport. Self-gating: with no resolver (or none configured for the tenant)
// every destination goes to the broker, which is the behaviour of a deployment that publishes no private apps.
func NewConnectorOrBrokerRoundTripper(resolve ConnectorResolveFunc, tenantID string, connectorTransport, brokerTransport http.RoundTripper) http.RoundTripper {
	if resolve == nil || connectorTransport == nil {
		return brokerTransport
	}
	return &connectorOrBrokerRoundTripper{resolve: resolve, tenantID: tenantID, connector: connectorTransport, broker: brokerTransport}
}

func (c *connectorOrBrokerRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	host := req.URL.Hostname()
	// Same call shape as the connector egress dialer (host without port, empty namespace), so the selector and
	// the dialer can never disagree about what "fronted by a connector" means.
	_, fronted, err := c.resolve(req.Context(), c.tenantID, host, "")
	switch {
	case err != nil:
		// Treat an unresolvable route layer as "no connector", matching ConnectorEgressDialContext. The request
		// goes to the broker and the SSRF pre-flight still guards it, so an internal destination fails closed
		// rather than being direct-dialed unchecked.
		log.Printf("swg egress: connector route lookup failed for %s (%v) — treating as public and re-originating via the broker", host, err)
	case fronted:
		return c.connector.RoundTrip(req)
	}
	return c.broker.RoundTrip(req)
}
