package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/lantern-networks/dsse-core/idpregistry"
)

// an_identity_provider_may_be_on_a_private_authority.go — reaching an IdP whose certificate the public web
// does not vouch for.
//
// ★★★ FOUND BY PUTTING THE LAB'S OWN KEYCLOAK BEHIND TLS (2026-09-03). Until today it spoke plain HTTP, so
// nothing had ever asked how an Edge verifies an identity provider it calls SERVER-SIDE — the token exchange
// and the signing-key fetch, both of which go out from the Edge rather than from the browser.
//
// They used one shared http.Client, so they verified against the container's system roots. An organization
// whose IdP sits on an internal authority — an on-premises Keycloak, ADFS, PingFederate; which is what a
// great many of the organizations this product is for actually run — could name its endpoints in the Console
// and then never complete a sign-in, with the failure arriving as a TLS error three layers below the screen
// that accepted the configuration.
//
// ★ THE AUTHORITY IS A PROPERTY OF THE CONNECTION, NOT OF THE NODE. Adding it to the container's trust store
// would make one customer's private authority trusted for every organization on that Edge, and for every
// other thing the Edge talks to. This trusts it for exactly the connection that declared it.
var idpClients sync.Map // ca pem -> *http.Client

// idpHTTPClient returns the client to call this connection with: the shared one when the provider is on the
// public web, and one pinned to the connection's own authority when it is not.
func idpHTTPClient(shared *http.Client, conn idpregistry.Connection) (*http.Client, error) {
	pem := strings.TrimSpace(conn.CAPEM)
	if pem == "" {
		return shared, nil
	}
	if c, ok := idpClients.Load(pem); ok {
		return c.(*http.Client), nil
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(pem)) {
		// ★ REFUSE RATHER THAN FALL BACK TO THE SYSTEM ROOTS. A connection that names an authority and is
		// then verified against a different set is the shape where a misconfiguration passes in the lab and
		// fails at a customer, or worse, passes at the customer for the wrong reason.
		return nil, fmt.Errorf("identity provider %q names a certificate authority that holds no certificate, "+
			"so there is nothing to verify it against", conn.IdPID)
	}
	timeout := 10 * time.Second
	if shared != nil && shared.Timeout > 0 {
		timeout = shared.Timeout
	}
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	actual, _ := idpClients.LoadOrStore(pem, client)
	return actual.(*http.Client), nil
}
