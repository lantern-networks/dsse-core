package main

import (
	"crypto/tls"
	"log"
	"net/url"
	"strings"
	"sync/atomic"
)

// the_step_up_portal_is_a_browser_facing_page.go — the certificate a USER'S BROWSER validates when a held
// flow sends them to authenticate.
//
// ★★★ IT IS NOT DERIVED FROM THIS DEPLOYMENT'S CAs, AND THAT IS THE POINT (2026-09-02, decided by the
// operator after the ceremony was walked on a real device).
//
// The portal was served on the agent plane, with the deployment's transport certificate, which a browser has
// no reason to trust: the only deployment-related root a steered device carries is its organization's
// INTERCEPTION root. Two ways to reuse what is already trusted were considered and both are wrong:
//
//   - Sign the portal with the organization's interception CA. That makes the interception authority vouch
//     for a real server this deployment runs, so mistrusting or rotating it takes the step-up — a recovery
//     path — down with it.
//   - Steer the portal so it is intercepted like any site. Measured: impossible as things stand. The device's
//     transparent passthrough matches by ADDRESS, and every one of this deployment's names (console, admin,
//     agents, authority, recovery) resolves to the same address per region — so the portal is passed through
//     with the agent's own control channel and cannot be intercepted without giving it an address of its own.
//
// The operator's reading is the one that settles it: the identity provider is NOT part of DSSE. It is the
// customer's — Okta, Entra ID — and the browser reaches it over a publicly trusted certificate. The DSSE hop
// in the middle is a browser-facing page like any other, and its certificate is provided for it, per
// deployment, for a name the operator holds. Not minted here, and not borrowed from a CA that exists to do
// something else.
//
// Absent one, the portal keeps being served by the agent plane's certificate — which is right for a lab and
// visible as a browser warning, rather than a trust decision made quietly on the operator's behalf.
type stepUpPortalCertificate struct {
	host string
	cert *tls.Certificate
}

var stepUpPortalCert atomic.Pointer[stepUpPortalCertificate]

// configureStepUpPortalCertificate loads the operator-supplied pair and binds it to the host in the portal's
// base URL. Any part missing leaves the portal on the agent plane's certificate.
func configureStepUpPortalCertificate(baseURL, certPath, keyPath string) {
	certPath, keyPath = strings.TrimSpace(certPath), strings.TrimSpace(keyPath)
	if certPath == "" || keyPath == "" {
		return
	}
	host := stepUpPortalHost(baseURL)
	if host == "" {
		log.Printf("step-up portal certificate: -clientless-tls-cert was given but -clientless-base-url names " +
			"no host, so there is no name to present it for — the portal keeps the agent plane's certificate")
		return
	}
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		// ★ NOT FATAL. A portal served on the wrong certificate is a browser warning; a node that refuses to
		// start takes a region's enforcement with it. See the store that used to log.Fatalf.
		log.Printf("step-up portal certificate: %v — the portal keeps the agent plane's certificate, so a "+
			"browser sent there will not trust it", err)
		return
	}
	stepUpPortalCert.Store(&stepUpPortalCertificate{host: host, cert: &cert})
	log.Printf("step-up portal certificate: serving %s from %s", host, certPath)
}

// stepUpPortalHost is the host a browser asks for when it is sent to the portal.
func stepUpPortalHost(baseURL string) string {
	u, err := url.Parse(strings.TrimSpace(baseURL))
	if err != nil || u == nil {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(u.Hostname()))
}

// stepUpPortalCertificateFor answers with the operator's certificate when the browser asked for the portal's
// name, and nil otherwise so the caller falls through to what it served before.
func stepUpPortalCertificateFor(serverName string) *tls.Certificate {
	held := stepUpPortalCert.Load()
	if held == nil {
		return nil
	}
	if !strings.EqualFold(strings.TrimSpace(serverName), held.host) {
		return nil
	}
	return held.cert
}
