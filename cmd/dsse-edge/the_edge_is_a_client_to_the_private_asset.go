package main

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/lantern-networks/dsse-core/internalca"
)

// ★★★ INTERCEPTION MAKES THE EDGE A TLS CLIENT, AND NOBODY GAVE IT A TRUST STORE FOR THAT DIRECTION
// (2026-09-01, found by walking one intercepted internal flow from a real steered Mac to a real intranet
// server behind a connector).
//
// Everything about the flow was right. The device was handed a certificate for hq.kaede.internal minted by
// this organization's own interception issuing CA, chaining to the root the deployment announces. The route
// layer resolved the destination to the organization's connector. The connector was up. And then the page
// never came, because the Edge — now the client to the asset — verified the asset's certificate against the
// PLATFORM'S PUBLIC ROOTS and refused it. An intranet server's certificate is issued by the organization's
// own authority. The public roots are exactly the set that will never contain it.
//
// So the deployment could inspect an internal flow and could not deliver one, and the two failures look
// identical from the browser. The trust for this direction is per organization, and it is authored by the
// organization that owns the assets — see the internalca package for why it is not the interception root.
//
// ★★ SCOPE. The widened pool applies to a flow of THAT organization only, and it is the platform's roots PLUS
// the organization's anchors — never the anchors alone, or every public site would stop verifying for anyone
// whose organization pasted one authority.

type organizationInternalCAPool interface {
	AnchorsPEM(tenantID string, now time.Time) []string
	Revision(tenantID string) uint64
}

// perOrganizationUpstreamTransports caches the exact material snapshot used to build the pool.
// Reading a revision separately can associate old material with a newer revision after a concurrent
// deletion. Material identity also separates stores whose local revision counters happen to match.
var perOrganizationUpstreamTransports sync.Map

// upstreamTransportTrustingTheOrganizationsPrivateAssets returns base unchanged when the organization vouches
// for nothing, which is the whole public web and must stay on the platform's own verification.
func upstreamTransportTrustingTheOrganizationsPrivateAssets(base http.RoundTripper, anchors organizationInternalCAPool, tenantID string, now time.Time) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	if anchors == nil || tenantID == "" {
		return base
	}
	pem := anchors.AnchorsPEM(tenantID, now)
	if len(pem) == 0 {
		return base
	}
	cacheKey := fmt.Sprintf("%p|%s|%x", base, tenantID, sha256.Sum256([]byte(strings.Join(pem, "\x00"))))
	if cached, ok := perOrganizationUpstreamTransports.Load(cacheKey); ok {
		return cached.(http.RoundTripper)
	}
	transport, ok := base.(*http.Transport)
	if !ok {
		// Nothing to widen: a transport we did not build owns its own verification. Say nothing and change
		// nothing rather than silently falling back to a pool that trusts less.
		return base
	}
	// ★ SYSTEM ROOTS FIRST, THEN THE ORGANIZATION'S. An x509.CertPool handed to crypto/tls REPLACES the
	// platform's roots; building from the organization's anchors alone would make every public origin fail to
	// verify for every device in that organization — an outage shaped like a certificate problem on the
	// internet rather than a change we made here.
	merged, err := x509.SystemCertPool()
	if err != nil || merged == nil {
		merged = x509.NewCertPool()
	}
	for _, anchor := range pem {
		merged.AppendCertsFromPEM([]byte(anchor))
	}
	widened := transport.Clone()
	if widened.TLSClientConfig == nil {
		widened.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	} else {
		widened.TLSClientConfig = widened.TLSClientConfig.Clone()
	}
	widened.TLSClientConfig.RootCAs = merged
	var result http.RoundTripper = widened
	actual, _ := perOrganizationUpstreamTransports.LoadOrStore(cacheKey, result)
	return actual.(http.RoundTripper)
}

// ★★ THE STORE MUST KEEP SATISFYING THIS. The interface exists so the durable store can replace the memory
// one; this line is what makes that swap a compile error instead of a silent loss of the feature.
var _ organizationInternalCAPool = (*internalca.Store)(nil)
