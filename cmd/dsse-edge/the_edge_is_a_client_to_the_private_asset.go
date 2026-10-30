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

	"github.com/lantern-networks/dsse-core/edgeplane"
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

type unavailableTenantConnectorTransport struct{}

func (unavailableTenantConnectorTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, fmt.Errorf("tenant-specific connector transport is unavailable")
}

// upstreamTransportTrustingTheOrganizationsPrivateAssets isolates connections by
// tenant even when no private CA is configured. The same host can name different
// applications behind different tenant Connectors; a pooled connection bypasses
// DialContext, so a request context alone cannot isolate those routes.
// Without authored anchors, the base TLS verification policy is unchanged.
func upstreamTransportTrustingTheOrganizationsPrivateAssets(base http.RoundTripper, anchors organizationInternalCAPool, tenantID string, now time.Time) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	if tenantID == "" {
		return base
	}
	var pem []string
	if anchors != nil {
		pem = anchors.AnchorsPEM(tenantID, now)
	}
	cacheKey := fmt.Sprintf("%p|%s|%x", base, tenantID, sha256.Sum256([]byte(strings.Join(pem, "\x00"))))
	if cached, ok := perOrganizationUpstreamTransports.Load(cacheKey); ok {
		return cached.(http.RoundTripper)
	}
	transport, ok := base.(*http.Transport)
	scope, scoped := base.(edgeplane.TenantConnectorTransport)
	if scoped {
		transport, ok = scope.ConnectorTransport().(*http.Transport)
	}
	if !ok {
		if scoped {
			// Keep the public broker path usable, but do not share an opaque connector pool across tenants.
			return scope.WithTenantConnectorTransport(tenantID, unavailableTenantConnectorTransport{})
		}
		// Nothing to widen: a transport we did not build owns its own verification. Say nothing and change
		// nothing rather than silently falling back to a pool that trusts less.
		return base
	}
	widened := transport.Clone()
	if len(pem) > 0 {
		// Preserve an explicitly configured root pool; otherwise start with the
		// operating system roots. Add only this tenant's authored authorities.
		var merged *x509.CertPool
		if widened.TLSClientConfig != nil && widened.TLSClientConfig.RootCAs != nil {
			merged = widened.TLSClientConfig.RootCAs.Clone()
		} else {
			merged, _ = x509.SystemCertPool()
			if merged == nil {
				merged = x509.NewCertPool()
			}
		}
		for _, anchor := range pem {
			merged.AppendCertsFromPEM([]byte(anchor))
		}
		if widened.TLSClientConfig == nil {
			widened.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		}
		widened.TLSClientConfig.RootCAs = merged
	}
	var result http.RoundTripper = widened
	if scoped {
		result = scope.WithTenantConnectorTransport(tenantID, widened)
	}
	actual, _ := perOrganizationUpstreamTransports.LoadOrStore(cacheKey, result)
	return actual.(http.RoundTripper)
}

// ★★ THE STORE MUST KEEP SATISFYING THIS. The interface exists so the durable store can replace the memory
// one; this line is what makes that swap a compile error instead of a silent loss of the feature.
var _ organizationInternalCAPool = (*internalca.Store)(nil)
