package main

import (
	"crypto/tls"
	"log"
	"net/http"
	"sync"

	"github.com/lantern-networks/dsse-core/edgeplane"
	"github.com/lantern-networks/dsse-core/outboundtls"
	"github.com/lantern-networks/dsse-core/policy"
	"github.com/lantern-networks/dsse-core/upstreamtrust"
)

const (
	upstreamTLSStrict            = "strict"
	upstreamTLSBrowserCompatible = "browser_compatible"
)

// upstreamTLSModeForTenant returns the organization's mode. Unset means the
// default (browser compatible); only an explicit strict choice narrows it. A
// flow without an established organization gets the default as well.
func upstreamTLSModeForTenant(store policy.RuntimeStore, tenantID string) string {
	mode := policy.UpstreamTLSDefault
	if store != nil && tenantID != "" {
		if reader, ok := store.(interface{ UpstreamTLSModeFor(string) string }); ok {
			mode = reader.UpstreamTLSModeFor(tenantID)
		} else {
			// Alternate durable RuntimeStores still receive the distributed
			// setting; the concrete Store avoids copying unrelated policy here.
			mode = store.SnapshotTenantConfig(tenantID).UpstreamTLSMode
		}
	}
	if mode != upstreamTLSStrict {
		return upstreamTLSBrowserCompatible
	}
	return mode
}

type tenantUpstreamTLSKey struct {
	// The caller has already selected an immutable tenant trust snapshot. A
	// different dialer or CA snapshot has a different transport identity.
	base   *http.Transport
	tenant string
}

type tenantUpstreamTLSPool struct {
	mode     string
	profiles map[string]*http.Transport
}

var tenantUpstreamTLSPools = struct {
	sync.Mutex
	current map[tenantUpstreamTLSKey]*tenantUpstreamTLSPool
}{current: make(map[tenantUpstreamTLSKey]*tenantUpstreamTLSPool)}

// upstreamTransportForTenantTLSMode keeps standard Go TLS verification and the
// caller's routing/HTTP2 policy. Compatibility only expands a default cipher
// policy to what Chrome offers; explicit cipher lists and custom TLS engines
// remain authoritative. A flow without an organization uses its own pool.
// The two modes have distinct connection pools and resumption caches. Reusing
// those immutable profiles prevents each toggle from retaining another derived
// AIA/vendor pool. Returning to strict can resume only its own strict sessions.
// It neither retries HTTP requests nor disconnects established active requests.
func upstreamTransportForTenantTLSMode(base http.RoundTripper, tenantID, mode string) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	if mode != upstreamTLSStrict {
		mode = upstreamTLSBrowserCompatible
	}
	transport, ok := base.(*http.Transport)
	scope, scoped := base.(edgeplane.TenantConnectorTransport)
	if scoped {
		transport, ok = scope.ConnectorTransport().(*http.Transport)
	}
	if !ok || transport.DialTLSContext != nil || transport.DialTLS != nil {
		return base // An opaque transport/custom TLS dialer owns its TLS policy.
	}
	key := tenantUpstreamTLSKey{base: transport, tenant: tenantID}
	tenantUpstreamTLSPools.Lock()
	pools := tenantUpstreamTLSPools.current[key]
	if pools == nil {
		pools = &tenantUpstreamTLSPool{profiles: make(map[string]*http.Transport)}
		tenantUpstreamTLSPools.current[key] = pools
	}
	previous := pools.profiles[pools.mode]
	adapted := pools.profiles[mode]
	if adapted == nil {
		adapted = transport.Clone()
		if adapted.TLSClientConfig == nil {
			adapted.TLSClientConfig = &tls.Config{}
		}
		config := adapted.TLSClientConfig
		if config.MinVersion < tls.VersionTLS12 {
			config.MinVersion = tls.VersionTLS12
		}
		// Clone otherwise shares the ticket cache: a tenant, trust snapshot,
		// or strict policy must not resume a session from another profile.
		if config.ClientSessionCache != nil {
			config.ClientSessionCache = tls.NewLRUClientSessionCache(0)
		}
		if mode == upstreamTLSBrowserCompatible && config.CipherSuites == nil {
			config.CipherSuites = browserCompatibleUpstreamTLS12Suites()
		}
		pools.profiles[mode] = adapted
	}
	pools.mode = mode
	tenantUpstreamTLSPools.Unlock()
	if previous != nil && previous != adapted {
		outboundtls.CloseIdleConnectionsForTransport(previous)
		upstreamtrust.CloseIdleConnectionsForTransport(previous)
	}
	if scoped {
		return scope.WithTenantConnectorTransport(tenantID, adapted)
	}
	return adapted
}

// chromeStaticRSASuites are the RSA key exchange suites Chrome 156 offers
// (captured from its ClientHello on 2026-10-29). Go stopped offering them by
// default in 1.22; every other suite Chrome offers is already a Go default.
// Not added: 3DES, RC4 and CBC-SHA256, which Chrome does not offer either.
var chromeStaticRSASuites = []uint16{
	tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_RSA_WITH_AES_128_CBC_SHA,
	tls.TLS_RSA_WITH_AES_256_CBC_SHA,
}

func browserCompatibleUpstreamTLS12Suites() []uint16 {
	// With Go 1.27 the supported secure TLS 1.2 suites are the default
	// families, including ECDHE AES-CBC-SHA (not CBC-SHA256). Do not replace
	// those defaults with the server listener's narrower AEAD-only list.
	var suites []uint16
	for _, suite := range tls.CipherSuites() {
		for _, version := range suite.SupportedVersions {
			if version == tls.VersionTLS12 {
				suites = append(suites, suite.ID)
				break
			}
		}
	}
	return append(suites, chromeStaticRSASuites...)
}

func logUpstreamTLSCompatibilityUse(tenantID, hostname, mode string, response *http.Response) {
	if mode != upstreamTLSBrowserCompatible || response == nil || response.TLS == nil {
		return
	}
	for _, suite := range chromeStaticRSASuites {
		if response.TLS.CipherSuite != suite {
			continue
		}
		// Deliberately omit URL, query, user information, headers and body.
		log.Printf("swg egress: upstream TLS compatibility used tenant=%q host=%q cipher=%s mode=%s", tenantID, hostname, tls.CipherSuiteName(response.TLS.CipherSuite), mode)
	}
}
