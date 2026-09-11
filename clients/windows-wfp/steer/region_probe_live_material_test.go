//go:build windows

package main

import (
	"crypto/tls"
	"crypto/x509"
	"sync/atomic"
	"testing"
)

// ★ THE REGION HEALTH PROBE MUST READ WHAT IS IN FORCE (2026-08-20). It built its TLS configuration from
// tc.rootCAs and tc.clientCert — the anchors this process started with and the certificate it was provisioned
// with — while every real dial uses the adopted anchors and the renewed identity. Both change at runtime on
// this deployment: anchors whenever a distribution is adopted, and the identity on every renewal.
//
// The failure is not a broken probe, it is a confident wrong answer: a healthy region verified against
// withdrawn anchors reads as unreachable, and a superseded certificate reads as not admitted. Failover is
// then decided on both.

func TestTheRegionProbeUsesAdoptedAnchorsNotStartupOnes(t *testing.T) {
	startup := newTestCA(t, "anchors this process started with")
	adopted := newTestCA(t, "anchors adopted at runtime")

	startupPool := x509.NewCertPool()
	startupPool.AddCert(startup.cert)
	tc := transportConfig{
		enabled:   true,
		rootCAs:   startupPool,
		pinnedCAs: []*x509.Certificate{startup.cert},
		liveTrust: &atomic.Pointer[trustMaterial]{},
	}
	tc.setTrustAnchors(adopted.pem, 7) // a distribution adopted while running

	cfg := regionProbeTLSConfig(tc, "edge-region-b.example")
	if cfg.RootCAs == nil {
		t.Fatalf("probe has no roots at all")
	}
	if cfg.RootCAs.Equal(startupPool) {
		t.Fatalf("the probe is verifying against the anchors this process started with; a region serving " +
			"under the adopted anchors would read as unreachable")
	}
	if cfg.ServerName != "edge-region-b.example" {
		t.Fatalf("ServerName = %q, want the region's own name", cfg.ServerName)
	}
}

func TestTheRegionProbePresentsTheRenewedIdentity(t *testing.T) {
	provisionedPEM, provisionedKey, provisioned := mkSelfSigned(t, "win-dev-1-provisioned", nil)
	_, _, renewed := mkSelfSigned(t, "win-dev-1-renewed", nil)
	_, _ = provisionedPEM, provisionedKey

	tc := transportConfig{
		enabled:        true,
		clientCert:     &provisioned,
		liveClientCert: &atomic.Pointer[tls.Certificate]{},
		liveTrust:      &atomic.Pointer[trustMaterial]{},
	}
	tc.setClientCert(&renewed) // what an automated renewal does

	cfg := regionProbeTLSConfig(tc, "edge-region-b.example")
	if len(cfg.Certificates) != 1 {
		t.Fatalf("probe presents %d certificates, want 1", len(cfg.Certificates))
	}
	if commonNameOf(t, &cfg.Certificates[0]) != "win-dev-1-renewed" {
		t.Fatalf("the probe presents the provisioned certificate after a renewal; the region would read as " +
			"not admitted while the real tunnel is fine")
	}
}
