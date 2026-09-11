package dnsresolver

import (
	"testing"
	"time"
)

// The DNS-over-tunnel diagnostic must be rate-limited: a storm of resolve failures (the exact condition that
// fail-opens an endpoint agent) must not flood the Edge log. Only the first event in each window logs.
func TestDNSOverTunnelShouldLogRateLimits(t *testing.T) {
	dnsOverTunnelLastLogNanos.Store(0)
	base := time.Unix(1_700_000_000, 0)

	if !dnsOverTunnelShouldLog(base) {
		t.Fatal("first event in a fresh window must log")
	}
	if dnsOverTunnelShouldLog(base.Add(10 * time.Millisecond)) {
		t.Fatal("a second event 10ms later must be suppressed (< 1s window)")
	}
	if dnsOverTunnelShouldLog(base.Add(500 * time.Millisecond)) {
		t.Fatal("an event 500ms later must still be suppressed")
	}
	if !dnsOverTunnelShouldLog(base.Add(dnsOverTunnelLogInterval + time.Millisecond)) {
		t.Fatal("an event past the window must log again")
	}
}
