package main

import (
	"net"
	"testing"
	"time"
)

// TestDNSProxyNoHardcodedPublicFallback pins fail-open review finding #26: a fresh proxy must NOT carry any
// hardcoded public resolvers (8.8.8.8/1.1.1.1) — the fail-open path uses only the captured PRE-STEER upstream
// unless an operator explicitly opts into a public last resort.
func TestDNSProxyNoHardcodedPublicFallback(t *testing.T) {
	p := newDNSProxy(transportConfig{}, "http://127.0.0.1:1", true, newEdgeHealth(3, time.Second))
	if len(p.publicFallback) != 0 {
		t.Fatalf("a fresh proxy must have NO public fallback by default (no undisclosed third-party egress); got %v", p.publicFallback)
	}
	// Opt-in works and is exactly what the operator set (no implicit additions).
	p.setPublicFallback(PublicResolverDefaults)
	if len(p.publicFallback) != 2 {
		t.Fatalf("opt-in public fallback = %v, want the 2 configured resolvers", p.publicFallback)
	}
}

// TestDNSProxyFailOpenUsesPreSteerUpstreamOnly proves the default fail-open path resolves via the captured
// pre-steer upstream alone (no public fallback configured), i.e. it "restores toward the pre-steer DNS".
func TestDNSProxyFailOpenUsesPreSteerUpstreamOnly(t *testing.T) {
	query := []byte{0x00, 0x01, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	want := []byte{0x00, 0x01, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0}
	upstream, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()
	go func() {
		buf := make([]byte, 512)
		for {
			_, addr, err := upstream.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = upstream.WriteTo(want, addr)
		}
	}()

	p := newDNSProxy(transportConfig{}, "http://127.0.0.1:1", true, newEdgeHealth(3, time.Second))
	p.setFallback([]string{upstream.LocalAddr().String()}) // pre-steer upstream; NO public fallback set
	got, err := p.resolve(query)
	if err != nil {
		t.Fatalf("fail-open via pre-steer upstream returned error: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("fail-open answer mismatch: got %x want %x", got, want)
	}
}
