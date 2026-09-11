package main

// Live, on-the-real-tunnel proof that the DNS-over-tunnel proxy's TTL cache (64b5c89c) serves a repeated
// question from cache instead of re-hitting the Edge — exercising the SHIPPED dnsProxy.resolve()+dnsCache,
// not a re-implementation. Gated behind DSSE_LIVE_DNS=1.
//
//   DSSE_LIVE_DNS=1 DSSE_T_URL=https://203.0.113.10:18543 \
//   DSSE_T_CA=...\transport_ca.pem DSSE_T_CERT=...\win-device.pem DSSE_T_KEY=...\win-device.key \
//   go test -run TestLiveDNSCacheServesRepeat -v .

import (
	"bytes"
	"os"
	"strings"
	"testing"
	"time"
)

func dnsQueryWire(txid uint16, name string, qtype uint16) []byte {
	b := []byte{byte(txid >> 8), byte(txid), 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	for _, label := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		b = append(b, byte(len(label)))
		b = append(b, []byte(label)...)
	}
	b = append(b, 0x00, byte(qtype>>8), byte(qtype), 0x00, 0x01) // root, QTYPE, QCLASS=IN
	return b
}

func TestLiveDNSCacheServesRepeat(t *testing.T) {
	if os.Getenv("DSSE_LIVE_DNS") != "1" {
		t.Skip("set DSSE_LIVE_DNS=1 to run the live DNS-over-tunnel cache probe")
	}
	tc, err := buildTransportConfig(
		os.Getenv("DSSE_T_URL"), os.Getenv("DSSE_T_CA"),
		os.Getenv("DSSE_T_CERT"), os.Getenv("DSSE_T_KEY"))
	if err != nil {
		t.Fatalf("buildTransportConfig: %v", err)
	}
	if !tc.enabled {
		t.Fatalf("transport not enabled — set DSSE_T_URL")
	}
	p := newDNSProxy(tc, "", false, nil)
	if p.cache == nil {
		t.Fatalf("dnsProxy has no cache — fix 64b5c89c not in this binary")
	}

	const name = "www.rakuten.co.jp"
	q1 := dnsQueryWire(0x1111, name, 1) // A
	t0 := time.Now()
	r1, err := p.resolve(q1)
	d1 := time.Since(t0)
	if err != nil {
		t.Fatalf("resolve#1 (tunnel) for %s: %v", name, err)
	}
	if _, ok := p.cache.get(q1); !ok {
		t.Fatalf("answer was not cached after the first resolve (zero-TTL? unparseable?)")
	}

	// Same question, DIFFERENT transaction id → must be a cache hit (keyed by question, not txid).
	q2 := dnsQueryWire(0x2222, name, 1)
	t1 := time.Now()
	r2, err := p.resolve(q2)
	d2 := time.Since(t1)
	if err != nil {
		t.Fatalf("resolve#2 (expected cache) for %s: %v", name, err)
	}

	t.Logf("resolve#1 (tunnel) = %v, len=%d | resolve#2 (cache) = %v, len=%d",
		d1.Round(time.Microsecond), len(r1), d2.Round(time.Microsecond), len(r2))

	// 1) cache hit is dramatically faster (no tunnel round-trip)
	if d2 >= d1 {
		t.Errorf("cache hit not faster: #1=%v #2=%v", d1, d2)
	}
	// 2) txid rewritten to match the ASKING query (0x2222), body identical to the cached answer
	if len(r2) < 2 || r2[0] != 0x22 || r2[1] != 0x22 {
		t.Errorf("cache hit did not rewrite txid to 0x2222: got % x", r2[:min(2, len(r2))])
	}
	if !bytes.Equal(r1[2:], r2[2:]) {
		t.Errorf("cache hit body differs from cached answer (only txid should change)")
	}
}
