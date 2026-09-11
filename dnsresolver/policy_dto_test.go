package dnsresolver

import (
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/dns"

	"golang.org/x/net/dns/dnsmessage"
)

// the admin DNS-policy DTO conversion validates + normalizes a ruleset (pure, no server).
func TestDNSPolicyFromDTOValidation(t *testing.T) {
	echOn := true
	echOff := false
	// Valid ruleset round-trips (names normalized to lowercase, no trailing dot).
	p, err := PolicyFromDTO(PolicyDTO{
		Deny:     []string{"Blocked.COM."},
		Sinkhole: map[string]string{"Bad.com": "100.64.0.250"},
		StubIPv4: map[string]string{"protected.example.com": "100.64.0.9"},
		ECHStrip: &echOn,
	})
	if err != nil {
		t.Fatalf("valid dto: %v", err)
	}
	if !p.deny["blocked.com"] || p.sinkhole["bad.com"] != "100.64.0.250" || p.stubIPv4["protected.example.com"] != "100.64.0.9" || !p.echStrip {
		t.Fatalf("normalization/round-trip wrong: %+v", p)
	}

	// Tri-state ech_strip: OMITTED (nil) keeps the secure default ON (a PUT that forgets the field must not
	// silently disable strip); explicit false opts out.
	if pol, err := PolicyFromDTO(PolicyDTO{Deny: []string{"x.com"}}); err != nil || !pol.echStrip {
		t.Fatalf("omitted ech_strip must default ON: echStrip=%v err=%v", pol.echStrip, err)
	}
	if pol, err := PolicyFromDTO(PolicyDTO{ECHStrip: &echOff}); err != nil || pol.echStrip {
		t.Fatalf("ech_strip:false must opt out: echStrip=%v err=%v", pol.echStrip, err)
	}

	// Bad sinkhole IP -> rejected (would fail open otherwise).
	if _, err := PolicyFromDTO(PolicyDTO{Sinkhole: map[string]string{"x.com": "not-an-ip"}}); err == nil {
		t.Fatal("bad sinkhole IP must be rejected")
	}
	// Empty deny name -> rejected.
	if _, err := PolicyFromDTO(PolicyDTO{Deny: []string{"  "}}); err == nil {
		t.Fatal("empty deny name must be rejected")
	}
	// deny+sinkhole collision -> rejected (ambiguous intent).
	if _, err := PolicyFromDTO(PolicyDTO{Deny: []string{"x.com"}, Sinkhole: map[string]string{"x.com": "1.2.3.4"}}); err == nil {
		t.Fatal("deny+sinkhole collision must be rejected")
	}
}

// setPolicy hot-swaps the live ruleset and handleQuery reads it (env policy fully overridden).
func TestDNSResolverHotSwapPolicy(t *testing.T) {
	now := time.Now()
	r := &Resolver{
		tenantID:  "t",
		upstream:  fakeUpstream{resp: dnsAplusHTTPSEch(t, "free.example.com.", [4]byte{203, 0, 113, 7})},
		conntrack: dns.NewConntrackStore(),
		policy:    Policy{}, // env policy: nothing blocked
	}
	// Before: free.example.com forwards (allow).
	var m dnsmessage.Message
	_ = m.Unpack(mustQuery(t, r, "free.example.com.", dnsmessage.TypeA, now))
	if m.Header.RCode != dnsmessage.RCodeSuccess {
		t.Fatalf("pre-swap should allow, got %v", m.Header.RCode)
	}
	// Hot-apply a ruleset that denies it.
	r.SetPolicy(Policy{deny: map[string]bool{"free.example.com": true}})
	var dm dnsmessage.Message
	_ = dm.Unpack(mustQuery(t, r, "free.example.com.", dnsmessage.TypeA, now))
	if dm.Header.RCode != dnsmessage.RCodeNameError {
		t.Fatalf("post-swap should deny (NXDOMAIN), got %v", dm.Header.RCode)
	}
}
