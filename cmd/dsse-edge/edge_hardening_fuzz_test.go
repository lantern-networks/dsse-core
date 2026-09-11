package main

import (
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/dns"
	dnsresolver "github.com/lantern-networks/dsse-core/dnsresolver"
)

// fuzz the OIDC return-to sanitizer (open-redirect defense). Invariant: whenever it accepts a
// value, that value is a SAME-ORIGIN relative path — starts with a single "/", parses with no scheme and no
// host — so it can never redirect to an attacker origin. Must never panic.
func FuzzSanitizeOIDCReturnTo(f *testing.F) {
	for _, seed := range []string{
		"", "/", "//", "/app", "/a/b?c=d", "//evil.com", "https://evil.com", "/\\evil.com",
		"\t/x", "/%2e%2e", "javascript:alert(1)", "/path#frag", strings.Repeat("/a", 1000),
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, in string) {
		out, ok := sanitizeOIDCReturnTo(in)
		if !ok {
			return
		}
		if !strings.HasPrefix(out, "/") || strings.HasPrefix(out, "//") {
			t.Fatalf("accepted non-same-origin return_to %q (in=%q)", out, in)
		}
		parsed, err := url.ParseRequestURI(out)
		if err != nil || parsed.IsAbs() || parsed.Host != "" {
			t.Fatalf("accepted return_to that resolves off-origin: out=%q host=%q abs=%v err=%v", out, parsed.Host, parsed.IsAbs(), err)
		}
	})
}

// fuzz the DNS resolver query parser. Invariant: an arbitrary byte string passed as a DNS query
// must never panic — handleQuery either parses + applies policy or fails open to the upstream.
func FuzzDNSResolverHandleQuery(f *testing.F) {
	for _, seed := range [][]byte{
		{}, {0x00}, {0xff, 0xff}, make([]byte, 12), make([]byte, 512),
		append([]byte{0x42, 0x42, 0x01, 0x00, 0x00, 0x01}, make([]byte, 20)...),
	} {
		f.Add(seed)
	}
	now := time.Unix(1700000000, 0)
	f.Fuzz(func(t *testing.T, raw []byte) {
		r := dnsresolver.NewWithUpstream("t", fakeUpstreamDNS{reply: nil}, dns.NewConntrackStore())
		echOff := false
		fuzzPol, _ := dnsresolver.PolicyFromDTO(dnsresolver.PolicyDTO{Deny: []string{"blocked.example"}, Sinkhole: map[string]string{"bad.example": "100.64.0.250"}, ECHStrip: &echOff})
		r.SetPolicy(fuzzPol)
		// Must not panic for any input; an error return is acceptable.
		_, _ = r.HandleQuery(raw, now)
	})
}
