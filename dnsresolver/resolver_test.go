package dnsresolver

import (
	"context"
	"github.com/lantern-networks/dsse-core/dns"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

type fakeUpstream struct{ resp []byte }

func (f fakeUpstream) Resolve(raw []byte) ([]byte, error) { return f.resp, nil }

func dnsQuery(t *testing.T, name string, typ dnsmessage.Type) []byte {
	m := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: 0x4242, RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName(name), Type: typ, Class: dnsmessage.ClassINET}},
	}
	raw, err := m.Pack()
	if err != nil {
		t.Fatalf("pack query: %v", err)
	}
	return raw
}

func dnsAplusHTTPSEch(t *testing.T, name string, ipv4 [4]byte) []byte {
	n := dnsmessage.MustNewName(name)
	m := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: 0x4242, Response: true, RecursionAvailable: true},
		Questions: []dnsmessage.Question{{Name: n, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}},
		Answers: []dnsmessage.Resource{
			{Header: dnsmessage.ResourceHeader{Name: n, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60}, Body: &dnsmessage.AResource{A: ipv4}},
			{Header: dnsmessage.ResourceHeader{Name: n, Type: dnsmessage.Type(dnsTypeHTTPS), Class: dnsmessage.ClassINET, TTL: 60}, Body: &dnsmessage.UnknownResource{Type: dnsmessage.Type(dnsTypeHTTPS), Data: buildHTTPSRdata(true)}},
		},
	}
	raw, err := m.Pack()
	if err != nil {
		t.Fatalf("pack upstream resp: %v", err)
	}
	return raw
}

func httpsEchPresent(raw []byte) bool {
	var m dnsmessage.Message
	if m.Unpack(raw) != nil {
		return false
	}
	for _, rr := range m.Answers {
		if uint16(rr.Header.Type) != dnsTypeHTTPS {
			continue
		}
		// x/net dnsmessage parses HTTPS records into a typed *HTTPSResource.
		h, ok := rr.Body.(*dnsmessage.HTTPSResource)
		if !ok {
			continue
		}
		if _, present := h.GetParam(dnsmessage.SVCParamECH); present {
			return true
		}
	}
	return false
}

func TestDNSResolverPipeline(t *testing.T) {
	now := time.Now()
	ct := dns.NewConntrackStore()
	r := &Resolver{
		tenantID:  "t",
		upstream:  fakeUpstream{resp: dnsAplusHTTPSEch(t, "app.example.com.", [4]byte{203, 0, 113, 7})},
		conntrack: ct,
		policy: Policy{
			deny:     map[string]bool{"blocked.example.com": true},
			stubIPv4: map[string]string{"protected.example.com": "100.64.0.9"},
			echStrip: true,
		},
	}

	// Forward: ECH stripped + conntrack recorded -> FQDN recoverable.
	resp, err := r.HandleQuery(dnsQuery(t, "app.example.com.", dnsmessage.TypeA), now)
	if err != nil {
		t.Fatal(err)
	}
	if httpsEchPresent(resp) {
		t.Fatalf("ech should be stripped from forwarded response")
	}
	if fqdn, _, ok := ct.LookupFQDN("t", "203.0.113.7", now); !ok || fqdn != "app.example.com" {
		t.Fatalf("conntrack should record app.example.com -> 203.0.113.7, got %q ok=%v", fqdn, ok)
	}

	// Deny -> NXDOMAIN.
	dr, err := r.HandleQuery(dnsQuery(t, "blocked.example.com.", dnsmessage.TypeA), now)
	if err != nil {
		t.Fatal(err)
	}
	var dm dnsmessage.Message
	if dm.Unpack(dr); dm.Header.RCode != dnsmessage.RCodeNameError {
		t.Fatalf("deny should be NXDOMAIN, got rcode %v", dm.Header.RCode)
	}

	// Stub IP -> synthesized A + conntrack, no upstream.
	sr, err := r.HandleQuery(dnsQuery(t, "protected.example.com.", dnsmessage.TypeA), now)
	if err != nil {
		t.Fatal(err)
	}
	if ips := ExtractResolvedIPs(sr); len(ips) != 1 || ips[0] != "100.64.0.9" {
		t.Fatalf("stub should synthesize A 100.64.0.9, got %v", ips)
	}
	if fqdn, _, ok := ct.LookupFQDN("t", "100.64.0.9", now); !ok || fqdn != "protected.example.com" {
		t.Fatalf("stub conntrack not recorded: %q ok=%v", fqdn, ok)
	}
}

// DNS-layer sinkhole (resolve a blocked name to a controlled IP) + domain-tree (subdomain) matching
// for both deny and sinkhole.
func TestDNSResolverSinkholeAndSuffix(t *testing.T) {
	now := time.Now()
	ct := dns.NewConntrackStore()
	r := &Resolver{
		tenantID:  "t",
		upstream:  fakeUpstream{resp: dnsAplusHTTPSEch(t, "x.example.com.", [4]byte{203, 0, 113, 9})},
		conntrack: ct,
		policy: Policy{
			deny:     map[string]bool{"blocked.example.com": true},
			sinkhole: map[string]string{"bad.com": "100.64.0.250"},
		},
	}

	// Sinkhole exact (A) -> the sinkhole IP, conntrack recorded.
	if ips := ExtractResolvedIPs(mustQuery(t, r, "bad.com.", dnsmessage.TypeA, now)); len(ips) != 1 || ips[0] != "100.64.0.250" {
		t.Fatalf("sinkhole A should be 100.64.0.250, got %v", ips)
	}
	if fqdn, _, ok := ct.LookupFQDN("t", "100.64.0.250", now); !ok || fqdn != "bad.com" {
		t.Fatalf("sinkhole conntrack not recorded: %q ok=%v", fqdn, ok)
	}
	// Sinkhole subdomain (domain-tree) -> the sinkhole IP.
	if ips := ExtractResolvedIPs(mustQuery(t, r, "ads.bad.com.", dnsmessage.TypeA, now)); len(ips) != 1 || ips[0] != "100.64.0.250" {
		t.Fatalf("sinkhole subdomain A should be 100.64.0.250, got %v", ips)
	}
	// Sinkhole AAAA -> NODATA (success, no answer) so IPv6 cannot bypass the sinkhole.
	var am dnsmessage.Message
	_ = am.Unpack(mustQuery(t, r, "bad.com.", dnsmessage.TypeAAAA, now))
	if am.Header.RCode != dnsmessage.RCodeSuccess || len(am.Answers) != 0 {
		t.Fatalf("sinkhole AAAA should be NODATA (success, 0 answers), got rcode=%v answers=%d", am.Header.RCode, len(am.Answers))
	}
	// Deny subdomain (domain-tree) -> NXDOMAIN.
	var dm dnsmessage.Message
	_ = dm.Unpack(mustQuery(t, r, "sub.blocked.example.com.", dnsmessage.TypeA, now))
	if dm.Header.RCode != dnsmessage.RCodeNameError {
		t.Fatalf("deny subdomain should be NXDOMAIN, got %v", dm.Header.RCode)
	}

	// Precedence + no-match.
	p := Policy{deny: map[string]bool{"x.com": true}, sinkhole: map[string]string{"x.com": "1.2.3.4"}}
	if a, _ := p.policyAction("x.com"); a != "deny" {
		t.Fatalf("deny must win over sinkhole, got %q", a)
	}
	if a, _ := p.policyAction("allowed.com"); a != "" {
		t.Fatalf("no policy match should be empty, got %q", a)
	}

	// Review #27: a PARENT deny must win over a CHILD sinkhole. login.evil.com has an exact sinkhole, but
	// evil.com is denied at the parent — the whole tree is denied, so the child must be NXDOMAIN'd, not
	// resolved to the sinkhole IP. The old order returned the exact child sinkhole before checking the
	// subdomain-deny loop.
	pt := Policy{deny: map[string]bool{"evil.com": true}, sinkhole: map[string]string{"login.evil.com": "1.2.3.4"}}
	if a, _ := pt.policyAction("login.evil.com"); a != "deny" {
		t.Fatalf("a parent deny must beat a child sinkhole, got %q", a)
	}
	if a, _ := pt.policyAction("evil.com"); a != "deny" {
		t.Fatalf("exact parent deny, got %q", a)
	}
	// A child sinkhole with NO parent deny still sinkholes.
	ps := Policy{sinkhole: map[string]string{"login.other.com": "5.6.7.8"}}
	if a, ip := ps.policyAction("login.other.com"); a != "sinkhole" || ip != "5.6.7.8" {
		t.Fatalf("child sinkhole without a parent deny should sinkhole, got %q/%q", a, ip)
	}
}

func mustQuery(t *testing.T, r *Resolver, name string, typ dnsmessage.Type, now time.Time) []byte {
	t.Helper()
	resp, err := r.HandleQuery(dnsQuery(t, name, typ), now)
	if err != nil {
		t.Fatalf("handleQuery %s: %v", name, err)
	}
	return resp
}

type fakeConnectorDNS struct {
	resp        []byte
	called      bool
	gotUpstream string
}

func (f *fakeConnectorDNS) ResolveViaConnector(_ context.Context, upstream string, _ []byte) ([]byte, error) {
	f.called, f.gotUpstream = true, upstream
	return f.resp, nil
}

// An internal forward-zone resolves THROUGH its connector; deny/stub still win; a public name uses the default
// upstream; and with no connector wired a matching zone fails CLOSED to SERVFAIL (never leaks to public DNS).
func TestDNSResolverForwardZone(t *testing.T) {
	now := time.Now()
	ct := dns.NewConntrackStore()
	conn := &fakeConnectorDNS{resp: dnsAplusHTTPSEch(t, "dc01.corp.example.com.", [4]byte{10, 10, 0, 10})}
	r := &Resolver{
		tenantID:     "t",
		upstream:     fakeUpstream{resp: dnsAplusHTTPSEch(t, "www.example.com.", [4]byte{203, 0, 113, 7})},
		conntrack:    ct,
		connectorDNS: conn,
		policy: Policy{
			deny:         map[string]bool{"blocked.corp.example.com": true},
			forwardZones: []ForwardZone{{Zone: "corp.example.com", Upstream: "10.10.0.10:53"}},
			echStrip:     true,
		},
	}
	rcode := func(b []byte) dnsmessage.RCode { var m dnsmessage.Message; _ = m.Unpack(b); return m.Header.RCode }

	// _msdcs SRV (a subdomain of the zone) routes to the connector, with the configured upstream.
	if _, err := r.HandleQuery(dnsQuery(t, "_ldap._tcp.dc._msdcs.corp.example.com.", dnsmessage.TypeSRV), now); err != nil {
		t.Fatal(err)
	}
	if !conn.called || conn.gotUpstream != "10.10.0.10:53" {
		t.Fatalf("internal zone must resolve via the connector with the internal DNS: called=%v up=%q", conn.called, conn.gotUpstream)
	}
	// Deny beats the forward zone.
	if dr, _ := r.HandleQuery(dnsQuery(t, "blocked.corp.example.com.", dnsmessage.TypeA), now); rcode(dr) != dnsmessage.RCodeNameError {
		t.Fatal("deny must beat the forward zone (NXDOMAIN)")
	}
	// A public name uses the default upstream, not the connector.
	conn.called = false
	if _, err := r.HandleQuery(dnsQuery(t, "www.example.com.", dnsmessage.TypeA), now); err != nil {
		t.Fatal(err)
	}
	if conn.called {
		t.Fatal("a public name must NOT go via the connector")
	}
	// No connector wired => a matching zone fails closed to SERVFAIL (never leaks to public upstream).
	r.connectorDNS = nil
	if sr, _ := r.HandleQuery(dnsQuery(t, "host.corp.example.com.", dnsmessage.TypeA), now); rcode(sr) != dnsmessage.RCodeServerFailure {
		t.Fatal("no connector => SERVFAIL, not a public leak")
	}
}
