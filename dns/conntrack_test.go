package dns

import (
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/model"
)

func TestRecoverCertPinName(t *testing.T) {
	ct := NewConntrackStore()
	now := time.Now()
	ct.Record(ObservationRequest{TenantID: "t", FQDN: "api.vendor.example", ResolvedIPs: []string{"2606:4700:4700::1111"}, TTLSeconds: 60}, now)

	// connect-by-IP, no SNI, IP is a known DNS answer -> recovered FQDN + DNS-correlated.
	fqdn, ip, ok := RecoverCertPinName(ct, "t", "2606:4700:4700::1111", "", now)
	if !ok || fqdn != "api.vendor.example" || ip != "2606:4700:4700::1111" {
		t.Fatalf("recover hit: ok=%v fqdn=%q ip=%q", ok, fqdn, ip)
	}
	// An SNI was already seen -> nothing to recover (already attributed).
	if _, _, ok := RecoverCertPinName(ct, "t", "2606:4700:4700::1111", "api.vendor.example", now); ok {
		t.Fatal("must not correlate when an SNI is present")
	}
	// host is a hostname, not a raw IP -> not the connect-by-IP case.
	if _, _, ok := RecoverCertPinName(ct, "t", "api.vendor.example", "", now); ok {
		t.Fatal("must not correlate a non-IP host")
	}
	// unknown IP / no DNS answer -> miss.
	if _, _, ok := RecoverCertPinName(ct, "t", "203.0.113.9", "", now); ok {
		t.Fatal("unknown IP must miss")
	}
	// nil store is safe.
	if _, _, ok := RecoverCertPinName(nil, "t", "2606:4700:4700::1111", "", now); ok {
		t.Fatal("nil conntrack must miss")
	}
}

func TestDNSConntrackRecordAndEnrich(t *testing.T) {
	ct := NewConntrackStore()
	now := time.Now()
	n := ct.Record(ObservationRequest{
		TenantID: "t", FQDN: "app.example.com", ResolvedIPs: []string{"203.0.113.5", "203.0.113.6"}, TTLSeconds: 60,
	}, now)
	if n != 2 {
		t.Fatalf("recorded = %d, want 2", n)
	}
	// connect-by-IP flow (FQDN empty, Destination is the resolved IP) -> FQDN recovered.
	req := model.DecisionRequest{TenantID: "t", Destination: "203.0.113.5"}
	out := EnrichDecisionRequestWithDNS(req, ct, now)
	if out.FQDN != "app.example.com" {
		t.Fatalf("FQDN not recovered: %q", out.FQDN)
	}
	// Explicit FQDN / SNI wins (no override).
	req2 := model.DecisionRequest{TenantID: "t", Destination: "203.0.113.5", FQDN: "real.sni.com"}
	if out2 := EnrichDecisionRequestWithDNS(req2, ct, now); out2.FQDN != "real.sni.com" {
		t.Fatalf("existing FQDN must not be overridden: %q", out2.FQDN)
	}
	// Expired entry -> no recovery.
	if out3 := EnrichDecisionRequestWithDNS(req, ct, now.Add(2*time.Minute)); out3.FQDN != "" {
		t.Fatalf("expired entry should not recover, got %q", out3.FQDN)
	}
	// Non-IP destination (hostname) -> untouched.
	req4 := model.DecisionRequest{TenantID: "t", Destination: "not-an-ip"}
	if out4 := EnrichDecisionRequestWithDNS(req4, ct, now); out4.FQDN != "" {
		t.Fatalf("non-IP destination should not be enriched")
	}
	// Wrong tenant -> no cross-tenant leak.
	req5 := model.DecisionRequest{TenantID: "other", Destination: "203.0.113.5"}
	if out5 := EnrichDecisionRequestWithDNS(req5, ct, now); out5.FQDN != "" {
		t.Fatalf("cross-tenant lookup must not match")
	}
}
