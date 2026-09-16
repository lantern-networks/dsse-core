package policycandidate

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

// Acceptance: cert-pinning detection creates a durable PENDING candidate that is never auto-bypassed;
// only an admin approval + materialize moves it into the bypass policy.
func TestCertPinObserveCreatesPendingAndIncrements(t *testing.T) {
	store := NewStore()
	ctx := context.Background()
	now := time.Now().UTC()
	c1, err := store.ObserveCertPinFailure(ctx, "acme", "pinned.example.com", "pinned.example.com", 443, "interception_handshake_rejected", now)
	if err != nil {
		t.Fatal(err)
	}
	if c1.Status != "pending" || c1.FailureCount != 1 || c1.Source != SourceCertPinningDetection || c1.ProposedAction != "bypass" || c1.CandidateType != "bypass_policy" {
		t.Fatalf("unexpected first candidate: %+v", c1)
	}
	c2, _ := store.ObserveCertPinFailure(ctx, "acme", "PINNED.example.com.", "pinned.example.com", 443, "interception_handshake_rejected", now)
	if c2.CandidateID != c1.CandidateID || c2.FailureCount != 2 {
		t.Fatalf("repeat observation should upsert the same id + increment: %+v", c2)
	}
}

// Acceptance (attribution design): a candidate identified only by a raw IP literal with no SNI is UNATTRIBUTED ->
// low confidence + investigate_only (never a strong active-bypass approval target). A hostname or SNI gives a
// named entity -> medium + review.
func TestCertPinAttributionConfidence(t *testing.T) {
	store := NewStore()
	ctx := context.Background()
	now := time.Now().UTC()
	cases := []struct {
		name, host, sni, wantConf, wantAction string
	}{
		{"hostname", "api.vendor.example", "", "medium", "review"},
		{"sni only", "2606:4700:4700::1111", "api.vendor.example", "medium", "review"},
		{"raw ipv6 no sni", "2606:4700:4700::1111", "", "low", "investigate_only"},
		{"raw ipv4 no sni", "1.1.1.1", "", "low", "investigate_only"},
	}
	for _, tc := range cases {
		c, err := store.ObserveCertPinFailure(ctx, "acme", tc.host, tc.sni, 443, "interception_handshake_rejected", now)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if c.Confidence != tc.wantConf || c.SuggestedAction != tc.wantAction {
			t.Fatalf("%s: confidence/action = %q/%q, want %q/%q", tc.name, c.Confidence, c.SuggestedAction, tc.wantConf, tc.wantAction)
		}
	}
}

// Acceptance: an unattributed (investigate_only) candidate must NOT materialize without an explicit high-risk
// override; an attributed (review) candidate materializes normally.
func TestCertPinMaterializeGatesUnattributed(t *testing.T) {
	store := NewStore()
	ctx := context.Background()
	now := time.Now().UTC()
	// raw-IP, no SNI -> investigate_only
	ip, _ := store.ObserveCertPinFailure(ctx, "acme", "2606:4700:4700::1111", "", 443, "reason", now)
	if _, ok, _ := store.Review(ctx, "acme", ip.CandidateID, ReviewRequest{Decision: "approved"}, now); !ok {
		t.Fatal("approve ip candidate")
	}
	if _, _, err := store.Materialize(ctx, "acme", ip.CandidateID, false, now); err == nil {
		t.Fatal("materialize of an investigate_only candidate without override must be blocked")
	}
	m, ok, err := store.Materialize(ctx, "acme", ip.CandidateID, true, now)
	if err != nil || !ok || m.Status != "materialized" {
		t.Fatalf("materialize with high-risk override should succeed: err=%v ok=%v %+v", err, ok, m)
	}
	// hostname -> review -> materializes without override
	h, _ := store.ObserveCertPinFailure(ctx, "acme", "api.vendor.example", "", 443, "reason", now)
	store.Review(ctx, "acme", h.CandidateID, ReviewRequest{Decision: "approved"}, now)
	if _, ok, err := store.Materialize(ctx, "acme", h.CandidateID, false, now); err != nil || !ok {
		t.Fatalf("attributed candidate should materialize without override: err=%v ok=%v", err, ok)
	}
}

// Acceptance (attribution design): a connect-by-IP candidate whose FQDN was recovered from the DNS-over-tunnel
// conntrack is the highest-trust attribution -> "high" confidence + "review", keyed by the recovered ENTITY (the
// FQDN, not the IP), with the originating IP kept as evidence. It materializes without a high-risk override (it is
// a named entity, not an unattributed raw IP).
func TestCertPinDNSCorrelatedAttribution(t *testing.T) {
	store := NewStore()
	ctx := context.Background()
	now := time.Now().UTC()
	c, err := store.ObserveCertPinFailureDNSCorrelated(ctx, "acme", "api.vendor.example", "2606:4700:4700::1111", 443, "interception_handshake_rejected", now)
	if err != nil {
		t.Fatal(err)
	}
	if c.Confidence != "high" || c.SuggestedAction != "review" {
		t.Fatalf("DNS-correlated should be high/review: %q/%q", c.Confidence, c.SuggestedAction)
	}
	if c.Host != "api.vendor.example" || c.SNI != "" || c.ObservedIP != "2606:4700:4700::1111" || c.AttributionSource != "dns_tunnel_correlation" {
		t.Fatalf("candidate should be keyed by FQDN with the IP as evidence: %+v", c)
	}
	// A named entity materializes without a high-risk override.
	if _, ok, _ := store.Review(ctx, "acme", c.CandidateID, ReviewRequest{Decision: "approved"}, now); !ok {
		t.Fatal("approve")
	}
	if _, ok, err := store.Materialize(ctx, "acme", c.CandidateID, false, now); err != nil || !ok {
		t.Fatalf("DNS-correlated candidate should materialize without override: err=%v ok=%v", err, ok)
	}
}

func TestCertPinDurableAcrossRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "candidates.json")
	store := NewStore()
	if err := store.SetStatePath(path); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	c, _ := store.ObserveCertPinFailure(ctx, "acme", "pin.example", "", 443, "reason", time.Now())
	store2 := NewStore() // simulate a restart
	if err := store2.SetStatePath(path); err != nil {
		t.Fatal(err)
	}
	got, ok, _ := store2.Get(ctx, "acme", c.CandidateID)
	if !ok || got.Status != "pending" || got.FailureCount != 1 {
		t.Fatalf("candidate must survive restart: ok=%v %+v", ok, got)
	}
}

func TestCertPinMaterializeOnlyAfterApprove(t *testing.T) {
	store := NewStore()
	ctx := context.Background()
	c, _ := store.ObserveCertPinFailure(ctx, "acme", "pin.example", "", 443, "reason", time.Now())
	if _, _, err := store.Materialize(ctx, "acme", c.CandidateID, false, time.Now()); err == nil {
		t.Fatal("materialize from pending must fail (unreviewed candidate must not bypass)")
	}
	if _, ok, err := store.Review(ctx, "acme", c.CandidateID, ReviewRequest{Decision: "approved"}, time.Now()); err != nil || !ok {
		t.Fatalf("approve: %v ok=%v", err, ok)
	}
	m, ok, err := store.Materialize(ctx, "acme", c.CandidateID, false, time.Now())
	if err != nil || !ok || m.Status != "materialized" {
		t.Fatalf("materialize after approve: %v ok=%v %+v", err, ok, m)
	}
}

func TestCertPinSuppress(t *testing.T) {
	store := NewStore()
	ctx := context.Background()
	c, _ := store.ObserveCertPinFailure(ctx, "acme", "pin.example", "", 443, "reason", time.Now())
	got, ok, err := store.Review(ctx, "acme", c.CandidateID, ReviewRequest{Decision: "suppressed"}, time.Now())
	if err != nil || !ok || got.Status != "suppressed" {
		t.Fatalf("suppress: %v ok=%v %+v", err, ok, got)
	}
}

// Acceptance (manual add): an operator can register a known pinned site directly — AddManualCertPinBypass
// creates it already APPROVED (skipping pending) and it materializes in one follow-up call, becoming a live
// bypass. It is an ordinary cert-pin candidate (same source/type) so it flows through the normal materialize +
// bypass-host plumbing. A raw IP literal is rejected (you cannot attribute a bare IP), and a manual add for a
// host that was already auto-detected keeps its observation history while advancing it to approved.
func TestAddManualCertPinBypassApprovesAndMaterializes(t *testing.T) {
	store := NewStore()
	ctx := context.Background()
	now := time.Now().UTC()

	approved, err := store.AddManualCertPinBypass(ctx, "acme", "Gateway.Example.com", now)
	if err != nil {
		t.Fatal(err)
	}
	if approved.Status != "approved" || approved.Source != SourceCertPinningDetection || approved.CandidateType != "bypass_policy" || approved.ProposedAction != "bypass" {
		t.Fatalf("manual add should yield an approved cert-pin bypass candidate: %+v", approved)
	}
	if approved.Host != "gateway.example.com" {
		t.Fatalf("host should be normalized: %q", approved.Host)
	}
	if approved.SuggestedAction == suggestedActionInvestigateOnly {
		t.Fatalf("a named host must not be investigate_only: %+v", approved)
	}

	materialized, ok, err := store.Materialize(ctx, "acme", approved.CandidateID, false, now)
	if err != nil || !ok {
		t.Fatalf("approved manual candidate must materialize without a high-risk override: ok=%v err=%v", ok, err)
	}
	if materialized.Status != "materialized" {
		t.Fatalf("expected materialized, got %s", materialized.Status)
	}

	// A raw IP literal is rejected — a bypass no-decrypts its destination and a bare IP is unattributable.
	if _, err := store.AddManualCertPinBypass(ctx, "acme", "2606:4700:4700::1111", now); err == nil {
		t.Fatal("expected raw IP literal to be rejected")
	}

	// Manual add of an already-detected host keeps the observation count and advances it to approved.
	det, _ := store.ObserveCertPinFailure(ctx, "acme", "pinned.example.com", "", 443, "operator_manual_add", now)
	if det.Status != "pending" || det.FailureCount != 1 {
		t.Fatalf("seed detection unexpected: %+v", det)
	}
	re, err := store.AddManualCertPinBypass(ctx, "acme", "pinned.example.com", now)
	if err != nil {
		t.Fatal(err)
	}
	if re.CandidateID != det.CandidateID {
		t.Fatalf("manual add should reuse the detected candidate id: %q vs %q", re.CandidateID, det.CandidateID)
	}
	if re.Status != "approved" || re.FailureCount != 1 {
		t.Fatalf("manual add should approve the existing candidate and keep its history: %+v", re)
	}
}

func TestMaterializationRetryKeepsReviewAndRiskGates(t *testing.T) {
	ctx := context.Background()
	s := NewStore()
	now := time.Now()
	c, e := s.ObserveCertPinFailure(ctx, "own", "192.0.2.10", "", 443, "rejected", now)
	if e != nil {
		t.Fatal(e)
	}
	if _, _, e = s.Review(ctx, "own", c.CandidateID, ReviewRequest{Decision: "approved"}, now); e != nil {
		t.Fatal(e)
	}
	if _, _, e = s.Materialize(ctx, "own", c.CandidateID, true, now); e != nil {
		t.Fatal(e)
	}
	if _, _, e = s.Materialize(ctx, "own", c.CandidateID, false, now); e == nil {
		t.Fatal("retry dropped high-risk gate")
	}
	if _, _, e = s.Materialize(ctx, "own", c.CandidateID, true, now); e != nil {
		t.Fatal("explicit retry", e)
	}
	if _, _, e = s.Review(ctx, "own", c.CandidateID, ReviewRequest{Decision: "rejected"}, now); e != nil {
		t.Fatal(e)
	}
	if _, _, e = s.Materialize(ctx, "own", c.CandidateID, true, now); e == nil {
		t.Fatal("retry bypassed later rejection")
	}
	if _, ok, e := s.Materialize(ctx, "other", c.CandidateID, true, now); ok || e != nil {
		t.Fatal("cross-tenant retry", ok, e)
	}
}
