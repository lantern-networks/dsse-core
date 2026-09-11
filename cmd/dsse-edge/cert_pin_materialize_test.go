package main

import (
	"context"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/edgeplane"
	policycandidate "github.com/lantern-networks/dsse-core/policycandidate"
)

// The certificate-pinning bypass-candidate workflow's central property — nothing is bypassed until it is
// MATERIALISED — checked through the Edge's real wiring: materializedCertPinBypassHosts feeding
// interception.SetBypassHosts.
func TestMaterializedCertPinCandidateBypassesOnlyAfterMaterialize(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_700_000_000, 0).UTC()
	store := policycandidate.NewStore()

	// Detection: a pinning destination's handshake failures make it a pending candidate.
	c, err := store.ObserveCertPinFailure(ctx, "acme", "gateway.icloud.com", "gateway.icloud.com", 443, "interception_handshake_rejected", now)
	if err != nil {
		t.Fatalf("observe: %v", err)
	}

	// Build the interception engine under decrypt-all.
	interception, err := edgeplane.NewNetworkExtensionLabTLSInterception([]string{"*"}, func() time.Time { return now })
	if err != nil {
		t.Fatalf("new interception: %v", err)
	}
	interception.SetSNIBasedDecision(true)
	route := edgeplane.NetworkExtensionRuntimeCopyTCPRoute{Host: "17.253.1.1", Port: 443, SNI: "gateway.icloud.com"}

	applyBypass := func(tenant string) {
		interception.SetBypassHosts(materializedCertPinBypassHosts(store, tenant))
	}

	// While it is only pending it is not in the bypass set, so it is still intercepted.
	applyBypass("acme")
	if got := materializedCertPinBypassHosts(store, "acme"); len(got) != 0 {
		t.Fatalf("pending candidate must not be a bypass host, got %v", got)
	}
	if !interception.Matches(route) {
		t.Fatalf("pending candidate: host must stay intercepted")
	}

	// Approving alone does not materialise it, so it is still not bypassed.
	if _, ok, err := store.Review(ctx, "acme", c.CandidateID, policycandidate.ReviewRequest{Decision: "approved", ReviewReasonCode: "operator_approved"}, now); err != nil || !ok {
		t.Fatalf("review approved: ok=%v err=%v", ok, err)
	}
	applyBypass("acme")
	if !interception.Matches(route) {
		t.Fatalf("approved-but-not-materialized: host must stay intercepted")
	}

	// Only materialising puts it in the bypass set, and it is raw-forwarded from then on.
	if _, ok, err := store.Materialize(ctx, "acme", c.CandidateID, false, now); err != nil || !ok {
		t.Fatalf("materialize: ok=%v err=%v", ok, err)
	}
	hosts := materializedCertPinBypassHosts(store, "acme")
	if len(hosts) == 0 {
		t.Fatalf("materialized candidate must be a bypass host")
	}
	applyBypass("acme")
	if interception.Matches(route) {
		t.Fatalf("materialized candidate: host must be raw_forwarded (Matches=false)")
	}

	// And it reverts: an administrator suppressing a live bypass takes it out of the materialised set and it
	// is intercepted again, which is how a bypass is disabled.
	if _, ok, err := store.Review(ctx, "acme", c.CandidateID, policycandidate.ReviewRequest{Decision: "suppressed", ReviewReasonCode: "operator_revoked"}, now); err != nil || !ok {
		t.Fatalf("review suppressed: ok=%v err=%v", ok, err)
	}
	if got := materializedCertPinBypassHosts(store, "acme"); len(got) != 0 {
		t.Fatalf("suppressed candidate must drop out of the bypass set, got %v", got)
	}
	applyBypass("acme")
	if !interception.Matches(route) {
		t.Fatalf("reverted candidate: host must be intercepted again (Matches=true)")
	}
}
