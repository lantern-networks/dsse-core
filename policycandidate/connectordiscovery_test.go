package policycandidate

import (
	"context"
	"testing"
	"time"
)

// TestConnectorDiscoveredSourceIsValid covers the additive source/type/action enums Slice 4 adds.
func TestConnectorDiscoveredSourceIsValid(t *testing.T) {
	if !validSource(SourceConnectorDiscovered) {
		t.Fatalf("connector_discovered must be a valid source")
	}
	if !validType("private_app") {
		t.Fatalf("private_app must be a valid candidate type")
	}
	if !validAction("publish") {
		t.Fatalf("publish must be a valid proposed action")
	}
	if got := proposedActionForCandidateType("private_app"); got != "publish" {
		t.Fatalf("proposedActionForCandidateType(private_app) = %q, want publish", got)
	}
}

// TestObserveConnectorDiscoveredCreatesPendingCandidate covers the happy path: a discovered FQDN destination
// becomes a PENDING private-app candidate with medium/review attribution and the observed-from metadata, and
// it is NEVER auto-approved/published (status stays pending).
func TestObserveConnectorDiscoveredCreatesPendingCandidate(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	store := NewStore()
	cand, err := store.ObserveConnectorDiscovered(ctx, "tenant_a", "Jira.Internal.Example.com.", 0, "web", "conn-1", "tokyo-dc", "", []string{"declared reachable route (fqdn_domains)"}, now)
	if err != nil {
		t.Fatalf("observe: %v", err)
	}
	if cand.Status != "pending" {
		t.Fatalf("status = %q, want pending (no auto-approve)", cand.Status)
	}
	if cand.Source != SourceConnectorDiscovered || cand.CandidateType != "private_app" || cand.ProposedAction != "publish" {
		t.Fatalf("unexpected classification: %#v", cand)
	}
	if cand.Host != "jira.internal.example.com" {
		t.Fatalf("host = %q, want normalized jira.internal.example.com", cand.Host)
	}
	if cand.Confidence != "medium" || cand.SuggestedAction != "review" {
		t.Fatalf("attribution = %q/%q, want medium/review", cand.Confidence, cand.SuggestedAction)
	}
	if cand.ObservedFromConnectorID != "conn-1" || cand.ObservedFromSite != "tokyo-dc" {
		t.Fatalf("observed-from = %q/%q", cand.ObservedFromConnectorID, cand.ObservedFromSite)
	}
	if len(cand.Evidence) != 1 {
		t.Fatalf("evidence = %#v", cand.Evidence)
	}
}

// TestObserveConnectorDiscoveredLowConfidenceForCIDRAndIP covers attribution: a CIDR or a bare IP is not a
// named entity, so it is low/investigate_only (the UI de-emphasizes publish CTAs).
func TestObserveConnectorDiscoveredLowConfidenceForCIDRAndIP(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	store := NewStore()
	for _, dest := range []string{"10.20.0.0/16", "10.20.0.5"} {
		cand, err := store.ObserveConnectorDiscovered(ctx, "tenant_a", dest, 0, "network", "conn-1", "tokyo-dc", "vnet-1", nil, now)
		if err != nil {
			t.Fatalf("observe %s: %v", dest, err)
		}
		if cand.Confidence != "low" || cand.SuggestedAction != "investigate_only" {
			t.Fatalf("attribution for %s = %q/%q, want low/investigate_only", dest, cand.Confidence, cand.SuggestedAction)
		}
	}
}

// TestObserveConnectorDiscoveredDedupAndStatusPreserved covers re-discovery: the same destination upserts the
// same candidate (refreshing evidence), and a prior admin decision is never reset to pending (fail-closed).
func TestObserveConnectorDiscoveredDedupAndStatusPreserved(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	store := NewStore()
	first, err := store.ObserveConnectorDiscovered(ctx, "tenant_a", "jira.internal.example.com", 0, "web", "conn-1", "tokyo-dc", "", []string{"evidence-a"}, now)
	if err != nil {
		t.Fatalf("observe first: %v", err)
	}
	// Admin rejects it.
	if _, _, err := store.Review(ctx, "tenant_a", first.CandidateID, ReviewRequest{Decision: "rejected", ReviewReasonCode: "ops_reviewed"}, now); err != nil {
		t.Fatalf("review: %v", err)
	}
	// Re-discovery must NOT resurrect it to pending; evidence merges.
	again, err := store.ObserveConnectorDiscovered(ctx, "tenant_a", "jira.internal.example.com", 0, "web", "conn-2", "tokyo-dc", "", []string{"evidence-b"}, now.Add(time.Minute))
	if err != nil {
		t.Fatalf("observe again: %v", err)
	}
	if again.CandidateID != first.CandidateID {
		t.Fatalf("dedup failed: %q != %q", again.CandidateID, first.CandidateID)
	}
	if again.Status != "rejected" {
		t.Fatalf("status = %q, want rejected preserved (no resurrection)", again.Status)
	}
	if len(again.Evidence) != 2 {
		t.Fatalf("evidence = %#v, want merged a+b", again.Evidence)
	}
	if again.ObservedFromConnectorID != "conn-2" {
		t.Fatalf("observed-from connector not refreshed: %q", again.ObservedFromConnectorID)
	}
}

// TestConnectorDiscoveredNormalizeRequiresDestinationNotAppID covers the normalize branch: a connector-discovered
// candidate is keyed by destination (host), and unlike policy_learning candidates it does NOT require an
// application_id (that is minted at approve time).
func TestConnectorDiscoveredNormalizeRequiresDestinationNotAppID(t *testing.T) {
	now := time.Now().UTC()
	// No application_id, just a destination -> valid.
	if _, err := normalize(Candidate{CandidateID: "connector-disc-x", Source: SourceConnectorDiscovered, Host: "jira.internal.example.com"}, "tenant_a", now); err != nil {
		t.Fatalf("connector-discovered with destination and no app id should normalize: %v", err)
	}
	// No destination -> rejected (fail-closed).
	if _, err := normalize(Candidate{CandidateID: "connector-disc-y", Source: SourceConnectorDiscovered}, "tenant_a", now); err == nil {
		t.Fatalf("connector-discovered without a destination must be rejected")
	}
	// Invalid publish_protocol -> rejected.
	if _, err := normalize(Candidate{CandidateID: "connector-disc-z", Source: SourceConnectorDiscovered, Host: "x.example.com", PublishProtocol: "bogus"}, "tenant_a", now); err == nil {
		t.Fatalf("invalid publish_protocol must be rejected")
	}
}

// TestObserveConnectorDiscoveredTenantScoped covers tenant isolation: a candidate is only visible under the
// tenant that observed it.
func TestObserveConnectorDiscoveredTenantScoped(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	store := NewStore()
	a, err := store.ObserveConnectorDiscovered(ctx, "tenant_a", "jira.internal.example.com", 0, "web", "conn-1", "tokyo-dc", "", nil, now)
	if err != nil {
		t.Fatalf("observe: %v", err)
	}
	if _, ok, _ := store.Get(ctx, "tenant_b", a.CandidateID); ok {
		t.Fatalf("candidate leaked into tenant_b")
	}
	if _, ok, _ := store.Get(ctx, "tenant_a", a.CandidateID); !ok {
		t.Fatalf("candidate missing under owning tenant")
	}
}
