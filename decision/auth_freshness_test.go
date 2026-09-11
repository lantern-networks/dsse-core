package decision

import (
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/model"
)

// TestAuthenticationMaxAgeRequiresReauth verifies : a policy with authentication_max_age_seconds
// allows a fresh authentication but forces require_reauthentication when it is stale or unknown.
func TestAuthenticationMaxAgeRequiresReauth(t *testing.T) {
	policy := model.Policy{
		ID: "pol_fresh", TenantID: "t", Status: "active", Priority: 10,
		Conditions: map[string]any{"actor_type": "human", "service_family": "https"},
		Action:     model.PolicyAction{Decision: "allow"},
		Metadata:   map[string]any{"authentication_max_age_seconds": 1800},
	}
	ev := Evaluator{Policies: []model.Policy{policy}, PolicyBundle: model.PolicyBundle{TenantID: "t"}}
	base := model.DecisionRequest{TenantID: "t", ActorType: "human", ServiceFamily: "https", Destination: "app", DestinationPort: 443}

	// Fresh (authenticated 5 min ago) -> allow.
	fresh := base
	fresh.AuthTime = time.Now().Add(-5 * time.Minute).UTC().Format(time.RFC3339)
	if d := ev.Evaluate(fresh); d.Decision != "allow" {
		t.Fatalf("fresh auth should allow, got %q", d.Decision)
	}

	// Stale (authenticated 2h ago, > 30min max) -> require_reauthentication.
	stale := base
	stale.AuthTime = time.Now().Add(-2 * time.Hour).UTC().Format(time.RFC3339)
	if d := ev.Evaluate(stale); d.Decision != "require_reauthentication" {
		t.Fatalf("stale auth should require reauth, got %q", d.Decision)
	}

	// Missing auth_time -> unprovable freshness -> require_reauthentication (fail-closed).
	if d := ev.Evaluate(base); d.Decision != "require_reauthentication" {
		t.Fatalf("missing auth_time should require reauth, got %q", d.Decision)
	}

	// No max-age policy -> normal allow (no gating).
	noMax := policy
	noMax.Metadata = map[string]any{}
	ev2 := Evaluator{Policies: []model.Policy{noMax}, PolicyBundle: model.PolicyBundle{TenantID: "t"}}
	if d := ev2.Evaluate(base); d.Decision != "allow" {
		t.Fatalf("no max-age policy should allow regardless of auth_time, got %q", d.Decision)
	}
}
