package main

import (
	"testing"

	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/model"
)

// TestSteerHttpsAllowPolicyScopedToSteerPlane verifies the committed steer-plane allow policy:
// it allows the generic /steer https flow (steering_mode="steer") but does NOT over-match the macOS NE
// path (steering_mode="network_extension"), which keeps its own internet_default_allow scoping.
func TestSteerHttpsAllowPolicyScopedToSteerPlane(t *testing.T) {
	steerAllow := model.Policy{
		ID:       "pol_steer_https_allow_001",
		TenantID: "t",
		Status:   "active",
		Priority: 8950,
		Conditions: map[string]any{
			"actor_type":       "human",
			"service_family":   "https",
			"destination_port": 443,
			"steering_mode":    "steer",
		},
		Action: model.PolicyAction{Decision: "allow"},
	}
	ev := decision.Evaluator{
		Policies:     []model.Policy{steerAllow},
		PolicyBundle: model.PolicyBundle{TenantID: "t"},
	}

	// Generic steered https flow -> allowed by the steer-plane policy.
	steer := steerDecisionRequest("t", "www.example.com", 443)
	if d := ev.Evaluate(steer); d.Decision != "allow" {
		t.Fatalf("steered https flow should be allowed, got %q", d.Decision)
	}

	// macOS NE flow (network_extension) must NOT be allowed by the steer-scoped policy (no over-match).
	ne := steerDecisionRequest("t", "www.example.com", 443)
	ne.SteeringMode = "network_extension"
	if d := ev.Evaluate(ne); d.Decision == "allow" {
		t.Fatalf("network_extension flow must not match the steer-scoped allow (over-match), got allow")
	}

	// Non-https steered flow (e.g. ssh 22) must NOT be allowed by the https-scoped policy.
	ssh := steerDecisionRequest("t", "10.0.0.5", 22)
	if d := ev.Evaluate(ssh); d.Decision == "allow" {
		t.Fatalf("non-https steered flow must not match the https allow, got allow")
	}
}
