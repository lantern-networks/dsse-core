package policy

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/lantern-networks/dsse-core/model"
)

// SetPolicyStatus enable/disables a built-in (seeded) policy at runtime and the override survives a restart
// even though the policy re-seeds from config — the durable half of "every rule/policy has an active/disabled
// toggle" (the unified policy model).
func TestSetPolicyStatusPersistsAcrossReload(t *testing.T) {
	seed := []model.Policy{{ID: "pol_builtin_1", TenantID: "t1", Status: "active", Priority: 100,
		Conditions: map[string]any{"sni": "x.example.com"}, Action: model.PolicyAction{Decision: "allow"}}}
	path := filepath.Join(t.TempDir(), "admin_runtime_state.json")

	s1 := NewStore(seed)
	s1.SetRuntimeStatePath(path)
	if !s1.SetPolicyStatus("t1", "pol_builtin_1", "disabled") {
		t.Fatalf("SetPolicyStatus should succeed for an existing policy")
	}
	if p, ok, _ := s1.Get(context.Background(), "t1", "pol_builtin_1"); !ok || p.Status != "disabled" {
		t.Fatalf("policy status not disabled after toggle: %+v", p)
	}
	if s1.SetPolicyStatus("t1", "nope", "disabled") {
		t.Fatalf("SetPolicyStatus should fail for an absent policy")
	}

	// Fresh store re-seeds (active) then loads the override -> the disable survives the restart.
	s2 := NewStore(seed)
	s2.SetRuntimeStatePath(path)
	if p2, ok, _ := s2.Get(context.Background(), "t1", "pol_builtin_1"); !ok || p2.Status != "disabled" {
		t.Fatalf("disable did not survive restart: %+v", p2)
	}

	// Re-enable + reload -> active.
	s2.SetPolicyStatus("t1", "pol_builtin_1", "active")
	s3 := NewStore(seed)
	s3.SetRuntimeStatePath(path)
	if p3, _, _ := s3.Get(context.Background(), "t1", "pol_builtin_1"); p3.Status != "active" {
		t.Fatalf("re-enable did not survive restart: %+v", p3)
	}
}
