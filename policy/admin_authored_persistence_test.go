package policy

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/model"
)

// TestUpsertAdminPolicySurvivesRestart is the regression for the T0 defect: POST /admin/policies -> Upsert added a
// policy to the in-memory set only, so it vanished on the next restart (the bundle re-seed covers only committed
// policies). Upsert must now persist admin-authored policies and restore them as a bundle overlay on boot.
func TestUpsertAdminPolicySurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "admin_runtime_state.json")
	now := time.Now()
	bundle := []model.Policy{{ID: "pol_bundle", TenantID: "t1", Name: "bundle", Status: "active", Priority: 100,
		Conditions: map[string]any{"actor_type": "user"}, Action: model.PolicyAction{Decision: "allow"}}}

	// Store 1: seeded from the bundle; an admin authors a NEW policy not in the bundle.
	s1 := NewStore(bundle)
	s1.SetRuntimeStatePath(path)
	if _, err := s1.Upsert(context.Background(),
		model.Policy{ID: "pol_admin_1", TenantID: "t1", Name: "authored", Status: "active", Priority: 200,
			Conditions: map[string]any{"actor_type": "user"},
			Action:     model.PolicyAction{Decision: "allow"}}, "t1", now); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	// Store 2 = a restart: re-seeded from the bundle ONLY (no admin policy), then loads the durable state.
	s2 := NewStore(bundle)
	s2.SetRuntimeStatePath(path)

	if _, ok, _ := s2.Get(context.Background(), "t1", "pol_admin_1"); !ok {
		t.Fatal("admin-authored policy did not survive the restart (Upsert must persist it)")
	}
	if _, ok, _ := s2.Get(context.Background(), "t1", "pol_bundle"); !ok {
		t.Fatal("bundle-seeded policy missing after restart")
	}

	// A disable persisted via the status override still applies to the restored admin policy.
	s1.SetPolicyStatus("t1", "pol_admin_1", "disabled")
	s3 := NewStore(bundle)
	s3.SetRuntimeStatePath(path)
	if p, ok, _ := s3.Get(context.Background(), "t1", "pol_admin_1"); !ok || p.Status != "disabled" {
		t.Fatalf("persisted disable did not apply to the restored admin policy: ok=%v status=%q", ok, p.Status)
	}
}
