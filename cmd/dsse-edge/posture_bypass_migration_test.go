package main

import (
	"testing"

	"github.com/lantern-networks/dsse-core/inspectionposture"
	"github.com/lantern-networks/dsse-core/policyrule"
)

// TestMigratePostureOptimizeBypassToRules verifies the one-time legacy migration: an enabled posture.bypass_groups
// selection becomes an authored Egress bypass rule (Any -> bi-grp-<name> => allow x bypass), the selection is
// cleared (so the engine reads ONE source), and re-running is a no-op.
func TestMigratePostureOptimizeBypassToRules(t *testing.T) {
	store := inspectionposture.NewStore()
	p := store.Get()
	p.BypassGroups = []string{"m365_optimize"}
	store.Set(p)
	rules := policyrule.NewStore()

	if n := migratePostureOptimizeBypassToRules(store, rules, "tenant_a"); n != 1 {
		t.Fatalf("emitted = %d, want 1", n)
	}

	// The emitted rule is the Console's exact optimize-bypass shape (so the UI's two-way toggle recognizes it).
	egress := rules.List("tenant_a", policyrule.PlaneEgress)
	if len(egress) != 1 {
		t.Fatalf("egress rules = %d, want 1", len(egress))
	}
	r := egress[0]
	if r.Action.Inspection != policyrule.InspectionBypass || r.Action.Access != policyrule.AccessAllow {
		t.Fatalf("action = %+v, want allow x bypass", r.Action)
	}
	if len(r.Destination) != 1 || r.Destination[0] != "bi-grp-m365_optimize" {
		t.Fatalf("destination = %v, want [bi-grp-m365_optimize]", r.Destination)
	}
	if r.Status != policyrule.StatusActive {
		t.Fatalf("status = %q, want active", r.Status)
	}

	// The legacy selection is cleared — the rule is now the single source.
	if got := store.Get().BypassGroups; len(got) != 0 {
		t.Fatalf("bypass_groups after migrate = %v, want empty", got)
	}

	// Idempotent: re-running emits nothing (selection cleared) and does not duplicate the rule.
	if n := migratePostureOptimizeBypassToRules(store, rules, "tenant_a"); n != 0 {
		t.Fatalf("second run emitted = %d, want 0", n)
	}
	if got := len(rules.List("tenant_a", policyrule.PlaneEgress)); got != 1 {
		t.Fatalf("egress rules after re-run = %d, want 1 (no duplicate)", got)
	}
}

// TestMigratePostureOptimizeBypassSkipsExistingRule verifies that when a bypass rule already targets the group's
// bi-grp destination (e.g. the Console authored it), the migration does NOT add a second rule.
func TestMigratePostureOptimizeBypassSkipsExistingRule(t *testing.T) {
	store := inspectionposture.NewStore()
	p := store.Get()
	p.BypassGroups = []string{"google_optimize"}
	store.Set(p)
	rules := policyrule.NewStore()
	if _, err := rules.Upsert(policyrule.Rule{
		ID: "existing", TenantID: "tenant_a", Plane: policyrule.PlaneEgress, Priority: 60,
		Source: []string{policyrule.SubjectAny}, Destination: []string{"bi-grp-google_optimize"},
		Action: policyrule.Action{Access: policyrule.AccessAllow, Inspection: policyrule.InspectionBypass},
		Status: policyrule.StatusActive,
	}); err != nil {
		t.Fatalf("seed rule: %v", err)
	}

	if n := migratePostureOptimizeBypassToRules(store, rules, "tenant_a"); n != 0 {
		t.Fatalf("emitted = %d, want 0 (rule already exists)", n)
	}
	if got := len(rules.List("tenant_a", policyrule.PlaneEgress)); got != 1 {
		t.Fatalf("egress rules = %d, want 1 (no duplicate)", got)
	}
}

// TestMigratePostureOptimizeBypassDefaultIsNoOp verifies the North Star path: a default posture (no Optimize
// group enabled) migrates nothing, so removing the legacy EffectiveBypassGroupHosts read changes nothing.
func TestMigratePostureOptimizeBypassDefaultIsNoOp(t *testing.T) {
	store := inspectionposture.NewStore() // DefaultPosture: decrypt_all, empty bypass_groups
	rules := policyrule.NewStore()
	if n := migratePostureOptimizeBypassToRules(store, rules, "tenant_a"); n != 0 {
		t.Fatalf("emitted = %d, want 0 for default posture", n)
	}
	if got := len(rules.List("tenant_a", policyrule.PlaneEgress)); got != 0 {
		t.Fatalf("egress rules = %d, want 0", got)
	}
}
