package policyrule

import (
	"path/filepath"
	"testing"
)

// TestRulesPersistAcrossRestart proves authored rules survive a restart and a deletion is also persisted.
func TestRulesPersistAcrossRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.json")

	s1 := NewStore()
	if err := s1.SetStatePath(path); err != nil {
		t.Fatalf("SetStatePath: %v", err)
	}
	r, err := s1.Upsert(Rule{TenantID: "t1", Plane: PlaneEgress, Status: StatusActive, Source: []string{"ep-mac"}, Destination: []string{"ep-saas"}, Action: Action{Access: AccessAllow, Inspection: InspectionBypass}})
	if err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	keep, err := s1.Upsert(Rule{TenantID: "t1", Plane: PlaneEgress, Status: StatusActive, Source: []string{"ep-mac"}, Destination: []string{"ep-saas"}, Action: Action{Access: AccessDeny}})
	if err != nil {
		t.Fatalf("Upsert keep: %v", err)
	}

	// Restart.
	s2 := NewStore()
	if err := s2.SetStatePath(path); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if _, ok := s2.Get("t1", r.ID); !ok {
		t.Fatal("rule did not survive restart")
	}
	if got := len(s2.List("t1", PlaneEgress)); got != 2 {
		t.Fatalf("expected 2 rules after restart, got %d", got)
	}

	// A delete is persisted too.
	if ok, err := s2.Delete("t1", r.ID); !ok || err != nil {
		t.Fatal("delete returned false")
	}
	s3 := NewStore()
	if err := s3.SetStatePath(path); err != nil {
		t.Fatalf("reload after delete: %v", err)
	}
	if _, ok := s3.Get("t1", r.ID); ok {
		t.Fatal("deleted rule reappeared after restart")
	}
	if _, ok := s3.Get("t1", keep.ID); !ok {
		t.Fatal("kept rule lost after restart")
	}
}
