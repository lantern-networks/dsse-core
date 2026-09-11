package tenantca

import (
	"bytes"
	"fmt"
	"path/filepath"
	"testing"
)

func TestMaterialOwnershipCommitsWithAnchorsAndSurvivesRestart(t *testing.T) {
	_, old := selfSignedCAForTest(t, "old")
	_, next := selfSignedCAForTest(t, "next")
	_, byo := selfSignedCAForTest(t, "byo")
	r := NewTenantCARegistry()
	if _, err := r.Register("byo", byo); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "registry.json")
	persist := func(c *TenantCARegistry) error { return c.Save(path) }
	if err := r.ReplaceManagedTenantPersisted("managed", old, persist); err != nil {
		t.Fatal(err)
	}
	before, _ := r.Snapshot()
	if err := r.ReplaceManagedTenantPersisted("managed", next, func(*TenantCARegistry) error { return fmt.Errorf("disk failure") }); err == nil {
		t.Fatal("failed persistence accepted")
	}
	after, _ := r.Snapshot()
	if !bytes.Equal(before, after) {
		t.Fatal("failed install changed live attribution or ownership")
	}
	if err := r.ReplaceManagedTenantPersisted("new", next, func(*TenantCARegistry) error { return fmt.Errorf("disk failure") }); err == nil || r.MaterialManaged("new") {
		t.Fatal("failed initial install claimed ownership")
	}
	restarted, err := LoadTenantCARegistry(path)
	if err != nil {
		t.Fatal(err)
	}
	if !restarted.MaterialManaged("MANAGED") || restarted.MaterialManaged("byo") {
		t.Fatal("restart lost material/BYO distinction")
	}
	// A remote snapshot cannot clear local ownership, nor assert ownership of BYO.
	if _, err := restarted.Adopt([]byte(`{"tenants":[],"material_managed_tenants":["byo"]}`)); err != nil {
		t.Fatal(err)
	}
	if !restarted.MaterialManaged("managed") || restarted.MaterialManaged("byo") {
		t.Fatal("remote snapshot authored local ownership")
	}
	if err := restarted.ReplaceTenantPersisted("managed", next, persist); err != nil {
		t.Fatal(err)
	}
	again, err := LoadTenantCARegistry(path)
	if err != nil || !again.MaterialManaged("managed") {
		t.Fatalf("ordinary replacement erased ownership: %v", err)
	}
	again.Withdraw("managed")
	if err := again.Save(path); err != nil {
		t.Fatal(err)
	}
	gone, err := LoadTenantCARegistry(path)
	if err != nil || gone.MaterialManaged("managed") {
		t.Fatalf("tenant erasure left ownership: %v", err)
	}
}
