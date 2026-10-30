package tenantca

import "testing"

func TestCaseDistinctTenantsCannotTakeEachOthersCA(t *testing.T) {
	upperCA, upperPEM := selfSignedCAForTest(t, "Acme CA")
	lowerCA, lowerPEM := selfSignedCAForTest(t, "acme CA")
	registry := NewTenantCARegistry()
	if _, err := registry.Register("Acme", upperPEM); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.Register("acme", lowerPEM); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.Register("acme", upperPEM); err == nil {
		t.Fatal("case-distinct tenant took ownership of another tenant's CA")
	}
	registry.BeginTrustWithdrawal("acme", shaOf(upperCA))
	if got := registry.PendingWithdrawals("acme"); len(got) != 0 {
		t.Fatalf("case-distinct tenant began another tenant's CA withdrawal: %v", got)
	}
	if removed, _ := registry.WithdrawAnchor("acme", shaOf(upperCA)); removed {
		t.Fatal("case-distinct tenant withdrew another tenant's CA")
	}
	if removed := registry.Withdraw("acme"); removed != 1 {
		t.Fatalf("lower-case tenant withdrawal removed %d CAs, want only its own", removed)
	}
	if got := resolves(registry, upperCA); got != "Acme" {
		t.Fatalf("upper-case tenant's CA was changed to %q", got)
	}
	if got := resolves(registry, lowerCA); got != "" {
		t.Fatalf("lower-case tenant's CA remains attributed to %q", got)
	}
}

func TestMaterialManagedOwnerPreservesTenantCase(t *testing.T) {
	_, pem := selfSignedCAForTest(t, "Acme managed CA")
	registry := NewTenantCARegistry()
	if err := registry.ReplaceManagedTenantPersisted("Acme", pem, nil); err != nil {
		t.Fatal(err)
	}
	if !registry.MaterialManaged("Acme") || registry.MaterialManaged("acme") {
		t.Fatal("material management merged case-distinct tenant IDs")
	}
	snapshot, err := registry.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	restored, err := RegistryFromSnapshot(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if !restored.MaterialManaged("Acme") || restored.MaterialManaged("acme") {
		t.Fatal("snapshot recovery merged case-distinct material-managed owners")
	}
}
