package main

import (
	"context"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/enrolledinventory"
)

// ★ THE MEASURED DEFECT (2026-08-15). Deleting an organization removed its registry row and nothing else, so
// its administrators went on authenticating — and could not be cleaned up afterwards, because the last-admin
// guard outlived the tenant. Deleting an organization has to take its accounts with it.
func TestDeletingATenantTakesItsAdministratorsWithIt(t *testing.T) {
	credentials := newLocalAdminCredentialStore("Lantern DSSE")
	now := time.Now()
	for _, seed := range []struct{ email, tenant string }{
		{"alice@corp.example", "tenant_gone"},
		{"bob@corp.example", "tenant_gone"},
		{"carol@corp.example", "tenant_stays"},
	} {
		if _, err := credentials.Invite(seed.email, seed.tenant, "adm_"+seed.email, []string{"admin"}, now); err != nil {
			t.Fatalf("seed %s: %v", seed.email, err)
		}
	}

	auth := newAdminAuthStore()
	auth.UpsertSession(adminSession{ID: "sess_gone", TenantID: "tenant_gone", Status: "active"})
	auth.UpsertSession(adminSession{ID: "sess_stays", TenantID: "tenant_stays", Status: "active"})
	auth.UpsertAPIToken(adminAPIToken{ID: "tok_gone", TenantID: "tenant_gone", Status: "active"})

	result := cascadeTenantDeletion(context.Background(), credentials, auth, nil, "tenant_gone", now)

	if got := len(credentials.List("tenant_gone")); got != 0 {
		t.Fatalf("%d administrator(s) survived their organization", got)
	}
	if got := len(credentials.List("tenant_stays")); got != 1 {
		t.Fatalf("the cascade reached another tenant: %d account(s) left in tenant_stays", got)
	}
	if removed, _ := result["administrators"].([]string); len(removed) != 2 {
		t.Fatalf("the result must name who was removed, got %v", result["administrators"])
	}
	if result["sessions_revoked"] != 1 {
		t.Fatalf("sessions_revoked = %v, want 1 — a live session outlasting its tenant is eight more hours of access", result["sessions_revoked"])
	}
	if result["api_tokens_revoked"] != 1 {
		t.Fatalf("api_tokens_revoked = %v, want 1", result["api_tokens_revoked"])
	}
	if session := auth.sessions["sess_stays"]; session.Status != "active" {
		t.Fatal("another tenant's session was revoked")
	}
}

// The enrolled ledger is the admission decision, so it has to lose the tenant's identities too — and only
// that tenant's.
func TestDeletingATenantRemovesItsEnrolledIdentities(t *testing.T) {
	ledger := enrolledinventory.NewLedger()
	now := time.Now().UTC().Format(time.RFC3339)
	if _, err := ledger.Enroll("device-gone-1", "tenant_gone", "", now); err != nil {
		t.Fatalf("enroll: %v", err)
	}
	if _, err := ledger.Enroll("device-gone-2", "tenant_gone", "", now); err != nil {
		t.Fatalf("enroll: %v", err)
	}
	if _, err := ledger.Enroll("device-stays", "tenant_stays", "", now); err != nil {
		t.Fatalf("enroll: %v", err)
	}

	result := cascadeTenantDeletion(context.Background(), nil, newAdminAuthStore(), ledger, "tenant_gone", time.Now())

	if result["enrolled_identities"] != 2 {
		t.Fatalf("enrolled_identities = %v, want 2", result["enrolled_identities"])
	}
	if ledger.IsAdmitted("device-gone-1") || ledger.IsAdmitted("device-gone-2") {
		t.Fatal("a deleted tenant's device is still admitted")
	}
	if !ledger.IsAdmitted("device-stays") {
		t.Fatal("the cascade removed another tenant's device")
	}
}

// Removing a tenant's identities must advance the ledger's config generation, or the removal never leaves this
// node — the same defect the tenant registry had, one store along.
func TestRemovingATenantAdvancesTheLedgerGeneration(t *testing.T) {
	ledger := enrolledinventory.NewLedger()
	now := time.Now().UTC().Format(time.RFC3339)
	if _, err := ledger.Enroll("device-1", "tenant_gone", "", now); err != nil {
		t.Fatalf("enroll: %v", err)
	}
	before := ledger.ConfigGeneration()
	if removed := ledger.RemoveTenant("tenant_gone"); len(removed) != 1 {
		t.Fatalf("RemoveTenant = %v, want one identity", removed)
	}
	if after := ledger.ConfigGeneration(); after <= before {
		t.Fatalf("the generation did not advance (%d -> %d); no Edge would re-pull the removal", before, after)
	}
	// A tenant with nothing in the ledger is a no-op, not a generation bump: a counter that moves when nothing
	// changed makes every Edge re-apply on every poll.
	settled := ledger.ConfigGeneration()
	if removed := ledger.RemoveTenant("tenant_never_existed"); removed != nil {
		t.Fatalf("removing an absent tenant reported %v", removed)
	}
	if now := ledger.ConfigGeneration(); now != settled {
		t.Fatalf("an empty removal advanced the generation (%d -> %d)", settled, now)
	}
}
