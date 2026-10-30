package delegatedgrant

import (
	"context"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/model"
)

func TestRemoveTenantPreservesCaseDistinctDelegatedGrants(t *testing.T) {
	store := NewStore(0)
	for _, tenant := range []string{"Acme", "acme"} {
		if _, err := store.Upsert(model.DelegatedAccessGrant{
			ID: "same-id", TenantID: tenant, SubjectUserID: "user", ActorNHIID: "agent",
			Status: "active", ExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
		}); err != nil {
			t.Fatalf("upsert %s: %v", tenant, err)
		}
	}
	if got := store.CountForTenant("Acme"); got != 1 {
		t.Fatalf("Acme count included the distinct tenant acme: %d", got)
	}
	if got := store.CountForTenant("acme"); got != 1 {
		t.Fatalf("acme count included the distinct tenant Acme: %d", got)
	}
	// A denial for an absent record can remain pending after an unconfirmed
	// shared write. Purging Acme must not release acme's pending denial.
	store.pendingRevocations = map[string]pendingRevocation{
		grantKey("Acme", "pending"): {},
		grantKey("acme", "pending"): {},
	}
	removed, err := store.RemoveTenantContext(context.Background(), "Acme")
	if err != nil || removed != 1 {
		t.Fatalf("RemoveTenantContext(Acme) = %d, %v; want 1, nil", removed, err)
	}
	if _, ok, err := store.GetForTenantContext(context.Background(), "acme", "same-id"); err != nil || !ok {
		t.Fatalf("case-distinct tenant's grant was erased: present=%v err=%v", ok, err)
	}
	if _, ok, err := store.GetForTenantContext(context.Background(), "Acme", "same-id"); err != nil || ok {
		t.Fatalf("selected tenant's grant remains: present=%v err=%v", ok, err)
	}
	if _, ok := store.pendingRevocations[grantKey("acme", "pending")]; !ok {
		t.Fatal("case-distinct tenant's pending revocation was erased")
	}
	if _, ok := store.pendingRevocations[grantKey("Acme", "pending")]; ok {
		t.Fatal("selected tenant's pending revocation remains")
	}
}
