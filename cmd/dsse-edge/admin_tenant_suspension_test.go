package main

import (
	"context"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/model"
)

// ★★ SUSPENDING AN ORGANIZATION DID NOTHING (2026-08-18, measured on the reference deployment).
//
// The tenant model validates status as active|suspended|archived, the Console offers all three in a dropdown,
// and the API reference calls it "the tenant lifecycle". Nothing read it. Measured: an organization was set to
// suspended and its administrator signed in immediately afterwards — the response that served them said
// "status":"suspended" while doing it.
//
// Decided the same day: suspension freezes the ADMINISTRATIVE plane and stops NEW admission. Devices already
// enrolled keep being enforced and the data is kept, because a billing dispute must not become a security
// incident by taking protection off a customer's laptops.
func TestSuspensionRefusesAdministrativeAccessAndKeepsTheData(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	store := newOperatorAwareAdminTenantModelStore(model.PolicyBundle{TenantID: "tenant_lab"}, now, "", "")
	for _, tenant := range []adminTenantModel{
		{TenantID: "tenant_active", DisplayName: "Active", Status: "active"},
		{TenantID: "tenant_suspended", DisplayName: "Suspended", Status: "suspended"},
		{TenantID: "tenant_archived", DisplayName: "Archived", Status: "archived"},
	} {
		if _, err := store.Put(ctx, tenant, now); err != nil {
			t.Fatalf("seed %s: %v", tenant.TenantID, err)
		}
	}

	if _, refuse := adminTenantAdministrativelySuspended(ctx, store, "tenant_suspended"); !refuse {
		t.Fatal("a suspended organization still admits administrative access")
	}
	if _, refuse := adminTenantAdministrativelySuspended(ctx, store, "tenant_archived"); !refuse {
		t.Fatal("an archived organization still admits administrative access — it was equally inert")
	}

	// ★ THE CONTROL: an ACTIVE organization must not be refused, or this is an outage rather than a lifecycle.
	if reason, refuse := adminTenantAdministrativelySuspended(ctx, store, "tenant_active"); refuse {
		t.Fatalf("an active organization was refused: %s", reason)
	}
	// And an organization nobody has heard of is not suspended either: "I don't know" must never invent a
	// refusal an operator did not ask for. The same asymmetry adminTenantIsGone uses.
	if reason, refuse := adminTenantAdministrativelySuspended(ctx, store, "tenant_never_seen"); refuse {
		t.Fatalf("an unknown organization was treated as suspended: %s", reason)
	}
	if reason, refuse := adminTenantAdministrativelySuspended(ctx, nil, "tenant_suspended"); refuse {
		t.Fatalf("a nil registry suspended somebody: %s", reason)
	}

	// ★★ THE DATA IS KEPT, WHICH IS THE HALF THAT MAKES THIS SAFE. Suspension is not erasure: the record is
	// still there to be reactivated, and a test that only checked the refusal would pass just as well for a
	// suspension that deleted the organization.
	kept, err := store.Get(ctx, "tenant_suspended")
	if err != nil {
		t.Fatalf("read the suspended organization: %v", err)
	}
	if kept.DisplayName != "Suspended" || kept.Status != "suspended" {
		t.Fatalf("the suspended organization's record did not survive: %+v", kept)
	}
}
