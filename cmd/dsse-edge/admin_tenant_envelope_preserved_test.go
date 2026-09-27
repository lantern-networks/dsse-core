package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/model"
)

// ★★★ AN UNRELATED EDIT REVOKED THE DELEGATION (2026-08-18, done by accident on the reference deployment and
// measured immediately afterwards).
//
// POST /admin/tenants is a whole-record upsert. Sending {tenant_id, display_name, status} to put an
// organization back to active wiped its timezone, plan, home region and allowed regions — and, far worse, its
// operator_managed flag and all SIXTEEN recorded elevations. That is the standing delegation and the customer's
// own record of when the operator used it (the envelope design), gone as collateral damage of a status change.
//
// Those fields have their own routes. They are carried on this model only so a read/modify/write round-trip
// does not lose them, so omission must stop meaning erasure — the same treatment CreatedAt already gets.
func TestAnUpsertThatOmitsTheEnvelopeDoesNotRevokeIt(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	store := newOperatorAwareAdminTenantModelStore(model.PolicyBundle{TenantID: "tenant_lab"}, now, "", "")
	full := adminTenantModel{
		TenantID: "tenant_customer", DisplayName: "Customer", Status: "active",
		Timezone: "Asia/Tokyo", Plan: "standard",
		OperatorManaged:                   true,
		OperatorElevationRequiresApproval: true,
		OperatorElevations:                []operatorElevation{{ID: "elev_1"}, {ID: "elev_2"}},
	}
	if _, err := store.Put(ctx, full, now); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// The body that caused it: three fields, and nothing about the envelope.
	preserved, err := mergeTenantSettingsEdit(ctx, store, "tenant_customer", []byte(`{"tenant_id":"tenant_customer","display_name":"Customer","status":"suspended"}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Put(ctx, preserved, now); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	after, err := store.Get(ctx, "tenant_customer")
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if !after.OperatorManaged {
		t.Fatal("the standing delegation was revoked by an edit that never mentioned it")
	}
	if len(after.OperatorElevations) != 2 {
		t.Fatalf("the customer's record of when the operator acted was erased: %d elevation(s) left", len(after.OperatorElevations))
	}
	if !after.OperatorElevationRequiresApproval {
		t.Fatal("the organization's 'ask me first' requirement was dropped by omission — it fails OPEN, which is the worst direction")
	}
	// The edit itself still lands, or this is a merge that ignores the caller.
	if after.Status != "suspended" {
		t.Fatalf("the status the caller actually sent did not take: %q", after.Status)
	}

	// Explicit authorization changes must use the consent-aware delegation routes.
	_, err = mergeTenantSettingsEdit(ctx, store, "tenant_customer", []byte(`{"operator_managed":false,"operator_elevations":[],"operator_elevation_requires_approval":false,"operator_delegation_changed_at":null,"operator_delegation_changed_by":""}`))
	if !errors.Is(err, errTenantEnvelopeEdit) {
		t.Fatalf("explicit authorization edit: %v", err)
	}
}
