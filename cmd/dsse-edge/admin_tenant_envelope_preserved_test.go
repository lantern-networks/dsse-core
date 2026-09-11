package main

import (
	"context"
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
	partial := adminTenantModel{TenantID: "tenant_customer", DisplayName: "Customer", Status: "suspended"}
	named := bodyNamesOperatorEnvelope([]byte(`{"tenant_id":"tenant_customer","display_name":"Customer","status":"suspended"}`))
	if len(named) != 0 {
		t.Fatalf("the body named no envelope field, but the probe found %v", named)
	}
	preserved := preserveOperatorEnvelopeOnUpsert(ctx, store, partial, named)
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

	// ★ AND A BODY THAT DOES NAME THE ENVELOPE IS HONOURED — omission stops meaning erasure, but an explicit
	// value is still an instruction. Without this the fix would make the envelope unwritable through a restore.
	explicit := adminTenantModel{TenantID: "tenant_customer", DisplayName: "Customer", Status: "active"}
	namedExplicit := bodyNamesOperatorEnvelope([]byte(`{"tenant_id":"tenant_customer","operator_managed":false,"operator_elevations":[],"operator_elevation_requires_approval":false,"operator_delegation_changed_at":null,"operator_delegation_changed_by":""}`))
	if len(namedExplicit) != 5 {
		t.Fatalf("the probe missed an explicitly named envelope field: %v", namedExplicit)
	}
	revoked := preserveOperatorEnvelopeOnUpsert(ctx, store, explicit, namedExplicit)
	if revoked.OperatorManaged {
		t.Fatal("an explicit operator_managed:false was overridden by the preservation — the customer can no longer withdraw the delegation")
	}
}
