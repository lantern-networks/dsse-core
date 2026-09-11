package main

import (
	"testing"
)

// ★★ A CONTROL THE OTHER PARTY CAN UNDO INVISIBLY IS A CONTROL IN NAME (2026-08-17, measured on the lab).
//
// Either side may write the standing delegation. The operator sets it at onboarding — necessary, because a
// brand-new organization has no administrator to grant it — and the organization can withdraw it, since "a
// delegation only the holder can end is not a delegation". The consequence nobody had written down: the
// operator can set it BACK, and measured live they can, in one call, for an organization that had not
// delegated.
//
// That is fine as long as the organization can SEE it. Its own "Operator access" screen listed elevations
// only, so a re-grant left no trace where the customer looks. The delegation now records when it last moved
// and who moved it.
//
// The stamp is only written on a real change: re-saving the same value must not make an untouched delegation
// look freshly re-granted, which would be the same defect pointing the other way.
func TestTheDelegationRecordsWhenItMovedAndWho(t *testing.T) {
	tenant := adminTenantModel{TenantID: "tenant_customer"}

	// Granted by the operator at onboarding.
	changed := applyDelegationChange(&tenant, true, "adm_operator", "2026-08-17T00:00:00Z")
	if !changed {
		t.Fatal("turning the delegation on is a change")
	}
	if tenant.OperatorDelegationChangedAt == nil || *tenant.OperatorDelegationChangedAt != "2026-08-17T00:00:00Z" {
		t.Fatalf("the change was not stamped: %v", tenant.OperatorDelegationChangedAt)
	}
	if tenant.OperatorDelegationChangedBy == nil || *tenant.OperatorDelegationChangedBy != "adm_operator" {
		t.Fatalf("the actor was not recorded: %v", tenant.OperatorDelegationChangedBy)
	}

	// Re-saving the same value is not a change and must not move the stamp — otherwise an untouched
	// delegation reads as freshly re-granted every time anything writes the record.
	if applyDelegationChange(&tenant, true, "adm_operator", "2026-08-17T09:99:99Z") {
		t.Fatal("saving the same value is not a change")
	}
	if *tenant.OperatorDelegationChangedAt != "2026-08-17T00:00:00Z" {
		t.Fatalf("the stamp moved without a change: %v", *tenant.OperatorDelegationChangedAt)
	}

	// The customer withdraws it, then the operator sets it back: both are recorded, and the second one is
	// what the screen shows.
	applyDelegationChange(&tenant, false, "adm_customer", "2026-08-17T10:00:00Z")
	if *tenant.OperatorDelegationChangedBy != "adm_customer" {
		t.Fatalf("the withdrawal must name the customer, got %v", *tenant.OperatorDelegationChangedBy)
	}
	applyDelegationChange(&tenant, true, "adm_operator", "2026-08-17T10:02:00Z")
	if !tenant.OperatorManaged {
		t.Fatal("the re-grant did not take effect")
	}
	if *tenant.OperatorDelegationChangedAt != "2026-08-17T10:02:00Z" || *tenant.OperatorDelegationChangedBy != "adm_operator" {
		t.Fatalf("a re-grant two minutes after a withdrawal must be visible as such, got %v by %v",
			*tenant.OperatorDelegationChangedAt, *tenant.OperatorDelegationChangedBy)
	}
}
