package main

import (
	"strings"
	"testing"
)

// ★★★ A RESTART GAVE THE OPERATOR BACK A DELEGATION THE CUSTOMER HAD WITHDRAWN (2026-08-20, measured).
//
// Northwind withdrew its delegation through the API. The row read false. The control plane was restarted. The
// row read true again — no act, no actor, no audit entry, the operator simply had it back. Measured within the
// hour of the operator deciding that an MSSP operator may not reopen what the customer closed: the API door was
// shut and this one was still open.
//
// The boot-time merge fills fields the shared store cannot distinguish from "never set", and for the standing
// delegation that premise holds only until the organization writes it. A false that arrived through a decision
// is not an absence.
func TestABootImportDoesNotUndoACustomersWithdrawal(t *testing.T) {
	changed := "2026-08-20T03:20:00Z"

	// The row as the organization left it: withdrawn, and stamped with when it moved.
	withdrawn := adminTenantModel{TenantID: "tenant_northwind", OperatorManaged: false,
		OperatorDelegationChangedAt: &changed, OperatorDelegationWithdrawnByCustomer: true}
	// The file the control plane imports from still remembers the delegation as granted.
	carried := adminTenantModel{TenantID: "tenant_northwind", OperatorManaged: true}

	merged, filled := mergeEmptyTenantFields(withdrawn, carried)
	if merged.OperatorManaged {
		t.Fatalf("a restart re-granted the delegation the organization withdrew (filled: %s)",
			strings.Join(filled, ","))
	}
	if !merged.OperatorDelegationWithdrawnByCustomer {
		t.Fatal("the fact the reopen rule rests on did not survive the merge")
	}

	// ★ AND THE CASE THE MERGE EXISTS FOR STILL WORKS: a row nobody has written yet takes the file's answer,
	// which is how a file→Postgres migration keeps a delegation that was granted before the switch.
	fresh := adminTenantModel{TenantID: "tenant_acme"}
	if merged, _ := mergeEmptyTenantFields(fresh, adminTenantModel{TenantID: "tenant_acme", OperatorManaged: true}); !merged.OperatorManaged {
		t.Fatal("an untouched row no longer takes the delegation the file records, so migrating to the shared " +
			"store silently ends every delegation")
	}

	// A withdrawal recorded ONLY in the file survives too, or the operator could grant it again on the far side
	// of the switch.
	if merged, _ := mergeEmptyTenantFields(adminTenantModel{TenantID: "tenant_acme"},
		adminTenantModel{TenantID: "tenant_acme", OperatorDelegationWithdrawnByCustomer: true}); !merged.OperatorDelegationWithdrawnByCustomer {
		t.Fatal("a withdrawal recorded before the switch to the shared store is lost by it")
	}
}
