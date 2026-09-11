package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/lantern-networks/dsse-core/enrolledinventory"
	"github.com/lantern-networks/dsse-core/humanidentity"
)

// a_risk_mark_names_someone_elses_device.go — who may mark an entity high risk.
//
// ★★★ WHY (2026-08-22, measured on the reference control plane with tenant_northwind's own administrator —
// roles ["admin"], no cross-organization permission of any kind).
//
// On 2026-08-18 the risk overlay's READ was scoped, and its own comment says why: "win-dev-1: critical" is a
// statement about another customer's incident, and the note even records that the route was "three files away
// and was missed" by an earlier sweep. The WRITE beside it was missed the same way — and it is the sharper
// half. Measured, on a throwaway device enrolled in the lab organization for the purpose:
//
//	POST /admin/risk-signals  {"entity_type":"device","entity_id":"risk-probe","severity":"critical"}
//	  as tenant_northwind's administrator  ->  200 {"high_risk":true,"applied":true}
//	GET  /admin/risk-signals as the LAB's own administrator -> {"high_risk":{"risk-probe":"critical"}}
//
// What that mark does is written on the handler itself: it "folds into the device's risk state (decisions
// react via risk_state_severity/admin_high_risk) and revokes the device's standing east-west grants", and it
// is "reflected into the shared high-risk overlay so EVERY node's decision path treats the device as
// high-risk (fleet-consistent risk-based deny/re-auth; reconnect-elsewhere blocked)".
//
// So one customer could have another customer's named laptop denied across the whole fleet, and its standing
// grants cut, from an account with no relationship to it. Not a disclosure — a denial of service aimed at one
// machine, with the victim's own console showing the mark as though their own operator had made it.
//
// ★ THE ORGANIZATION WAS ALREADY IN HAND AND DROPPED. applyAdminRiskSignal takes a tenantID parameter and the
// device branch never reads it: it calls ApplyRiskSignal(entityID, …) on the runtime store, keyed by id alone.
// The value was threaded all the way in and then not used, which is why nothing looked wrong at the call site.

// riskEntityOwnedByCaller reports whether the caller's organization owns the entity a risk signal names, and
// why not when it does not. Devices are resolved through the enrolled ledger — the same helper the read and
// the kill-switch beside it use — and people through the organization's own directory.
//
// An entity that cannot be placed at all is NOT the caller's: a mark on something nobody can attribute is one
// nobody can lift, and accepting it is how an id that belongs to no one becomes an id that belongs to whoever
// asked last.
func riskEntityOwnedByCaller(ctx context.Context, entityType, entityID, callerTenant string,
	ledger *enrolledinventory.Ledger, directory humanidentity.HumanIdentityDirectoryRuntimeStore) (bool, string) {
	entityID = strings.TrimSpace(entityID)
	callerTenant = strings.TrimSpace(callerTenant)
	if entityID == "" {
		return false, "no entity was named"
	}
	switch strings.ToLower(strings.TrimSpace(entityType)) {
	case "device", "":
		belongs, placeable := identityBelongsToTenant(ledger, entityID, callerTenant)
		if !placeable {
			return false, fmt.Sprintf("no enrolled device %q that this deployment can attribute to an organization", entityID)
		}
		if !belongs {
			return false, fmt.Sprintf("no enrolled device %q in your organization", entityID)
		}
		return true, ""
	case "user", "human":
		if directory == nil {
			return false, "this node holds no directory, so a person cannot be placed in an organization here; " +
				"mark them where the directory is"
		}
		people, err := directory.List(ctx, callerTenant)
		if err != nil {
			// Refusing on an unreadable directory is the fail-safe direction: the alternative is marking
			// somebody because the lookup broke.
			return false, "the directory could not be read, so this person could not be placed in your organization"
		}
		for _, p := range people {
			if strings.EqualFold(strings.TrimSpace(p.ID), entityID) ||
				strings.EqualFold(strings.TrimSpace(p.Subject), entityID) ||
				(p.Email != nil && strings.EqualFold(strings.TrimSpace(*p.Email), entityID)) {
				return true, ""
			}
		}
		return false, fmt.Sprintf("nobody in your organization's directory is %q", entityID)
	}
	return false, "entity_type must be device or user"
}
