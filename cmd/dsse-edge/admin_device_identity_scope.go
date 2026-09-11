package main

// A device identity is one organization's, and these screens listed everybody's.
//
// ★★★ MY OWN SWEEP MISSED THIS, AND LOOKING AT A SCREEN CAUGHT IT (2026-08-17). The route sweep scanned every
// response for another organization's TENANT ID; these carry device NAMES, which match no such pattern. It
// surfaced by opening a newly created organization's certificate screen and reading it: a red line saying
// "currently refusing this certificate: win-dev-1" — another organization's machine — and a trust list reading
// "held by: mac-dev-1, win-dev-1".
//
// Measured signed in as Northwind's administrator, a customer with one device of their own:
//
//   GET /admin/pki/trust-refusals        -> mac-dev-1, win-dev-1
//   GET /admin/pki/certificates          -> mac-dev-1, win-dev-1, conn-lab-1 (the trusted-by / not-reporting
//                                           lists carried on deployment-level material)
//   GET /admin/transport-trust-anchors   -> conn-lab-1, mac-dev-1, win-dev-1
//
// The material these lists hang off IS everybody's — the transport anchor, the interception root — and that is
// why it is shown. Who holds it is not: those are another organization's machines, by name.
//
// The count of what was withheld travels with the answer wherever there is somewhere to put it, because a
// coverage figure computed over a list the reader cannot see is a figure about other people.

import (
	"net/http"
	"strings"

	"github.com/lantern-networks/dsse-core/enrolledinventory"
)

// deviceIdentitiesForCaller keeps the identities that belong to the organization this answer is about.
//
// An identity the ledger cannot place is dropped for a scoped caller and counted: "not attributable" is not
// the same as "yours", and the second is the assumption that leaks. An unscoped caller — a deployment with no
// tenant model — keeps everything, the same rule scopeDeviceRuntimeToTenant settled for the fleet view.
func deviceIdentitiesForCaller(ids []string, ledger *enrolledinventory.Ledger, r *http.Request) (kept []string, withheld int) {
	tenant, wholeDeployment := adminAnswerScope(r)
	if wholeDeployment || strings.TrimSpace(tenant) == "" {
		return ids, 0
	}
	if ledger == nil {
		// Scoped caller, nothing to scope with: show none rather than all, and say how many were held back.
		return nil, len(ids)
	}
	kept = make([]string, 0, len(ids))
	for _, id := range ids {
		belongs, placeable := identityBelongsToTenant(ledger, id, tenant)
		if !placeable || !belongs {
			withheld++
			continue
		}
		kept = append(kept, id)
	}
	return kept, withheld
}
