package main

import (
	"log"
	"strings"

	"github.com/lantern-networks/dsse-core/enrolledinventory"
)

// scopeDeviceRuntimeToTenant keeps only the devices that belong to one tenant, and reports what it dropped.
//
// ★ A CUSTOMER COULD SEE ANOTHER CUSTOMER'S DEVICES (2026-08-15). GET /admin/device-runtime returned the
// node's whole presence map — every device steering through this Edge, with its operating system, logged-in
// users and posture — to any admin holding admin.enrollment.read, with NO tenant filter of any kind.
//
// What is measured and what is not, because the difference matters. The route had no filter: that is read off
// the code, not inferred, and it is why the sibling route /admin/device-certificates was found handing one
// tenant's admin another tenant's device identity on the reference lab (live, before and after). Presence rows
// for a second tenant's device have NOT been observed, because presence is written only on the (T) mux CONNECT
// path and no tenant_northwind device has completed one on this lab yet — it is admitted at the handshake and
// nothing more. So: the hole is certain, the sibling's disclosure is measured, and this route's rows are
// covered by tests rather than by a live sighting. Saying "measured" of all three would be the kind of claim
// this tree keeps finding in its own comments.
//
// It stayed invisible for the reason this whole review exists: with one tenant on the lab, an unscoped read
// and a correctly scoped one return exactly the same thing.
//
// The presence record carries no tenant of its own, so the owner comes from the ENROLLED LEDGER — the same
// place admission gets it, rather than a second answer to "whose device is this". A device the ledger cannot
// place is EXCLUDED (it cannot be shown to a tenant that may not own it) and counted, because a screen that
// quietly drops rows teaches an operator that the fleet is smaller than it is.
func scopeDeviceRuntimeToTenant(devices map[string]deviceRuntimeView, ledger *enrolledinventory.Ledger, tenantID string) (map[string]deviceRuntimeView, int) {
	if strings.TrimSpace(tenantID) == "" {
		// An UNSCOPED CALLER — a deployment with no tenant model at all, where adminTenantIDFromRequest cannot
		// resolve one. Withholding here would blank the fleet view of the only admin who owns it, which is the
		// rule deviceGroupVisibleToTenant already settled for the enrolled-device screens (2026-08-12): an empty
		// CALLER tenant is a deployment fact, an empty OBJECT tenant is "belongs to nobody". Answering that
		// question differently on this screen than on the one next door is how a boundary ends up with one
		// answer per screen instead of one answer.
		return devices, 0
	}
	if ledger == nil {
		// A scoped caller and no ledger to scope with: nothing can be attributed, so show nothing and say so.
		return map[string]deviceRuntimeView{}, len(devices)
	}
	out := make(map[string]deviceRuntimeView, len(devices))
	unplaceable := 0
	for id, view := range devices {
		belongs, placeable := identityBelongsToTenant(ledger, id, tenantID)
		if !placeable {
			unplaceable++
			continue
		}
		if !belongs {
			continue // another tenant's device: not this caller's to see
		}
		out[id] = view
	}
	if unplaceable > 0 {
		log.Printf("device-runtime: %d device(s) present on this node are not in the enrolled ledger, so they "+
			"cannot be attributed to a tenant and are not shown to %q", unplaceable, tenantID)
	}
	return out, unplaceable
}

// identityBelongsToTenant answers whether the enrolled ledger places this identity in this tenant, and
// whether it could place it at all. Shared by every read that shows per-device data, so "whose device is
// this" has ONE answer — the admission authority's — rather than one per screen.
//
// The comparison itself is deviceGroupVisibleToTenant's, deliberately: that is where this tree already
// decided what an empty tenant means on each side, and a second copy of the rule is a second rule the day
// somebody changes one of them.
//
// A device the ledger does not know, OR knows with no tenant of its own, is NOT PLACEABLE. Both are the same
// fact to a caller — nobody can say whose it is — and "belongs to nobody" must not be shown to a tenant that
// may not own it. Not placeable is counted rather than dropped, because an unassigned fleet should be a
// number an operator can act on.
func identityBelongsToTenant(ledger *enrolledinventory.Ledger, identity, tenantID string) (belongs bool, placeable bool) {
	if strings.TrimSpace(tenantID) == "" {
		// Unscoped caller — see scopeDeviceRuntimeToTenant. Everything is theirs, and nothing is withheld.
		return true, true
	}
	if ledger == nil {
		return false, false
	}
	entry, ok := ledger.EntryFor(identity)
	if !ok || strings.TrimSpace(entry.TenantID) == "" {
		return false, false
	}
	return deviceGroupVisibleToTenant(entry.TenantID, tenantID), true
}
