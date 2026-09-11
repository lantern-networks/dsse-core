package main

// Whose break-glass is it?
//
// ★★★ A CREDENTIAL FROM ONE ORGANIZATION MINTED AN ACTIVE SESSION IN ANOTHER (2026-08-16, measured on the
// lab). POST /break-glass/sessions on the device-facing listener, presenting an API token belonging to
// tenant_operator_001 — a principal with no cross-tenant permission — returned HTTP 201 with a live session in
// tenant_reference_lab, as a user_id the caller supplied itself:
//
//     {"id":"sess_bg_…","tenant_id":"tenant_reference_lab","user_id":"probe@lab.local","status":"active"}
//
// Every route in this surface took its organization from evaluator.PolicyBundle.TenantID — the NODE's — rather
// than from the caller, and the by-id routes resolved a request without asking whose it was.
// admin.break_glass.write is held by the ordinary tenant `admin` role, so on a multi-tenant node this was a
// cross-organization authentication bypass reachable by any customer administrator.
//
// The check the builder needed already existed: breakGlassAuthenticationEvent and Create both take an
// expectedTenantID and refuse a mismatch. They were simply being handed the wrong expectation.

import (
	"net/http"
	"strings"
)

// breakGlassCallerTenant is the organization a break-glass request acts within.
//
// The caller's own organization wins. The node's is used ONLY when the caller has none — a single-tenant
// deployment with no tenant model, where every identity is unscoped and the node's tenant is the only one
// there is. That keeps single-tenant behaviour exactly as it was while closing the multi-tenant hole.
func breakGlassCallerTenant(r *http.Request, nodeTenant string) string {
	if t := strings.TrimSpace(adminTenantIDFromRequest(r)); t != "" {
		return t
	}
	return strings.TrimSpace(nodeTenant)
}

// breakGlassRequestVisibleTo reports whether this caller may act on a stored request. An operator may act
// across the deployment; anyone else may act only on their own organization's.
func breakGlassRequestVisibleTo(item breakGlassAccessRequest, r *http.Request, nodeTenant string) bool {
	if adminCallerIsOperator(r) {
		return true
	}
	owner := strings.TrimSpace(item.TenantID)
	if owner == "" {
		return true // unattributed: a single-tenant deployment's own
	}
	return strings.EqualFold(owner, breakGlassCallerTenant(r, nodeTenant))
}

// breakGlassEventsForCaller narrows the export to the caller's own organization. The export is the record of
// who used emergency access; another organization's belongs to that organization.
func breakGlassEventsForCaller(events []map[string]any, r *http.Request, nodeTenant string) []map[string]any {
	if adminCallerIsOperator(r) {
		return events
	}
	caller := breakGlassCallerTenant(r, nodeTenant)
	out := make([]map[string]any, 0, len(events))
	for _, e := range events {
		owner := strings.TrimSpace(stringValue(e["tenant_id"]))
		if owner != "" && !strings.EqualFold(owner, caller) {
			continue
		}
		out = append(out, e)
	}
	return out
}
