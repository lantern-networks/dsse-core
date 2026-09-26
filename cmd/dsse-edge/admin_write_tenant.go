package main

// Which organization does this write land in?
//
// ★★★ THE ANSWER MUST NOT COME FROM THE REQUEST BODY (2026-08-16, measured three times on the lab). The idiom
// `x.TenantID = valueOrDefault(x.TenantID, adminTenantIDFromRequest(r))` reads "use the caller's organization
// unless one was supplied" — and what supplies it is the CALLER, in the body they control. Signed in as
// Northwind's administrator, a principal with no cross-tenant permission:
//
//   - a Named Network filed under tenant_reference_lab: HTTP 200, stored with that organization's id
//   - a STEERING EXCLUSION filed under tenant_reference_lab: HTTP 200, and it appeared in that organization's
//     list beside their real ones. A steering exclusion decides which apps bypass the secure gateway, so a
//     customer could exempt an application for another organization's entire fleet — and could not even see
//     what they had written, because the read path IS scoped and their own list came back empty.
//
// An operator legitimately authors on behalf of an organization; that is what X-Operate-Tenant means, and
// adminTenantIDFromRequest already resolves it. Everybody else writes into their own organization, full stop.

import (
	"fmt"
	"net/http"
	"strings"
)

// adminTenantForWrite is the organization a write belongs to. bodyTenant is whatever the request body asked
// for — an operator must first select the same organization so the middleware
// checks its delegation and elevation. Tenantless/lab compatibility is explicit.
//
// ★★ AND A NAME YOU MAY NOT USE IS REFUSED, NOT QUIETLY SWAPPED (2026-08-17, measured as the first
// administrator of a self-run organization). Returning the caller's own organization is right when the body
// says nothing and wrong when it names somebody else: the act then lands in the caller's own organization and
// is reported as success, with a body that asked for a different one. Measured — a customer posted a device
// group naming tenant_northwind and got HTTP 200 with the group in their OWN organization.
//
// That is the same shape the middleware already refuses for X-Operate-Tenant, and the same one
// /admin/policies already refuses for the body ("does not match authenticated tenant"). Some routes refused
// it and some swapped it, which is what a rule kept in each call site rather than in one place looks like
// after a while.
//
// The error is the caller's to see: it names both organizations, because "you may only write into your own"
// is not actionable without saying which one that is.
func adminTenantForWrite(r *http.Request, bodyTenant string) (string, error) {
	resolved := adminTenantIDFromRequest(r)
	if adminCallerIsOperator(r) {
		target := valueOrDefault(bodyTenant, resolved)
		if err := adminOperatorWriteTargetAllowed(r, target, "writing into"); err != nil {
			return "", err
		}
		return target, nil
	}
	if named := strings.TrimSpace(bodyTenant); named != "" && !strings.EqualFold(named, strings.TrimSpace(resolved)) {
		return "", fmt.Errorf(
			"this request writes into organization %q and you may only write into %q — it would otherwise have "+
				"been carried out in your own organization, which is not what you asked for", named, resolved)
	}
	return resolved, nil
}
