package main

import (
	"fmt"
	"net/http"
	"strings"
)

// an_organizations_life_is_not_a_customers_to_end.go — who may create, delete, erase and count an organization.
//
// ★★★ WHY THIS EXISTS (2026-08-22, measured end to end against the reference control plane). Five routes in
// the organization-lifecycle family took the organization from the REQUEST and never asked whether the caller
// had any business naming it. They were gated on the permission `admin.tenant.admin` alone — and a customer's
// own super_admin holds that permission, because it is also what lets them administer their own organization.
//
// So the gate answered "does this caller hold the tenant-admin role", and the question that mattered was
// "which organization is this caller FROM". That is the same mistake operator_is_an_organization_not_a_role.go
// was written for; these five routes were behind it and were missed, because a path parameter never passes
// through the X-Operate-Tenant guard in the middleware — the victim is named in the URL, not in a header.
//
// Measured, as the customer super_admin of tenant_reference_lab, with a throwaway organization created for
// the purpose so that nothing real was destroyed to prove it:
//
//	POST   /admin/tenants                                200  a customer created an organization
//	DELETE /admin/tenants/{other}                        200  {"deleted":true} — and a fleet-wide tombstone
//	POST   /admin/tenants/{other}/purge                  200  {"complete":true,"remaining":{"total":0}}
//	GET    /admin/tenants/{other}/data-footprint         200  669 records counted, per store, for tenant_northwind
//	GET    /admin/fleet/tenant-erasure/{other}           200  which nodes still hold another customer's data
//
// The first three are not a disclosure. A customer of this product could END another customer, completely and
// irreversibly, in two requests — the delete writes the tombstone the whole fleet honours, and the purge is
// the erasure this product deliberately makes unrecoverable. Nothing in either answer suggested anything was
// wrong, because from the handler's point of view nothing was: it was asked to erase an organization by
// somebody holding the permission to erase organizations.
//
// ★ TWO RULES, NOT ONE, BECAUSE THE ROUTES ARE NOT THE SAME SHAPE.
//
//	counting  — an organization may count ITS OWN data; another's requires cross-organization rights. That is
//	            adminTenantPKITargetAllowed, which every PKI path route already uses.
//	lifecycle — creating, deleting and erasing an organization are acts of whoever OPERATES the deployment,
//	            never of a customer inside it, and that includes a customer naming their own organization: an
//	            administrator who deletes the organization they administer strands every colleague in it, and
//	            "the customer asked for it" is a contract event, not an API call. Operator only.
//
// ★ AND A DEPLOYMENT WITH NO TENANT MODEL IS UNAFFECTED. adminCallerIsOperator answers true for an unscoped
// caller, which is how a single-tenant Edge addresses itself; the refusal below only ever fires where there
// are organizations to confuse in the first place.

// adminOperatorOnlyOrganizationAct refuses a caller who is not operating this deployment, and says which
// organization they are in — the refusal a customer reads should tell them why, not merely that.
// It writes the response and returns false when it refuses; the handler returns on false.
func adminOperatorOnlyOrganizationAct(w http.ResponseWriter, r *http.Request, act string) bool {
	if adminCallerIsOperator(r) {
		return true
	}
	caller := strings.TrimSpace(adminTenantIDFromRequest(r))
	if caller == "" {
		caller = "no organization"
	}
	writeError(w, http.StatusForbidden, fmt.Errorf(
		"%s is an act of whoever operates this deployment, not of an organization inside it; you are "+
			"operating in %q. If this organization's contract is ending, that is a request to your provider",
		act, caller))
	return false
}

// adminTenantPathReadAllowed is the counting rule: your own organization, or cross-organization rights.
// Same helper the PKI path routes use, wrapped so a read route can refuse in one line.
func adminTenantPathReadAllowed(w http.ResponseWriter, r *http.Request, target, act string) bool {
	if err := adminTenantPKITargetAllowed(r, target, act); err != nil {
		writeError(w, http.StatusForbidden, err)
		return false
	}
	return true
}
