package main

import (
	"log"
	"strings"
	"sync/atomic"
)

// operator_is_an_organization_not_a_role.go — who may act inside an organization that is not their own.
//
// ★★★ WHY THIS EXISTS (2026-08-21, measured live on the reference lab). The answer was a ROLE. Any principal
// holding admin.tenant.admin — super_admin or owner, roles a CUSTOMER organization grants inside itself —
// could put X-Operate-Tenant on a request and be answered as that organization. Measured, signed in as
// a named super_admin of a customer organization, whose own session says
// is_operator_tenant: false:
//
//	GET /admin/tenant-install-bundle/tenant_northwind      200  their interception root, their transport CA,
//	                                                            their signed trust bundle
//	GET /admin/policies          X-Operate-Tenant: …       200  another organization's policies
//	GET /admin/license           X-Operate-Tenant: …       200  their seat count and contract dates
//	GET /admin/logs/audit        X-Operate-Tenant: …       200  their entire audit trail
//	DELETE /admin/tenant-cas/tenant_northwind/{sha}        404  from the HANDLER — the gate had let it through
//
// A customer's own administrator, reading and writing another customer. The deployment already knows which
// organization is the operator's — -operator-tenant-id, seeded, flagged is_operator, refused for deletion —
// and every one of these checks asked about the role instead.
//
// ★ THE ROLE IS STILL REQUIRED; IT IS NO LONGER SUFFICIENT. An operator organization's ordinary administrator
// does not gain cross-organization reach by working there, and a customer's super_admin does not gain it by
// being called super_admin. Both must be true.
//
// ★ AND AN UNCONFIGURED DEPLOYMENT REFUSES RATHER THAN OPENS. When -operator-tenant-id is not set there is no
// operator organization, so nobody may cross — except a deployment with no tenant model at all, where the
// identity carries no organization and there is nothing to cross. The start-up line below says so out loud,
// because a deployment that quietly lost cross-tenant administration would be diagnosed as a broken Console.
//
// populated-by: assertion — set once from the flag at start-up, never inferred from a request.
// restart-durability: derived — this is a copy of a start-up flag, not state; a restart re-reads the flag.
var operatorTenantAuthority atomic.Value // string

// declareOperatorTenant records which organization operates this deployment. Called once, at start-up.
func declareOperatorTenant(tenantID string, tenantModelInUse bool) {
	id := strings.ToLower(strings.TrimSpace(tenantID))
	operatorTenantAuthority.Store(id)
	switch {
	case id != "":
		log.Printf("operator organization: %q — only its administrators holding admin.tenant.admin may act "+
			"inside another organization. A super_admin of a customer organization is a super_admin OF THAT "+
			"ORGANIZATION and is refused elsewhere.", id)
	case tenantModelInUse:
		log.Printf("★ WARNING: no operator organization is configured (-operator-tenant-id is empty) but this " +
			"deployment has a tenant model. NOBODY may act inside an organization that is not their own — " +
			"cross-organization administration is refused, including from the Console. Set -operator-tenant-id " +
			"to the organization that operates this deployment. This is deliberate: the alternative is every " +
			"customer's super_admin reaching every other customer.")
	}
}

// operatorTenantConfigured reports the operator organization, or "" when there is none.
// adminLabBypassAuthMethod is what adminRequestIdentity stamps on the identity it synthesises for an
// unauthenticated request under -lab-mode. Named rather than written as a literal at the comparison, so that
// renaming it in one place cannot silently turn the check below into one that never matches.
const adminLabBypassAuthMethod = "lab_bypass"

func operatorTenantConfigured() string {
	id, _ := operatorTenantAuthority.Load().(string)
	return id
}

// adminIdentityMayActAcrossOrganizations answers the one question every cross-tenant gate needs: may THIS
// caller be answered as an organization that is not their own?
func adminIdentityMayActAcrossOrganizations(identity adminIdentity) bool {
	// ★ THE ROLE IS CHECKED FIRST, INCLUDING FOR AN IDENTITY THAT CARRIES NO ORGANIZATION. An earlier draft
	// of this let an empty organization short-circuit ahead of the role, and the fail-closed test caught it:
	// a plain admin with no tenant and an X-Operate-Tenant header was answered as the organization it named.
	if !adminPermissionAllowed(identity.Roles, "admin.tenant.admin") {
		return false
	}
	// A deployment with no tenant model attaches no organization to the identity. There is nothing to cross,
	// and this is the same answer the tenant helpers have always given for an empty caller organization.
	home := strings.ToLower(strings.TrimSpace(identity.TenantID))
	if home == "" {
		return true
	}
	// ★ AND A DEPLOYMENT WITH NO ADMINISTRATOR AUTHENTICATION AT ALL IS NOT MAKING THIS DISTINCTION (2026-08-22).
	// -lab-mode synthesises an identity for every unauthenticated request and stamps it with the node's own
	// policy-bundle tenant. That id is not a claim about who is calling — nobody proved anything — so reading
	// it as "this caller belongs to that customer" would let a lab deployment refuse its own administration
	// while still letting anyone at all through the front door, which measures the wrong thing entirely.
	//
	// SAFE BECAUSE IT CANNOT REACH PRODUCTION: adminRequestIdentity returns lab_bypass only when devMode is
	// set, and returns "not authenticated" before it otherwise. TestLabBypassIsUnreachableWithoutDevMode
	// stands on that, so this stays a lab affordance and not a role anybody can present.
	if strings.EqualFold(strings.TrimSpace(identity.AuthMethod), adminLabBypassAuthMethod) {
		return true
	}
	operator := operatorTenantConfigured()
	if operator == "" {
		return false
	}
	return home == operator
}
