package main

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// operatorDelegatedVerdict is what the middleware learned about an operator acting inside a customer's
// organization. Separate from a bare bool because the two refusals lead to DIFFERENT fixes — obtain the
// delegation, or obtain an elevation — and a 403 that does not say which sends an operator to the wrong one.
type operatorDelegatedVerdict struct {
	// Delegated is true when this organization has asked the operator to run it.
	Delegated bool
	// NeedsElevation is true when the ROUTE is one of the irreversible or organization-wide acts.
	NeedsElevation bool
	// Elevated is true when an elevation for this operator over this organization is active right now.
	Elevated bool
	// Why carries the reason the route is on the elevated list, for the refusal message.
	Why string
	// Target is the organization being acted on, or "" when this is not an operate-within request at all.
	Target string
	// Resolved is true when this node could look the organization up at all.
	//
	// ★ THE DEPLOYMENT FACT / OBJECT DISTINCTION, AGAIN (the answer settled at deviceGroupVisibleToTenant,
	// 2026-08-12). A node that does not run the tenant model has no delegations to consult, and making every
	// act inside it fail closed would blank the operator on exactly the deployments this design says nothing
	// about — the shape of the fix that emptied the fleet view. So an UNRESOLVED organization leaves behaviour
	// exactly as it was; a resolvable one that has delegated nothing is a real answer and is refused.
	Resolved bool
}

// operatorDelegationForRequest reads the standing delegation and the live elevation state for a request.
//
// It answers only for the case the envelope is about: an OPERATOR (admin.tenant.admin) acting inside ANOTHER
// organization via X-Operate-Tenant. A tenant administrator acting in their own organization is that
// organization's business — the elevation exists because the operator is not the customer, not because the
// act is frightening.
func operatorDelegationForRequest(ctx context.Context, r *http.Request, identity adminIdentity,
	store adminTenantModelRuntimeStore, now time.Time) operatorDelegatedVerdict {

	verdict := operatorDelegatedVerdict{}
	if r == nil || store == nil {
		return verdict
	}
	if !adminIdentityMayActAcrossOrganizations(identity) {
		return verdict
	}
	target, overridden := adminOperateTenant(r, identity)
	target = strings.TrimSpace(target)
	if !overridden || target == "" || strings.EqualFold(target, strings.TrimSpace(identity.TenantID)) {
		return verdict
	}
	verdict.Target = target
	if operatorRouteIsEnvelopeControl(r.URL.Path) {
		return verdict
	}
	verdict.Why, verdict.NeedsElevation = operatorActNeedsElevation(r.Method, r.URL.Path)

	tenant, resolved := operatorDelegationRecord(ctx, store, target)
	if !resolved {
		// Not resolvable here — see the note on Resolved. The caller keeps whatever permissions they hold in
		// their own right and gains nothing from a delegation, because there is no record to have granted one.
		return verdict
	}
	// ★ THE OPERATOR'S OWN ORGANIZATION HAS NOBODY TO DELEGATE FROM (found live, 2026-08-16). The delegation
	// route refuses to set one on the operator tenant — correctly, it does not delegate to itself — and this
	// rule then required one anyway, so acting inside the operator's own organization became impossible for
	// everyone. Measured while trying to mint the operator's first named credential: refused, and there was no
	// act available that would have unrefused it.
	//
	// Acting inside the operator tenant is not acting inside a customer. It is bounded by ordinary
	// permissions, like any other principal in their own organization.
	if tenant.IsOperator {
		return verdict
	}
	verdict.Resolved = true
	verdict.Delegated = tenant.OperatorManaged
	verdict.Elevated = operatorHasActiveElevation(tenant, identity.PrincipalID, now)
	return verdict
}

// operatorDelegationRecord returns the organization's REGISTERED row, and whether this node has one at all.
//
// ★ Get CANNOT ANSWER THIS. The runtime read SYNTHESIZES a row for an unknown id — an organization nobody
// created comes back looking like an organization with every default, which is why the routes carry a
// separate existence check. Reading the delegation through it would have made every id on this node
// "registered and not delegated", so a deployment that does not run the tenant model at all would have had
// its operator refused everywhere. Found by three tests going red at once with a harness whose registry
// contains one seeded tenant and nothing else.
//
// An empty registry is treated as "this node does not run the model" rather than "no organization has
// delegated anything", for the same reason: the first is a deployment fact, the second is a claim about
// organizations that do not exist here.
func operatorDelegationRecord(ctx context.Context, store adminTenantModelRuntimeStore, target string) (adminTenantModel, bool) {
	admin, ok := store.(adminTenantModelAdminStore)
	if !ok {
		return adminTenantModel{}, false
	}
	tenants, err := admin.List(ctx)
	if err != nil || len(tenants) == 0 {
		return adminTenantModel{}, false
	}
	for _, tenant := range tenants {
		if strings.EqualFold(strings.TrimSpace(tenant.TenantID), target) {
			return tenant, true
		}
	}
	return adminTenantModel{}, false
}

// operatorEnvelopeControlRoutes are the routes an operator must be able to reach REGARDLESS of the
// delegation: the envelope's own controls, and the discovery surface that says whether an organization is set
// up at all.
//
// ★ A CONTROL PLANE FOR A PERMISSION MUST NOT BE GATED BY THAT PERMISSION. Found live, in two goes, and the
// second one was the dangerous half:
//
//   - GET /admin/operator-access is gated "admin.config.read|admin.tenant.admin". admin.config.read is
//     tenant-side, so the delegation rule fired on the one route whose purpose is to say whether a delegation
//     exists: the operator was refused with a message telling them to obtain the thing they were trying to
//     find out about, and given no way to look.
//
//   - DELETE /admin/operator-elevations/{id} is gated "admin.tenant.admin|admin.config.write", so once an
//     organization withdrew its delegation the operator could no longer END an elevation that was still open.
//     Withdrawing the delegation is exactly the moment somebody wants every window shut, and it was the
//     moment the operator lost the ability to shut one. Measured on the lab: five elevations reported active
//     that neither run could close, and the destructive-act check passed for the wrong reason as a result.
//
// Their handlers do their own bounding, and it is stricter than the delegation rule rather than looser: the
// grant is operator-only, the approval reads the caller's OWN tenant and ignores the operate-within header,
// and every one of them goes through adminTenantPKITargetAllowed. What is removed here is the rule that would
// make the envelope's own state unrecoverable, not the boundary.
// ★ AND THE SETUP CHECKLIST BELONGS HERE TOO (2026-08-16, found in the Console). It is gated
// "admin.tenant.read|admin.tenant.admin", and admin.tenant.read is tenant-side, so the delegation rule
// refused an operator reading the setup state of an organization that had delegated nothing — which is every
// organization that has just been created, and exactly when the checklist matters. The Organizations list
// showed "unknown" for it while showing a full answer for the two that had delegated.
//
// The delegation governs ACTING inside an organization. Finding out whether an organization works at all is
// what the operator does BEFORE there is anything to delegate, and it is their own business: they created it,
// they allocate its capacity, and onboarding it is their job. The tenant boundary is untouched — a tenant
// administrator still sees their own organization and no other.
var operatorEnvelopeControlRoutes = []string{
	"/admin/operator-access",
	"/admin/organization-setup",
	"/admin/operator-delegation",
	"/admin/operator-elevations",
	"/admin/operator-elevations/*",
	"/admin/operator-elevations/*/approve",
}

// operatorRouteIsEnvelopeControl reports whether this path is one of the envelope's own controls.
func operatorRouteIsEnvelopeControl(path string) bool {
	segments := splitRoutePath(path)
	for _, pattern := range operatorEnvelopeControlRoutes {
		if routePatternMatches(splitRoutePath(pattern), segments) {
			return true
		}
	}
	return false
}

// operatorDelegationGrants reports whether the standing delegation covers this permission.
//
// ★ IT GRANTS EXACTLY WHAT A TENANT ADMINISTRATOR HOLDS, AND NOTHING ELSE. The delegation is the customer
// saying "run my organization for me", so the ceiling is what an administrator of that organization can do.
// It must not reach admin.platform.write (the deployment's own PKI, trust anchors, agent releases),
// admin.quota.write (capacity the operator sells) or admin.tenant.admin (the registry itself) — those are the
// operator's own powers, held or not held on their own merits, and folding them into a customer's delegation
// would mean a customer's signature widened what the operator can do to the installation.
func operatorDelegationGrants(permission string) bool {
	tenantAdmin := adminPermissionsByRole["admin"]
	for _, candidate := range strings.Split(permission, "|") {
		if candidate = strings.TrimSpace(candidate); candidate != "" && tenantAdmin[candidate] {
			return true
		}
	}
	return false
}

// operatorElevationRefusal is the message for an elevated act attempted without an active elevation.
func operatorElevationRefusal(verdict operatorDelegatedVerdict) error {
	// ★ NO API CALL IN THE SENTENCE. This used to end "Grant one with POST /admin/operator-elevations
	// (X-Operate-Tenant: …)", which a screen showed to an operator as the way forward. The answer now carries
	// elevation_required as a field instead, and the screen offers the act; the words say what it is and what
	// it costs, in the reader's terms.
	return fmt.Errorf(
		"this act needs time you have been granted over %q, and none is running: %s. Ask for it — it ends by "+
			"the clock, nothing renews it silently, and %s can see every one",
		verdict.Target, verdict.Why, verdict.Target)
}

// operatorDelegationRefusal is the message for an organization that has not delegated its management.
func operatorDelegationRefusal(verdict operatorDelegatedVerdict, permission string) error {
	return fmt.Errorf(
		"%q has not delegated its management to the operator, so admin permission %s is not yours inside it. "+
			"The organization grants it with PUT /admin/operator-delegation, and can withdraw it at any time",
		verdict.Target, permission)
}

// operatorMaySeatFirstAdministrator is the ONE act an organization that has delegated nothing still needs the
// operator for, and the only exception to the delegation gate.
//
// ★★ THE BOOTSTRAP DEAD END (2026-08-17, walked from the creation wizard and measured end to end). Create an
// organization, choose "it runs itself", name its first administrator — and the invitation is refused with
// "has not delegated its management", because the delegation is what supplies the operator's customer-side
// writes. The wizard then advises inviting from the Administrators screen, which refuses for the same reason.
// So a self-run organization could never be given the administrator that would let it run itself. Measured:
// POST /admin/admins/invite → 403, GET /admin/admins → 403, no act available that would have unrefused it.
//
// The rule this states is true rather than convenient: seating the FIRST administrator is not ordinary work
// inside somebody's organization — it is the act that creates the party who could delegate at all. It is
// bounded by the same fact:
//
//   - exactly one route, the invitation, and only for the accounts permission it needs;
//   - only when the organization has ZERO administrators. The moment it has one, this closes and ordinary
//     rules apply — and it cannot be re-opened, because emptying an organization of administrators needs the
//     very permission this gate withholds (and the last-administrator guard refuses it even to the owner);
//   - recorded as its own audit event, because an operator acting inside a customer that has not asked them
//     to is exactly the thing the envelope exists to make visible.
//
// The alternative considered and rejected: have the wizard switch the delegation on, seat the administrator,
// and switch it off. That hands the operator EVERY customer-side write for the window to perform one act, and
// leaves the customer's own control flapping in their audit trail. A narrow permanent rule beats a broad
// temporary one.
func operatorMaySeatFirstAdministrator(ctx context.Context, r *http.Request, permission string,
	verdict operatorDelegatedVerdict, hasAdministrators func(context.Context, string) (bool, bool)) bool {
	if r == nil || !strings.EqualFold(r.Method, http.MethodPost) {
		return false
	}
	if strings.TrimSpace(r.URL.Path) != "/admin/admins/invite" {
		return false
	}
	if strings.TrimSpace(permission) != "admin.accounts.write" {
		return false
	}
	target := strings.TrimSpace(verdict.Target)
	if target == "" {
		return false
	}
	if hasAdministrators == nil {
		return false
	}
	// ★ AND "HAS AN ADMINISTRATOR" INCLUDES ONE WHO HAS NOT SIGNED IN YET (2026-08-17, caught by the boundary
	// half of the live walk). The first version asked the auth store for its PRINCIPAL count, which is written
	// at ACTIVATION — an invited administrator who has not yet set a password is not one. So after seating the
	// first, the count was still zero and a second invitation was accepted, and a third would have been: the
	// exception never closed. Measured: invite → 201, invite again → 201.
	//
	// The question is "does this organization have anybody who can administer it", and an invitation already
	// answers yes: that person can activate whenever they like, and until they do the organization is not
	// waiting on the operator for anything.
	has, known := hasAdministrators(ctx, target)
	if !known {
		// Cannot establish that the organization is empty, so do not assume it. A bootstrap that cannot be
		// proven is a delegation gate quietly widened.
		return false
	}
	return !has
}
