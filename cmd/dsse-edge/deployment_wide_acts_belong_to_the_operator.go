package main

import (
	"fmt"
	"strings"
)

// deployment_wide_acts_belong_to_the_operator.go — the second half of "operator is an organization, not a role".
//
// ★★★ WHY THIS EXISTS (2026-08-22, measured on the reference deployment with a real customer account).
//
// On 2026-08-15 this tree found that fleet trust anchors, the foundation interception PKI and agent release
// publishing were gated on permissions every ordinary tenant `admin` holds. The fix created two new
// permissions — admin.platform.write and admin.quota.write — and granted them to `super_admin`, described in
// the role table as "the cross-tenant operator".
//
// On 2026-08-21 this tree found that super_admin is NOT the operator. It is a ROLE, and every customer's own
// top administrator holds it — that is what operator_is_an_organization_not_a_role.go was written for. Nobody
// went back to 2026-08-15. So the deployment-wide permissions had been moved out of reach of a customer's
// `admin` and into reach of a customer's `super_admin`, which is the account the customer actually signs in
// with.
//
// Measured, as the customer super_admin of tenant_reference_lab, against all thirteen routes gated on
// admin.platform.write. NONE of them refused on authorization. Every one was reached; they failed on content
// or on this node's configuration, which is not a boundary:
//
//	POST   /admin/transport-trust-anchors/{sha256}/acknowledge      200  recorded, and this counts towards
//	                                                                     allowing a fleet-wide withdrawal
//	DELETE /admin/transport-trust-anchors/{sha256}/acknowledge/{id} 200  {"withdrawn":true}
//	POST   /admin/agent-updates                                     400  "refusing to sign: version is empty"
//	                                                                     — i.e. INSIDE the signing path for the
//	                                                                     software every device installs
//	POST   /admin/interception-intermediate/rotate                  503  "interception is not enabled on this
//	                                                                     edge" — a configuration fact, and on an
//	                                                                     Edge where it IS enabled this rotates
//	                                                                     the CA signing every intercepted leaf
//	                                                                     for every organization on that node
//	POST   /admin/transport-trust-anchors, DELETE …, device-client-cas …   409/410, likewise configuration
//
// ★ SO THE RULE IS CENTRAL, NOT PER ROUTE. Thirteen routes today, and the reason they were missed twice is
// that "remember to also check the caller's organization" is a rule that has to be remembered thirteen times.
// A permission that names a deployment-wide act carries the requirement with it instead.
//
// ★ AND IT IS KEYED ON THE ACT, NOT ON THE ROLE. adminCallerIsOperator asks which organization the caller
// belongs to; a deployment with no tenant model, and a lab deployment with no administrator authentication at
// all, are both unaffected — there is no boundary there to cross.

// adminDeploymentWidePermissions names the permissions that exist only for acts on the whole installation.
// Each is listed with what it gates, because a set nobody can read is one nobody will keep correct.
//
//	admin.platform.write — fleet transport trust anchors, the device-trust CA set, this node's interception
//	                       signing authority, and publishing agent releases to every device.
//	admin.quota.write    — the licence and the seat allocations drawn from it. The party a limit constrains
//	                       must not be the party who writes it.
//	admin.certs.write    — the certificates this node PRESENTS, and staged transport trust rotations.
//	admin.dns.write      — the node's DNS resolver policy: deny, sinkhole, stub. One route, no organization
//	                       in it, and it decides what every organization on the node can resolve.
//
// ★ THE LAST TWO WERE MOVED TO super_admin ON THE SAME DAY AND FOR THE SAME REASON as the first two, and were
// measured with the same result. PUT /admin/dns-policy answered a customer super_admin with 200 and REPLACED
// the deployment's resolver policy — the probe that established it emptied the reference control plane's stub
// entry, which is exactly the failure this deployment's own compose file documents observing on 2026-07-30:
// an Edge that pulls config from a control plane serving an empty DNS policy stops resolving the private app,
// and it reaches a person as "no internet" rather than as anything DNS-shaped. (Restored by hand; all three
// nodes agree again.) The other four reached 400/409/503 on this node's configuration, which is not a
// boundary — PUT /admin/certs/{name} replaces a certificate the node presents.
var adminDeploymentWidePermissions = map[string]string{
	"admin.platform.write": "trust anchors, the deployment's own PKI and agent release publishing",
	"admin.quota.write":    "the licence and the seats drawn from it",
	"admin.certs.write":    "the certificates this node serves, and staged transport trust rotations",
	"admin.dns.write":      "this node's DNS resolver policy",
}

// adminDeploymentWideActAllowed refuses a caller who does not operate this deployment. It returns nil for
// every route that is not a deployment-wide act, so it is safe to call on all of them.
//
// ★ AN EITHER-OF GATE IS NOT ONE OF THESE. A permission written "a|b" is a route that is a TENANT act one way
// and an operator act the other — GET /admin/break-glass-token is the measured example — and the handler
// decides which case it is looking at. Folding those in here would take a customer's own read away from them
// in order to close an operator hole, which is the mistake the 2026-08-15 note explicitly warns against.
//
// ★★ IT TAKES THE IDENTITY, NOT THE REQUEST, AND THAT IS THE WHOLE POINT (2026-08-22, caught on the first
// live re-measurement). The first version of this asked adminCallerIsOperator(r). Inside the admin middleware
// the identity has NOT been attached to the request context yet — that happens on the last line, when the
// handler is finally called — so adminIdentityFromRequest found nothing, read the request as an unscoped
// single-tenant deployment, and returned true for every caller. All thirteen routes still answered a customer,
// and the unit test beside this passed, because it called this helper directly with a request that DID carry
// an identity. The helper was right and its one real call site was not, which is why the test below now goes
// through the middleware.
func adminDeploymentWideActAllowed(identity adminIdentity, permission string) error {
	what, deploymentWide := adminDeploymentWidePermissions[strings.TrimSpace(permission)]
	if !deploymentWide {
		return nil
	}
	if adminIdentityMayActAcrossOrganizations(identity) {
		return nil
	}
	caller := strings.TrimSpace(identity.TenantID)
	if caller == "" {
		caller = "no organization"
	}
	return fmt.Errorf(
		"this changes %s for the whole deployment, not for one organization in it, so it belongs to whoever "+
			"operates this installation; you are operating in %q", what, caller)
}
