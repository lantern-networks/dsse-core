package main

// Who is this answer about?
//
// ★★ TWO ROUTES ON ONE SCREEN DISAGREED (2026-08-17, found by onboarding a new organization through the
// Console). An operator ENTERED "Contoso Ltd" — the banner said so — and:
//
//   GET /admin/state              answered about Contoso: its tenant id, its (empty) policy list
//   GET /admin/pki/certificates   answered about the whole node, so Contoso's certificate screen said
//                                 "connections are verified with Northwind Device Issuing CA 2028
//                                 (tenant_northwind)" and warned in red about win-dev-1, another
//                                 organization's device
//
// Both were "right" by their own rule: the first scopes to whatever organization the request NAMES, the second
// skipped scoping entirely for an operator. Entering an organization is a mode — the whole banner exists to say
// which organization the screen in front of you is about — and a screen that answers for somebody else inside
// that mode is how an operator acts on the wrong customer's material while believing otherwise.
//
// One rule, in one place: the answer is about the organization the request names. An operator who has not
// entered one is asking about the deployment, and gets it.

import (
	"net/http"
	"strings"

	"github.com/lantern-networks/dsse-core/decision"
)

// adminAnswerScope returns the organization an answer should be about, and whether it should instead cover the
// whole deployment.
func adminAnswerScope(r *http.Request) (tenant string, wholeDeployment bool) {
	named := strings.TrimSpace(adminTenantIDFromRequest(r))
	if !adminCallerIsOperator(r) {
		// A customer administrator: their own organization, always.
		return named, false
	}
	// An operator. Having entered an organization is a deliberate act with a banner attached, so it decides
	// what they are shown as well as what they act on.
	if operating := strings.TrimSpace(r.Header.Get("X-Operate-Tenant")); operating != "" {
		return operating, false
	}
	return named, true
}

// evaluatorForCaller is the policy engine as this answer's organization sees it.
//
// ★ The "what is actually in force for me" screens read every policy the NODE evaluates. Measured as
// Northwind's administrator: /admin/egress-effective-rules and /admin/effective-policies both listed
// pol_general_egress_allow_001 and _002, which belong to another organization — on the two screens whose whole
// purpose is to tell a customer what is being enforced ON THEM. /admin/rules beside them returned their own
// rules only, so the customer could see one answer or the other depending on which screen they opened.
func evaluatorForCaller(eval decision.Evaluator, r *http.Request) decision.Evaluator {
	tenant, wholeDeployment := adminAnswerScope(r)
	if wholeDeployment {
		return eval
	}
	eval.Policies = policiesForTenant(eval.Policies, tenant)
	return eval
}
