package main

// What GET /admin/state may say to the organization that asked.
//
// ★★★ IT SAID EVERYTHING THE NODE KNEW (2026-08-16, found by sweeping all 120 parameterless admin GET routes
// signed in as Northwind's administrator — roles ["admin"], no cross-tenant permission). The route already had
// the caller's organization in hand and used it for devices and connectors; three other parts of the same
// answer ignored it:
//
//   - recent_logs returned the LATEST line of every stream whoever asked. Four streams came back, all another
//     organization's: an access decision naming their real user and source IP, a device-state row naming their
//     device, a config generation, a connector heartbeat.
//   - the counts were the NODE's totals — 272 access decisions and 5000 inspection events reported to an
//     organization with one device. Every one of those records carries the organization it belongs to, so the
//     count can simply be the caller's own.
//   - policies listed the node's whole bundle: a customer with one policy of their own was shown three.
//
// Records with no organization on them are kept, the rule this tree uses everywhere else: on a single-tenant
// deployment that is all there is, and dropping it would blank the dashboard of the only organization present.

import (
	"strings"

	"github.com/lantern-networks/dsse-core/model"
)

// adminStateCount answers with the caller's own total, or the node's when there is no caller organization to
// scope to (a single-tenant deployment).
func adminStateCount(tenantID string, wholeNode func() int, own func() int) int {
	if strings.TrimSpace(tenantID) == "" {
		return wholeNode()
	}
	return own()
}

// countByTenant counts the records in a snapshot that belong to one organization.
func countByTenant[T any](all []T, tenantID string, owner func(T) string) int {
	n := 0
	for _, item := range all {
		if strings.EqualFold(strings.TrimSpace(owner(item)), tenantID) {
			n++
		}
	}
	return n
}

// policiesForTenant keeps the caller's own policies, and the ones carrying no organization at all — those are
// evaluated for every request this node serves, so they are the caller's business too.
func policiesForTenant(policies []model.Policy, tenantID string) []model.Policy {
	if strings.TrimSpace(tenantID) == "" {
		return policies
	}
	out := make([]model.Policy, 0, len(policies))
	for _, p := range policies {
		owner := strings.TrimSpace(p.TenantID)
		if owner == "" || strings.EqualFold(owner, tenantID) {
			out = append(out, p)
		}
	}
	return out
}

// policyBundleFactsForTenant answers with this node's policy-bundle identity, or with the reason it is being
// withheld — never with another organization's.
//
// ★★ THE FOURTH PART OF THE SAME ANSWER (2026-08-22, found by re-running the 2026-08-16 sweep as the same
// customer administrator). recent_logs, the counts and the policy list were all scoped that day; the
// policy_bundle block was not, and it carries the bundle's ID — which on this deployment reads
// "bundle_cp_tenant_reference_lab". So a customer administrator of tenant_northwind, holding roles ["admin"]
// and no cross-organization permission at all, was handed another customer's organization id in the first
// screenful of their own dashboard.
//
// ★ AND IT IS WITHHELD OUT LOUD. Blanking the fields silently would read as "this node has no policy bundle",
// which is the shape this tree keeps finding: a refusal drawn as a zero. The note says what is true — the
// bundle belongs to somebody else, and the caller's own policies are listed beside it either way.
//
// Nothing consumed these fields: the Console reads policy_bundle_version from the tenant registry, and
// policy_bundle_id only as a column of an audit row. Kept as fields rather than removed, because an answer
// that loses a key is a different kind of break for whatever reads it next.
func policyBundleFactsForTenant(bundleTenantID, bundleID, version, status, bundleType, callerTenantID string) map[string]any {
	caller := strings.TrimSpace(callerTenantID)
	if caller == "" || strings.EqualFold(strings.TrimSpace(bundleTenantID), caller) {
		return map[string]any{"id": bundleID, "version": version, "status": status, "type": bundleType}
	}
	return map[string]any{
		"id": "", "version": "", "status": "", "type": "",
		"withheld": "this node's policy bundle belongs to a different organization, so its identity is not " +
			"shown here. The policies that apply to you are listed in this same answer.",
	}
}
