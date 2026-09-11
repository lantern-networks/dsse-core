package main

import (
	"net/http"
	"strings"
)

// The acts an operator may not perform on a customer's organization under the STANDING delegation alone.
//
// ★ WHY A LIST OF ROUTES AND NOT A LIST OF PERMISSIONS (the envelope design, 2026-08-16). The destructive acts live INSIDE
// permissions that also cover the daily work: withdrawing an organization's last device CA and adding its
// first are both admin.enrollment.write; revoking its interception authority and authoring a policy are both
// admin.policy.write. Classifying by permission therefore has only two outcomes, and both are wrong — take
// the permission away and the operator cannot do the job the customer is paying for, or leave it and the
// standing delegation is a credential that can strand a fleet.
//
// The list is small on purpose. Every entry is irreversible, or takes effect across the whole of one
// organization at once, or both. If an act does not meet that bar it belongs to the daily work, and putting
// it here buys a false sense of ceremony at the cost of the thing being sold.
//
// This governs the DELEGATED path only: an act performed by the organization's own administrator is that
// organization's business and is unchanged. Elevation exists because the operator is not the customer.
type operatorElevatedAct struct {
	Method string
	// Path is matched by segment against the request path, with "*" standing for one wildcard segment. Written
	// as the route pattern is written, so a reader can compare this file to the mux without translating.
	Path string
	// Why keeps the list arguable. A list of rules whose reasons were never written down is one nobody can
	// safely shorten later, so it only ever grows.
	Why string
}

var operatorElevatedActs = []operatorElevatedAct{
	// ★★★ ADDED THE DAY THE ROUTES WERE (2026-08-20), because they were not, and it showed. Both were built
	// this morning and walked straight through with an operator credential and no elevation — measured, on the
	// running lab, the first time anybody held a credential that could cross organizations. Widening the
	// cross-organization PKI surface without extending this list is the defect this list exists to prevent,
	// and it is easy to commit because everything still works.
	{
		Method: http.MethodPost, Path: "/admin/tenant-device-authority",
		Why: "creates the authority this deployment ENROLS an organization's devices under — every certificate " +
			"its fleet is identified by from then on is minted with a key the operator holds, which is the " +
			"managed-service arrangement itself and not a thing to enter into on somebody's behalf unasked",
	},
	{
		Method: http.MethodPost, Path: "/admin/tenant-transport-authority",
		Why: "creates the authority that signs the certificate this organization's devices meet when they " +
			"connect; every Edge in the fleet will present certificates minted under it",
	},
	{
		Method: http.MethodPost, Path: "/admin/tenant-transport-authority/rotate",
		Why: "asks every device of this organization to adopt a second authority, and every Edge to announce " +
			"it — additive, but it is the act that starts a fleet-wide movement nobody can call back by hand",
	},
	{
		Method: http.MethodPost, Path: "/admin/tenant-transport-authority/retire-previous",
		Why: "destroys the authority this organization's Edges may still be serving; an Edge that has not " +
			"promoted yet loses what it presents, and its devices meet a certificate they cannot verify",
	},
	{
		Method: http.MethodPost, Path: "/admin/tenant-transport-authority/rename",
		Why: "changes the name every device of this organization must present to be served at all; the " +
			"certificate carries both while they move, and the move is fleet-wide and cannot be called back " +
			"by hand",
	},
	{
		Method: http.MethodPost, Path: "/admin/tenant-transport-authority/retire-previous-name",
		Why: "stops the certificate answering to the name this organization's devices may still be sending; " +
			"anything that has not adopted the new one fails the handshake, which is not a refusal it can be " +
			"told about",
	},
	{
		Method: http.MethodPost, Path: "/admin/tenant-transport-authority/abandon-rotation",
		Why: "un-announces an authority this organization's devices were asked to adopt; nothing is served " +
			"under it, so it takes nothing away — but the fleet was told, and untelling it is the operator's",
	},
	{
		Method: http.MethodPost, Path: "/admin/tenant-device-authority/abandon-rotation",
		Why: "stops the incoming device authority signing while it stays admitted; every certificate already " +
			"issued under it keeps working, and which authority enrols this organization is the operator's",
	},
	{
		Method: http.MethodPost, Path: "/admin/tenant-transport-authority/abandon-rename",
		Why: "puts this organization back on the name it was being moved off; harmless to a device, and it " +
			"ends a movement the fleet was told about, which is the operator's to answer for",
	},
	{
		Method: http.MethodPost, Path: "/admin/tenant-device-authority/rotate",
		Why: "moves every new and renewed device certificate of this organization onto a second authority; " +
			"additive, and it is what starts a migration only the fleet's own evidence can end",
	},
	{
		Method: http.MethodPost, Path: "/admin/tenant-device-authority/retire-previous",
		Why: "stops admitting every device of this organization still holding a certificate from the outgoing " +
			"authority — refused at the handshake, including a laptop that was switched off throughout",
	},
	{
		Method: http.MethodPost, Path: "/admin/tenant-interception-authority/promote",
		Why: "makes this organization's staged interception authority the one every Edge signs under; every " +
			"device that has not adopted its root loses every HTTPS site at that moment",
	},
	{
		Method: http.MethodPost, Path: "/admin/tenant-interception-authority/withdraw-incoming",
		Why: "abandons the root this organization's devices were asked to adopt; harmless to traffic, and it " +
			"ends a movement the fleet was told about, which is the operator's to answer for",
	},
	{
		Method: http.MethodPost, Path: "/admin/tenant-interception-authority",
		Why: "accepts the authority this organization delegated for INTERCEPTING its traffic, and every Edge " +
			"is then handed material minted under it",
	},
	{
		Method: http.MethodPost, Path: "/admin/interception-intermediate/*/revoke",
		Why: "revokes the authority that signs everything this organization's devices see; afterwards its " +
			"traffic is not intercepted at all until a replacement is loaded, and the revoked certificates can " +
			"never be loaded on this node again",
	},
	{
		Method: http.MethodPost, Path: "/admin/interception-intermediate/*",
		Why: "replaces what signs this organization's intercepted traffic — every device of theirs is shown a " +
			"different certificate from the next handshake onward",
	},
	{
		Method: http.MethodDelete, Path: "/admin/tenant-cas/*/*",
		Why: "stops this organization's devices being admitted under that CA; a device that has not moved to " +
			"the replacement cannot connect at its next handshake, and the credential it would renew with is " +
			"the one that just stopped being trusted",
	},
	{
		Method: http.MethodDelete, Path: "/admin/tenant-cas/*",
		Why: "retires the organization's identity basis entirely — not the end of a rotation, the end of its " +
			"ability to admit any device at all",
	},
	// ★★ THE ROOT ITSELF WAS NOT ON THIS LIST (2026-08-19, roadmap item B). The list covered the interception
	// INTERMEDIATE — what signs — and not the ROOT, which is what an organization's devices are told to trust.
	// Replacing it is strictly larger than replacing the intermediate: the intermediate changes what signs and
	// leaves the anchor alone, while the root changes the anchor every one of that organization's endpoints
	// must already hold. A device that does not hold the new one loses every HTTPS request it makes the moment
	// it is signed under — which is not a thought experiment here; it happened to win-dev-1 on 2026-08-19.
	{
		Method: http.MethodPost, Path: "/admin/interception-roots/*",
		Why: "mints or replaces the root this organization's devices are told to trust — a device that does " +
			"not already hold the new one loses every HTTPS request it makes as soon as traffic is signed under it",
	},
	{
		Method: http.MethodDelete, Path: "/admin/interception-roots/*",
		Why: "removes this organization's own interception authority; afterwards its traffic is not inspected " +
			"under a root of its own, and what its devices were told to trust no longer corresponds to anything",
	},
	{
		Method: http.MethodPost, Path: "/admin/transport-admission/revoke",
		Why: "the kill-switch: the one act permitted to cut an established (T) session, so it takes a device " +
			"off the network while it is being used",
	},
}

// operatorActNeedsElevation reports whether this request is one of them, and why.
func operatorActNeedsElevation(method, path string) (string, bool) {
	method = strings.ToUpper(strings.TrimSpace(method))
	segments := splitRoutePath(path)
	for _, act := range operatorElevatedActs {
		if !strings.EqualFold(act.Method, method) {
			continue
		}
		if routePatternMatches(splitRoutePath(act.Path), segments) {
			return act.Why, true
		}
	}
	return "", false
}

func splitRoutePath(path string) []string {
	out := []string{}
	for _, segment := range strings.Split(strings.TrimSpace(path), "/") {
		if segment != "" {
			out = append(out, segment)
		}
	}
	return out
}

// routePatternMatches compares segment by segment, with "*" matching exactly one segment.
//
// Segment-wise rather than by prefix, because a prefix match would make the longer route inherit the shorter
// one's classification: DELETE /admin/tenant-cas/{tenant}/{sha256} would match the pattern for
// DELETE /admin/tenant-cas/{tenant}, which happens to be harmless here (both are on the list) and would not
// be if a narrower route were ever added under a listed prefix. A rule that is right by coincidence is one
// that changes behaviour the next time somebody adds a route.
func routePatternMatches(pattern, segments []string) bool {
	if len(pattern) != len(segments) {
		return false
	}
	for i, want := range pattern {
		if want == "*" {
			continue
		}
		if !strings.EqualFold(want, segments[i]) {
			return false
		}
	}
	return true
}

// The tenant-scoped PKI writes an operator MAY perform under the standing delegation, and why each is daily
// work rather than ceremony.
//
// ★ IT EXISTS SO A ROUTE CANNOT BE NEITHER (2026-08-19). The elevated list grew by exception, so a new
// tenant-scoped PKI route was un-elevated by default and nothing said so — which is how POST and DELETE
// /admin/interception-roots/{tenant}, the pair that replaces what an organization's devices must trust, sat
// outside the envelope while the intermediate beside them sat inside it. A gate now requires every
// tenant-scoped PKI write to appear in one list or the other, so adding a route forces the question rather
// than answering it by omission.
var operatorDailyWorkActs = []operatorElevatedAct{
	{
		Method: http.MethodPost, Path: "/admin/tenant-cas",
		Why: "registers a CA this organization's devices are admitted under. Additive: it takes nothing away " +
			"from any device, and it is the act that makes a new organization work at all",
	},
	{
		Method: http.MethodDelete, Path: "/admin/interception-intermediate/*/retiring/*",
		Why: "stops ANNOUNCING a root this organization has already moved off. It signs nothing by definition — " +
			"the route refuses the one that is currently signing — so no device loses anything it is using",
	},
	{
		Method: http.MethodPost, Path: "/admin/interception-intermediate/*/csr",
		Why: "produces a signing request for this organization's own authority to sign. It changes nothing on " +
			"the node: the result is a request an offline root may or may not act on",
	},
	{
		Method: http.MethodPost, Path: "/admin/interception-roots/*/announce",
		Why: "asks this organization's devices to LOOK FOR a root and say whether they hold it. Nothing signs " +
			"under it, so no traffic changes and no device loses anything — and it is the act that makes the " +
			"switch measurable instead of blind, which is the difference between a rotation and an outage",
	},
}

// ★★★ THE ENVELOPE'S OWN CONTROLS ARE CLASSIFIED BY THE GUARD THAT ALREADY RUNS (2026-08-20).
//
// The gate that reads the source (not the URL) turned up two acts neither list could take:
// PUT /admin/operator-delegation and DELETE /admin/operator-elevations/{id}.
//
//   - Requiring an elevation for the delegation write DEADLOCKS. An elevation is refused unless the
//     organization is already delegated ("elevation adds to a delegation; it does not replace one"), so an act
//     that turns the delegation ON can never be performed under one. That rule would read strict and, at the
//     only moment it matters, refuse everybody.
//   - Calling them ordinary daily work would say the operator may rewrite the terms of their own delegation as
//     part of the work the delegation covers, which is the one thing a delegation must not permit.
//
// They are neither, and the codebase already knew it: operatorEnvelopeControlRoutes is the list the running
// guard consults to let an operator reach the envelope's own state regardless of the delegation. So this asks
// THAT list rather than keeping a second copy beside it — a second copy of a boundary is where the two answers
// start to differ, which is the note adminTenantPKITargetAllowed carries for the same reason.
//
// ★ OPEN, FOR THE OPERATOR TO DECIDE: today an operator holding admin.tenant.admin may re-enable a delegation
// the customer withdrew, and may clear the customer's "elevation needs my approval" flag. The route says so out
// loud (it returns operator_may_enable, and the customer's screen asks that guard rather than asserting a
// softer sentence). It is deliberate — the operator performs onboarding for customers who cannot — but "the
// holder may reopen what the customer closed" is not a delegation. The fix is a narrower guard (may set at
// onboarding; may not re-enable after a withdrawal; may not lower the approval requirement), not a class here.

// operatorActIsClassified reports whether this act appears in any of the lists — the property the gate asserts.
func operatorActIsClassified(method, path string) bool {
	if _, ok := operatorActNeedsElevation(method, path); ok {
		return true
	}
	if operatorRouteIsEnvelopeControl(path) {
		return true
	}
	segments := splitRoutePath(path)
	for _, act := range operatorDailyWorkActs {
		if strings.EqualFold(act.Method, method) && routePatternMatches(splitRoutePath(act.Path), segments) {
			return true
		}
	}
	return false
}
