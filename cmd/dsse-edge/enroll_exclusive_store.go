package main

import (
	"flag"
	"strings"
)

// enroll_exclusive_store.go — an Edge that issues device certificates must be able to consume an identity
// ONCE, and that is not something a process can decide by itself.
//
// ★ THE HISTORY IS WORTH KEEPING, BECAUSE THE WRONG ANSWER LASTED THREE ROUNDS. "Has this identity already
// enrolled?" was answered from an in-memory ledger saved back as a whole blob. First fix: refuse a SHARED
// store, on the reasoning that two issuers sharing one document overwrite each other. Second: a
// `-enroll-sole-issuer` flag, which guaranteed nothing — every signer can pass it, and it says nothing about
// the non-signer processes writing the same store. Third, and the one that finally named it: separate
// node-local files are WORSE, not better, because then the enrolment markers cannot reach each other at all.
//
// None of those were the fix. A one-time decision taken by more than one process needs one place to take it —
// a conditional row, where exactly one UPDATE reports success. That is migration 035 and
// postgresEnrolledIdentityClaims, and this is the rule that makes an issuer have one.
//
// ★ AND THE "ZERO-DB ENFORCEMENT EDGE" IT SEEMED TO CONTRADICT WAS NEVER A REQUIREMENT. It came from
// 5b0cf5ed (2026-06-18), whose subject is the workload-attestation NONCE store: the Edge should not need
// Postgres merely to hold nonces. That is a good reason for a nonce store and no reason at all about issuing
// certificates — and it was allowed to constrain a security decision for three review rounds because it was
// written in a compose file as though it were a property somebody wanted. Handing out identities is exactly
// the kind of thing that needs durable, shared state.

// enrolIssuerNeedsClaimStore reports whether this configuration must be refused: it hands out device
// certificates without any way to consume an identity once across the whole deployment.
//
// A named predicate rather than an inline condition so the startup gate and its test are the same statement.
func enrolIssuerNeedsClaimStore(hasDeviceCA, hasIdentityClaims bool) bool {
	return hasDeviceCA && !hasIdentityClaims
}

// enrolIssuerNeedsExclusiveStore reports the OTHER half: even with a claim, an issuing Edge must not keep its
// inventory somewhere another process rewrites wholesale, because the claim decides who may issue and the
// ledger is still what an operator reads.
func enrolIssuerNeedsExclusiveStore(hasDeviceCA bool, inventoryStore string) bool {
	if !hasDeviceCA {
		return false
	}
	return storeBackend(inventoryStore) == "postgres"
}

// edgeNodeIdentityForClaims names WHICH node took a claim, for the incident that starts "two certificates for
// one device name". A claim that records only that it happened cannot answer where.
func edgeNodeIdentityForClaims(regionID, listenAddr string) string {
	parts := []string{}
	if r := strings.TrimSpace(regionID); r != "" {
		parts = append(parts, r)
	}
	if a := strings.TrimSpace(listenAddr); a != "" {
		parts = append(parts, a)
	}
	if len(parts) == 0 {
		return "edge"
	}
	return strings.Join(parts, "/")
}

// registerEnrolClaimFreshDeploymentFlag is the operator saying there is no fleet to migrate into the shared
// identity claim.
//
// It is a statement about HISTORY, made once, and that is what separates it from the -enroll-sole-issuer flag
// this thread removed: that one asserted a standing property nobody could check and which could stop being
// true the moment a second node was deployed. This one is checkable in the only way that matters — after it
// is used, the barrier row exists and no later node needs to claim anything about the past again.
//
// In a sibling file because the decomposition ratchet says new flags go in one.
func registerEnrolClaimFreshDeploymentFlag() *bool {
	return flag.Bool("enrol-claim-fresh-deployment", false,
		"declare that this deployment has never enrolled a device, so there is no existing fleet to import into "+
			"the shared identity claim. Required for the FIRST issuing Edge of a new deployment; on an existing "+
			"one, start the Edge that holds the enrolments instead — it declares the migration complete by "+
			"contributing them.")
}

// validAgentReleaseChannel reports whether a channel is one the durable store will accept.
//
// The list is the migration's CHECK constraint (019). Kept as a named predicate so the startup gate and its
// test are the same statement, and beside the migration's values so a reader can compare them.
// ★ EXACT, NOT CASE-FOLDED (2026-08-13, thirtieth review #9b). The CHECK constraint compares literally, so
// "Lab" satisfied this predicate and then failed every INSERT — the gate passed the value that jams the queue,
// which is the one thing it exists to catch. A validator looser than the thing it validates is a validator that
// reports the wrong answer, and here the wrong answer is the dangerous one.
func validAgentReleaseChannel(channel string) bool {
	// ★★ NOT EVEN TrimSpace (2026-08-13, thirty-first review #7). The previous round made this literal "like the
	// column" and kept the trim, while normalizeAgentUpdateReportForRuntime stores the device's UNTRIMMED value
	// — so " stable " passed the predicate and was then refused by the CHECK, 500, retried for ever. That is the
	// self-jam of #9c surviving in a whitespace variant, and the test written for #9b asserted " stable " must be
	// ACCEPTED, which is how it survived: the test encoded the gap.
	//
	// A caller with surrounding spaces should trim before asking, or be told no. This predicate answers exactly
	// the question the database answers, which is the only way it can be the gate for it.
	switch channel {
	case "lab", "alpha", "pilot", "stable":
		return true
	default:
		return false
	}
}
