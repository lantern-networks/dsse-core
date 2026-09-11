package main

// procbypass.go — the pure (OS-independent) core of the steer-all AppID safety decision. Kept untagged so
// it builds and unit-tests on any platform; the Windows TCP-table / image-path resolution lives in
// procbypass_windows.go behind this decision. See that file for the ownership-resolution mechanics.

// AppID-bypass reason enums (non-secret; safe to log). owner_unresolved is the fail-open case.
const (
	appBypassReasonExcluded   = "appid_excluded"   // owner resolved AND is an excluded app -> passthrough
	appBypassReasonUnresolved = "owner_unresolved" // owner not yet resolvable -> fail-open passthrough
)

// appBypassDecision is the steer-all AppID safety decision (pure; no OS calls).
//
// FAIL-OPEN is the whole point: when a flow's owning app cannot be resolved yet -- a brand-new flow whose
// socket has not landed in the OS TCP table at the instant we see its SYN -- it is PASSED THROUGH, never
// steered. A race on owner resolution must never strand a new connection; steering an unknown-owner flow to
// the edge would default-deny it and kill, e.g., Automation's brand-new api.anthropic.com:443 connection. We
// would rather miss steering a flow than break connectivity. Only a resolved, excluded owner is bypassed
// for the AppID reason; a resolved, non-excluded owner is steered.
//
// This is consistent with "adopt new SYN only": a flow passed through at SYN time is never put in conntrack,
// so even if its owner resolves to a non-excluded app on a later packet, the mid-stream packet still has no
// conntrack entry and stays passed through.
func appBypassDecision(ownerResolved bool, ownerExcluded bool) (bypass bool, reason string) {
	if !ownerResolved {
		return true, appBypassReasonUnresolved
	}
	if ownerExcluded {
		return true, appBypassReasonExcluded
	}
	return false, ""
}
