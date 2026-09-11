package main

import "fmt"

// validateFailOpenPosture is the PRODUCTION GUARD for --fail-open. Enabling fail-open changes an Edge/tunnel
// OUTAGE from a DENY into an ENFORCEMENT BYPASS: on an unreachable Edge, DNS forwards upstream and TCP egresses
// UNMEDIATED, and on a SUSTAINED outage the agent tears steering down to the native network entirely. That means
// anyone who can make the Edge unreachable (an on-path attacker on a hostile network, a malicious local admin)
// can disable zero-trust on the box — the opposite of the steer-all / fail-closed North Star.
//
// So fail-open must NOT be silently enablable in production. It requires an explicit --acknowledge-fail-open;
// without it the agent refuses to start. This makes the DEFAULT (no acknowledgment) STRUCTURALLY fail-closed: a
// production deploy / service-install that does not pass the acknowledgment cannot run fail-open even if
// --fail-open leaks into its args. Pure + platform-neutral so it is unit-tested on any OS (the agent itself is
// Windows-only).
func validateFailOpenPosture(failOpen, acknowledged bool) error {
	if failOpen && !acknowledged {
		return fmt.Errorf("--fail-open disables zero-trust enforcement on an Edge outage " +
			"(Edge unreachable => DNS upstream + TCP UNMEDIATED; sustained outage => steering torn down to the " +
			"native network), so anyone who can make the Edge unreachable can bypass enforcement. It is a " +
			"stabilization-ONLY posture. Re-run with --acknowledge-fail-open, or drop --fail-open for " +
			"production fail-closed")
	}
	return nil
}

// failOpenPostureBanner is the loud startup warning shown when fail-open IS enabled (acknowledged), so the
// degraded security posture is never silent in the logs.
//
// ★★★ IT ALSO SAYS HOW TO LEAVE, BECAUSE THERE IS NO LOCAL WAY OUT (2026-08-31, measured on win-dev-1).
// Everything above tells an operator what fail-open DOES. Nobody enables a stabilization posture intending to
// keep it, so the sentence they actually need is about getting back — and the way back is not where anyone
// looks for it: re-applying the profile that preceded this one is REFUSED by the anti-rollback floor, exactly
// as it should be (replaying an older signed profile would otherwise be enough to walk a fleet back to a
// weaker posture). Leaving fail-open therefore requires the control plane to issue a NEW profile.
//
// ★ AND THE TRAP IS IN THE ORDER: the reason to reach for fail-open is usually that the deployment is
// unreachable — which is the same condition that puts the new profile out of reach. Measured today only
// because the regions came back BEFORE the attempt to restore; with the two events the other way round there
// is no way back at all. That is not a defect in the floor. It is what this posture costs, and it belongs in
// the warning rather than in a runbook nobody opens during an outage.
func failOpenPostureBanner(disarmAfter fmt.Stringer) string {
	return "⚠ FAIL-OPEN ENABLED (acknowledged): zero-trust enforcement is NOT guaranteed. An " +
		"Edge/tunnel outage lets traffic egress UNMEDIATED, and a sustained outage (>" + disarmAfter.String() +
		") tears steering down to the native network. STABILIZATION ONLY — never enable in production. " +
		"★ AND THERE IS NO LOCAL WAY BACK: the anti-rollback floor refuses the profile that preceded this " +
		"one, so leaving fail-open needs the control plane to issue a NEW profile. If you enabled this to " +
		"diagnose an outage of that control plane, the way back is behind the thing you could not reach."
}
