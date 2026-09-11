package main

import "fmt"

// ★★★ THE NUMBER THE LICENCE IS SOLD ON WAS NEVER COMPUTED (2026-08-27).
//
// A vendor licence is addressed to an MSSP and grants a number of AGENTS. So the one quantity that decides
// whether the operator is inside their contract is "how many agents does this deployment have enrolled". Before
// this file, nothing in the tree asked it: every CountAdmitted call named a tenant, and the licence route
// reported `unallocated = seats - allocations.Allocated()` — the operator's own PLAN, not a count of anything.
//
// So a deployment with 500 seats, 200 allocated and 400 devices enrolled reported "300 not yet given to a
// tenant" and no number anywhere said 400. The operator could add the per-tenant rows by eye, and would still
// be wrong: an enrolled entry carrying no tenant appears in NO row, and this route already knows that (it says
// so, as "seat_counting: not_counting").
//
// ★ SEPARATE FROM THE QUOTA GATE ON PURPOSE. Nothing here refuses anything. Seat quotas stopped refusing in
// August by operator decision, and the OSS release has no limit at all — this is the operator's own view of
// their contract, which they need whether or not anything enforces it.
type licenceUsageCounter interface{ CountAdmitted(string) int }

// deploymentAgentsEnrolled counts every enabled enrolled identity in this deployment, tenanted or not.
//
// ★ THE EMPTY TENANT IS THE WHOLE DEPLOYMENT, not "the untenanted ones" — CountAdmitted documents it and the
// per-tenant rows rely on the opposite reading, so this wrapper exists to make the intent unmistakable at the
// call site rather than to save a line.
func deploymentAgentsEnrolled(ledger licenceUsageCounter) int {
	if ledger == nil {
		return 0
	}
	return ledger.CountAdmitted("")
}

// licenceUsageNote is what an operator reads when the deployment is over the number it licensed.
//
// Empty when there is nothing to say. It does NOT tell them anything broke, because nothing did: going past the
// pool is a commercial fact between the operator and their vendor, and the fleet keeps running.
func licenceUsageNote(seats, enrolled int) string {
	if seats <= 0 || enrolled <= seats {
		return ""
	}
	return fmt.Sprintf("this deployment has %d agent(s) enrolled against %d licensed; nothing is refused and "+
		"no device is affected — the licence is counted in agents, so this is a contract to settle with the vendor",
		enrolled, seats)
}
