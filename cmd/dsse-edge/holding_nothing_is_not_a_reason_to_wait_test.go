package main

import (
	"os"
	"strings"
	"testing"
)

// ★★★ AN EDGE THAT HELD NOTHING WAITED AN HOUR, AND THAT IS THE HOUR A DEPLOYMENT IS SET UP IN (2026-08-28,
// measured while setting one up).
//
// The fetcher slept an HOUR when no material had a stated expiry, reasoning that a deployment issuing none
// need not be asked often. An Edge cannot tell "this deployment issues none" from "nobody has set an
// organization up YET" — and the second is the normal state of a deployment being installed, which is exactly
// when organizations are created.
//
// Walked: the Edge fetched at 00:56 and was handed nothing; the operator created an organization's device and
// interception authorities in the Console at 01:02; the Edge had already decided to look again at 01:56. The
// Console said the customer's own root was in force, the Edge went on signing under the shared one, and
// nothing anywhere said why.
//
// ★ THE CHEAP QUESTION IS WHAT MAKES ASKING OFTEN SAFE: known_generation is compared first and an unchanged
// answer mints nothing. There was never a cost to pay here.
func TestAnEdgeHoldingNoMaterialStillAsksOften(t *testing.T) {
	body, err := os.ReadFile("tenant_transport_material_fetch.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(body)
	if strings.Contains(source, "wait = time.Hour") {
		t.Error("an Edge that holds no organization material still backs off to an hour — which is the hour " +
			"an operator spends creating those organizations, and nothing tells them why their customer's " +
			"root is not being used")
	}
	// ★★ THE CONTROL, AND IT IS WHAT KEEPS THIS FROM BEING "ASK CONSTANTLY": a FAILING fetch still backs off.
	// Asking often is safe because the answer is cheap; a control plane that is refusing or unreachable is
	// not made better by being asked every minute.
	//
	// ★ THE TEN MINUTES IS NOW A CEILING, NOT THE INTERVAL (2026-09-08). backoffAfterFailure shortens it
	// when the material this node holds would end first — see the test beside it — so what this control
	// asserts is that a failure still backs off AT ALL, and that the ordinary back-off is still ten
	// minutes when there is room for it.
	if !strings.Contains(source, "wait = f.backoffAfterFailure(time.Now(), 10*time.Minute)") {
		t.Error("a failing fetch no longer backs off — the cheap-question argument covers an answer, not an " +
			"error, and hammering an unreachable control plane helps nobody")
	}
	if !strings.Contains(source, "wait := time.Minute") {
		t.Error("the ordinary cadence is no longer a minute")
	}
}
