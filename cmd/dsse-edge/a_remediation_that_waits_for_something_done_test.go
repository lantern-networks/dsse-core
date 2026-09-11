package main

import (
	"strings"
	"testing"
)

// ★★★ A REMEDIATION THAT TOLD THE OPERATOR TO WAIT FOR SOMETHING ALREADY DONE — AND FOR A THING THEY SHOULD
// NOT BUILD ANYWAY (2026-08-29).
//
// win-dev-1 spent an evening measuring that intercepted certificates carry no CRL distribution point and no
// AIA, that curl over schannel therefore answers CRYPT_E_NO_REVOCATION_CHECK, and that --ssl-no-revoke makes
// the same request succeed — then asked for a decision. The decision existed, with their own earlier
// measurement written beside it. It had also gone stale: it said "wait for the agent plane to fold onto one
// port and serve a signed, empty CRL from it", and the fold had landed (`agent-facing ports: 1`).
//
// The first fix made the item say "the condition is met, go and serve a CRL". That was wrong too, and the
// operator caught it: with the real lifetimes there is no security in it. A leaf is minted per host by the
// Edge and withdrawn by not minting it; the per-Edge CA expires in twelve hours; the one certificate where
// revocation carries meaning is the tenant's interception CA, and revoking THAT already exists as an act the
// Edges enforce themselves — which is stronger than a CRL, because it does not depend on the client checking.
//
// So this guards two things at once: that the screen no longer tells anyone to wait for the fold, and that it
// does not tell them to build a formality either.
func TestTheRevocationItemNeitherWaitsNorSendsThemToBuildIt(t *testing.T) {
	item := pkiReadinessItemByID(t, assessPKIReadiness(pkiReadinessInput{IntermediateActive: true}),
		"interception_leaf_revocation")

	if item.Status != "ok" {
		t.Fatalf("this is a decision with its reasons written down, not an open task — a permanent attention "+
			"item teaches an operator to skim the list. status=%q", item.Status)
	}
	if strings.Contains(item.Remediation, "wait for the agent plane") {
		t.Fatalf("the remediation still tells the operator to wait for a fold that has already landed:\n%s",
			item.Remediation)
	}
	// It must name the revocation that DOES exist, or the reader concludes this deployment has none.
	if !strings.Contains(item.Remediation, "/admin/interception-intermediate/") {
		t.Fatalf("the remediation does not name the revocation this deployment actually performs, so it reads "+
			"as though there is none:\n%s", item.Remediation)
	}
	// And the loop, because it is the trap in the obvious implementation if anyone revisits this.
	if !strings.Contains(item.Remediation, "WITHOUT being steered") {
		t.Fatalf("the remediation does not warn that a CRL address fetched through the tunnel is itself "+
			"intercepted:\n%s", item.Remediation)
	}
	// The consequence must still say what a strict client does, because that is how an operator recognises it.
	if !strings.Contains(item.Consequence, "revocation") {
		t.Fatalf("the consequence no longer describes the failure a strict client produces:\n%s", item.Consequence)
	}
}

func pkiReadinessItemByID(t *testing.T, report pkiReadinessReport, id string) pkiReadinessItem {
	t.Helper()
	for _, item := range report.Items {
		if item.ID == id {
			return item
		}
	}
	t.Fatalf("no readiness item %q — this test is measuring nothing", id)
	return pkiReadinessItem{}
}
