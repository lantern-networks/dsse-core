package main

import (
	"strings"
	"testing"
)

// ★ THE VERDICT MUST NOT NAME A FALLBACK THIS DEPLOYMENT NO LONGER HAS (2026-08-20).
//
// The dedicated recovery listener was closed on 2026-08-19 once every device had been measured onto the SNI,
// and the bundle stopped announcing the endpoint with it. The verdict sentence kept saying "the dedicated
// recovery port must stay open" — which, right after a restart when nobody has reported yet, is the first
// thing an operator reads about recovery, and it points at a port that is gone. What is at stake after the
// close is the opposite: a device NOT on the list has no way back if its certificate expires.
func TestTheRecoveryVerdictSaysWhatIsActuallyAtStake(t *testing.T) {
	notReady := recoveryNameReadiness{Name: "recovery.dsse.invalid", Silent: []string{"win-dev-1"}}

	stillThere := notReady.Line()
	if !strings.Contains(stillThere, "must stay open") {
		t.Fatalf("with the port still offered, the verdict no longer says to keep it: %s", stillThere)
	}

	notReady.DedicatedPortRetired = true
	retired := notReady.Line()
	if strings.Contains(retired, "must stay open") {
		t.Fatalf("the verdict tells the operator to keep a port this deployment has already retired: %s", retired)
	}
	if !strings.Contains(retired, "no way back") {
		t.Fatalf("the verdict does not say what is at stake once the port is gone: %s", retired)
	}

	ready := recoveryNameReadiness{Name: "recovery.dsse.invalid", Holds: []string{"mac-dev-1"},
		DedicatedPortRetired: true}
	if line := ready.Line(); strings.Contains(line, "may close") {
		t.Fatalf("the verdict offers to close a port that is already closed: %s", line)
	}
}
