package main

import (
	"os"
	"strings"
	"testing"
)

// ★★★ A CONTROL THAT REACHES HALF A FLEET HAS TO SAY SO (2026-08-31, found by reading both agents).
//
// -steer-region-failover is a CP-signed steering posture and the Windows agent obeys it: it re-fetches every
// minute and reports the disagreement while one exists. The macOS agent does not read it at all — there,
// region-failover is a CAPABILITY, on when the device holds an agent-policy pin and a (T) transport and off
// when it does not. So an operator who sets this false has turned it off for half a mixed fleet and been told
// nothing.
//
// The fix is the third answer this project keeps arriving at: between "it works" and "it does not" there is
// "it does not reach that platform", and it belongs where the person setting it will read it. Until the macOS
// agent honours the posture, this sentence is the true one — so the check is that it is still being said.
func TestTheRegionFailoverFlagSaysItDoesNotReachMacOS(t *testing.T) {
	body, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(body)
	i := strings.Index(src, `flag.Bool("steer-region-failover"`)
	if i < 0 {
		t.Fatal("the flag is gone; if region-failover stopped being a CP-signed posture, this check should be " +
			"removed deliberately rather than left passing on nothing")
	}
	decl := src[i:]
	if j := strings.Index(decl, "\n\t"+`steer`); j > 0 {
		decl = decl[:j]
	}
	// ★ WHAT THE OPERATOR READS IS THE JOINED STRING, NOT THE SOURCE. Go's concatenation splits a sentence
	// across literals wherever the line got long, so matching the source finds "does NOT stop a " and
	// "capable Mac" in different places and reports a sentence that is there as missing. This test made that
	// mistake on its first run.
	for _, join := range []string{"\"+\n\t\t\"", "\"+\n\t\t\t\"", "\" +\n\t\t\"", "\" +\n\t\t\t\""} {
		decl = strings.ReplaceAll(decl, join, "")
	}
	decl = strings.ReplaceAll(decl, "\"+\n", "")

	for _, want := range []string{"macOS", "CAPABILITY", "does NOT stop a capable Mac"} {
		if !strings.Contains(decl, want) {
			t.Errorf("the flag no longer says %q, so an operator setting it false is told nothing about the "+
				"half of a mixed fleet it does not reach", want)
		}
	}
	// ★ AND IT MUST NOT OVERSTATE. A Mac still fails over only within this deployment's signed region list, so
	// this is a policy that does not arrive rather than a boundary a device can cross.
	if !strings.Contains(decl, "signed region list") {
		t.Error("the flag does not bound the claim: without that, a reader takes this for a residency breach, " +
			"which it is not")
	}
}
