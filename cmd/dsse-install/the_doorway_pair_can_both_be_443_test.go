package main

import (
	"strings"
	"testing"
)

// ★★★ A PAIR OF DOORS COULD ONLY EVER BE TWO PORTS (2026-08-28, measured on the first deployment where every
// component had its own machine).
//
// The doorway is a PAIR — losing one must not take the region's agent plane or its administration with it —
// and every mouth of this product is 443. A host has one 443 per ADDRESS, so on one machine the two doors
// could only be 18443 and 18444, and that is what a fresh deployment published even on machines that had
// nothing else on 443. The compose file's own comment says what it should be: "on a real host it is 443:443,
// which is the whole point — a device, a connector and an administrator all arrive through some enterprise's
// proxy, and a non-standard port is where they stop".
//
// So each door binds an ADDRESS. Empty is every interface, which is exactly what a one-host rendering had.
func TestEachFrontDoorCanBindItsOwnAddress(t *testing.T) {
	dir := t.TempDir()
	if err := run(dir, "dsse.example", "Test Deployment", 10, false); err != nil {
		t.Fatalf("install: %v", err)
	}
	compose := composeForShape(t, dir, machineShape{holds: regionShapeStateBearing, edges: true})
	// ★ ONE DOOR SINCE 2026-09-02. The pair is gone — a region whose door stops answering is a region a device
	// fails over out of — so what has to hold is that THE door can be given an address of its own.
	for _, want := range []string{"${DSSE_REGION_BIND_A:-}"} {
		if !strings.Contains(compose, want) {
			t.Errorf("the front door cannot be given an address of its own (%s), so every deployment "+
				"publishes its doorway on a port an enterprise proxy stops at", want)
		}
	}
	// ★ AND THE ANSWER HAS A PLACE IN THE FILE THE OPERATOR EDITS, with what leaving it empty costs. It is
	// the one value in deployment.env that differs between the copies of it, which is worth saying out loud.
	env := deploymentFileContents(t, dir, "deployment.env")
	if !strings.Contains(env, "DSSE_REGION_BIND_A") {
		t.Error("deployment.env names no DSSE_REGION_BIND_A, so the address each door binds is a value only " +
			"the compose file mentions and nothing tells an operator to set")
	}
	if !strings.Contains(strings.ToUpper(env), "PER MACHINE") {
		t.Error("nothing says this value differs between machines — every other line in deployment.env is " +
			"the same on all of them, and an operator copying the file would reasonably expect this to be too")
	}
}
