package main

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/model"
)

// ★ THE PREDICATE MUST BE AS STRICT AS THE COLUMN (2026-08-13, thirtieth review #9b). The migration's CHECK
// compares literally, so a case-folded predicate passed "Lab" and every INSERT then failed — the gate admitting
// exactly the value it exists to catch. A validator looser than the thing it validates reports the wrong
// answer, and here the wrong answer jams every device's report queue.
func TestTheChannelPredicateIsAsStrictAsTheDatabase(t *testing.T) {
	for _, ok := range []string{"lab", "alpha", "pilot", "stable"} {
		if !validAgentReleaseChannel(ok) {
			t.Errorf("%q is one the store accepts and was refused", ok)
		}
	}
	// ★ " stable " BELONGS IN THIS LIST, and the first version of this test put it in the other one (2026-08-13,
	// thirty-first review #7). The CHECK constraint compares literally, so a padded value is one the database
	// refuses — and the report path stored the device's untrimmed string, so a device reporting " stable "
	// passed this predicate and then jammed its own queue for ever. A test that asserts the gap is how the gap
	// survives a round of fixing it.
	for _, bad := range []string{"Lab", "STABLE", "Beta", "beta", "", "prod", " stable ", "stable "} {
		if validAgentReleaseChannel(bad) {
			t.Errorf("%q was accepted — the database will refuse it, the route answers 500, and both clients "+
				"retry for ever", bad)
		}
	}
}

// ★★ AND A DEVICE'S OWN CHANNEL IS NOT TRUSTED TO BE STORABLE (#9c). The startup gate checks the operator's
// flag; this field arrives in the report body. One endpoint sending "Beta" failed the CHECK, was answered 500,
// and retried for ever — jamming its own drain on a value it chose.
func TestADeviceSuppliedChannelCannotJamItsOwnQueue(t *testing.T) {
	device := model.Device{ID: "dev_1", TenantID: "t1"}
	event := model.AgentUpdateEvent{DeviceID: "dev_1", TenantID: "t1", ReleaseChannel: "Beta",
		UpdateStatus: "installed", CurrentAgentVersion: "0.2.9"}

	got, err := normalizeAgentUpdateReportForRuntime(event, device, "0.2.9", "stable", time.Now().UTC())
	if err != nil {
		t.Fatalf("the report was rejected outright, losing the outcome: %v", err)
	}
	if !validAgentReleaseChannel(got.ReleaseChannel) {
		t.Fatalf("release_channel is %q — the database will refuse this row and the device will retry for ever",
			got.ReleaseChannel)
	}
	if got.ReleaseChannel != "stable" {
		t.Fatalf("want the edge's own channel, got %q", got.ReleaseChannel)
	}
	// The outcome itself must survive: the label is worth less than the event it labels.
	if got.UpdateStatus != "installed" || !strings.Contains(got.CurrentAgentVersion, "0.2.9") {
		t.Fatalf("the outcome was altered while fixing its label: %+v", got)
	}
}

// ★★ THE GATE ITSELF, NOT THE PREDICATE (2026-08-13, thirty-first review #2). This check has now been in the
// wrong place twice: first inside `if enrollSigner != nil`, so every Edge that issues no certificates skipped
// it, and then — while moving it — inside `if lerr := SetPersisterChecked(…); lerr != nil`, so it ran ONLY when
// the enrolled inventory failed to load. A healthy Edge started happily with -agent-release-channel=Beta.
//
// Both mistakes are invisible to a test of validAgentReleaseChannel, which is the only thing the previous round
// added, and both were invisible in review. What distinguishes them is nesting, so nesting is what is asserted:
// the call sits at the function's own indentation, not inside a condition.
//
// A source assertion is the honest tool here. The gate ends in log.Fatalf, so an in-process test cannot reach
// it, and the alternative — trusting that nobody moves it into a branch again — has now failed twice.
func TestTheChannelGateIsNotNestedInsideACondition(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	const call = "if !validAgentReleaseChannel(*agentReleaseChannel) {"
	var found bool
	for _, line := range strings.Split(string(src), "\n") {
		if !strings.Contains(line, call) {
			continue
		}
		found = true
		// One tab = the body of main/run. Two or more means it is inside something, which is how it died twice.
		if indent := len(line) - len(strings.TrimLeft(line, "\t")); indent != 1 {
			t.Fatalf("the release-channel gate is nested %d levels deep:\n  %s\n\nIt must run on every start. "+
				"Inside a condition it runs only when that condition holds — which has meant 'only when this Edge "+
				"issues certificates' and 'only when the enrolled inventory failed to load', and in both cases a "+
				"healthy Edge started with a channel the database will refuse.", indent, strings.TrimSpace(line))
		}
	}
	if !found {
		t.Fatal("the release-channel gate is not called from main.go at all — a predicate nobody calls is a " +
			"comment with a test attached")
	}
}

// And the report path trims before it judges, so a sloppy device is corrected rather than jammed.
func TestADeviceReportingAPaddedChannelIsStoredAsOneTheDatabaseAccepts(t *testing.T) {
	got, err := normalizeAgentUpdateReportForRuntime(
		model.AgentUpdateEvent{DeviceID: "dev_1", TenantID: "t1", ReleaseChannel: " stable ",
			UpdateStatus: "installed", CurrentAgentVersion: "0.2.9"},
		model.Device{ID: "dev_1", TenantID: "t1"}, "0.2.9", "stable", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if got.ReleaseChannel != "stable" {
		t.Fatalf("stored %q — the CHECK constraint compares literally, so this row is refused and the device "+
			"retries for ever", got.ReleaseChannel)
	}
}
