//go:build windows

package main

import (
	"flag"
	"testing"
)

// ★ The MSI's service line is `--service-run --config-store` and names no mode, so the stand-aside branch —
// which exists so the SCM does not restart-loop an unenrolled box — was never reached: it tested for
// `--mode redirect`. The box fell through to the transport build, exited on the missing pinned CA, and the
// SCM reported that DsseSteer could not be started. Measured on win-dev-1, 2026-08-11.
func TestTheDefaultModeStandsAsideRatherThanFailingToStart(t *testing.T) {
	// The flag's own default, spelled the way main() declares it. This is the value an MSI box runs with.
	if !modeTakesTheNetworkPath("observe") {
		t.Fatal("the default mode does not stand aside, so an unenrolled MSI box exits instead of idling and " +
			"the SCM reports a service that cannot start")
	}
	if !modeTakesTheNetworkPath("redirect") {
		t.Error("redirect must still stand aside — this is the case the branch was written for")
	}
	if !modeTakesTheNetworkPath("inbound") {
		t.Error("inbound enforces on the server-initiated path and has no identity either")
	}
	// A mode nobody has added yet must be covered by default: the safe direction for this list to be wrong in
	// is "a new enforcing mode stands aside", not "a new enforcing mode enforces with no identity".
	if !modeTakesTheNetworkPath("some-future-enforcing-mode") {
		t.Error("an unknown mode must be treated as one that takes the path")
	}
}

// The other half: refusing to answer is not a safe default for the modes that diagnose or repair a box.
func TestDiagnosticAndRecoveryModesStillWorkWithoutAnIdentity(t *testing.T) {
	for _, mode := range []string{"print-config", "recover", "watchdog", "bypass-observe", "enroll"} {
		if modeTakesTheNetworkPath(mode) {
			t.Errorf("%s would idle on an unenrolled box: a print-config that prints nothing, or a recover that "+
				"refuses to give a machine its network back because nobody approved it, is worse than useless", mode)
		}
	}
	// Spelled with surrounding space because the value can arrive from a service argument list.
	if modeTakesTheNetworkPath("  recover  ") {
		t.Error("a mode with surrounding whitespace must resolve to the same answer")
	}
}

// flagWasSet is what keeps the profile derivation from overriding an operator. A value comparison cannot do
// this job: `--mode observe` on a profiled box is a deliberate diagnostic run and looks exactly like silence.
func TestFlagWasSetDistinguishesAnExplicitFlagFromItsDefault(t *testing.T) {
	old := flag.CommandLine
	defer func() { flag.CommandLine = old }()

	flag.CommandLine = flag.NewFlagSet("test", flag.ContinueOnError)
	mode := flag.String("mode", "observe", "")
	steerAll := flag.Bool("steer-all", false, "")
	// --mode is passed with the value that is ALSO its default: the case a value comparison gets wrong.
	if err := flag.CommandLine.Parse([]string{"--mode", "observe"}); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if *mode != "observe" || *steerAll {
		t.Fatalf("unexpected parse result: mode=%q steer-all=%v", *mode, *steerAll)
	}
	if !flagWasSet("mode") {
		t.Error("a flag passed with its default value must count as set, or a deliberate diagnostic run gets " +
			"silently overridden by the profile derivation")
	}
	if flagWasSet("steer-all") {
		t.Error("a flag nobody passed must not count as set, or the derivation never fires and the MSI box " +
			"enforces nothing")
	}
}
