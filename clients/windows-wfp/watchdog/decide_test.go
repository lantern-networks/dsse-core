package main

import (
	"strings"
	"testing"
	"time"
)

// blackHole is the state this process exists for: driver redirecting, nobody accepting. A real black-holed
// box also has DNS taken over — the agent points the resolver at itself whenever it steers — so the fixture
// says so rather than leaving it unknown.
func blackHole() Observation {
	return Observation{
		DriverPresent: true, DriverStateKnown: true, DriverArmed: true,
		DriverOwnerPresent: false, AgentStateKnown: true, AgentRunning: false,
		DNSResidueKnown: true, DNSTakeoverResidue: true,
		// A real box has an agent binary to run recovery with; win-dev-1's real ImagePath is used so the
		// fixture is not quietly describing the MSI layout only.
		RecoveryToolPath: `C:\Program Files\Lantern\DSSE\steer.exe`,
	}
}

// dnsOrphanedOnly is what win-dev-1 actually produced on 2026-08-09 once the driver's handle-close disarm
// worked: a fail-open box whose redirect cleared itself, whose agent is gone, and whose resolver still points
// at the dead loopback proxy. The first version of Decide answered "none" here.
func dnsOrphanedOnly() Observation {
	o := blackHole()
	o.DriverArmed = false // the driver disarmed itself on owner-handle close
	o.DriverOwnerPresent = false
	return o
}

func TestRecoversABlackHoledBox(t *testing.T) {
	d := Decide(blackHole())
	if d.Action != ActionRecover {
		t.Fatalf("got %s (%s), want recover", d.Action, d.Reason)
	}
	if !strings.Contains(d.Reason, "refused") {
		t.Fatalf("the reason must say what the user is experiencing, got %q", d.Reason)
	}
}

func TestLeavesNormalSteeringAlone(t *testing.T) {
	o := blackHole()
	o.DriverOwnerPresent = true
	o.AgentRunning = true
	if d := Decide(o); d.Action != ActionNone {
		t.Fatalf("normal steering must not be touched: %s (%s)", d.Action, d.Reason)
	}
}

// ★ The regression win-dev-1 found. The driver's handle-close disarm closed the black hole on fail-open boxes
// and, by clearing `armed`, moved them into the state Decide used to answer "none" for. The kernel cannot
// restore a resolver, so nothing else was ever going to.
func TestRecoversAnAgentThatDiedLeavingTheResolverPointedAtItself(t *testing.T) {
	d := Decide(dnsOrphanedOnly())
	if d.Action != ActionRecover {
		t.Fatalf("got %s (%s), want recover — this is the fail-open case after the driver auto-disarms", d.Action, d.Reason)
	}
	// The reason has to explain why the box does not LOOK broken, or an operator reading the log will assume
	// the watchdog fired for nothing.
	if !strings.Contains(d.Reason, "flaky") {
		t.Fatalf("the reason must say how this presents to a user, got %q", d.Reason)
	}
}

// The same residue while the agent is RUNNING is the normal steady state — DNS is taken over for as long as
// the box is steered. Acting on it would tear DNS off every healthy machine every 15 seconds.
func TestDNSResidueWithTheAgentRunningIsNormal(t *testing.T) {
	o := dnsOrphanedOnly()
	o.AgentRunning = true
	if d := Decide(o); d.Action != ActionNone {
		t.Fatalf("residue plus a live agent is normal steering: got %s (%s)", d.Action, d.Reason)
	}

	steering := blackHole() // armed + residue + owner present + agent running
	steering.DriverOwnerPresent = true
	steering.AgentRunning = true
	if d := Decide(steering); d.Action != ActionNone {
		t.Fatalf("a fully healthy steered box must be left alone: got %s (%s)", d.Action, d.Reason)
	}
}

// A clean agent stop restores DNS and consumes the backup, so a stopped-but-tidy box has nothing to undo.
func TestACleanlyStoppedAgentLeavesNothingToRecover(t *testing.T) {
	o := dnsOrphanedOnly()
	o.DNSTakeoverResidue = false
	if d := Decide(o); d.Action != ActionNone {
		t.Fatalf("got %s (%s), want none", d.Action, d.Reason)
	}
}

// The most expensive wrong answer: tearing enforcement off a machine that was fine. Each of these must NOT
// recover.
func TestNeverRecoversWhenItWouldRemoveWorkingEnforcement(t *testing.T) {
	tidy := func(o *Observation) { o.DNSTakeoverResidue = false } // nothing left behind
	for name, mut := range map[string]func(*Observation){
		"not armed, DNS restored":    func(o *Observation) { o.DriverArmed = false; tidy(o) },
		"observe-only":               func(o *Observation) { o.DriverObserveOnly = true; o.DriverOwnerPresent = true; o.AgentRunning = true },
		"observe-only, agent gone":   func(o *Observation) { o.DriverObserveOnly = true; tidy(o) },
		"no driver at all":           func(o *Observation) { o.DriverPresent = false; o.DriverArmed = false; tidy(o) },
		"agent up, no owner handle":  func(o *Observation) { o.AgentRunning = true },
		"driver state unreadable":    func(o *Observation) { o.DriverStateKnown = false; tidy(o) },
		"agent state unknown":        func(o *Observation) { o.AgentStateKnown = false },
		"agent unknown, driver fine": func(o *Observation) { o.AgentStateKnown = false; o.DriverOwnerPresent = true },
		"residue unknown, not armed": func(o *Observation) { o.DriverArmed = false; o.DNSResidueKnown = false },
	} {
		o := blackHole()
		mut(&o)
		if d := Decide(o); d.Action == ActionRecover {
			t.Errorf("%s: recovered, but must not (%s)", name, d.Reason)
		}
	}
}

// An unreadable driver must not become a licence to skip recovery when the OTHER evidence is conclusive: the
// resolver residue alone is enough, and it is readable without the driver.
func TestDNSResidueRecoversEvenWhenTheDriverCannotBeRead(t *testing.T) {
	o := dnsOrphanedOnly()
	o.DriverStateKnown = false
	if d := Decide(o); d.Action != ActionRecover {
		t.Fatalf("got %s (%s), want recover — the residue is conclusive on its own", d.Action, d.Reason)
	}
}

// And the reverse: nothing readable, nothing concluded, so report rather than act or shrug.
func TestNothingReadableIsReportedNotShruggedOff(t *testing.T) {
	o := dnsOrphanedOnly()
	o.DriverStateKnown = false
	o.DNSResidueKnown = false
	if d := Decide(o); d.Action != ActionReportOnly {
		t.Fatalf("got %s (%s), want report_only", d.Action, d.Reason)
	}
}

// An unknown must surface as report-only, not silently as "fine". A watchdog whose failed read looks like a
// healthy box is the failure mode the three-state fields exist to prevent.
func TestUnknownsAreReportedNotSwallowed(t *testing.T) {
	// An unreadable driver, with the other evidence saying nothing is wrong. The uncertainty must surface
	// rather than resolve into "fine". (When the residue IS conclusive it overrides this — see
	// TestDNSResidueRecoversEvenWhenTheDriverCannotBeRead.)
	unreadable := blackHole()
	unreadable.DriverStateKnown = false
	unreadable.DNSTakeoverResidue = false
	d := Decide(unreadable)
	if d.Action != ActionReportOnly {
		t.Fatalf("an unreadable driver must be reported, got %s (%s)", d.Action, d.Reason)
	}
	if !strings.Contains(d.Reason, "cannot tell") {
		t.Fatalf("reason must admit the uncertainty, got %q", d.Reason)
	}

	noService := blackHole()
	noService.AgentStateKnown = false
	if d := Decide(noService); d.Action != ActionReportOnly {
		t.Fatalf("an unqueryable service manager must be reported, got %s", d.Action)
	}
}

// A driver too old to have the arming handle reports OwnerPresent=false forever. If the agent is running,
// that is normal for that pair and must not be mistaken for a dead agent.
func TestAnAgentRunningWithoutAnOwnerHandleIsNotRecovered(t *testing.T) {
	o := blackHole()
	o.AgentRunning = true // no owner handle, but the service is up
	d := Decide(o)
	if d.Action != ActionReportOnly {
		t.Fatalf("got %s, want report_only (%s)", d.Action, d.Reason)
	}
	if !strings.Contains(d.Reason, "predates") {
		t.Fatalf("reason should name the old-driver case, got %q", d.Reason)
	}
}

// The service being gone is sufficient on its own; waiting for the owner handle to be reaped too would just
// lengthen the outage.
func TestServiceGoneIsEnoughEvenIfTheHandleLingers(t *testing.T) {
	o := blackHole()
	o.DriverOwnerPresent = true // not yet reaped
	if d := Decide(o); d.Action != ActionRecover {
		t.Fatalf("got %s, want recover (%s)", d.Action, d.Reason)
	}
}

func TestRecoveryLimiterStopsFlapping(t *testing.T) {
	l := &RecoveryLimiter{Max: 3, Window: time.Hour}
	base := time.Date(2026, 8, 9, 3, 0, 0, 0, time.UTC)
	for i := 0; i < 3; i++ {
		if ok, why := l.Allow(base.Add(time.Duration(i) * time.Minute)); !ok {
			t.Fatalf("attempt %d refused: %s", i+1, why)
		}
	}
	ok, why := l.Allow(base.Add(4 * time.Minute))
	if ok {
		t.Fatalf("the 4th recovery inside the window must be refused")
	}
	if !strings.Contains(why, "flap") {
		t.Fatalf("the refusal must explain itself, got %q", why)
	}

	// The window rolls: once the old attempts age out, recovery is allowed again. A limiter that latched
	// permanently would leave a box black-holed forever after one bad hour.
	if ok, why := l.Allow(base.Add(2 * time.Hour)); !ok {
		t.Fatalf("after the window passes, recovery must be allowed again: %s", why)
	}
}

func TestRecoveryLimiterUnboundedWhenMaxIsZero(t *testing.T) {
	l := &RecoveryLimiter{}
	for i := 0; i < 10; i++ {
		if ok, _ := l.Allow(time.Date(2026, 8, 9, 3, i, 0, 0, time.UTC)); !ok {
			t.Fatalf("Max=0 means no limit")
		}
	}
}

// The watchdog must be able to name the agent binary it has to launch. This is not a parsing nicety: on
// win-dev-1, 2026-08-09, the watchdog decided `recover` on a genuinely black-holed box and then did nothing,
// because it looked for a hard-coded `dsse-steer.exe` next to itself and that box runs `steer.exe`. The first
// case below is that box's real ImagePath.
func TestExecutableFromServiceCommandLineFindsTheAgentWhateverItIsCalled(t *testing.T) {
	for _, tc := range []struct{ name, in, want string }{
		{
			// A hand-deployed endpoint: quoted path with spaces, followed by a long flag list. The flag values
			// are incidental — what is asserted is that the executable is recovered from the quoted prefix and
			// nothing after it is mistaken for part of the path.
			name: "quoted path with spaces and flags",
			in:   `"C:\Program Files\Lantern\DSSE\steer.exe" --service-run --mode redirect --bypass-app somedesktopapp`,
			want: `C:\Program Files\Lantern\DSSE\steer.exe`,
		},
		{
			name: "what the MSI writes",
			in:   `"C:\Program Files\Lantern\DSSE\dsse-steer.exe" --service-run --config-store`,
			want: `C:\Program Files\Lantern\DSSE\dsse-steer.exe`,
		},
		{
			// Unquoted WITH spaces is the case a naive split on the first space gets wrong, and it is the one
			// that would silently pick "C:\Program" and fail the Stat.
			name: "unquoted path containing spaces",
			in:   `C:\Program Files\Lantern\DSSE\steer.exe --service-run`,
			want: `C:\Program Files\Lantern\DSSE\steer.exe`,
		},
		{
			name: "unquoted, no spaces",
			in:   `C:\dsse\steer.exe --service-run`,
			want: `C:\dsse\steer.exe`,
		},
		{
			// Services can carry this prefix; DsseWfp's ImagePath on win-dev-1 does. Handled so it never
			// becomes the reason recovery cannot start.
			name: "kernel-style prefix",
			in:   `\??\C:\Program Files\Lantern\DSSE\steer.exe --service-run`,
			want: `C:\Program Files\Lantern\DSSE\steer.exe`,
		},
		{
			name: "no arguments at all",
			in:   `C:\dsse\steer.exe`,
			want: `C:\dsse\steer.exe`,
		},
		{
			name: "empty",
			in:   "   ",
			want: "",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := ExecutableFromServiceCommandLine(tc.in); got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// ★ The gap win-dev-1 named and I deferred: a dry run reported `recover` on a box where recovery could not
// run, because the binary was only resolved at the moment of acting. Resolving it every tick means the box
// says "I carry a watchdog that cannot save me" on the first quiet tick instead of during the outage.
func TestABoxWhoseRecoveryToolIsMissingSaysSoInsteadOfPromisingToRecover(t *testing.T) {
	o := blackHole()
	o.RecoveryToolPath = ""
	o.RecoveryToolErr = "could not find the steering agent binary to run recovery with; tried: " +
		`the DsseSteer service ImagePath (unreadable: service does not exist); C:\Program Files\DSSE\dsse-steer.exe`

	d := Decide(o)
	if d.Action != ActionCannotRecover {
		t.Fatalf("got %s, want cannot_recover (%s)", d.Action, d.Reason)
	}
	// Both halves have to be in the message. What is wrong with the box does not change because this process
	// cannot fix it, and an operator needs the outage AND the reason nothing is coming.
	if !strings.Contains(d.Reason, "refused") {
		t.Errorf("the reason must still describe the outage, got %q", d.Reason)
	}
	if !strings.Contains(d.Reason, "CANNOT FIX IT") || !strings.Contains(d.Reason, o.RecoveryToolErr) {
		t.Errorf("the reason must say it cannot act, and what it tried, got %q", d.Reason)
	}
	// And it must tell whoever reads it what to do, since the answer is now "a person goes to the box".
	if !strings.Contains(d.Reason, "--mode recover") {
		t.Errorf("the reason must name the manual recovery, got %q", d.Reason)
	}
}

// cannot_recover must be distinct from report_only. They read the same to a naive collector and mean opposite
// things: report_only is "nothing is expected to happen", cannot_recover is "something must".
func TestCannotRecoverIsNotReportOnly(t *testing.T) {
	broken := blackHole()
	broken.RecoveryToolPath = ""
	if Decide(broken).Action == ActionReportOnly {
		t.Fatal("a box that needs recovery and cannot get it must not be filed as report_only")
	}
	if ActionCannotRecover.String() != "cannot_recover" {
		t.Fatalf("the action must be nameable in a log line, got %q", ActionCannotRecover.String())
	}
	// The DNS-only case must also downgrade, not silently keep promising recovery.
	dnsOnly := dnsOrphanedOnly()
	dnsOnly.RecoveryToolPath = ""
	if got := Decide(dnsOnly).Action; got != ActionCannotRecover {
		t.Fatalf("DNS-orphaned with no tool: got %s, want cannot_recover", got)
	}
}

// A missing recovery tool must NOT invent an outage on a healthy box. The only thing it changes is what
// happens when recovery was already warranted.
func TestAMissingRecoveryToolDoesNotAlarmAHealthyBox(t *testing.T) {
	healthy := blackHole()
	healthy.AgentRunning = true
	healthy.DriverOwnerPresent = true
	healthy.RecoveryToolPath = ""
	if d := Decide(healthy); d.Action != ActionNone {
		t.Fatalf("a steering box with no resolvable binary is still healthy: got %s (%s)", d.Action, d.Reason)
	}
}

// --- the post-recovery re-check -------------------------------------------------------------------------
//
// ★ win-dev-1, 2026-08-09: a recovery that WORKED was filed as event 1002, error. The agent came back during
// the recovery window and re-armed the driver, and the re-check read `armed` as failure without ever asking
// whether anything was listening behind it. That is not an edge case on a real box — DsseSteer carries
// RESTART/5000 and recovery took 5.4 s and 9.2 s in the two measured runs, so the agent is DESIGNED to return
// inside the window. An operator who sees "recovery FAILED" on a box that is fine stops reading 1002.

// recoveredBox is what the box looks like when recovery did exactly what it was asked to do.
func recoveredBox() Observation {
	return Observation{
		DriverPresent: true, DriverStateKnown: true, DriverArmed: false,
		AgentStateKnown: true, AgentRunning: false,
		DNSResidueKnown: true, DNSTakeoverResidue: false,
	}
}

func TestPostRecoveryClearedIsTheUnsteeredOutcome(t *testing.T) {
	got, why := ClassifyPostRecovery(recoveredBox())
	if got != PostRecoveryCleared {
		t.Fatalf("got %s (%s), want cleared", got, why)
	}
}

// The measured false alarm. Armed WITH the agent behind it is steering, not a black hole.
func TestTheAgentComingBackDuringRecoveryIsNotAFailure(t *testing.T) {
	o := recoveredBox()
	o.DriverArmed = true
	o.DriverOwnerPresent = true
	o.AgentRunning = true
	o.DNSTakeoverResidue = true // the agent has re-taken DNS; its backup file is supposed to be there again

	got, why := ClassifyPostRecovery(o)
	if got != PostRecoverySteeringResumed {
		t.Fatalf("got %s, want steering_resumed — this is the SCM restart race, and filing it as a failure is "+
			"what teaches operators to ignore the event: %s", got, why)
	}
	if strings.Contains(strings.ToUpper(why), "STILL REFUSING") {
		t.Fatalf("the sentence must not describe an outage on a box that is steering: %q", why)
	}
}

// Mid-startup: the agent is back but has not claimed ownership. There is still a listener, so it is not the
// outage — but the sentence must say ownership is missing rather than claim a clean resume.
func TestSteeringResumedNamesAMissingPolicyOwner(t *testing.T) {
	o := recoveredBox()
	o.DriverArmed = true
	o.AgentRunning = true
	o.DriverOwnerPresent = false
	got, why := ClassifyPostRecovery(o)
	if got != PostRecoverySteeringResumed {
		t.Fatalf("got %s, want steering_resumed (%s)", got, why)
	}
	if !strings.Contains(why, "not claimed") {
		t.Fatalf("an unclaimed policy owner has to be visible in the sentence, got %q", why)
	}
}

// The real failure, which must keep failing. A fix for the false alarm that also swallowed this one would be
// worse than the bug: the whole point of the re-check is that a disarm which silently did not happen looks
// exactly like one that did.
func TestARedirectStillArmedWithNoAgentIsStillAFailure(t *testing.T) {
	o := recoveredBox()
	o.DriverArmed = true
	o.DriverOwnerPresent = false
	o.AgentRunning = false
	got, why := ClassifyPostRecovery(o)
	if got != PostRecoveryStillBroken {
		t.Fatalf("got %s, want still_broken (%s)", got, why)
	}
}

func TestDNSStillOrphanedAfterRecoveryIsAFailure(t *testing.T) {
	o := recoveredBox()
	o.DNSTakeoverResidue = true
	got, _ := ClassifyPostRecovery(o)
	if got != PostRecoveryStillBroken {
		t.Fatalf("got %s, want still_broken — a DNS-only recovery that did not restore DNS is a failed one", got)
	}
}

// Unverifiable must not be reported as success. This is the direction the whole component leans.
func TestAnUnreadableBoxAfterRecoveryIsNotCalledRecovered(t *testing.T) {
	o := recoveredBox()
	o.DriverArmed = true
	o.AgentStateKnown = false
	if got, _ := ClassifyPostRecovery(o); got != PostRecoveryStillBroken {
		t.Fatalf("got %s, want still_broken when the agent state cannot be read", got)
	}
	unreadable := recoveredBox()
	unreadable.DriverStateKnown = false
	if got, _ := ClassifyPostRecovery(unreadable); got != PostRecoveryStillBroken {
		t.Fatalf("got %s, want still_broken when the driver will not answer after recovery", got)
	}
}

// --- where the agent's state lives ----------------------------------------------------------------------
//
// ★ win-dev-1: the residue check went through the same lookup as the runnable binary, so renaming the agent
// blinded it — dns_residue_known=false — and an unknown residue degrades the decision to report_only, which
// made cannot_recover unreachable in the one state it exists to name.

func TestAgentStateDirsUsesTheServiceImagePathEvenWhenTheBinaryIsGone(t *testing.T) {
	dirs := AgentStateDirs(`C:\Program Files\Lantern\DSSE\steer.exe`, `C:\Program Files\Lantern\DSSE\dsse-watchdog.exe`)
	if len(dirs) != 1 {
		t.Fatalf("one install directory, two binaries in it: got %v", dirs)
	}
	if dirs[0] != `C:\Program Files\Lantern\DSSE` {
		t.Fatalf("got %q", dirs[0])
	}
}

// A hand-deployed box can have the agent somewhere other than beside the watchdog. Both are searched, the
// service's own answer first.
func TestAgentStateDirsSearchesBothAndPrefersTheService(t *testing.T) {
	dirs := AgentStateDirs(`C:\dsse\steer.exe`, `C:\Program Files\Lantern\DSSE\dsse-watchdog.exe`)
	want := []string{`C:\dsse`, `C:\Program Files\Lantern\DSSE`}
	if len(dirs) != 2 || dirs[0] != want[0] || dirs[1] != want[1] {
		t.Fatalf("got %v, want %v", dirs, want)
	}
}

// Case differences are the same directory on Windows, and de-duplicating avoids reporting one residue twice.
func TestAgentStateDirsTreatsCaseAsTheSameDirectory(t *testing.T) {
	dirs := AgentStateDirs(`C:\Program Files\Lantern\DSSE\steer.exe`, `c:\program files\lantern\dsse\dsse-watchdog.exe`)
	if len(dirs) != 1 {
		t.Fatalf("got %v, want one directory", dirs)
	}
}

func TestAgentStateDirsSurvivesAnUnknownServicePath(t *testing.T) {
	dirs := AgentStateDirs("", `C:\Program Files\Lantern\DSSE\dsse-watchdog.exe`)
	if len(dirs) != 1 || dirs[0] != `C:\Program Files\Lantern\DSSE` {
		t.Fatalf("got %v", dirs)
	}
	if got := AgentStateDirs("", ""); len(got) != 0 {
		t.Fatalf("nothing known means no directories, got %v", got)
	}
}

// windowsDir must behave on Windows shapes while the test host is a Mac — filepath.Dir would answer "." here
// and the whole thing would pass for the wrong reason.
func TestWindowsDirHandlesTheShapesAWindowsBoxProduces(t *testing.T) {
	cases := map[string]string{
		`C:\Program Files\Lantern\DSSE\steer.exe`: `C:\Program Files\Lantern\DSSE`,
		`C:\steer.exe`: `C:\`,
		`C:\dsse\`:     `C:\`, // a trailing separator names the same place, as filepath.Dir does on Windows
		`steer.exe`:    "",
		"":             "",
	}
	for in, want := range cases {
		if got := windowsDir(in); got != want {
			t.Fatalf("windowsDir(%q) = %q, want %q", in, got, want)
		}
	}
}

// --- event-log throttling -------------------------------------------------------------------------------
//
// ★ win-dev-1: four 1004s, 15 seconds apart, from one unchanged condition. 240 an hour buries the four IDs
// this design numbered stably so a collector could match them.

func TestAnUnchangedConditionIsAnnouncedOnce(t *testing.T) {
	tr := &EventThrottle{ReassertAfter: time.Hour}
	now := time.Date(2026, 8, 9, 11, 0, 0, 0, time.UTC)
	if emit, _ := tr.Observe("report_only|the resolver could not be checked", now); !emit {
		t.Fatal("the first occurrence must always be announced")
	}
	for i := 1; i <= 60; i++ { // 15 minutes of ticks
		at := now.Add(time.Duration(i) * 15 * time.Second)
		if emit, _ := tr.Observe("report_only|the resolver could not be checked", at); emit {
			t.Fatalf("tick %d re-announced an unchanged condition", i)
		}
	}
}

func TestAChangedConditionIsAnnouncedImmediately(t *testing.T) {
	tr := &EventThrottle{ReassertAfter: time.Hour}
	now := time.Date(2026, 8, 9, 11, 0, 0, 0, time.UTC)
	tr.Observe("report_only|A", now)
	if emit, _ := tr.Observe("cannot_recover|B", now.Add(15*time.Second)); !emit {
		t.Fatal("a different condition is new information and must reach the event log")
	}
}

// A problem that lasts all day must not age out of a collector's window silently.
func TestALongRunningConditionIsReasserted(t *testing.T) {
	tr := &EventThrottle{ReassertAfter: time.Hour}
	now := time.Date(2026, 8, 9, 11, 0, 0, 0, time.UTC)
	tr.Observe("report_only|A", now)
	if emit, _ := tr.Observe("report_only|A", now.Add(59*time.Minute)); emit {
		t.Fatal("re-asserted early")
	}
	if emit, _ := tr.Observe("report_only|A", now.Add(time.Hour)); !emit {
		t.Fatal("an unchanged condition must be re-asserted after ReassertAfter")
	}
}

// A collector that saw the alert and never sees a resolution has to assume the box is still broken.
func TestAClearedConditionIsAnnouncedOnceAndThenStaysQuiet(t *testing.T) {
	tr := &EventThrottle{ReassertAfter: time.Hour}
	now := time.Date(2026, 8, 9, 11, 0, 0, 0, time.UTC)
	tr.Observe("report_only|A", now)
	emit, cleared := tr.Observe("", now.Add(15*time.Second))
	if emit {
		t.Fatal("clearing is not an occurrence of the condition")
	}
	if cleared != "report_only|A" {
		t.Fatalf("the cleared condition must be named so the resolution can be matched to the alert, got %q", cleared)
	}
	if _, again := tr.Observe("", now.Add(30*time.Second)); again != "" {
		t.Fatal("a healthy box must be silent, not repeatedly announcing that nothing is wrong")
	}
}

// The same condition returning after it cleared is a NEW incident and must be announced again.
func TestAConditionThatReturnsIsAnnouncedAgain(t *testing.T) {
	tr := &EventThrottle{ReassertAfter: time.Hour}
	now := time.Date(2026, 8, 9, 11, 0, 0, 0, time.UTC)
	tr.Observe("report_only|A", now)
	tr.Observe("", now.Add(time.Minute))
	if emit, _ := tr.Observe("report_only|A", now.Add(2*time.Minute)); !emit {
		t.Fatal("a recurrence is a new incident")
	}
}

// ★★ THE STATE NOBODY OWNED (2026-08-14, measured on win-dev-1).
//
// An unattended update installed a build whose agent exited on its own two minutes later. It exited CLEANLY —
// disarmed the redirect, restored the resolver, restored the NCSI probe — so there was no residue for this
// watchdog to undo and it answered `none`, and the SCM did not restart it either because a graceful exit is
// not a failure. The box was not steering for thirty minutes and nothing said so.
func TestACleanlyStoppedAgentThatShouldBeRunningIsReported(t *testing.T) {
	d := Decide(Observation{
		DriverPresent: true, DriverStateKnown: true, DriverArmed: false,
		AgentStateKnown: true, AgentRunning: false,
		DNSResidueKnown: true, DNSTakeoverResidue: false,
		AgentStartTypeKnown: true, AgentShouldBeRunning: true,
		RecoveryToolPath: `C:\Program Files\DSSE\dsse-steer.exe`,
	})
	if d.Action != ActionReportOnly {
		t.Fatalf("action = %s, want report_only — a tidy exit is not a correct one, and this box is unprotected",
			d.Action)
	}
	if !strings.Contains(d.Reason, "NOT STEERING") {
		t.Errorf("the sentence must say the box is not steering, got %q", d.Reason)
	}
}

// ...and it must NOT act. Starting the agent would make this a supervisor, and the operator's own runbook
// stops DsseSteer deliberately to test things.
func TestTheWatchdogDoesNotStartAStoppedAgentItMerelyReportsIt(t *testing.T) {
	d := Decide(Observation{
		DriverPresent: true, DriverStateKnown: true,
		AgentStateKnown: true, AgentRunning: false,
		DNSResidueKnown: true, DNSTakeoverResidue: false,
		AgentStartTypeKnown: true, AgentShouldBeRunning: true,
		RecoveryToolPath: `C:\Program Files\DSSE\dsse-steer.exe`,
	})
	if d.Action == ActionRecover || d.Action == ActionCannotRecover {
		t.Fatalf("action = %s: recovery undoes residues, and there are none here. Restarting the agent is a "+
			"supervisor's job and this process is not one", d.Action)
	}
}

// A box where the agent is deliberately not started must stay quiet, or the report becomes noise on every
// machine that has DsseSteer disabled on purpose.
func TestAStoppedAgentThatIsNotMeantToRunIsNotReported(t *testing.T) {
	d := Decide(Observation{
		DriverPresent: true, DriverStateKnown: true,
		AgentStateKnown: true, AgentRunning: false,
		DNSResidueKnown: true, DNSTakeoverResidue: false,
		AgentStartTypeKnown: true, AgentShouldBeRunning: false,
	})
	if d.Action != ActionNone {
		t.Fatalf("action = %s, want none on a box that does not start the agent automatically", d.Action)
	}
	if !strings.Contains(d.Reason, "not configured to start automatically") {
		t.Errorf("the quiet answer must say WHY it is quiet, got %q", d.Reason)
	}
}

// An unreadable start type claims nothing. The existing rule — an unknown never authorises action — extends
// to not inventing an alarm out of one.
func TestAnUnreadableStartTypeDoesNotRaiseAnAlarm(t *testing.T) {
	d := Decide(Observation{
		DriverPresent: true, DriverStateKnown: true,
		AgentStateKnown: true, AgentRunning: false,
		DNSResidueKnown: true, DNSTakeoverResidue: false,
		AgentStartTypeKnown: false,
	})
	if d.Action != ActionNone {
		t.Fatalf("action = %s, want none when the start type could not be read", d.Action)
	}
	if !strings.Contains(d.Reason, "could not be read") {
		t.Errorf("the gap must be stated rather than hidden, got %q", d.Reason)
	}
}

// The residue cases still outrank this one: a black-holed box is an outage to fix, not a state to report.
func TestABlackHoledBoxIsStillRecoveredNotMerelyReported(t *testing.T) {
	d := Decide(Observation{
		DriverPresent: true, DriverStateKnown: true, DriverArmed: true,
		AgentStateKnown: true, AgentRunning: false,
		DNSResidueKnown: true, DNSTakeoverResidue: false,
		AgentStartTypeKnown: true, AgentShouldBeRunning: true,
		RecoveryToolPath: `C:\Program Files\DSSE\dsse-steer.exe`,
	})
	if d.Action != ActionRecover {
		t.Fatalf("action = %s, want recover: an armed redirect with no listener is the outage this exists for",
			d.Action)
	}
}
