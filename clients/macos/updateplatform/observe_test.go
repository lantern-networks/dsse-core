package updateplatform

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/agentupdate"
	"github.com/lantern-networks/dsse-core/clients/windows-wfp/rollbackstore"
)

// The fixtures below are REAL output captured from this Mac on 2026-08-10, not invented shapes.
const (
	realIdleOutput = `    | | |   "HIDIdleTime" = 45743685916` + "\n"
	realACOutput   = "Now drawing from 'AC Power'\n -InternalBattery-0 (id=1234)\t100%; charged; 0:00 remaining present: true\n"
	// ★ Unlocked produced NO matching line at all — the key exists only while the screen is locked.
	realUnlockedIoreg = "+-o Root  <class IORegistryEntry, id 0x100000100, retain 15>\n"
	lockedIoreg       = `    "CGSSessionScreenIsLocked" = Yes` + "\n"
)

// ★ The trap in this API, and the reason parseScreenLocked takes an ok flag. A reader that greps for the key
// and finds nothing concludes "not locked" — and so does a reader whose ioreg call FAILED. The two must not
// produce the same answer, because one of them is "somebody may be sitting here".
func TestAFailedIoregIsNotAnUnlockedScreen(t *testing.T) {
	if got := parseScreenLocked("", false, "nagi"); got != lockUnknown {
		t.Fatalf("a failed ioreg produced %v; an unreadable lock state must never read as a definite answer", got)
	}
	if _, known := inUse(lockUnknown); known {
		t.Fatal("unknown became a known answer; the guess never made is 'nobody is here'")
	}
	// And the real unlocked output, which looks identical to a failure if you only grep.
	if got := parseScreenLocked(realUnlockedIoreg, true, "nagi"); got != lockUnlocked {
		t.Fatalf("real unlocked output parsed as %v", got)
	}
}

func TestALockedScreenIsNobodyToInterrupt(t *testing.T) {
	used, known := inUse(parseScreenLocked(lockedIoreg, true, "nagi"))
	if used || !known {
		t.Fatalf("locked: inUse = (%v, %v), want (false, true)", used, known)
	}
	used, known = inUse(parseScreenLocked(realUnlockedIoreg, true, "nagi"))
	if !used || !known {
		t.Fatalf("unlocked with a console user: inUse = (%v, %v), want (true, true)", used, known)
	}
}

// Nobody logged in at the display is a definite "not in use" — the same answer the Windows fold gives for a
// machine with no interactive sessions, so a mixed fleet reads one way.
func TestNobodyAtTheDisplayIsDefinitelyNotInUse(t *testing.T) {
	for _, user := range []string{"root", "", "  "} {
		if got := parseScreenLocked(realUnlockedIoreg, true, user); got != lockNoConsoleUser {
			t.Errorf("console user %q parsed as %v, want lockNoConsoleUser", user, got)
		}
	}
	used, known := inUse(lockNoConsoleUser)
	if used || !known {
		t.Fatalf("inUse = (%v, %v), want (false, true)", used, known)
	}
}

// ★ Idle is measurable here and is NOT on Windows. Pinned against the real number so the parse cannot quietly
// start returning nanoseconds as seconds — a 45-second idle read as 45 nanoseconds would satisfy any window.
func TestIdleIsParsedFromTheRealIoregOutput(t *testing.T) {
	got, known := parseHIDIdle(realIdleOutput, true)
	if !known {
		t.Fatal("the real ioreg output did not yield an idle time")
	}
	if got < 45*time.Second || got > 46*time.Second {
		t.Fatalf("idle = %s, want ~45.7s — the units are nanoseconds and a wrong scale satisfies every window", got)
	}
	if _, known := parseHIDIdle("", false); known {
		t.Fatal("a failed ioreg produced a known idle time")
	}
}

// The most recent input anywhere: several nodes report and the smallest is the answer.
func TestIdleTakesTheMostRecentInputAcrossNodes(t *testing.T) {
	out := `"HIDIdleTime" = 900000000000` + "\n" + `"HIDIdleTime" = 3000000000` + "\n"
	got, known := parseHIDIdle(out, true)
	if !known || got != 3*time.Second {
		t.Fatalf("idle = %s (known=%v), want 3s", got, known)
	}
}

func TestPowerIsParsedFromRealPmsetOutput(t *testing.T) {
	ac, known := parseACPower(realACOutput, true)
	if !ac || !known {
		t.Fatalf("AC = (%v, %v), want (true, true)", ac, known)
	}
	batt, known := parseACPower("Now drawing from 'Battery Power'\n", true)
	if batt || !known {
		t.Fatalf("battery = (%v, %v), want (false, true)", batt, known)
	}
	// Anything unrecognised is unknown, never "probably plugged in": the gate refuses on an unknown power
	// state and inventing one would defeat a check somebody turned on.
	if _, known := parseACPower("something new in a future macOS\n", true); known {
		t.Fatal("an unrecognised pmset answer became a known power state")
	}
}

// --- the running version ------------------------------------------------------------------------------------

func freshMarker(now time.Time) runtimeMarker {
	return runtimeMarker{Version: "0.1.0+abcd", PID: 42, StartedAt: now.Add(-time.Hour).Format(time.RFC3339),
		HeartbeatAt: now.Add(-5 * time.Second).Format(time.RFC3339)}
}

func TestALiveExtensionReportsItsVersion(t *testing.T) {
	now := time.Now()
	got, err := resolveRunningVersion(freshMarker(now), true, now)
	if err != nil || got != "0.1.0+abcd" {
		t.Fatalf("got (%q, %v)", got, err)
	}
}

// ★ The rule this platform had to satisfy rather than define: a value alone is a memory. A marker that stopped
// being refreshed is a dead extension, and the version it last recorded must not gate an update.
func TestAStaleMarkerIsNotARunningVersion(t *testing.T) {
	now := time.Now()
	m := freshMarker(now)
	m.HeartbeatAt = now.Add(-10 * time.Minute).Format(time.RFC3339)

	_, err := resolveRunningVersion(m, true, now)
	if !errors.Is(err, agentupdate.ErrAgentNotRunning) {
		t.Fatalf("err = %v, want ErrAgentNotRunning", err)
	}
	if !strings.Contains(err.Error(), "0.1.0+abcd") || !strings.Contains(err.Error(), "memory") {
		t.Fatalf("the stale value belongs in the prose so a human can use it and a machine cannot: %v", err)
	}
}

func TestNoMarkerIsNotRunningRatherThanUnknown(t *testing.T) {
	if _, err := resolveRunningVersion(runtimeMarker{}, false, time.Now()); !errors.Is(err, agentupdate.ErrAgentNotRunning) {
		t.Fatalf("err = %v, want ErrAgentNotRunning", err)
	}
}

// A running extension that records no version is the other sentinel — that device needs an install, not a
// recovery, and it must be countable rather than folded in with dead agents.
func TestARunningExtensionWithNoVersionIsItsOwnCase(t *testing.T) {
	now := time.Now()
	m := freshMarker(now)
	m.Version = ""
	_, err := resolveRunningVersion(m, true, now)
	if !errors.Is(err, agentupdate.ErrRunningVersionUnknown) {
		t.Fatalf("err = %v, want ErrRunningVersionUnknown", err)
	}
}

// An unparseable heartbeat must not be read as fresh: that would credit a dead extension with running a
// version, which is the single thing this whole mechanism exists to prevent.
func TestAnUnreadableHeartbeatIsNotFresh(t *testing.T) {
	m := freshMarker(time.Now())
	m.HeartbeatAt = "yesterday"
	if _, err := resolveRunningVersion(m, true, time.Now()); !errors.Is(err, agentupdate.ErrAgentNotRunning) {
		t.Fatalf("err = %v, want ErrAgentNotRunning", err)
	}
}

// ★ CROSS-LANGUAGE: the exact bytes the Swift extension wrote on this machine, read by the Go side.
//
// Captured from /Library/Application Support/Dsse/runtime_version.json on 2026-08-10, minutes after the NE was
// redeployed with DsseRuntimeMarker. It is here rather than as a shape someone typed out because the failure
// this guards is silent in the worst way: if the writer used `heartbeatAt` and the reader expects
// `heartbeat_at`, encoding/json simply leaves the field empty, the resolver sees an unparseable heartbeat, and
// EVERY Mac in the fleet is reported as not-running forever. Nothing errors. The updater just refuses, quietly
// and correctly, on a device that is perfectly healthy.
//
// The version in it also matched what the Console showed for this device at the same moment
// (0.1.0+20260810102048), which is the other half worth pinning: the marker and the heartbeat both come from
// DsseDeviceHeartbeat.agentVersion(), so they agree by construction rather than by two call sites staying in
// step — and now that is observed rather than assumed.
func TestTheRealMarkerWrittenBySwiftIsReadableHere(t *testing.T) {
	const captured = `{"heartbeat_at":"2026-08-10T01:23:50Z","pid":7671,"started_at":"2026-08-10T01:20:50Z","version":"0.1.0+20260810102048"}`

	var m runtimeMarker
	if err := json.Unmarshal([]byte(captured), &m); err != nil {
		t.Fatalf("the bytes the extension writes do not decode here: %v", err)
	}
	for name, got := range map[string]string{
		"version":      m.Version,
		"started_at":   m.StartedAt,
		"heartbeat_at": m.HeartbeatAt,
	} {
		if got == "" {
			t.Fatalf("%s came back empty — the two sides have drifted, and the symptom is every Mac reported "+
				"as not-running with nothing erroring", name)
		}
	}
	if m.PID == 0 {
		t.Error("pid did not decode")
	}

	// Fresh at the moment it was captured: the version is the answer.
	at := time.Date(2026, 8, 10, 1, 23, 55, 0, time.UTC)
	got, err := resolveRunningVersion(m, true, at)
	if err != nil {
		t.Fatalf("a marker written seconds earlier resolved to an error: %v", err)
	}
	if got != "0.1.0+20260810102048" {
		t.Fatalf("running version = %q", got)
	}

	// And the same bytes an hour later are a memory, not a running version. This is the property the whole
	// mechanism exists for, checked against real output rather than a constructed one.
	if _, err := resolveRunningVersion(m, true, at.Add(time.Hour)); !errors.Is(err, agentupdate.ErrAgentNotRunning) {
		t.Fatalf("a stale real marker resolved to %v, want ErrAgentNotRunning", err)
	}
}

// ★ THE NAME THE INSTALLER WRITES AND THE NAME THE UPDATER LOOKS FOR MUST BE THE SAME STRING.
//
// They are produced by different programs — a shell postinstall inside the .pkg, and this Go code — so nothing
// but a test holds them together. The failure mode has no symptom: Lookup returns ErrNoMaterial, Run refuses
// with "this box has nothing to roll back to", and it reads as a stash that was never implemented while the
// postinstall is running correctly on every device.
//
// The expected value here was captured from an ACTUAL run of the built package's postinstall on 2026-08-10:
//
//	postinstall: rollback material stored for 0.1.0+20260810020647
//	             at .../rollback/dsse-agent-0.1.0+20260810020647.pkg
func TestTheStoreLooksForExactlyWhatThePostinstallWrites(t *testing.T) {
	const version = "0.1.0+20260810020647"
	const writtenByPostinstall = "dsse-agent-0.1.0+20260810020647.pkg"

	dir := t.TempDir()
	store := rollbackstore.NewForPackages(dir, PackageExtension)

	// Put the file there the way the installer does, then ask the way the updater does.
	if err := os.WriteFile(filepath.Join(dir, writtenByPostinstall), []byte("a package"), 0o640); err != nil {
		t.Fatal(err)
	}
	got, err := store.Lookup(version)
	if err != nil {
		t.Fatalf("the updater could not find what the installer wrote: %v", err)
	}
	if filepath.Base(got) != writtenByPostinstall {
		t.Fatalf("looked up %q, want %q", filepath.Base(got), writtenByPostinstall)
	}
}

// And the staged artifact carries the same extension, for the same reason: Execute hands that path to
// `installer -pkg`, which will not accept an .msi whatever it contains.
func TestTheStagedArtifactIsAPkg(t *testing.T) {
	p, err := StagedPath("0.2.0")
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Ext(p) != ".pkg" {
		t.Fatalf("staged path %q does not end in .pkg", p)
	}
}
