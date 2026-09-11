//go:build windows

package updateplatform

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ★ THE MEASURED FAILURE, REPRODUCED. win-dev-1's journal, 2026-08-11T21:45:52Z:
//
//	execute failed: locate msiexec: exec: "msiexec.exe": executable file not found in %PATH%;
//	★ steering could NOT be restored afterwards ... this endpoint is NOT steering
//
// An empty %PATH% is the sharpest form of whatever the updater actually inherited that day, and it is the one
// a test can state. What made it expensive is that the sequencing takes steering DOWN before handing over on a
// fail-open endpoint: this lookup decides whether the box is protected, not merely whether an install starts.
func TestTheInstallerIsFoundWithNoPATHAtAll(t *testing.T) {
	t.Setenv("PATH", "")
	p, err := systemBinary("msiexec.exe")
	if err != nil {
		t.Fatalf("msiexec could not be located with an empty %%PATH%%, which is exactly the failure this removes: %v", err)
	}
	if !filepath.IsAbs(p) {
		t.Fatalf("systemBinary returned %q — a process about to hand a package to a privileged installer must not "+
			"name it relative to anything", p)
	}
	if _, serr := os.Stat(p); serr != nil {
		t.Fatalf("systemBinary returned %q, which is not there: %v", p, serr)
	}
	if !strings.EqualFold(filepath.Base(p), "msiexec.exe") {
		t.Fatalf("systemBinary resolved to %q, which is not the binary that was asked for", p)
	}
}

// And the half that is a security property rather than a reliability one: %PATH% is an ordered list anything
// running as an administrator can prepend to, and this process runs as LocalSystem. A planted binary must not
// be able to answer for a system one — which is also why the fallback inside systemBinary is %SystemRoot% and
// never LookPath, since falling back would restore the dependency quietly on precisely the box where the
// primary answer failed.
func TestAPlantedBinaryOnPATHIsNotASystemBinary(t *testing.T) {
	dir := t.TempDir()
	name := "dsse-not-a-system-binary.exe"
	if err := os.WriteFile(filepath.Join(dir, name), []byte("MZ"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	if p, err := systemBinary(name); err == nil {
		t.Fatalf("a binary planted at the front of %%PATH%% was accepted as a system binary: %q", p)
	}
}

// ★ THE DISARM AND THE REARM READ THE SAME ABSENCE AND REASONED IN OPPOSITE DIRECTIONS (win-dev-1,
// 2026-08-12). confirmDisarmed treats "no control device" as a definite, safe answer — no driver, no redirect,
// nothing to take down — while Rearm required an ARMED redirect before it would call the restoration done. On
// a box with no WFP driver loaded the first always succeeds and the second can never succeed, so every failed
// launch ended with "★ steering could NOT be restored ... this endpoint is NOT steering" on a machine that was
// in exactly the state it chose.
//
// Being wrong here is asymmetric, which is what the third case is about: answering "restored" when something
// really was armed reports a protected endpoint that is not one.
func TestARestorationIsJudgedAgainstWhatTheDisarmTookDown(t *testing.T) {
	for _, tc := range []struct {
		name      string
		observed  bool
		wasArmed  bool
		serviceOK bool
		why       string
	}{
		{"nothing was armed, so the service coming back IS the restoration", true, false, true,
			"an unenrolled box that stands aside, or one with no driver loaded, had nothing to put back"},
		{"a redirect WAS armed, so only the driver may say it is back", true, true, false,
			"this is the case the strict confirmation exists for"},
		{"no disarm was observed in this process, so keep the strict path", false, false, false,
			"the safe default: never assume nothing was taken down"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := &Platform{disarmObserved: tc.observed, armedBeforeDisarm: tc.wasArmed}
			if got := p.restorationIsTheServiceComingBack(); got != tc.serviceOK {
				t.Fatalf("restorationIsTheServiceComingBack() = %v, want %v — %s", got, tc.serviceOK, tc.why)
			}
		})
	}
}

// The recording must happen at all, on this host, with whatever driver state it has: a Disarm that forgot to
// look would leave disarmObserved false and silently restore the old absolute behaviour.
func TestTheDisarmRecordsWhatItFound(t *testing.T) {
	p := &Platform{}
	if p.disarmObserved {
		t.Fatal("a fresh Platform claims to have observed a disarm")
	}
	p.noteArmedBeforeDisarm()
	if !p.disarmObserved {
		t.Fatal("noteArmedBeforeDisarm did not record that it looked, so Rearm would take the strict path on a box " +
			"whose redirect it had just cleared")
	}
}
