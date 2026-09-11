package main

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The agent checking who can rewrite it. Every guarantee it makes — policy, logging, revocation — is only
// whatever the binary says it is, so a binary a third party can replace makes no guarantees at all. The real
// case that prompted this: the Windows agent was running from a build-output directory an unresolved
// AppContainer principal could write to, found by a person reading ACLs rather than by the product.

type fakeDirInfo struct{ mode fs.FileMode }

func (f fakeDirInfo) Name() string       { return "dir" }
func (f fakeDirInfo) Size() int64        { return 0 }
func (f fakeDirInfo) Mode() fs.FileMode  { return f.mode | fs.ModeDir }
func (f fakeDirInfo) ModTime() time.Time { return time.Time{} }
func (f fakeDirInfo) IsDir() bool        { return true }
func (f fakeDirInfo) Sys() any           { return nil }

func statAs(mode fs.FileMode) func(string) (os.FileInfo, error) {
	return func(string) (os.FileInfo, error) { return fakeDirInfo{mode: mode}, nil }
}

// noProbe stands in for the platform probe in the tests that are about everything EXCEPT the probe: which
// locations count as build output, which finding outranks which, what gets logged. Those answers are the same
// on every platform and must not need a directory that exists — the paths below are deliberately
// hypothetical, and on Windows the real probe would try to read the ACL of a path that is not there.
func noProbe(string, os.FileInfo, *selfIntegrityReport) error { return nil }

// What the probe reports has to survive into the operator-facing note. The probes themselves are
// platform-specific and are tested against the real thing in self_integrity_posix_test.go and
// self_integrity_windows_test.go; what is checked here is that checkSelfIntegrity does not swallow the answer.
func TestAProbeFindingReachesTheNote(t *testing.T) {
	report, err := checkSelfIntegrity("/opt/dsse/steer", statAs(0o755),
		func(_ string, _ os.FileInfo, r *selfIntegrityReport) error {
			r.WorldWritable = true
			return nil
		})
	if err != nil {
		t.Fatal(err)
	}
	if !report.WorldWritable {
		t.Fatal("the probe's finding was dropped on the way to the report")
	}
	if report.Note == "" {
		t.Fatal("flagged but with nothing to say; an operator needs to know what to do")
	}
}

// A probe that cannot answer must surface as an error, not as a clean report: "I could not read the ACL" and
// "the ACL is fine" are different facts, and only one of them means the agent is safe to trust.
func TestAProbeThatCannotAnswerIsAnError(t *testing.T) {
	report, err := checkSelfIntegrity("/opt/dsse/steer", statAs(0o755),
		func(string, os.FileInfo, *selfIntegrityReport) error { return os.ErrPermission })
	if err == nil {
		t.Fatal("a probe failure returned no error — 'could not tell' must not read as 'fine'")
	}
	if report.Note != "" {
		t.Fatalf("a failed probe still produced a note (%q), which reads as a completed check", report.Note)
	}
}

// The location matters even when today's permissions look fine: the next build resets them, so tightening the
// ACL is not a fix. This is exactly where the Windows agent was found running from.
func TestRunningFromABuildOutputDirectoryIsReported(t *testing.T) {
	for _, path := range []string{
		`C:\Users\dev\src\lantern-dsse\outputs\windows\steer.exe`,
		"/home/dev/project/build/steer",
		"/src/app/target/release-x/steer",
	} {
		report, err := checkSelfIntegrity(path, statAs(0o755), noProbe)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if !report.InBuildOutput {
			t.Fatalf("%s was not flagged as a build-output location — permissions there are reset by the next "+
				"build, so fixing the ACL does not fix it", path)
		}
	}
}

// A properly installed agent must NOT be flagged, or the warning becomes noise and gets ignored — which is
// how the finding that prompted this went unnoticed for as long as it did.
func TestAProperlyInstalledAgentIsNotFlagged(t *testing.T) {
	for _, path := range []string{
		`C:\Program Files\Lantern\DSSE\steer.exe`,
		"/usr/local/bin/steer",
		// The bundle name here is arbitrary — checkSelfIntegrity asks whether a path looks like a build-output
		// location, not what the app is called — so this does not have to track the real bundle identifier.
		"/Applications/DsseAgent.app/Contents/MacOS/steer",
	} {
		report, err := checkSelfIntegrity(path, statAs(0o755), noProbe)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if report.Note != "" {
			t.Fatalf("%s was flagged (%s) — a false alarm here trains operators to ignore the real one",
				path, report.Note)
		}
	}
}

// Success must be stated, not silent: "the check ran and found nothing" and "the check never ran" look
// identical in a log when only failures speak.
func TestACleanResultIsStillLogged(t *testing.T) {
	var lines []string
	logSelfIntegrity(selfIntegrityReport{Path: "/usr/local/bin/steer"}, nil,
		func(f string, a ...any) { lines = append(lines, f) })
	if len(lines) != 1 || !strings.Contains(lines[0], "ok") {
		t.Fatalf("a clean check logged %v — an operator cannot tell it ran", lines)
	}
}

// An unreadable directory is reported as UNKNOWN rather than passing quietly. "We could not tell" is not
// "it is fine".
func TestAnUnreadableDirectoryIsUnknownNotClean(t *testing.T) {
	var lines []string
	report, err := checkSelfIntegrity("/opt/dsse/steer",
		func(string) (os.FileInfo, error) { return nil, os.ErrPermission }, noProbe)
	logSelfIntegrity(report, err, func(f string, a ...any) { lines = append(lines, f) })
	if err == nil {
		t.Fatal("an unreadable directory returned no error")
	}
	if len(lines) != 1 || !strings.Contains(lines[0], "UNKNOWN") {
		t.Fatalf("logged %v, want an UNKNOWN line — 'could not tell' must not read as 'fine'", lines)
	}
}

// The real executable must pass its own check, so the test suite would notice if the agent shipped from
// somewhere hazardous.
//
// This is the one test that wires the REAL platform probe to a REAL directory, which is what makes it worth
// keeping alongside the injected-probe tests above: it proves the syscall path is plumbed in on whichever
// platform is running the suite. It asserts only that the probe could answer — not WHAT it answered — because
// the answer legitimately differs (a POSIX temp dir is 0700, a Windows one grants the running user write
// access, which is a true finding about temp directories and not a defect in the agent).
func TestTheCheckRunsAgainstARealPath(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "steer")
	if err := os.WriteFile(exe, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := checkSelfIntegrity(exe, os.Stat, probeDirectoryWritability); err != nil {
		t.Fatalf("the check failed on a real path: %v", err)
	}
}

// ★★ THE ACL FINDING OUTRANKS EVERYTHING AND NAMES THE PRINCIPAL (2026-08-14, reported from a Windows machine).
// The check reported C:\Windows\System32 as WORLD-WRITABLE on every start, because it read POSIX permission
// bits that Windows does not have — Go synthesises them from the read-only attribute alone. A warning that
// cannot be cleared is one operators learn to scroll past, which is worse than no check: it spends the
// attention a real finding would need. Windows now reads the DACL, and what it produces has to be ACTIONABLE,
// which means naming who can write rather than restating that somebody can.
func TestUntrustedWritersAreNamedAndOutrankTheOtherNotes(t *testing.T) {
	report := selfIntegrityReport{
		Path: `C:\Program Files\Lantern DSSE\steer.exe`,
		// Deliberately alongside the two weaker findings: an executable in a build-output directory that is ALSO
		// writable by Users must report the writer, because that is the one somebody can act on today.
		InBuildOutput:    true,
		GroupWritable:    true,
		UntrustedWriters: []string{`BUILTIN\Users`, `DESKTOP-X\alice`},
	}
	// Re-run only the note selection, which is what checkSelfIntegrity does after the probe.
	got := noteFor(report)
	if !strings.Contains(got, `BUILTIN\Users`) || !strings.Contains(got, `DESKTOP-X\alice`) {
		t.Fatalf("the note does not name who can rewrite the agent, so nobody can act on it: %q", got)
	}
	if strings.Contains(got, "build-output") {
		t.Fatalf("a weaker finding won over an untrusted writer: %q", got)
	}
}

// And the log line has to carry the finding, not just a severity marker.
func TestTheLogLineCarriesTheWriters(t *testing.T) {
	var lines []string
	logSelfIntegrity(selfIntegrityReport{
		Path:             `C:\ProgramData\dsse\steer.exe`,
		UntrustedWriters: []string{`BUILTIN\Users`},
		Note:             noteFor(selfIntegrityReport{UntrustedWriters: []string{`BUILTIN\Users`}}),
	}, nil, func(f string, a ...any) { lines = append(lines, fmt.Sprintf(f, a...)) })
	if len(lines) != 1 {
		t.Fatalf("logged %d lines, want 1", len(lines))
	}
	if !strings.Contains(lines[0], `BUILTIN\Users`) {
		t.Fatalf("the log line does not say who: %q", lines[0])
	}
}
