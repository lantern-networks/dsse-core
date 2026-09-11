//go:build !windows

package main

import "testing"

// self_integrity_posix_test.go — the permission-bit half of the check, which only exists on platforms that
// have permission bits.
//
// ★ WHY THESE ARE NOT IN THE SHARED TEST FILE (2026-08-14). WorldWritable and GroupWritable are documented as
// "the POSIX view, ONLY set on platforms that honour it": the Windows probe leaves them false on purpose and
// answers a different question (which principals hold write access in the DACL). A shared test asserting
// WorldWritable therefore asserts something Windows is designed never to do, and the honest place for it is
// behind the same build tag as the implementation it describes.

func TestWorldWritableDirectoryIsReported(t *testing.T) {
	report, err := checkSelfIntegrity("/opt/dsse/steer", statAs(0o777), probeDirectoryWritability)
	if err != nil {
		t.Fatal(err)
	}
	if !report.WorldWritable {
		t.Fatal("a world-writable directory was not flagged — anyone on the machine could replace the agent")
	}
	if report.Note == "" {
		t.Fatal("flagged but with nothing to say; an operator needs to know what to do")
	}
}

// Group-writable is the weaker finding and must still be reported, but it must not be mistaken for the
// world-writable one: the set of people who can rewrite the agent is the whole point of the distinction.
func TestGroupWritableDirectoryIsReportedSeparately(t *testing.T) {
	report, err := checkSelfIntegrity("/opt/dsse/steer", statAs(0o775), probeDirectoryWritability)
	if err != nil {
		t.Fatal(err)
	}
	if report.WorldWritable {
		t.Fatal("a group-writable directory was reported as world-writable — that overstates who can rewrite the agent")
	}
	if !report.GroupWritable {
		t.Fatal("a group-writable directory was not flagged")
	}
}

// A correctly installed directory must produce no finding at all, or the check becomes noise.
func TestATightlyPermissionedDirectoryIsClean(t *testing.T) {
	report, err := checkSelfIntegrity("/usr/local/bin/steer", statAs(0o755), probeDirectoryWritability)
	if err != nil {
		t.Fatal(err)
	}
	if report.WorldWritable || report.GroupWritable || report.Note != "" {
		t.Fatalf("a 0755 directory was flagged (%q) — a false alarm trains operators to ignore the real one",
			report.Note)
	}
}
