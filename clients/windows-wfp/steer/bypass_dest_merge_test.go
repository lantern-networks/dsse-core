package main

import (
	"strings"
	"testing"
)

// ★★ THE REGRESSION THIS FILE EXISTS FOR (2026-08-17, measured on win-dev-1).
//
// The profile-application block assigned every knob from the verified profile, destinations included:
//
//	*bypassDests = strings.Join(prof.BypassDests, ",")
//
// A profile carrying `bypass_dests: null` therefore erased whatever the MSI had baked into the service
// arguments. `-BypassDest` was added to build-msi.ps1 specifically so the SSH management path would survive
// steer-all (never route the management path through the managed object), and on every provisioned box
// — which is every box with a verified profile — it did nothing. The startup line printed
// `bypass_dests=[127.0.0.1:18090]`, and nothing anywhere said a destination had been dropped.
//
// The first assertion below is that erasure, stated directly.
func TestAProfileWithNoDestinationsDoesNotErasePackagedOnes(t *testing.T) {
	csv, note := mergeBypassDests("100.72.135.18:22,203.0.113.10:22", nil)

	for _, want := range []string{"100.72.135.18:22", "203.0.113.10:22"} {
		if !strings.Contains(csv, want) {
			t.Fatalf("the packaged destination %s was dropped by a profile that names none — this is the defect: %q",
				want, csv)
		}
	}
	if note == "" {
		t.Error("a device exempting destinations must say so at startup; an exemption nobody can see is how the " +
			"opposite defect (a bypass nobody intended) survives too")
	}
	if !strings.Contains(note, "PACKAGE") {
		t.Errorf("the log line does not say where the destinations came from: %q", note)
	}
}

// The profile can ADD. Both sets end up in force, and the log names both, because an operator reading it has
// to be able to attribute every exemption to the thing that asked for it.
func TestTheProfileCanAddDestinationsToThePackagedOnes(t *testing.T) {
	csv, note := mergeBypassDests("203.0.113.10:22", []string{"10.10.0.10", "203.0.113.9:445"})

	for _, want := range []string{"203.0.113.10:22", "10.10.0.10", "203.0.113.9:445"} {
		if !strings.Contains(csv, want) {
			t.Fatalf("%s missing from the merged set %q", want, csv)
		}
	}
	if !strings.Contains(note, "MERGED") || !strings.Contains(note, "cannot remove") {
		t.Errorf("the merge must state its own limitation — the profile cannot remove a packaged destination: %q", note)
	}
	// Packaged first: the site's own management path should not be buried behind tenant-wide entries in the
	// startup line.
	if !strings.HasPrefix(csv, "203.0.113.10:22") {
		t.Errorf("packaged destinations should lead: %q", csv)
	}
}

// A destination named by BOTH is one rule. Two identical entries in the startup line read as two exemptions.
func TestADestinationNamedTwiceBecomesOneRule(t *testing.T) {
	csv, _ := mergeBypassDests("203.0.113.10:22", []string{"203.0.113.10:22", "10.0.0.1:53"})
	if got := strings.Count(csv, "203.0.113.10:22"); got != 1 {
		t.Fatalf("the shared destination appears %d times in %q", got, csv)
	}
	if !strings.Contains(csv, "10.0.0.1:53") {
		t.Fatalf("dedup dropped a distinct destination: %q", csv)
	}
}

// The ordinary case — no packaged destinations — must behave exactly as before this change, and say nothing.
// A log line on every boot of every device that has nothing to report is noise, and noise is what makes the
// line above easy to miss.
func TestWithNoPackagedDestinationsTheProfileStandsAloneAndSilently(t *testing.T) {
	csv, note := mergeBypassDests("", []string{"10.10.0.10"})
	if csv != "10.10.0.10" {
		t.Fatalf("csv = %q, want the profile's set unchanged", csv)
	}
	if note != "" {
		t.Errorf("nothing to report, but it reported %q", note)
	}
	csv, note = mergeBypassDests("", nil)
	if csv != "" || note != "" {
		t.Errorf("neither source names anything: csv=%q note=%q", csv, note)
	}
}

// Whitespace and empty entries in either source must not become rules. parseAddrPorts would reject them, but
// silently — and a rule set assembled from two strings joined with a comma is exactly where an empty element
// appears.
func TestBlankEntriesNeverBecomeRules(t *testing.T) {
	csv, _ := mergeBypassDests(" 203.0.113.10:22 , , ", []string{"", "  ", "10.0.0.1:53"})
	if csv != "203.0.113.10:22,10.0.0.1:53" {
		t.Fatalf("csv = %q", csv)
	}
}
