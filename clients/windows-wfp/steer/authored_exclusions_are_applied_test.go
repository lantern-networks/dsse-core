package main

import "testing"

// The bug this file exists for: the authored list must reach the device, and it must not displace the other.
func TestTheAuthoredListIsAppliedAlongsideTheRequestedOne(t *testing.T) {
	got := mergeCSV("automation", "publisher:Anthropic,signed:example.exe")
	want := "automation,publisher:Anthropic,signed:example.exe"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

// Neither author may erase the other. An empty authored list is "this organization authored none", which is
// not the same as "steer everything the package asked to be left alone".
func TestAnEmptyAuthoredListDoesNotEraseTheRequestedOne(t *testing.T) {
	if got := mergeCSV("automation", ""); got != "automation" {
		t.Fatalf("the requested list was lost: %q", got)
	}
	if got := mergeCSV("", "publisher:Anthropic"); got != "publisher:Anthropic" {
		t.Fatalf("the authored list was lost: %q", got)
	}
}

// One identifier spelled two ways is one rule, not two — the forms match case-insensitively downstream.
func TestOneIdentifierSpelledTwoWaysIsOneEntry(t *testing.T) {
	if got := mergeCSV("Publisher:Anthropic", "publisher:anthropic"); got != "Publisher:Anthropic" {
		t.Fatalf("got %q", got)
	}
}

// A trailing comma is a typo. It must not become an identifier that matches everything.
func TestBlanksAreNotIdentifiers(t *testing.T) {
	if got := mergeCSV("automation,", ",,publisher:Anthropic,"); got != "automation,publisher:Anthropic" {
		t.Fatalf("got %q", got)
	}
}

// ★★★ THE ONE THAT MATTERED (2026-08-30). subject: identifiers are X.500 Organization names and a comma is
// ORDINARY in them. Flattening the authored list into the comma-separated flag split "subject:Anthropic, PBC"
// into two rules, neither of which matches anything, while the device reported applying its exclusions and
// the Console showed them present. Measured with --mode bypass-observe: the process carried no BYPASS mark.
func TestAnIdentifierContainingACommaSurvives(t *testing.T) {
	authored := []string{"team-id:Q6L2SF6YDW", "subject:Anthropic, PBC"}
	got := effectiveBypassApps("automation", authored)
	if len(got) != 2 {
		t.Fatalf("the authored list was re-split: %#v", got)
	}
	if got[1] != "subject:Anthropic, PBC" {
		t.Fatalf("the comma did not survive: %q", got[1])
	}
}

// The operator's flag is still comma-separated — that is where a comma means "next identifier", and it is
// split exactly once.
func TestTheOperatorFlagIsStillCommaSeparated(t *testing.T) {
	got := effectiveBypassApps("automation,signed:example.exe", nil)
	if len(got) != 2 || got[0] != "automation" || got[1] != "signed:example.exe" {
		t.Fatalf("got %#v", got)
	}
}

// A profile that authored identifiers replaces the packaged default rather than merging with it: a stale
// build-time list must not resurrect itself beside a deliberate one.
func TestAnAuthoredListReplacesTheFlag(t *testing.T) {
	got := effectiveBypassApps("automation", []string{"subject:Contoso, Inc."})
	if len(got) != 1 || got[0] != "subject:Contoso, Inc." {
		t.Fatalf("got %#v", got)
	}
}

// And when the profile authored none, the flag stands.
func TestWithNothingAuthoredTheFlagStands(t *testing.T) {
	if got := effectiveBypassApps("automation", nil); len(got) != 1 || got[0] != "automation" {
		t.Fatalf("got %#v", got)
	}
}
