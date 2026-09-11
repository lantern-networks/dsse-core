//go:build windows

package main

import (
	"strings"
	"testing"
)

// TestAQuotedPublisherSurvivesTheRoundTrip is the tokenizer. DsseUpdater is registered with
// --update-publisher "subject:Aoba Networks"; splitting on whitespace records `"subject:Aoba` and writes back
// a command line whose trailing `Networks"` the service does not recognise.
func TestAQuotedPublisherSurvivesTheRoundTrip(t *testing.T) {
	exe, args := splitServiceCommand(`"C:\Program Files\DSSE\dsse-updater.exe" --service-run --update-publisher "subject:Aoba Networks"`)

	if exe != `C:\Program Files\DSSE\dsse-updater.exe` {
		t.Fatalf("executable parsed as %q", exe)
	}
	if got := pinsInArgs("DsseUpdater", args).get("Updater_Publisher"); got != publisher {
		t.Fatalf("publisher parsed as %q, want %q", got, publisher)
	}
	// And it must go back with its quotes, or the rebuilt ImagePath is two arguments.
	if rebuilt := joinArgs(args); !strings.Contains(rebuilt, `"subject:Aoba Networks"`) {
		t.Fatalf("rebuilt command line lost the quoting: %s", rebuilt)
	}
}

// TestTheCommandLineRoundTripsThroughWindowsOwnRules covers empty and escaped arguments. A hand-written quote
// toggler handled the publisher case above and still got the rest wrong: backslashes have a meaning before a
// quote, an empty argument must survive as "" rather than vanishing, and a trailing backslash inside a quoted
// path has to be doubled when the line is rebuilt. Each produces a service command line that parses into
// something other than what was read — silently, and only visible when the service refuses to start.
func TestTheCommandLineRoundTripsThroughWindowsOwnRules(t *testing.T) {
	for _, args := range [][]string{
		{"--service-run", "--update-publisher", "subject:Aoba Networks"},
		{"--service-run", "--config", ""},                            // an empty value must survive
		{"--service-run", "--dir", `C:\Program Files\DSSE\`},         // trailing backslash
		{"--service-run", "--note", `he said "hello"`},               // embedded quotes
		{"--service-run", "--note", `back\slash`, "--other", `a b\`}, // both, adjacent
		{"--service-run", "--update-publisher", `subject:A "B" C\`},  // all three at once
	} {
		exe := `C:\Program Files\DSSE\dsse-updater.exe`
		line := composeImagePath(exe, args)

		gotExe, gotArgs, err := decomposeImagePath(line)
		if err != nil {
			t.Fatalf("decompose %q: %v", line, err)
		}
		if gotExe != exe {
			t.Fatalf("executable round-tripped as %q, want %q (line %q)", gotExe, exe, line)
		}
		if len(gotArgs) != len(args) {
			t.Fatalf("argument count changed: %d -> %d (%q -> %v)", len(args), len(gotArgs), line, gotArgs)
		}
		for i := range args {
			if gotArgs[i] != args[i] {
				t.Fatalf("argument %d round-tripped as %q, want %q (line %q)", i, gotArgs[i], args[i], line)
			}
		}
	}
}

// TestAMalformedImagePathIsAnErrorNotAnEmptyService is the shape that let the pre-upgrade capture decide there
// was nothing to save and allow RemoveExistingProducts to proceed.
func TestAMalformedImagePathIsAnErrorNotAnEmptyService(t *testing.T) {
	for _, bad := range []string{"", "   "} {
		if _, _, err := decomposeImagePath(bad); err == nil {
			t.Fatalf("an ImagePath of %q must be an error, not an empty argument list", bad)
		}
	}
}
