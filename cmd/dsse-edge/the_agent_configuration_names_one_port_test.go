package main

import (
	"bytes"
	"log"
	"strings"
	"testing"
)

// ★★★ THE DOCUMENT THAT DECIDES WHERE EVERY NEW DEVICE GOES NAMED A PORT the enrolment fold FORBIDS (2026-08-21, measured
// on the reference deployment). "edge_url": "https://203.0.113.10:8443", while the section says an agent
// touches one port and that a port like 8443 must not appear in the configuration handed to an agent at all.
//
// It had been recorded in a code comment for a day. Nothing said it at run time, so nothing would ever have
// noticed it drifting further — which is the shape this repository keeps finding, in the file written about
// that shape.
func TestTheAgentConfigurationSaysWhenItNamesASecondPort(t *testing.T) {
	capture := func(published, listen string) string {
		var buf bytes.Buffer
		prev := log.Writer()
		log.SetOutput(&buf)
		defer log.SetOutput(prev)
		warnIfTheAgentConfigurationNamesAnotherPort(published, listen)
		return buf.String()
	}

	said := capture("https://203.0.113.10:8443", "0.0.0.0:18543")
	if said == "" {
		t.Fatal("★ the configuration handed to every new device names a second agent-facing port and this node " +
			"said nothing. A gap only a comment knows about is one that drifts.")
	}
	// ★ THE TWO PORTS AND WHAT THIS IS, not a section number (2026-08-22). It asserted on "9.1a" — a
	// pointer into a document that is not being published, so a reader who has only the deployment cannot
	// follow it. What makes the warning actionable is the two ports it names and the setting below; the name
	// of the thing ("enrolment fold") replaces the reference.
	for _, want := range []string{"enrolment fold", "8443", "18543"} {
		if !strings.Contains(said, want) {
			t.Fatalf("the warning does not name %q, so a reader cannot act on it: %s", want, said)
		}
	}
	// ★ AND IT SAYS WHAT TO CHANGE, not only that something is wrong.
	if !strings.Contains(said, "-network-extension-runtime-copy-edge-url") {
		t.Fatalf("the warning does not name the setting that produces it: %s", said)
	}

	// ★ THE CONTROL: a deployment that has folded says nothing, or this becomes noise that teaches skimming —
	// the same reason the interception-revocation readiness item is "ok" rather than a permanent "attention".
	if quiet := capture("https://203.0.113.10:18543", "0.0.0.0:18543"); quiet != "" {
		t.Fatalf("a folded deployment was warned anyway: %s", quiet)
	}
	// Nothing configured is not a finding either.
	if quiet := capture("", "0.0.0.0:18543"); quiet != "" {
		t.Fatalf("a deployment publishing no agent configuration was warned: %s", quiet)
	}
	if quiet := capture("https://203.0.113.10:8443", ""); quiet != "" {
		t.Fatalf("a deployment with no transport listener was warned about a fold it cannot make: %s", quiet)
	}
}
