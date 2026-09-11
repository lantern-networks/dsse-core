package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestAgentFacingPortsCountsWhatAnAgentDials(t *testing.T) {
	// One port serving both purposes is the goal — that must read as ONE, or the gate would refuse the fix.
	one := agentFacingPorts(agentFacingAddresses{MainListen: "0.0.0.0:443", TransportListen: "0.0.0.0:443", RecoveryListen: "0.0.0.0:443", PublishedRecoveryEndpoint: "edge.example:443"})
	if len(one) != 1 {
		t.Fatalf("transport and recovery on the same port counted as %d: %+v", len(one), one)
	}
	if !strings.Contains(describeAgentFacingPorts(one), "1 —") {
		t.Fatalf("the posture line does not say one: %q", describeAgentFacingPorts(one))
	}

	// Today's reference deployment: two.
	two := agentFacingPorts(agentFacingAddresses{TransportListen: "0.0.0.0:18543", RecoveryListen: "0.0.0.0:18545", PublishedRecoveryEndpoint: "203.0.113.10:18545"})
	if len(two) != 2 {
		t.Fatalf("a transport port and a separate recovery port counted as %d: %+v", len(two), two)
	}
	if line := describeAgentFacingPorts(two); !strings.Contains(line, "ONE port") || !strings.Contains(line, "18545") {
		t.Fatalf("the posture line does not name the problem or the port: %q", line)
	}

	// An Edge with no recovery listener at all — region-b — is one, not "one plus an empty".
	if got := agentFacingPorts(agentFacingAddresses{TransportListen: "0.0.0.0:18544"}); len(got) != 1 || got[0].Port != "18544" {
		t.Fatalf("an Edge with no recovery path counted as %+v", got)
	}

	// The published endpoint may be a bare port: the device resolves the host from the transport it holds.
	if got := agentFacingPorts(agentFacingAddresses{TransportListen: "0.0.0.0:443", PublishedRecoveryEndpoint: "443"}); len(got) != 1 {
		t.Fatalf("a bare published port was not recognised as the same port: %+v", got)
	}
	// ...and a bare port that DIFFERS is still a second port.
	if got := agentFacingPorts(agentFacingAddresses{TransportListen: "0.0.0.0:443", PublishedRecoveryEndpoint: "18545"}); len(got) != 2 {
		t.Fatalf("a bare published port on a different number was not counted: %+v", got)
	}
	// A URL form, which is how region endpoints are written.
	if got := portOfAddress("https://203.0.113.10:18543/steer"); got != "18543" {
		t.Fatalf("a URL's port read as %q", got)
	}
	// ★ THE CONTROL: something with no port must contribute nothing, or every count above is inflated by
	// whatever empty or hostname-only value happens to be configured.
	for _, junk := range []string{"", "   ", "edge.example", "https://edge.example/x"} {
		if got := portOfAddress(junk); got != "" {
			t.Fatalf("%q yielded port %q", junk, got)
		}
	}
}

// ★ AND THE REFERENCE DEPLOYMENT IS MEASURED, not assumed. The numbers above are hand-written; this reads the
// file the lab actually runs, so the day somebody adds a third agent-facing port the count moves here.
//
// It asserts the CURRENT state (two on region-a) rather than the target state (one). A gate that fails today
// blocks every push until a cross-platform change lands, which means it gets deleted instead of fixed — and
// the useful property, "tell me when this changes", works either way. When the fold in the enrolment fold lands, this
// expectation moves to 1 in the same commit.
func TestTheReferenceEdgePublishesTheAgentFacingPortsWeThinkItDoes(t *testing.T) {
	// ★★★ AND THE TWO SITUATIONS ARE NOW TOLD APART (2026-09-04, found by running this tree's tests from a
	// clone of it — which is what a receiver does first). The comment below always said the message would say
	// WHICH situation this is; it did not, so on the published surface, where there is no reference deployment
	// and the file is genuinely absent, this failed for every receiver on a file they were never given.
	//
	// The subject of this gate is the REFERENCE deployment, which is a monorepo artifact. Its absence is
	// therefore two different facts: no reference deployment here at all (a published clone — nothing to
	// report, and saying so is honest), or a reference deployment whose compose has moved (the gate's subject
	// is broken, and that is a failure). The directory is what distinguishes them.
	referenceDir := filepath.Join("..", "..", "..", "..", "deploy", "reference")
	if _, statErr := os.Stat(referenceDir); os.IsNotExist(statErr) {
		t.Skip("no reference deployment in this tree — this gate watches the monorepo's reference compose, " +
			"which the published tree does not carry. The ports a DEPLOYMENT publishes are settled by the " +
			"installer and checked by dsse-install -verify.")
	}
	compose, err := os.ReadFile(filepath.Join(referenceDir, "docker-compose.yml"))
	if err != nil {
		// ★ NOT A SKIP. This gate skipped on exactly this branch for its whole life, because the path it
		// named did not exist, and a skip reads as "checked, nothing to report". On the published surface
		// there is no reference deployment to read and the file is genuinely absent — which is why the
		// message says which of the two situations this is rather than assuming.
		t.Fatalf("the reference compose could not be read (%v). This gate reports a CHANGE in the ports an "+
			"agent dials, and one that cannot read its subject reports nothing while looking like it passed", err)
	}
	read := func(flag string) string {
		m := regexp.MustCompile(`-` + regexp.QuoteMeta(flag) + `=([^\s"']+)`).FindSubmatch(compose)
		if m == nil {
			return ""
		}
		return string(m[1])
	}
	transport := read("transport-tls-listen")
	if transport == "" {
		t.Fatal("no -transport-tls-listen in the reference compose — this gate is reading the wrong file")
	}
	// ★★★ TWO — AND THIS GATE HAD NEVER RUN (2026-08-23). It read the reference compose at a path that does
	// not exist, and a t.Skipf on an unreadable file made that look like "nothing to check here". It skipped
	// for its whole life, through the entire enrolment fold: the recovery listener was folded onto the
	// transport port and the count went 3 -> 2 without this ever saying so, which is precisely the change it
	// was written to report. Found when the package moved and the path had to be resolved for real.
	//
	// The expectation moves with the fold, as the message below always said it would. What remains is the last
	// step: the transport and the enrolment/steering door onto one port, after which this becomes 1.
	//
	// ★ AND IT NO LONGER SKIPS QUIETLY. An unreadable reference compose now fails: this gate exists to notice
	// a change, and a gate that cannot read its subject has not noticed anything.
	ports := agentFacingPorts(agentFacingAddresses{
		MainListen:                read("listen"),
		PublishedEdgeURL:          read("network-extension-runtime-copy-edge-url"),
		TransportListen:           transport,
		RecoveryListen:            read("enroll-renew-grace-listen"),
		PublishedRecoveryEndpoint: read("network-extension-renewal-recovery-endpoint"),
	})
	if len(ports) != 2 {
		t.Fatalf("region-a's Edge now publishes %d agent-facing ports (%+v). If this dropped the fold in the enrolment fold "+
			"landed and this expectation moves with it; if it rose, a new port was opened on the path an "+
			"agent dials, which cannot work on 443.", len(ports), ports)
	}
}
