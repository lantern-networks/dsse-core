package main

import (
	"os"
	"strings"
	"testing"
)

// ★★★ AN AGENT IN FAILOVER WAS GIVEN ADDRESSES AND NO NAME (2026-08-22, raised by win-dev-1).
//
// GET /steer/region-endpoints listed region → endpoint and nothing else, so a device failing over had no idea
// what server name to send. The Windows agent has a rule for it — region failover beats the announced name —
// written because a region lacking the organization's certificate serves the shared one, and a device
// verifying by the organization's name would lock itself out on arrival.
//
// The consequence is the one that matters here: the folded enrolment and recovery paths are selected BY that
// name, so a device in failover cannot reach either. Measured: SNI=enrol.<org> is the only thing that opens
// /enroll on the transport port; every other name, and no SNI at all, is refused.
//
// The name does not change on failover, and this fleet guarantees it: a node that cannot serve what the fleet
// announces exits rather than joining. So the agent does not need a rule, it needs to be told.
func TestTheRegionAnswerSaysWhichNameToPresent(t *testing.T) {
	raw, err := os.ReadFile("steer_agent_policy_routes.go")
	if err != nil {
		t.Fatalf("read the route: %v", err)
	}
	src := string(raw)
	start := strings.Index(src, `mux.HandleFunc("GET /steer/region-endpoints"`)
	if start < 0 {
		t.Fatal("the region-endpoints route is gone — this gate is reading the wrong file")
	}
	end := strings.Index(src[start+10:], "mux.HandleFunc(")
	handler := src[start:]
	if end > 0 {
		handler = src[start : start+10+end]
	}
	for _, want := range []string{`payload["transport_server_name"]`, `payload["enrolment_server_name"]`} {
		if !strings.Contains(handler, want) {
			t.Fatalf("the region answer does not carry %s, so a device that fails over cannot select the "+
				"folded enrolment path — it does not know the name to send", want)
		}
	}
	// ★ AND ONLY A NAME A CERTIFICATE CARRIES. the enrolment fold has paid for the opposite twice: an agent that dials a
	// name nothing answers to fails verification, and it reads as the Edge being down.
	if !strings.Contains(handler, "transportTenantCertificates.For(enrol)") {
		t.Fatal("the enrolment name is offered without checking that a certificate this node serves carries it")
	}
	if !strings.Contains(handler, "transportTenantCertificates.ServerNameFor(tenantID)") {
		t.Fatal("the transport name is not read from what this node actually serves")
	}
	// ★ THE CONTROL: an organization with no name of its own must get NO name rather than a guess. That is
	// what the ok/non-empty guard is for, and without it this would hand every device a name to invent.
	if !strings.Contains(handler, `ok && strings.TrimSpace(serverName) != ""`) {
		t.Fatal("an organization with no transport name of its own would be handed one anyway")
	}
	// And the answer explains itself, because a field with no reason is a field somebody will drop.
	if !strings.Contains(handler, "refuses to start") {
		t.Fatal("the note does not say why the name is the same at every region, which is the whole reason " +
			"an agent can stop guessing")
	}
}
