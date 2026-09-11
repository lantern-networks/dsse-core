package main

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

type admissionLedgerStub struct{ admitted map[string]bool }

func (s admissionLedgerStub) IsAdmitted(id string) bool { return s.admitted[strings.ToLower(id)] }

// ★★★ A DISABLED DEVICE KEPT COLLECTING ENFORCEMENT (2026-08-22, measured — see the file this tests).
func TestAnAgentRouteSaysWhenItAnsweredADeviceTheTransportPortWouldRefuse(t *testing.T) {
	var said []string
	say := func(format string, a ...any) { said = append(said, fmt.Sprintf(format, a...)) }
	now := time.Date(2026, 8, 22, 2, 0, 0, 0, time.UTC)
	o := &deviceAdmissionObserver{said: map[string]time.Time{}}

	if !o.noteAnsweredWithoutAdmission("/steer/agent-policy", "admission-probe", "tenant_reference_lab", false, now, say) {
		t.Fatal("a device the ledger does not admit was answered and nothing was said")
	}
	line := said[0]
	for _, want := range []string{"admission-probe", "tenant_reference_lab", "/steer/agent-policy",
		"transport port would refuse", "the enrolment fold"} {
		if !strings.Contains(line, want) {
			t.Fatalf("the line does not carry %q, so a reader cannot act on it: %s", want, line)
		}
	}

	// ★ RATE LIMITED, or a disabled agent's polling buries the one line that matters.
	if o.noteAnsweredWithoutAdmission("/steer/agent-policy", "admission-probe", "tenant_reference_lab", false,
		now.Add(30*time.Minute), say) {
		t.Fatal("the same device was reported twice within the hour")
	}
	if !o.noteAnsweredWithoutAdmission("/steer/agent-policy", "admission-probe", "tenant_reference_lab", false,
		now.Add(2*time.Hour), say) {
		t.Fatal("the report never comes back — a device disabled for a day would be reported once and forgotten")
	}

	// ★ THE CONTROL, and it is the whole test. Without it this passes for an implementation that reports EVERY
	// device, which on a healthy fleet is a line per poll per agent and reads as noise rather than as a finding.
	if o.noteAnsweredWithoutAdmission("/steer/agent-policy", "mac-dev-1", "tenant_reference_lab", true, now, say) {
		t.Fatal("an admitted device was reported")
	}
	// And a deployment with no enrolled inventory admits by other means: reporting there would be a warning
	// about the deployment's shape, not about a device.
	if !deviceIsAdmitted(nil, "anything") {
		t.Fatal("a deployment with no ledger reported its devices as unadmitted")
	}
	ledger := admissionLedgerStub{admitted: map[string]bool{"mac-dev-1": true}}
	if !deviceIsAdmitted(ledger, "mac-dev-1") || deviceIsAdmitted(ledger, "admission-probe") {
		t.Fatal("the ledger's answer is not being read")
	}
}

// And it is wired into the route, not only defined: a helper nothing calls is the shape this repo keeps finding.
func TestTheAdmissionObservationIsWiredIntoTheAgentPolicyRoute(t *testing.T) {
	raw, err := os.ReadFile("steer_agent_policy_routes.go")
	if err != nil {
		t.Fatalf("read the route: %v", err)
	}
	src := string(raw)
	if !strings.Contains(src, "unadmittedDeviceReports.noteAnsweredWithoutAdmission(") {
		t.Fatal("the agent-policy route does not report an unadmitted device, so the gap is silent again")
	}
	// It must be handed the LEDGER's answer, not a constant — a call site that passes true reports nothing
	// and looks exactly like one that works.
	if !strings.Contains(src, "deviceIsAdmitted(config.EnrolledLedger, identity)") {
		t.Fatal("the route does not ask the enrolled ledger, so the report can never fire")
	}
}
