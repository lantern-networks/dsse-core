package main

import (
	"strings"
	"testing"
	"time"
)

// Every item an operator has to ACT on must state this deployment's real values, not prose about them.
//
// The screen's problem was never that it lied — the assessment is accurate. It was that it ended at a sentence.
// "Move the key into a PKCS#11 token and point the Edge at it" is correct and leaves somebody to find out
// whether a sidecar exists here, where its socket is, and which flag names it. This assessment runs inside the
// deployment it describes and knows all three, so declining to say them is a choice to be less useful than it
// can be.
func TestActionableItemsCarryThisDeploymentsValues(t *testing.T) {
	in := pkiReadinessInput{
		KeyCustody:                "file", // the worst case, and the one most in need of a next step
		KeyCustodyChecked:         true,
		KeyCustodyHealthy:         true,
		IntermediateActive:        false,
		EnrollConfigured:          true,
		EnrollSharedToken:         true, // the item that must be acted on
		HSMAgentSocket:            "/run/dsse/hsm-agent.sock",
		EnrolmentTokenStore:       "postgres",
		EnrolmentTokenMaxLifetime: 72 * time.Hour,
		EnrolmentTokenOutstanding: 50,
		DevicesTotal:              3,
	}
	report := assessPKIReadiness(in)

	byID := map[string]pkiReadinessItem{}
	for _, item := range report.Items {
		byID[item.ID] = item
	}

	// Anything an operator must act on carries concrete values. "ok" items carry nothing — there is no step.
	for _, id := range []string{"key_custody", "intermediate", "enrolment"} {
		item, ok := byID[id]
		if !ok {
			t.Fatalf("%s is missing from the report", id)
		}
		if item.Status == "ok" {
			continue
		}
		if len(item.Concrete) == 0 {
			t.Fatalf("%s says %q and stops at prose — an operator is left to look up values this assessment already has",
				id, item.Remediation)
		}
	}

	joined := func(id string) string { return strings.Join(byID[id].Concrete, "\n") }

	if !strings.Contains(joined("key_custody"), "/run/dsse/hsm-agent.sock") {
		t.Fatalf("key custody does not name the sidecar this deployment is wired to:\n%s", joined("key_custody"))
	}
	if !strings.Contains(joined("intermediate"), "3") {
		t.Fatalf("the intermediate item should say how many devices a rotation would re-provision:\n%s", joined("intermediate"))
	}
	for _, want := range []string{"postgres", "72h", "50"} {
		if !strings.Contains(joined("enrolment"), want) {
			t.Fatalf("enrolment omits the running configuration (%q):\n%s", want, joined("enrolment"))
		}
	}
}

// With nothing configured, the guide must say so rather than print a placeholder somebody pastes verbatim.
// A path that looks real and is not is worse than an admission that none is set: the first sends an operator
// to debug a socket that was never supposed to exist.
func TestConcreteStepsNeverInventValues(t *testing.T) {
	in := pkiReadinessInput{KeyCustody: "file", EnrollConfigured: true, EnrollSharedToken: true}
	report := assessPKIReadiness(in)
	for _, item := range report.Items {
		for _, line := range item.Concrete {
			for _, placeholder := range []string{"<", ">", "example.com", "YOUR_", "TODO", "xxx"} {
				if strings.Contains(line, placeholder) {
					t.Fatalf("%s prints a placeholder (%q): %q", item.ID, placeholder, line)
				}
			}
		}
	}
	// It must still be honest that no sidecar is configured, rather than silently omitting the item's step.
	for _, item := range report.Items {
		if item.ID == "key_custody" {
			if !strings.Contains(strings.ToLower(strings.Join(item.Concrete, " ")), "no signing sidecar") {
				t.Fatalf("with no sidecar configured, key custody should say so plainly:\n%v", item.Concrete)
			}
		}
	}
}
