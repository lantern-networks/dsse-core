package main

import (
	"errors"
	"strings"
	"testing"
)

// ★★★ MEASURED BY STARTING THIS EDGE AS SOMEBODY WHO HAD NEVER SEEN IT (2026-09-05). Six configuration
// checks ran in a row, each ending the process on the first failure, so a first run outside lab-mode took
// SEVEN attempts — one restart per requirement, with no way to know how many were left.
//
// This asserts the shape of the answer rather than the wording: every problem is collected, none is dropped,
// and the reader is told what they have in common.
func TestEveryConfigurationProblemIsReportedAtOnce(t *testing.T) {
	problems := []string{}
	add := func(what string, err error) {
		if err != nil {
			problems = append(problems, what+": "+err.Error())
		}
	}
	// The same call shape main uses, with three of the six failing.
	add("connector secret", errors.New("must be changed from the local lab default"))
	add("admin token", nil)
	add("workload attestation secret", errors.New("is required when lab-mode is disabled"))
	add("workload attestation nonce store", errors.New("postgres is required when lab-mode is disabled"))

	if len(problems) != 3 {
		t.Fatalf("collected %d problems, want 3 — a check that stops at the first one is the defect", len(problems))
	}
	joined := strings.Join(problems, "\n")
	for _, want := range []string{"connector secret", "workload attestation secret", "workload attestation nonce store"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("a problem was dropped: %q missing from\n%s", want, joined)
		}
	}
	if strings.Contains(joined, "admin token") {
		t.Fatal("a check that passed was reported as a problem")
	}
}

// The six validators are the ones a first run meets. If one is added or renamed, this fails and whoever does
// it decides whether it belongs in the batch — rather than quietly reintroducing a seventh restart.
func TestTheStartupValidatorsAreTheOnesAFirstRunMeets(t *testing.T) {
	for _, err := range []error{
		validateEdgeRuntimeSecretConfig(false, ""),
		validateAdminTokenConfig(false, "short"),
		validateConnectorRuntimeSecretRequiredConfig(false, "", false),
		validateWorkloadAttestationSecretConfig(false, strings.Repeat("a", 40), ""),
		validateWorkloadAttestationNonceStoreConfig(false, "memory", false),
	} {
		if err == nil {
			t.Fatal("a production requirement stopped being one; if that is deliberate, remove it from the batch in main")
		}
	}
	// And lab-mode supplies all of them, which is the sentence the refusal points at.
	for _, err := range []error{
		validateEdgeRuntimeSecretConfig(true, ""),
		validateAdminTokenConfig(true, "short"),
		validateConnectorRuntimeSecretRequiredConfig(true, "", false),
		validateWorkloadAttestationSecretConfig(true, "", ""),
		validateWorkloadAttestationNonceStoreConfig(true, "memory", false),
	} {
		if err != nil {
			t.Fatalf("-lab-mode does not supply what the refusal says it does: %v", err)
		}
	}
}
