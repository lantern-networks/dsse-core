package main

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/lantern-networks/dsse-core/decision"
)

// ★★ THREE ROWS ABOUT ONE OPERATOR SESSION, THREE DIFFERENT ANSWERS TO "WHO DID THIS" (2026-08-17, read in a
// probe organization's own audit trail after seating its first administrator).
//
//	admin_tenant_model_created           -> the screen said "System"
//	operator_seated_first_administrator  -> the screen said "adm_fa6e5d2462edc1de49489e55fd66d56a"
//	admin_operate_within_tenant          -> the screen said an operator's own address
//
// Every one of those records HELD the actor. They disagreed about the field name — actor_admin_principal_id,
// nothing, operator_principal_id — and the console reads one of those names. The customer's audit screen is
// the single place this organization can learn that somebody outside it was working inside it, and two of the
// three rows there did not say so.
//
// The fix is a shared stamp rather than three call sites agreeing by habit, and this test is about the pair
// that has to hold: what the emitters write, and what the reader looks for.
func TestOneVocabularyForTheOperatorWhoActedInsideYourOrganization(t *testing.T) {
	identity := adminIdentity{
		PrincipalID:    "adm_operator",
		TenantID:       "tenant_operator_001",
		PrincipalLabel: "ops@lab.local",
		Roles:          []string{"super_admin"},
	}

	meta := map[string]any{}
	stampOperatorActor(meta, identity)
	for key, want := range map[string]string{
		"operator_principal_id": "adm_operator",
		"operator_tenant_id":    "tenant_operator_001",
		"email":                 "ops@lab.local",
		"display_name":          "ops@lab.local",
	} {
		if got, _ := meta[key].(string); got != want {
			t.Fatalf("metadata[%q] = %q, want %q", key, got, want)
		}
	}

	// An operator with no label still has to read as the operator rather than as nobody: the console's
	// no-actor case renders "System", which is a false statement about a person's act.
	bare := map[string]any{}
	stampOperatorActor(bare, adminIdentity{PrincipalID: "adm_operator", TenantID: "tenant_operator_001"})
	if _, ok := bare["operator_principal_id"]; !ok {
		t.Fatal("without a label the row must still say the operator acted, or the screen falls through to System")
	}
	if _, ok := bare["email"]; ok {
		t.Fatal("an absent label must not be written as an empty one — a blank name renders as a blank name")
	}

	// The built record carries it too, so the stamp cannot be added to the helper and forgotten at the call.
	record := adminOperateWithinTenantAuditLog(identity, "tenant_customer", "POST", "/admin/rules",
		decision.Evaluator{}, "10.0.0.1", "curl")
	if got, _ := record.Metadata["operator_principal_id"].(string); got != "adm_operator" {
		t.Fatalf("adminOperateWithinTenantAuditLog lost the operator stamp: %v", record.Metadata)
	}

	// ★ AND THE READER IS HALF THE CONTRACT. Asserting the emitters agree with each other proves nothing if
	// the console looks for a fourth name — which is exactly how this defect was born. The one key that
	// decides whether the row reads as the operator at all must be the key the console tests for.
	source, err := os.ReadFile("../../console/logsaudit.js")
	if err != nil {
		t.Skipf("console not present next to the server (%v) — the reader half was NOT checked", err)
	}
	if !strings.Contains(string(source), "operator_principal_id") {
		t.Fatal("console/logsaudit.js no longer reads meta.operator_principal_id: the audit screen and the " +
			"audit emitters have drifted apart, and the screen is the side a customer believes")
	}
	// Positive control: the check must be able to fail. A key nothing writes must not be found.
	if regexp.MustCompile(`\boperator_principal_id_that_nothing_writes\b`).Match(source) {
		t.Fatal("the control key was found, so the search proves nothing")
	}
}
