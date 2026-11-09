package main

import (
	"os"
	"strings"
	"testing"

	"github.com/lantern-networks/dsse-core/model"
)

// Found 2026-11-04 walking the step-up for a private application: every flow, including the one the sign-in let
// through, was recorded as authenticate_required, and no access was ever recorded.
func TestAFlowLetThroughBySignInIsRecordedAsAllowed(t *testing.T) {
	reason := "East-west access requires interactive authentication."
	required := model.AccessDecision{ID: "d1", Decision: "authenticate_required", Reason: &reason,
		ReasonCodes: []string{"east_west_authentication_required"}, Metadata: map[string]any{"east_west_protocol": "http"}}
	got := decisionAllowedByAuthentication(required)
	if got.Decision != "allow" || !decisionWasAllowedByAuthentication(got) {
		t.Fatalf("decision = %q, codes = %v", got.Decision, got.ReasonCodes)
	}
	if got.Metadata["required_decision"] != "authenticate_required" || got.Metadata["east_west_protocol"] != "http" {
		t.Fatalf("metadata lost what the rule required: %v", got.Metadata)
	}
	if required.Decision != "authenticate_required" || len(required.ReasonCodes) != 1 || required.Metadata["required_decision"] != nil {
		t.Fatal("the original decision was modified")
	}
	if decisionWasAllowedByAuthentication(model.AccessDecision{Decision: "allow"}) {
		t.Fatal("an ordinary allow claimed to be an authentication")
	}
}

// The steer-mux path is one long handler, so the order of its records is checked by its source: a decision
// needing sign-in is not recorded before the grant is known, a held flow records it, and a resumed one records
// the allowed form.
func TestTheSteerMuxRecordsHeldAndResumedFlowsDifferently(t *testing.T) {
	b, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, want := range []string{
		"authRecordedLater := federatedAuthGateForEgress != nil && decisionRequiresOIDCRedirect(dec.Decision)",
		"if shouldLogAccessDecision(dec) && !authRecordedLater {",
		"} else {\n\t\t\t\t\t\tlogHeldForAuthentication()",
		"dec = decisionAllowedByAuthentication(dec)",
		"if shouldLogAccessDecision(dec) || decisionWasAllowedByAuthentication(dec) {",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("steer-mux path is missing %q", want)
		}
	}
}

// The browser path forwards a request whose sign-in grant is live; its deferred record must say allowed.
func TestTheBrowserPathRecordsARequestLetThroughBySignInAsAllowed(t *testing.T) {
	b, err := os.ReadFile("swg_http_egress.go")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, want := range []string{
		"if allowedByAuthentication {\n\t\t\tdec = decisionAllowedByAuthentication(dec)",
		"// a live federated grant satisfies the authenticate requirement — fall through and forward.\n\t\t\tallowedByAuthentication = true",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("browser path is missing %q", want)
		}
	}
}

// The re-check before forwarding refused a flow that had a live grant, and nothing was recorded.
func TestAFlowRefusedAtTheLastRecheckIsRecordedAsRefused(t *testing.T) {
	original := model.AccessDecision{ID: "ad_1", TenantID: "tenant_a", Decision: "authenticate_required",
		ReasonCodes: []string{"rule_authenticate"}, Metadata: map[string]any{"rule_id": "r1"}}

	// The policy now denies: that decision is the record.
	deny := model.AccessDecision{ID: "ad_2", TenantID: "tenant_a", Decision: "deny", ReasonCodes: []string{"rule_deny"}}
	if got := decisionRefusedAtResume(original, deny); got.ID != "ad_2" || got.Decision != "deny" {
		t.Fatalf("the policy's own denial was not recorded as it is: %+v", got)
	}

	// No decision could be made, the sign-in no longer satisfies the rule, or the configuration moved during the
	// check (an allow that was still refused): a denial of the original request, never an allow.
	for _, current := range []model.AccessDecision{
		{},
		{TenantID: "tenant_a", Decision: "authenticate_required"},
		{TenantID: "tenant_a", Decision: "allow"},
		{TenantID: "tenant_b", Decision: "deny"},
	} {
		got := decisionRefusedAtResume(original, current)
		if got.Decision != "deny" || got.TenantID != "tenant_a" {
			t.Fatalf("%+v recorded as %+v", current, got)
		}
		// Its own id, so it cannot overwrite the held row; the held one is named.
		if got.ID == "" || got.ID == "ad_1" || got.Metadata["held_decision_id"] != "ad_1" {
			t.Fatalf("the refusal's id: %q, held %v", got.ID, got.Metadata["held_decision_id"])
		}
		if got.Metadata["required_decision"] != "authenticate_required" || got.Metadata["rule_id"] != "r1" {
			t.Fatalf("the record lost what the rule required: %+v", got.Metadata)
		}
		if codes := strings.Join(got.ReasonCodes, ","); codes != "rule_authenticate,"+reasonCodeResumeRefused {
			t.Fatalf("reason codes: %s", codes)
		}
		if decisionWasAllowedByAuthentication(got) {
			t.Fatal("a refused flow reads as allowed by authentication")
		}
	}
	if original.Decision != "authenticate_required" || len(original.ReasonCodes) != 1 || len(original.Metadata) != 1 {
		t.Fatalf("the original decision was changed: %+v", original)
	}
}

// And the steer handler records it where it refuses (a helper nobody calls would pass the test above).
func TestTheSteerResumeRefusalWritesTheRecord(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(src)
	i := strings.Index(text, `log.Printf("steer_mux_auth_resume_denied device=%q", transportDeviceID)`)
	if i < 0 {
		t.Fatal("the refusal branch moved")
	}
	branch := text[i:min(len(text), i+400)]
	if !strings.Contains(branch, "decisionRefusedAtResume(dec, current)") ||
		!strings.Contains(branch, "appendAccessDecisionLogs(r.Context(), writer, domainEventOutbox, refused, time.Now())") {
		t.Fatalf("the refusal branch does not record the refusal:\n%s", branch)
	}
}
