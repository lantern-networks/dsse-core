package aiops_test

import (
	"strings"
	"testing"

	"github.com/lantern-networks/dsse-core/aiops"
	"github.com/lantern-networks/dsse-core/model"
)

func TestExplainReasonCodeGrounded(t *testing.T) {
	known := aiops.ExplainReasonCode("application_denied")
	if !known.Known || known.EN == "" || known.Remediation == "" {
		t.Fatalf("a known code should be grounded with text + remediation: %+v", known)
	}
	unknown := aiops.ExplainReasonCode("some_future_code_xyz")
	if unknown.Known || !strings.Contains(unknown.EN, "some_future_code_xyz") {
		t.Fatalf("an unknown code must restate the code verbatim, never fabricate: %+v", unknown)
	}
}

func TestClampQueryLimitAndValueOrUnknown(t *testing.T) {
	if got := aiops.ClampQueryLimit("", 50, 100); got != 50 {
		t.Fatalf("empty -> default, got %d", got)
	}
	if got := aiops.ClampQueryLimit("9999", 50, 100); got != 100 {
		t.Fatalf("over-max -> clamp, got %d", got)
	}
	if got := aiops.ClampQueryLimit("nope", 50, 100); got != 50 {
		t.Fatalf("invalid -> default, got %d", got)
	}
	if aiops.ValueOrUnknown("") == "" {
		t.Fatal("empty should become a non-empty placeholder")
	}
	if aiops.ValueOrUnknown("x") != "x" {
		t.Fatal("non-empty must be preserved")
	}
}

func TestTemplateRendererEnglishReportGrounded(t *testing.T) {
	decs := []model.AccessDecision{
		{ID: "d1", TenantID: "acme", Decision: "allow", Timestamp: "2026-01-01T00:00:00Z", ReasonCodes: []string{"policy_matched"}},
		{ID: "d2", TenantID: "acme", Decision: "deny", Timestamp: "2026-01-01T00:01:00Z", ReasonCodes: []string{"no_policy_match"}},
	}
	in := aiops.BuildNarrativeReportInput(decs, "acme", "2026-01-01T00:05:00Z", 20)
	report, err := aiops.TemplateNarrativeRenderer{}.Render(in)
	if err != nil {
		t.Fatal(err)
	}
	if report.Renderer != "template" || report.BodyEN == "" {
		t.Fatalf("template report missing body: %+v", report)
	}
	if !strings.Contains(report.BodyEN, "no data is sent to any external AI service") {
		t.Fatalf("report must carry the no-external-transmission attestation: %s", report.BodyEN)
	}
}
