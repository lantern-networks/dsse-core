package decision

import (
	"testing"

	"github.com/lantern-networks/dsse-core/model"
)

func TestDLPRuleMatches(t *testing.T) {
	if !dlpRuleMatches(model.DLPRule{SaaSApplicationID: "saas_x"}, model.DecisionRequest{SaaSApplicationID: "saas_x"}) {
		t.Error("should match by SaaS application id")
	}
	if !dlpRuleMatches(model.DLPRule{Provider: "acme"}, model.DecisionRequest{SaaSProvider: "acme"}) {
		t.Error("should match by provider")
	}
	if !dlpRuleMatches(model.DLPRule{}, model.DecisionRequest{SaaSApplicationID: "anything"}) {
		t.Error("no-selector rule should match tenant-wide")
	}
	if dlpRuleMatches(model.DLPRule{SaaSApplicationID: "saas_x"}, model.DecisionRequest{SaaSApplicationID: "saas_y"}) {
		t.Error("should not match a different app")
	}
}

func TestDLPInspectAction(t *testing.T) {
	a := dlpInspectAction(model.DLPRule{ID: "r1", Identifiers: []string{"my_number"}, MinCount: 2, OnMatch: "block"})
	if a.Type != "dlp_inspect" {
		t.Fatalf("type = %q", a.Type)
	}
	if a.Metadata["dlp_rule_id"] != "r1" || a.Metadata["action"] != "block" || a.Metadata["min_count"] != 2 {
		t.Errorf("metadata = %+v", a.Metadata)
	}
	if dlpInspectAction(model.DLPRule{ID: "r2", Identifiers: []string{"my_number"}}).Metadata["action"] != "observe" {
		t.Error("empty OnMatch should default to observe")
	}
}

func TestDLPInspectActionFromSpec(t *testing.T) {
	a := dlpInspectActionFromSpec("pol-1", model.DLPSpec{Identifiers: []string{"credit_card"}, MinCount: 1, OnMatch: "authenticate"})
	if a.Type != "dlp_inspect" || a.Metadata["dlp_rule_id"] != "pol-1" || a.Metadata["action"] != "authenticate" {
		t.Errorf("policy-spec directive = %+v", a.Metadata)
	}
}
