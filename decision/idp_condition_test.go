package decision

import (
	"testing"

	"github.com/lantern-networks/dsse-core/model"
)

// A policy can match on WHICH IdP issued the end-user identity: idp_id (the registered connection id) and
// issuer (the OIDC token issuer). This is the matching half of per-policy IdP selection — the required-IdP
// resolution + redirect is layered on in a later slice.
func TestPolicyIdPIDCondition(t *testing.T) {
	policy := model.Policy{
		ID:         "p1",
		Status:     "active",
		Conditions: map[string]any{"idp_id": []any{"idp_partner", "idp_privileged"}},
		Action:     model.PolicyAction{Decision: "allow"},
	}
	if ok, _ := matchPolicy(policy, model.DecisionRequest{IDPID: "idp_partner"}, "human"); !ok {
		t.Fatal("should match a listed idp_id")
	}
	if ok, _ := matchPolicy(policy, model.DecisionRequest{IDPID: "idp_default"}, "human"); ok {
		t.Fatal("must NOT match an unlisted idp_id")
	}
	if ok, _ := matchPolicy(policy, model.DecisionRequest{}, "human"); ok {
		t.Fatal("must NOT match when no idp_id is present")
	}
}

// A require_reauthentication policy carries the federated re-auth requirements (which IdP + how strong) in
// its prompt_reauthentication action, so the (later) OIDC broker can build the redirect. This is the
// "require_authentication" action shape.
func TestRequireAuthenticationActionCarriesIdPAndAssurance(t *testing.T) {
	policy := model.Policy{
		ID: "p1", Status: "active",
		Conditions: map[string]any{"fqdn": "accounts.google.com"},
		Action:     model.PolicyAction{Decision: "require_reauthentication"},
		Metadata: map[string]any{
			"required_idp_id": "idp_privileged",
			"min_acr":         "AAL2",
			"required_amr":    "mfa,phr",
			"max_age_seconds": 300,
		},
	}
	actions := actionsForPolicyDecision("require_reauthentication", model.DecisionRequest{ApplicationID: "app1", ServiceFamily: "https"}, policy)
	if len(actions) != 1 || actions[0].Type != "prompt_reauthentication" {
		t.Fatalf("expected one prompt_reauthentication action, got %+v", actions)
	}
	m := actions[0].Metadata
	if m["required_idp_id"] != "idp_privileged" {
		t.Fatalf("required_idp_id = %v", m["required_idp_id"])
	}
	if m["min_acr"] != "AAL2" {
		t.Fatalf("min_acr = %v", m["min_acr"])
	}
	amr, ok := m["required_amr"].([]string)
	if !ok || len(amr) != 2 || amr[0] != "mfa" || amr[1] != "phr" {
		t.Fatalf("required_amr = %v", m["required_amr"])
	}
	if m["max_age_seconds"] != 300 {
		t.Fatalf("max_age_seconds = %v", m["max_age_seconds"])
	}
}

// Back-compat: a bare require_reauthentication (no metadata) carries no IdP/assurance requirements (= default
// IdP, default assurance).
func TestRequireReauthBareHasNoRequirements(t *testing.T) {
	actions := actionsForPolicyDecision("require_reauthentication", model.DecisionRequest{ApplicationID: "app1"}, model.Policy{})
	if len(actions) != 1 {
		t.Fatalf("expected one action, got %d", len(actions))
	}
	if _, ok := actions[0].Metadata["required_idp_id"]; ok {
		t.Fatal("a bare require_reauthentication must not carry required_idp_id")
	}
}

func TestPolicyIssuerCondition(t *testing.T) {
	policy := model.Policy{
		ID:         "p1",
		Status:     "active",
		Conditions: map[string]any{"issuer": "https://login.partner.example.com"},
		Action:     model.PolicyAction{Decision: "deny"},
	}
	if ok, _ := matchPolicy(policy, model.DecisionRequest{Issuer: "https://login.partner.example.com"}, "human"); !ok {
		t.Fatal("should match the exact issuer")
	}
	if ok, _ := matchPolicy(policy, model.DecisionRequest{Issuer: "https://accounts.google.com"}, "human"); ok {
		t.Fatal("must NOT match a different issuer")
	}
}
