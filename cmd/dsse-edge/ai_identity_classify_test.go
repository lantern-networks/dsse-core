package main

import (
	"testing"

	"github.com/lantern-networks/dsse-core/model"
)

func TestClassifyUserIdentity(t *testing.T) {
	cases := map[string]string{
		"alice@corp.example":            "user",
		"bob@lantern.io":                "user",
		"eve@gmail.com":                 "user_personal",
		"someone@outlook.com":           "user_personal",
		"google-oauth2|112933652439454": "user_opaque",
		"x7vaVY4E5EnxkKz7FV1vq":         "user_opaque",
		"auth0|abc":                     "user_opaque",
		"@nodomain":                     "user_opaque",
		"trailing@":                     "user_opaque",
	}
	for in, want := range cases {
		if got := classifyUserIdentity(in); got != want {
			t.Errorf("classifyUserIdentity(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestTwoIdentityModel_CorporateAndAIAccount(t *testing.T) {
	catalog := []model.SaaSCatalogEntry{{SaaSApplicationID: "saas_openai_chatgpt", Name: "ChatGPT", AIService: true}}
	// A corporate person (user_id from the IdP session) signed into ChatGPT with a PERSONAL account (ai_account
	// metadata from the JWT). Both must be captured; the person is shadow AI (personal account at the assistant).
	rows := []map[string]any{
		{"tenant_id": "t", "saas_application_id": "saas_openai_chatgpt", "user_id": "alice@corp.example",
			"metadata": map[string]any{"ai_account": "alice@gmail.com", "http_method": "POST"}},
	}
	rep := buildAIUsageReport(accessRowsForTenant(rows, "t"), catalog, "2026-07-05T00:00:00Z")
	if len(rep.ByIdentity) != 1 {
		t.Fatalf("want 1 identity, got %d", len(rep.ByIdentity))
	}
	e := rep.ByIdentity[0]
	if e.CorporateUser != "alice@corp.example" {
		t.Errorf("corporate_user = %q, want alice@corp.example", e.CorporateUser)
	}
	if len(e.AIAccounts) != 1 || e.AIAccounts[0] != "alice@gmail.com" {
		t.Errorf("ai_accounts = %v, want [alice@gmail.com]", e.AIAccounts)
	}
	if e.Identity != "alice@corp.example" { // grouped by corporate identity
		t.Errorf("identity key = %q, want the corporate identity", e.Identity)
	}
	// corporate person on a personal assistant account => shadow AI.
	if len(rep.ShadowAI) != 1 || rep.ShadowAI[0].CorporateUser != "alice@corp.example" {
		t.Errorf("shadow_ai should flag the corporate user on a personal account, got %+v", rep.ShadowAI)
	}
}
