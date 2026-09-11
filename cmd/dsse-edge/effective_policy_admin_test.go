package main

import (
	"testing"

	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/inspectionposture"
	"github.com/lantern-networks/dsse-core/knownbypass"
	"github.com/lantern-networks/dsse-core/model"
)

// effectivePolicyForDestination must surface the 2026-06-23 hidden competition: a built-in base allow and an
// authored rule at the same priority both match accounts.google.com; the authored rule wins and the built-in
// is marked shadowed, each tagged by source. This is the curl-able artifact behind the Effective-Policy view.
func TestEffectivePolicyForDestinationTagsAndShadowing(t *testing.T) {
	builtinAllow := model.Policy{
		ID: "pol_google_workspace_swg_allow_001", Status: "active", Priority: 100,
		Conditions: map[string]any{"sni": "accounts.google.com"},
		Action:     model.PolicyAction{Decision: "allow"},
	}
	authored := model.Policy{
		ID: "rule-egress-rule-15-0-sni", Status: "active", Priority: 100,
		Conditions: map[string]any{"sni": "accounts.google.com"},
		Action:     model.PolicyAction{Decision: "require_reauthentication"},
	}
	eval := decision.Evaluator{Policies: []model.Policy{builtinAllow, authored}}

	// accounts.google.com is decrypted (decrypt-all intercept "*", not in any bypass set).
	resp := effectivePolicyForDestination(eval, "t", effectivePolicyQuery{Destination: "accounts.google.com"}, inspectionSources{InterceptHosts: []string{"*"}})
	if resp.Inspection.Decision != "inspect" || resp.Inspection.Source != "default_decrypt_all" {
		t.Fatalf("inspection = %+v, want inspect/default_decrypt_all", resp.Inspection)
	}

	if resp.WinnerPolicyID != "rule-egress-rule-15-0-sni" || resp.WinnerDecision != "require_reauthentication" {
		t.Fatalf("winner = %q/%q, want authored require_reauthentication", resp.WinnerPolicyID, resp.WinnerDecision)
	}
	if resp.ActorType != "human" {
		t.Fatalf("actor_type defaulted wrong: %q", resp.ActorType)
	}
	bySrc := map[string]effectivePolicyEntry{}
	for _, e := range resp.Trace {
		bySrc[e.PolicyID] = e
	}
	if b := bySrc["pol_google_workspace_swg_allow_001"]; b.Source != "built_in" || !b.Shadowed || b.Winner {
		t.Fatalf("built-in entry = %+v, want source=built_in shadowed winner=false", b)
	}
	if a := bySrc["rule-egress-rule-15-0-sni"]; a.Source != "authored" || !a.Winner || a.Shadowed {
		t.Fatalf("authored entry = %+v, want source=authored winner shadowed=false", a)
	}
	if resp.Note == "" {
		t.Fatalf("response should note that the inspect/bypass basis is not yet included")
	}
}

// policyProvenanceTag: rule-* prefixes and created_by attribution are authored; bare pol_ ids are built-in.
func TestPolicyProvenanceTag(t *testing.T) {
	createdBy := "admin@example.com"
	cases := []struct {
		entry decision.PolicyTraceEntry
		want  string
	}{
		{decision.PolicyTraceEntry{PolicyID: "rule-egress-rule-15-0-sni"}, "authored"},
		{decision.PolicyTraceEntry{PolicyID: "rule-eastwest-7-0"}, "authored"},
		{decision.PolicyTraceEntry{PolicyID: "pol_demo", CreatedBy: createdBy}, "authored"},
		{decision.PolicyTraceEntry{PolicyID: "pol_google_workspace_swg_allow_001"}, "built_in"},
	}
	for _, c := range cases {
		if got := policyProvenanceTag(c.entry); got != c.want {
			t.Fatalf("policyProvenanceTag(%q) = %q, want %q", c.entry.PolicyID, got, c.want)
		}
	}
}

// classifyInspection: the engine's effective bypass set is authoritative for inspect-vs-bypass; when bypassed,
// the source is attributed to the matching known-bypass group / authored bypass / cert-pin, else static_bypass.
func TestClassifyInspectionDecryptAll(t *testing.T) {
	// decrypt-all: intercept "*", so everything not bypassed is decrypted.
	src := inspectionSources{
		InterceptHosts:  []string{"*"},
		EffectiveBypass: []string{"*.icloud.com", "pinned.example.com", "authored.example.com", "static.example.com"},
		KnownGroups:     []knownbypass.Group{{Name: "apple_push_icloud", Patterns: []string{"*.icloud.com"}}},
		AuthoredBypass:  []string{"authored.example.com"},
		CertPinBypass:   []string{"pinned.example.com"},
	}
	cases := []struct{ host, wantDecision, wantSource string }{
		{"accounts.google.com", "inspect", "default_decrypt_all"}, // not bypassed, intercept "*" → decrypted
		{"x.icloud.com", "bypass", "known_bypass"},                // *.icloud.com curated group (apex+subdomain)
		{"icloud.com", "bypass", "known_bypass"},                  // *.suffix matches the apex too
		{"authored.example.com", "bypass", "authored_bypass"},
		{"pinned.example.com", "bypass", "cert_pin_materialized"},
		{"static.example.com", "bypass", "static_bypass"}, // in the bypass set but no tracked source
	}
	for _, c := range cases {
		if got := classifyInspection(c.host, src); got.Decision != c.wantDecision || got.Source != c.wantSource {
			t.Fatalf("classifyInspection(%q) = %+v, want %s/%s", c.host, got, c.wantDecision, c.wantSource)
		}
	}
}

func TestClassifyInspectionBypassDefault(t *testing.T) {
	// bypass-default: intercept set is the decrypt allowlist; only those hosts are decrypted, the rest bypassed.
	src := inspectionSources{
		InterceptHosts:  []string{"login.microsoftonline.com", "accounts.google.com"},
		EffectiveBypass: []string{"*.icloud.com", "*.teams.microsoft.com"},
		KnownGroups:     []knownbypass.Group{{Name: "apple_push_icloud", Patterns: []string{"*.icloud.com"}}},
		OptimizeGroups:  []inspectionposture.AuthDecryptGroup{{Name: "m365_optimize", Patterns: []string{"*.teams.microsoft.com"}}},
	}
	cases := []struct{ host, wantDecision, wantSource string }{
		{"accounts.google.com", "inspect", "decrypt_allowlist"},       // in the allowlist → decrypted
		{"login.microsoftonline.com", "inspect", "decrypt_allowlist"}, // in the allowlist → decrypted
		{"www.example.com", "bypass", "bypass_default"},               // NOT in the allowlist → bypassed by default
		{"x.icloud.com", "bypass", "known_bypass"},                    // bypass set still wins, attributed
		{"x.teams.microsoft.com", "bypass", "saas_optimize"},          // SaaS Optimize bypass group attributed
	}
	for _, c := range cases {
		if got := classifyInspection(c.host, src); got.Decision != c.wantDecision || got.Source != c.wantSource {
			t.Fatalf("classifyInspection(%q) = %+v, want %s/%s", c.host, got, c.wantDecision, c.wantSource)
		}
	}
}
