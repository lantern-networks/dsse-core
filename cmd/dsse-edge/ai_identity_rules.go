package main

import (
	"strings"

	"github.com/lantern-networks/dsse-core/model"
)

// AI identity attribution rules (read model + the ground truth the extractor runs). Each AI service has a FIXED
// rule saying exactly WHERE to read the signed-in user's email and display name — per service, because each
// exposes identity differently. Fixing the source+claim per service beats a generic scan-every-token heuristic: it
// cannot mis-attribute by grabbing an unrelated token's email. The rule is reference data on the SaaS catalog
// (model.SaaSIdentityRule; ignored by the OSS decision engine, read only here); a code default applies when the
// catalog carries none. Config only — never a real captured value. See docs/ai_identity_attribution_ui_design.md.

var bearerEmail = model.SaaSIdentitySource{Source: "bearer", Claim: "email"}
var bearerName = model.SaaSIdentitySource{Source: "bearer", Claim: "name"}

// aiIdentityRuleNeedsVerification marks AI services whose identity extraction rule is a BEST-EFFORT default:
// decryption + classification are verified live, but the ACTUAL identity fields each service exposes have NOT been
// confirmed with a real signed-in account. MUST be verified before productization — a service may expose only a
// name, or nothing (Chinese assistants often use phone / opaque login, so email/name may be absent -> device
// fallback). Verified from real signed-in traffic: chatgpt (email), claude (name), microsoft copilot (email),
// gemini (none). Kept as a code-level marker: the admin surface that used to display it was removed, so
// nothing renders this today — it records which shipped rules are best-effort rather than verified.
var aiIdentityRuleNeedsVerification = map[string]bool{
	"saas_github_copilot":   true,
	"saas_perplexity":       true,
	"saas_mistral":          true,
	"saas_deepseek":         true,
	"saas_xai_grok":         true,
	"saas_poe":              true,
	"saas_meta_ai":          true,
	"saas_alibaba_qwen":     true,
	"saas_moonshot_kimi":    true,
	"saas_bytedance_doubao": true,
	"saas_felo":             true,
}

// builtinAIServiceIdentityRules are the shipped, per-service code defaults (used when the catalog entry carries no
// IdentityRule of its own).
var builtinAIServiceIdentityRules = map[string]model.SaaSIdentityRule{
	// ChatGPT access token is a Bearer JWT carrying the corporate email (sometimes under OpenAI's namespaced key).
	"saas_openai_chatgpt": {
		EmailFrom: []model.SaaSIdentitySource{bearerEmail, {Source: "bearer", Claim: "https://api.openai.com/email"}},
		NameFrom:  []model.SaaSIdentitySource{bearerName},
	},
	"saas_microsoft_copilot": {EmailFrom: []model.SaaSIdentitySource{bearerEmail}, NameFrom: []model.SaaSIdentitySource{bearerName}},
	"saas_github_copilot":    {EmailFrom: []model.SaaSIdentitySource{bearerEmail}, NameFrom: []model.SaaSIdentitySource{bearerName}},
	// Claude's session JWT carries a DISPLAY NAME but no email — so there is NO EmailFrom (never grab a stray email).
	"saas_anthropic_claude": {NameFrom: []model.SaaSIdentitySource{bearerName, {Source: "cookie", Claim: "name", SkipCookiePatterns: []string{"anon"}}}},
	"saas_perplexity":       {EmailFrom: []model.SaaSIdentitySource{bearerEmail}, NameFrom: []model.SaaSIdentitySource{bearerName}},
	// Gemini exposes only opaque Google cookies — nothing to read; both empty -> device/OS fallback.
	"saas_google_gemini": {},
}

// aiGenericIdentityRule is the best-effort rule for AI services with neither a catalog rule nor a code default.
func aiGenericIdentityRule() model.SaaSIdentityRule {
	skipAnon := []string{"anon"}
	return model.SaaSIdentityRule{
		EmailFrom: []model.SaaSIdentitySource{bearerEmail, {Source: "cookie", Claim: "email", SkipCookiePatterns: skipAnon}},
		NameFrom:  []model.SaaSIdentitySource{bearerName, {Source: "cookie", Claim: "name", SkipCookiePatterns: skipAnon}},
	}
}

// aiServiceIdentityRuleForEntry resolves a catalog entry's identity rule: the entry's own IdentityRule (a tenant
// custom/override) wins; else the shipped code default; else the generic best-effort rule. custom reports whether
// the resolved rule came from the catalog entry (vs a built-in default).
func aiServiceIdentityRuleForEntry(e model.SaaSCatalogEntry) (rule model.SaaSIdentityRule, custom bool) {
	if e.IdentityRule != nil {
		return *e.IdentityRule, true
	}
	if r, ok := builtinAIServiceIdentityRules[strings.TrimSpace(e.SaaSApplicationID)]; ok {
		return r, false
	}
	return aiGenericIdentityRule(), false
}

// aiServiceIdentityRuleFor resolves the rule for an app id given the tenant's catalog (custom rule on the entry ->
// code default -> generic). Used by the extractor.
func aiServiceIdentityRuleFor(catalog []model.SaaSCatalogEntry, appID string) model.SaaSIdentityRule {
	appID = strings.TrimSpace(appID)
	for _, e := range catalog {
		if strings.TrimSpace(e.SaaSApplicationID) == appID && e.IdentityRule != nil {
			return *e.IdentityRule
		}
	}
	if r, ok := builtinAIServiceIdentityRules[appID]; ok {
		return r
	}
	return aiGenericIdentityRule()
}
