package main

import (
	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/inspectionposture"
	"github.com/lantern-networks/dsse-core/model"
)

// A clean installation logs inspected destinations without a seeded SaaS catalog. Use the
// product's existing AI host catalog for reporting those records; this does not change
// policy matching, inspection, or enforcement. Explicit service IDs remain authoritative.
var aiUsageDestinationCatalog = func() []model.SaaSCatalogEntry {
	names := map[string]string{
		"openai": "OpenAI ChatGPT", "anthropic": "Anthropic Claude",
		"google_gemini": "Google Gemini", "microsoft_copilot": "Microsoft Copilot",
		"github_copilot": "GitHub Copilot", "perplexity": "Perplexity",
		"mistral": "Mistral", "deepseek": "DeepSeek", "xai_grok": "Grok",
		"poe": "Poe", "meta_ai": "Meta AI", "alibaba_qwen": "Qwen",
		"moonshot_kimi": "Kimi", "bytedance_doubao": "Doubao", "felo": "Felo",
	}
	var entries []model.SaaSCatalogEntry
	for _, group := range inspectionposture.AuthDecryptGroups {
		name, known := names[group.Name]
		if !known || group.Category != inspectionposture.CategoryAI {
			continue
		}
		id := "saas_" + group.Name
		switch group.Name {
		case "openai":
			id = "saas_openai_chatgpt"
		case "anthropic":
			id = "saas_anthropic_claude"
		}
		entries = append(entries, model.SaaSCatalogEntry{
			SaaSApplicationID: id, Name: name, Category: "ai", AIService: true,
			DomainPatterns: append([]string(nil), group.Patterns...),
		})
	}
	return entries
}()

func aiUsageCatalogForTenant(tenant string, catalog []model.SaaSCatalogEntry) []model.SaaSCatalogEntry {
	var scoped []model.SaaSCatalogEntry
	for _, entry := range catalog {
		if entry.TenantID == "" || entry.TenantID == tenant {
			scoped = append(scoped, entry)
		}
	}
	return scoped
}

func aiUsageServiceFromDestination(row map[string]any, catalog []model.SaaSCatalogEntry) (string, string) {
	// The caller filters records by authenticated tenant before aggregation. Retain that
	// same scope when matching tenant-owned catalog entries (including the grouped path).
	tenant := stringFromRow(row, "tenant_id")
	entries := make([]model.SaaSCatalogEntry, 0, len(catalog)+len(aiUsageDestinationCatalog))
	for _, entry := range catalog {
		if entry.TenantID == "" || entry.TenantID == tenant {
			entries = append(entries, entry)
		}
	}
	entries = append(entries, aiUsageDestinationCatalog...)
	ctx, ok := decision.SaaSContextForRequest(model.PolicyBundle{TenantID: tenant, SaaSCatalog: entries}, model.DecisionRequest{Destination: stringFromRow(row, "destination")})
	if !ok {
		return "", ""
	}
	return ctx.SaaSApplicationID, ctx.Name
}
