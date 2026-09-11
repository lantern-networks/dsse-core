package main

import (
	"testing"

	"github.com/lantern-networks/dsse-core/model"
)

// tenant isolation: the AI usage report is built from the SHARED access log, so it must be scoped
// to the requesting tenant — never aggregate another tenant's rows.
func TestAccessRowsForTenantIsolation(t *testing.T) {
	rows := []map[string]any{
		{"tenant_id": "tenant_a", "saas_application_id": "saas_openai_chatgpt"},
		{"tenant_id": "tenant_b", "saas_application_id": "saas_openai_chatgpt"},
		{"tenant_id": "tenant_a", "saas_application_id": "saas_anthropic_claude"},
		{"tenant_id": "tenant_b", "saas_application_id": "saas_anthropic_claude"},
	}
	a := accessRowsForTenant(rows, "tenant_a")
	if len(a) != 2 {
		t.Fatalf("expected 2 tenant_a rows, got %d", len(a))
	}
	for _, row := range a {
		if row["tenant_id"] != "tenant_a" {
			t.Fatalf("ISOLATION VIOLATION: tenant_b row leaked into tenant_a scope: %v", row)
		}
	}
	if got := accessRowsForTenant(rows, ""); got != nil {
		t.Fatalf("empty tenant must yield no rows (fail-closed), got %d", len(got))
	}
	if got := accessRowsForTenant(rows, "tenant_c"); len(got) != 0 {
		t.Fatalf("unknown tenant must yield 0 rows, got %d", len(got))
	}
}

func TestBuildAIUsageReport(t *testing.T) {
	catalog := []model.SaaSCatalogEntry{
		{SaaSApplicationID: "saas_openai_chatgpt", Name: "ChatGPT", AIService: true, AIGovernance: "prohibited"},
		{SaaSApplicationID: "saas_anthropic_claude", Name: "Claude"},           // known default -> approved
		{SaaSApplicationID: "saas_google_workspace", Name: "Google Workspace"}, // not AI
	}
	rows := []map[string]any{
		{"saas_application_id": "saas_openai_chatgpt", "saas_name": "ChatGPT"},
		{"saas_application_id": "saas_openai_chatgpt", "saas_name": "ChatGPT"},
		{"saas_application_id": "saas_openai_chatgpt", "saas_name": "ChatGPT"},
		{"saas_application_id": "saas_anthropic_claude", "saas_name": "Claude"},
		{"saas_application_id": "saas_google_workspace", "saas_name": "Google Workspace"},                   // ignored (not AI)
		{"metadata": map[string]any{"saas_application_id": "saas_anthropic_claude", "saas_name": "Claude"}}, // nested
	}
	rep := buildAIUsageReport(rows, catalog, "2026-06-17T00:00:00Z")
	if rep.TotalAIAccesses != 5 {
		t.Fatalf("total AI accesses = %d, want 4", rep.TotalAIAccesses)
	}
	if len(rep.Services) != 2 {
		t.Fatalf("services = %d, want 2", len(rep.Services))
	}
	if rep.Services[0].SaaSApplicationID != "saas_openai_chatgpt" || rep.Services[0].AccessCount != 3 || rep.Services[0].AIGovernance != "prohibited" {
		t.Fatalf("top service wrong: %+v", rep.Services[0])
	}
	if rep.ByGovernance["prohibited"] != 3 || rep.ByGovernance["approved"] != 2 {
		t.Fatalf("by_governance wrong: %+v", rep.ByGovernance)
	}
}

func TestBuildAIUsageReport_ByteVolume(t *testing.T) {
	catalog := []model.SaaSCatalogEntry{
		{SaaSApplicationID: "saas_anthropic_claude", Name: "Claude"},
		{SaaSApplicationID: "saas_openai_chatgpt", Name: "ChatGPT", AIService: true},
	}
	rows := []map[string]any{
		{"saas_application_id": "saas_anthropic_claude", "saas_name": "Claude", "metadata": map[string]any{"bytes_sent": float64(34), "bytes_received": float64(3493)}},
		{"saas_application_id": "saas_anthropic_claude", "saas_name": "Claude", "metadata": map[string]any{"bytes_sent": float64(100), "bytes_received": float64(500)}},
		{"saas_application_id": "saas_openai_chatgpt", "saas_name": "ChatGPT", "metadata": map[string]any{"bytes_received": float64(220)}}, // GET, no body sent
	}
	rep := buildAIUsageReport(rows, catalog, "2026-06-17T00:00:00Z")
	if rep.TotalBytesSent != 134 || rep.TotalBytesReceived != 4213 {
		t.Fatalf("totals: sent=%d received=%d, want 134/4213", rep.TotalBytesSent, rep.TotalBytesReceived)
	}
	var claude *aiUsageReportEntry
	for i := range rep.Services {
		if rep.Services[i].SaaSApplicationID == "saas_anthropic_claude" {
			claude = &rep.Services[i]
		}
	}
	if claude == nil || claude.BytesSent != 134 || claude.BytesReceived != 3993 {
		t.Fatalf("Claude service bytes: %+v, want sent=134 received=3993", claude)
	}
}
