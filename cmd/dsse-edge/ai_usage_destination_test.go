package main

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/hotstore"
	"github.com/lantern-networks/dsse-core/model"
)

func TestAIUsageCountsUnclassifiedRecordedDestinations(t *testing.T) {
	rows := []map[string]any{
		{"tenant_id": "aoba", "destination": "api.anthropic.com", "device_id": "mac", "timestamp": "2026-09-09T03:10:00Z", "metadata": map[string]any{"http_method": "POST", "bytes_sent": float64(120), "bytes_received": float64(240)}},
		{"tenant_id": "aoba", "destination": "chatgpt.com", "device_id": "mac", "timestamp": "2026-09-09T03:12:00Z"},
		{"tenant_id": "sumire", "destination": "claude.ai", "timestamp": "2026-09-09T03:12:00Z"},
		{"tenant_id": "aoba", "destination": "claude.ai.example.org", "timestamp": "2026-09-09T03:12:00Z"},
		{"tenant_id": "aoba", "destination": "notclaude.ai", "timestamp": "2026-09-09T03:12:00Z"},
	}
	before, _ := json.Marshal(rows)
	r := buildAIUsageReport(accessRowsForTenant(rows, "aoba"), nil, "2026-09-09T04:00:00Z")
	if r.TotalAIAccesses != 2 || r.TotalBytesSent != 120 || r.TotalBytesReceived != 240 || len(r.Services) != 2 {
		t.Fatalf("recorded AI traffic was not counted accurately: %+v", r)
	}
	for _, svc := range r.Services {
		if svc.Name == "" || svc.Sessions != 1 {
			t.Fatalf("service must have a name and its recorded session: %+v", svc)
		}
	}
	after, _ := json.Marshal(rows)
	if string(before) != string(after) {
		t.Fatal("report mutated stored records")
	}
}

func TestAIUsageDestinationGroupingPreservesReportAndTenantCatalog(t *testing.T) {
	row := map[string]any{"tenant_id": "aoba", "destination": "assistant.example.org", "timestamp": "2026-09-09T03:10:00Z", "device_id": "mac", "metadata": map[string]any{"http_method": "POST", "bytes_sent": float64(17)}}
	catalog := []model.SaaSCatalogEntry{
		{TenantID: "sumire", SaaSApplicationID: "other-ai", Name: "Other tenant", AIService: true, DomainPatterns: []string{"assistant.example.org"}},
		{TenantID: "aoba", SaaSApplicationID: "company-ai", Name: "Company assistant", AIService: true, DomainPatterns: []string{"assistant.example.org"}},
	}
	g := hotstore.FieldGroup{Fields: map[string]string{}, Rows: 1, BytesSent: 17}
	// Exercise the production query's declared fields, rather than assuming the new
	// destination survives a SQL GROUP BY merely because the raw-row reader has it.
	for _, f := range aiUsageGroupQuery("aoba", time.Date(2026, 9, 9, 3, 0, 0, 0, time.UTC), time.Date(2026, 9, 9, 4, 0, 0, 0, time.UTC)).Fields {
		g.Fields[f.Name] = stringFromRow(row, f.Name)
	}
	inputs := aiUsageInputsFromGroups([]hotstore.FieldGroup{g})
	// Remove timestamp/method from both paths for this parity check; their existing
	// session and message aggregation tests cover the independent store measures.
	delete(row, "timestamp")
	delete(row["metadata"].(map[string]any), "http_method")
	a := buildAIUsageReport([]map[string]any{row}, catalog, "2026-09-09T04:00:00Z")
	b := buildAIUsageReportFromInputs(inputs, catalog, "2026-09-09T04:00:00Z")
	if a.TotalAIAccesses != 1 || len(a.Services) != 1 || a.Services[0].Name != "Company assistant" || !reflect.DeepEqual(a, b) {
		t.Fatalf("grouped destination/scope diverged: rows=%+v groups=%+v", a, b)
	}
}

func TestAIUsageDoesNotReplaceExplicitServiceClassification(t *testing.T) {
	r := buildAIUsageReport([]map[string]any{{"destination": "claude.ai", "saas_application_id": "custom_non_ai"}}, nil, "2026-09-09T04:00:00Z")
	if r.TotalAIAccesses != 0 {
		t.Fatal("destination replaced an explicit classification")
	}
}
