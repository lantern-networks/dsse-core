package hotstore

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/logs"
)

func TestJSONLStoreSearchScopesTenantAndTimeRange(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	rows := []map[string]any{
		{"id": "old", "tenant_id": "tenant_lab_001", "decision": "allow", "timestamp": "2026-05-23T00:00:00Z"},
		{"id": "match", "tenant_id": "tenant_lab_001", "decision": "deny", "timestamp": "2026-05-23T02:00:00Z", "message": "database access"},
		{"id": "other_tenant", "tenant_id": "tenant_other_001", "decision": "deny", "timestamp": "2026-05-23T02:30:00Z"},
		{"id": "newer", "tenant_id": "tenant_lab_001", "decision": "deny", "timestamp": "2026-05-23T03:00:00Z", "message": "ssh access"},
	}
	for _, row := range rows {
		if err := writer.Append("access.log.jsonl", row); err != nil {
			t.Fatalf("Append returned error: %v", err)
		}
	}
	from := mustParseTime(t, "2026-05-23T01:00:00Z")
	to := mustParseTime(t, "2026-05-23T02:30:00Z")
	store := NewJSONLStore(writer, map[string]string{"access": "access.log.jsonl"})

	result, err := store.Search(context.Background(), SearchQuery{
		TenantID: "tenant_lab_001",
		Stream:   "access",
		Filters:  map[string]string{"decision": "deny"},
		Text:     "database",
		From:     &from,
		To:       &to,
		Limit:    10,
	})
	if err != nil {
		t.Fatalf("Search returned error: %v", err)
	}

	if result.TotalScanned != 4 || result.TotalMatches != 1 || len(result.Rows) != 1 {
		t.Fatalf("result = %#v", result)
	}
	if result.Rows[0]["id"] != "match" {
		t.Fatalf("row id = %v, want match", result.Rows[0]["id"])
	}
	if result.Filters["tenant_id"] != "tenant_lab_001" {
		t.Fatalf("tenant filter = %q", result.Filters["tenant_id"])
	}
}

func TestJSONLStoreSearchRejectsEmptyTenant(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	store := NewJSONLStore(writer, map[string]string{"access": "access.log.jsonl"})

	_, err = store.Search(context.Background(), SearchQuery{
		TenantID: "",
		Stream:   "access",
		Limit:    10,
	})

	if err == nil {
		t.Fatalf("Search returned nil error, want tenant_id error")
	}
}

func TestJSONLStoreExportRowsStreamsTenantScopedMatches(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	for _, row := range []map[string]any{
		{"id": "oldest", "tenant_id": "tenant_lab_001", "event_type": "access_allowed", "timestamp": "2026-05-23T00:00:00Z"},
		{"id": "match_001", "tenant_id": "tenant_lab_001", "event_type": "access_allowed", "timestamp": "2026-05-23T01:00:00Z"},
		{"id": "match_002", "tenant_id": "tenant_lab_001", "event_type": "access_allowed", "timestamp": "2026-05-23T02:00:00Z"},
		{"id": "other_tenant", "tenant_id": "tenant_other_001", "event_type": "access_allowed", "timestamp": "2026-05-23T03:00:00Z"},
	} {
		if err := writer.Append("access.log.jsonl", row); err != nil {
			t.Fatalf("Append returned error: %v", err)
		}
	}
	from := mustParseTime(t, "2026-05-23T00:30:00Z")
	to := mustParseTime(t, "2026-05-23T02:30:00Z")
	store := NewJSONLStore(writer, map[string]string{"access": "access.log.jsonl"})
	exported := []string{}

	result, err := store.ExportRows(context.Background(), SearchQuery{
		TenantID: "tenant_lab_001",
		Stream:   "access",
		Filters:  map[string]string{"event_type": "access_allowed"},
		From:     &from,
		To:       &to,
		Limit:    1,
	}, func(row map[string]any) error {
		exported = append(exported, row["id"].(string))
		return nil
	})
	if err != nil {
		t.Fatalf("ExportRows returned error: %v", err)
	}

	if result.TotalScanned != 4 || result.TotalMatches != 2 || result.RowsExported != 1 {
		t.Fatalf("result = %#v", result)
	}
	if len(exported) != 1 || exported[0] != "match_002" {
		t.Fatalf("exported = %#v, want newest matching row only", exported)
	}
	if result.Filters["tenant_id"] != "tenant_lab_001" {
		t.Fatalf("tenant filter = %q", result.Filters["tenant_id"])
	}
}

func TestJSONLStoreRelatedByAccessDecisionIDScopesTenant(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	for _, row := range []map[string]any{
		{"id": "access_match", "tenant_id": "tenant_lab_001", "access_decision_id": "dec_related_001"},
		{"id": "access_other_tenant", "tenant_id": "tenant_other_001", "access_decision_id": "dec_related_001"},
	} {
		if err := writer.Append("access.log.jsonl", row); err != nil {
			t.Fatalf("Append access returned error: %v", err)
		}
	}
	if err := writer.Append("audit.log.jsonl", map[string]any{"id": "audit_match", "tenant_id": "tenant_lab_001", "access_decision_id": "dec_related_001"}); err != nil {
		t.Fatalf("Append audit returned error: %v", err)
	}
	store := NewJSONLStore(writer, map[string]string{
		"access": "access.log.jsonl",
		"audit":  "audit.log.jsonl",
	})

	result, err := store.RelatedByAccessDecisionID(context.Background(), RelatedLogQuery{
		TenantID:         "tenant_lab_001",
		AccessDecisionID: "dec_related_001",
	})
	if err != nil {
		t.Fatalf("RelatedByAccessDecisionID returned error: %v", err)
	}

	if result.TotalRows != 2 {
		t.Fatalf("TotalRows = %d, want 2", result.TotalRows)
	}
	if len(result.RowsByStream["access"]) != 1 || result.RowsByStream["access"][0]["id"] != "access_match" {
		t.Fatalf("access rows = %#v", result.RowsByStream["access"])
	}
	if len(result.RowsByStream["audit"]) != 1 || result.RowsByStream["audit"][0]["id"] != "audit_match" {
		t.Fatalf("audit rows = %#v", result.RowsByStream["audit"])
	}
}

func TestJSONLStoreSearchReturnsQueryBoundCursor(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	rows := []map[string]any{
		{"id": "oldest", "tenant_id": "tenant_lab_001", "decision": "deny", "timestamp": "2026-05-23T00:00:00Z"},
		{"id": "middle", "tenant_id": "tenant_lab_001", "decision": "deny", "timestamp": "2026-05-23T01:00:00Z"},
		{"id": "newest", "tenant_id": "tenant_lab_001", "decision": "deny", "timestamp": "2026-05-23T02:00:00Z"},
	}
	for _, row := range rows {
		if err := writer.Append("access.log.jsonl", row); err != nil {
			t.Fatalf("Append returned error: %v", err)
		}
	}
	store := NewJSONLStore(writer, map[string]string{"access": "access.log.jsonl"})
	query := SearchQuery{
		TenantID: "tenant_lab_001",
		Stream:   "access",
		Filters:  map[string]string{"decision": "deny"},
		Limit:    2,
	}

	first, err := store.Search(context.Background(), query)
	if err != nil {
		t.Fatalf("first Search returned error: %v", err)
	}
	if first.NextCursor == nil || len(first.Rows) != 2 || first.Rows[0]["id"] != "newest" || first.Rows[1]["id"] != "middle" {
		t.Fatalf("first result = %#v", first)
	}

	query.Cursor = *first.NextCursor
	second, err := store.Search(context.Background(), query)
	if err != nil {
		t.Fatalf("second Search returned error: %v", err)
	}
	if second.NextCursor != nil || len(second.Rows) != 1 || second.Rows[0]["id"] != "oldest" {
		t.Fatalf("second result = %#v", second)
	}

	query.Filters["decision"] = "allow"
	if _, err := store.Search(context.Background(), query); err == nil {
		t.Fatalf("Search accepted cursor after query changed")
	}
}

func TestJSONLStoreSearchRejectsTamperedCursorOffset(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	for _, row := range []map[string]any{
		{"id": "oldest", "tenant_id": "tenant_lab_001", "decision": "deny", "timestamp": "2026-05-23T00:00:00Z"},
		{"id": "middle", "tenant_id": "tenant_lab_001", "decision": "deny", "timestamp": "2026-05-23T01:00:00Z"},
		{"id": "newest", "tenant_id": "tenant_lab_001", "decision": "deny", "timestamp": "2026-05-23T02:00:00Z"},
	} {
		if err := writer.Append("access.log.jsonl", row); err != nil {
			t.Fatalf("Append returned error: %v", err)
		}
	}
	store := NewJSONLStore(writer, map[string]string{"access": "access.log.jsonl"})
	query := SearchQuery{
		TenantID: "tenant_lab_001",
		Stream:   "access",
		Filters:  map[string]string{"decision": "deny"},
		Limit:    1,
	}

	first, err := store.Search(context.Background(), query)
	if err != nil {
		t.Fatalf("Search returned error: %v", err)
	}
	if first.NextCursor == nil {
		t.Fatalf("NextCursor is nil")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(*first.NextCursor)
	if err != nil {
		t.Fatalf("decode cursor: %v", err)
	}
	var cursor searchCursor
	if err := json.Unmarshal(decoded, &cursor); err != nil {
		t.Fatalf("unmarshal cursor: %v", err)
	}
	cursor.Offset = 2
	tampered, err := json.Marshal(cursor)
	if err != nil {
		t.Fatalf("marshal tampered cursor: %v", err)
	}
	query.Cursor = base64.RawURLEncoding.EncodeToString(tampered)

	if _, err := store.Search(context.Background(), query); err == nil {
		t.Fatalf("Search accepted cursor with tampered offset")
	}
}

func TestSearchCursorSigningSecretCanBeStableAcrossConfiguration(t *testing.T) {
	originalKey := currentSearchCursorSigningKey()
	defer setSearchCursorSigningKey(originalKey)

	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	for _, row := range []map[string]any{
		{"id": "oldest", "tenant_id": "tenant_lab_001", "decision": "deny", "timestamp": "2026-05-23T00:00:00Z"},
		{"id": "newest", "tenant_id": "tenant_lab_001", "decision": "deny", "timestamp": "2026-05-23T01:00:00Z"},
	} {
		if err := writer.Append("access.log.jsonl", row); err != nil {
			t.Fatalf("Append returned error: %v", err)
		}
	}
	store := NewJSONLStore(writer, map[string]string{"access": "access.log.jsonl"})
	query := SearchQuery{
		TenantID: "tenant_lab_001",
		Stream:   "access",
		Filters:  map[string]string{"decision": "deny"},
		Limit:    1,
	}
	ConfigureSearchCursorSigningSecret("stable-secret")
	first, err := store.Search(context.Background(), query)
	if err != nil {
		t.Fatalf("Search returned error: %v", err)
	}
	if first.NextCursor == nil {
		t.Fatalf("NextCursor is nil")
	}
	query.Cursor = *first.NextCursor
	ConfigureSearchCursorSigningSecret("stable-secret")
	if _, err := store.Search(context.Background(), query); err != nil {
		t.Fatalf("Search rejected cursor after same secret reconfiguration: %v", err)
	}
	ConfigureSearchCursorSigningSecret("different-secret")
	if _, err := store.Search(context.Background(), query); err == nil {
		t.Fatalf("Search accepted cursor after signing secret changed")
	}
}

func TestSearchCursorSigningSecretConcurrentReconfiguration(t *testing.T) {
	originalKey := currentSearchCursorSigningKey()
	defer setSearchCursorSigningKey(originalKey)

	cursor := searchCursor{
		Version:       1,
		Offset:        1,
		QueryChecksum: "sha256:test",
		CreatedAt:     "2026-05-23T00:00:00Z",
	}
	var wg sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				if worker%2 == 0 {
					ConfigureSearchCursorSigningSecret(fmt.Sprintf("secret-%d-%d", worker, i))
					continue
				}
				_ = signSearchCursor(cursor)
			}
		}(worker)
	}
	wg.Wait()
}

func mustParseTime(t *testing.T, raw string) time.Time {
	t.Helper()
	parsed, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		t.Fatalf("parse time: %v", err)
	}
	return parsed
}
