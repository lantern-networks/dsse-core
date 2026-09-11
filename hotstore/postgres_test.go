package hotstore

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestBuildPostgresSearchStatementScopesTenantStreamAndFilters(t *testing.T) {
	from := time.Date(2026, 5, 23, 1, 0, 0, 0, time.UTC)
	to := time.Date(2026, 5, 23, 2, 0, 0, 0, time.UTC)
	statement, err := buildPostgresSearchStatement(SearchQuery{
		TenantID: "tenant_lab_001",
		Stream:   "access",
		Filters: map[string]string{
			"tenant_id":      "tenant_other_001",
			"decision":       "deny",
			"application_id": "app_dummy_https",
		},
		Text:  "ransomware",
		From:  &from,
		To:    &to,
		Limit: 25,
	})
	if err != nil {
		t.Fatalf("buildPostgresSearchStatement returned error: %v", err)
	}
	for _, want := range []string{
		"tenant_id = $1",
		"stream = $2",
		"payload ->>",
		"ILIKE", // application_id is a partial-match (substring) field
		"lower(payload::text) LIKE",
		"occurred_at >= ",
		"occurred_at <= ",
		"ORDER BY occurred_at DESC, received_at DESC, event_id DESC",
		"LIMIT $",
	} {
		if !strings.Contains(statement.SQL, want) {
			t.Fatalf("SQL = %s, want %s", statement.SQL, want)
		}
	}
	if statement.Args[0] != "tenant_lab_001" || statement.Args[1] != "access" {
		t.Fatalf("args = %#v, want tenant and stream first", statement.Args)
	}
	// application_id is a substring field → ILIKE with wildcards wrapping the (escaped) value; decision stays exact.
	if statement.Args[2] != "application_id" || statement.Args[3] != `%app\_dummy\_https%` || statement.Args[4] != "decision" || statement.Args[5] != "deny" {
		t.Fatalf("args = %#v, want deterministic filter order with substring application_id", statement.Args)
	}
	for _, arg := range statement.Args {
		if arg == "tenant_other_001" {
			t.Fatalf("args = %#v, client-supplied tenant_id filter should be ignored", statement.Args)
		}
	}
	if statement.Args[len(statement.Args)-1] != 25 {
		t.Fatalf("args = %#v, want limit as last arg", statement.Args)
	}
}

func TestBuildPostgresIngestStatementDerivesCanonicalFields(t *testing.T) {
	receivedAt := time.Date(2026, 5, 23, 4, 0, 0, 0, time.UTC)
	statement, err := buildPostgresIngestStatement("access", map[string]any{
		"id":                 "alog_pg_001",
		"tenant_id":          "tenant_lab_001",
		"timestamp":          "2026-05-23T03:59:00Z",
		"access_decision_id": "dec_pg_001",
		"decision":           "allow",
		"edge_region_id":     "region-a",
	}, receivedAt)
	if err != nil {
		t.Fatalf("buildPostgresIngestStatement returned error: %v", err)
	}
	for _, want := range []string{
		"INSERT INTO hot_events",
		"ON CONFLICT (tenant_id, stream, event_id) DO UPDATE",
		"$8::jsonb",
		// The region is a COLUMN, not something to be dug out of the payload later: a region that cannot be
		// selected on cannot be retained, deleted or placed separately either.
		"edge_region_id",
	} {
		if !strings.Contains(statement.SQL, want) {
			t.Fatalf("SQL = %s, want %s", statement.SQL, want)
		}
	}
	if statement.Args[0] != "tenant_lab_001" || statement.Args[1] != "region-a" || statement.Args[2] != "access" ||
		statement.Args[3] != "alog_pg_001" || statement.Args[4] != "dec_pg_001" {
		t.Fatalf("args = %#v", statement.Args)
	}
}

func TestBuildPostgresIngestStatementRejectsInvalidRows(t *testing.T) {
	for name, row := range map[string]map[string]any{
		"nil row":        nil,
		"missing tenant": {"id": "evt_001"},
		"bad timestamp":  {"id": "evt_001", "tenant_id": "tenant_lab_001", "timestamp": "bad"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := buildPostgresIngestStatement("access", row, time.Now()); err == nil {
				t.Fatalf("buildPostgresIngestStatement accepted row %#v", row)
			}
		})
	}
}

func TestBuildPostgresSearchStatementRejectsUnsafeBoundaryInputs(t *testing.T) {
	for name, query := range map[string]SearchQuery{
		"empty tenant": {TenantID: "", Stream: "access", Limit: 1},
		"empty stream": {TenantID: "tenant_lab_001", Stream: "", Limit: 1},
		"zero limit":   {TenantID: "tenant_lab_001", Stream: "access", Limit: 0},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := buildPostgresSearchStatement(query); err == nil {
				t.Fatalf("buildPostgresSearchStatement accepted invalid query %#v", query)
			}
		})
	}
}

func TestBuildPostgresSearchStatementAddsCursorOffset(t *testing.T) {
	query := SearchQuery{
		TenantID: "tenant_lab_001",
		Stream:   "access",
		Limit:    10,
	}
	cursor := nextSearchCursor(query, 0, 20, []map[string]any{{"id": "row_010"}})
	if cursor == nil {
		t.Fatalf("nextSearchCursor returned nil")
	}
	query.Cursor = *cursor

	statement, err := buildPostgresSearchStatement(query)
	if err != nil {
		t.Fatalf("buildPostgresSearchStatement returned error: %v", err)
	}
	if !strings.Contains(statement.SQL, "OFFSET $") {
		t.Fatalf("SQL = %s, want OFFSET clause", statement.SQL)
	}
	if statement.Offset != 1 || statement.Args[len(statement.Args)-1] != 1 {
		t.Fatalf("statement = %#v, want offset 1 as last arg", statement)
	}

	query.Stream = "audit"
	if _, err := buildPostgresSearchStatement(query); err == nil {
		t.Fatalf("buildPostgresSearchStatement accepted cursor after query changed")
	}
}

func TestBuildPostgresRelatedByAccessDecisionIDStatementScopesTenant(t *testing.T) {
	statement, err := buildPostgresRelatedByAccessDecisionIDStatement(RelatedLogQuery{
		TenantID:         "tenant_lab_001",
		AccessDecisionID: "dec_related_001",
	})
	if err != nil {
		t.Fatalf("buildPostgresRelatedByAccessDecisionIDStatement returned error: %v", err)
	}
	for _, want := range []string{
		"tenant_id = $1",
		"access_decision_id = $2",
		"ORDER BY occurred_at DESC, received_at DESC, event_id DESC",
	} {
		if !strings.Contains(statement.SQL, want) {
			t.Fatalf("SQL = %s, want %s", statement.SQL, want)
		}
	}
	if len(statement.Args) != 2 || statement.Args[0] != "tenant_lab_001" || statement.Args[1] != "dec_related_001" {
		t.Fatalf("args = %#v", statement.Args)
	}

	for name, query := range map[string]RelatedLogQuery{
		"empty tenant":   {TenantID: "", AccessDecisionID: "dec_related_001"},
		"empty decision": {TenantID: "tenant_lab_001", AccessDecisionID: ""},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := buildPostgresRelatedByAccessDecisionIDStatement(query); err == nil {
				t.Fatalf("buildPostgresRelatedByAccessDecisionIDStatement accepted invalid query %#v", query)
			}
		})
	}
}

func TestPostgresHotEventsMigrationMatchesSchemaSQL(t *testing.T) {
	parts := []string{}
	for _, filename := range []string{
		"003_hot_events.sql",
		"010_hot_events_text_search.sql",
	} {
		data, err := os.ReadFile(filepath.Join("..", "..", "migrations", filename))
		if err != nil {
			if os.IsNotExist(err) {
				t.Skipf("migration fixture not shipped with the dsse-core module (monorepo-only): %s", filename)
			}
			t.Fatalf("read migration %s: %v", filename, err)
		}
		parts = append(parts, string(data))
	}
	want := normalizePostgresHotStoreSQLContract(strings.Join(PostgresSchemaSQL(), "\n"))
	got := normalizePostgresHotStoreSQLContract(strings.Join(parts, "\n"))
	if got != want {
		t.Fatalf("hot events migration SQL does not match schema helper\nmigration: %s\nhelper:    %s", got, want)
	}
}

func TestPostgresHotEventsTextSearchIndexMatchesSearchExpression(t *testing.T) {
	helperSQL := strings.Join(PostgresSchemaSQL(), "\n")
	if !strings.Contains(helperSQL, "CREATE EXTENSION IF NOT EXISTS pg_trgm") {
		t.Fatalf("schema SQL = %s, want pg_trgm extension", helperSQL)
	}
	if !strings.Contains(helperSQL, "hot_events_payload_text_trgm_idx") || !strings.Contains(helperSQL, "(lower(payload::text)) gin_trgm_ops") {
		t.Fatalf("schema SQL = %s, want trigram expression index on lower(payload::text)", helperSQL)
	}

	statement, err := buildPostgresSearchStatement(SearchQuery{
		TenantID: "tenant_lab_001",
		Stream:   "access",
		Text:     "ransomware",
		Limit:    10,
	})
	if err != nil {
		t.Fatalf("buildPostgresSearchStatement returned error: %v", err)
	}
	if !strings.Contains(statement.SQL, "lower(payload::text) LIKE") {
		t.Fatalf("SQL = %s, want search expression to match trigram index expression", statement.SQL)
	}
}

func normalizePostgresHotStoreSQLContract(sqlText string) string {
	sqlText = strings.ReplaceAll(sqlText, ";", " ")
	return strings.Join(strings.Fields(sqlText), " ")
}
