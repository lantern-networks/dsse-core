package hotstore

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

type PostgresStore struct {
	db *sql.DB
}

type postgresSearchStatement struct {
	SQL    string
	Args   []any
	Offset int
}

type postgresRelatedStatement struct {
	SQL  string
	Args []any
}

type postgresIngestStatement struct {
	SQL  string
	Args []any
}

func NewPostgresStore(db *sql.DB) *PostgresStore {
	return &PostgresStore{db: db}
}

func PostgresSchemaSQL() []string {
	return []string{
		strings.Join([]string{
			"CREATE TABLE IF NOT EXISTS hot_events (",
			"tenant_id text NOT NULL,",
			// Which region the record came from — see EventRegion. Empty means the producer did not say, which
			// is a defect to be counted rather than a row to be assigned to whoever is asking.
			"edge_region_id text NOT NULL DEFAULT '',",
			"stream text NOT NULL,",
			"event_id text NOT NULL,",
			"access_decision_id text,",
			"occurred_at timestamptz NOT NULL,",
			"received_at timestamptz NOT NULL DEFAULT now(),",
			"payload jsonb NOT NULL,",
			"PRIMARY KEY (tenant_id, stream, event_id)",
			")",
		}, " "),
		"ALTER TABLE hot_events ADD COLUMN IF NOT EXISTS edge_region_id text NOT NULL DEFAULT ''",
		"CREATE INDEX IF NOT EXISTS hot_events_search_idx ON hot_events (tenant_id, stream, occurred_at DESC, received_at DESC, event_id DESC)",
		"CREATE INDEX IF NOT EXISTS hot_events_region_idx ON hot_events (tenant_id, edge_region_id, occurred_at DESC)",
		"CREATE INDEX IF NOT EXISTS hot_events_decision_idx ON hot_events (tenant_id, access_decision_id, occurred_at DESC, received_at DESC, event_id DESC)",
		"CREATE EXTENSION IF NOT EXISTS pg_trgm",
		"CREATE INDEX IF NOT EXISTS hot_events_payload_text_trgm_idx ON hot_events USING gin ((lower(payload::text)) gin_trgm_ops)",
	}
}

func (store *PostgresStore) Search(ctx context.Context, query SearchQuery) (SearchResult, error) {
	if store == nil || store.db == nil {
		return SearchResult{}, fmt.Errorf("postgres hot store is not configured")
	}
	statement, err := buildPostgresSearchStatement(query)
	if err != nil {
		return SearchResult{}, err
	}
	rows, err := store.db.QueryContext(ctx, statement.SQL, statement.Args...)
	if err != nil {
		return SearchResult{}, err
	}
	defer rows.Close()

	resultRows := []map[string]any{}
	totalMatches := 0
	for rows.Next() {
		var payload []byte
		if err := rows.Scan(&payload, &totalMatches); err != nil {
			return SearchResult{}, err
		}
		var row map[string]any
		if err := json.Unmarshal(payload, &row); err != nil {
			return SearchResult{}, fmt.Errorf("decode hot event payload: %w", err)
		}
		resultRows = append(resultRows, row)
	}
	if err := rows.Err(); err != nil {
		return SearchResult{}, err
	}
	filters := copyFilters(query.Filters)
	filters["tenant_id"] = strings.TrimSpace(query.TenantID)
	nextCursor := nextSearchCursor(query, statement.Offset, totalMatches, resultRows)
	return SearchResult{
		Stream:       strings.TrimSpace(query.Stream),
		Limit:        query.Limit,
		Filters:      filters,
		Query:        strings.ToLower(strings.TrimSpace(query.Text)),
		TotalScanned: totalMatches,
		TotalMatches: totalMatches,
		NextCursor:   nextCursor,
		Rows:         resultRows,
	}, nil
}

func (store *PostgresStore) Ingest(ctx context.Context, stream string, row map[string]any) error {
	return store.IngestAt(ctx, stream, row, time.Now().UTC())
}

func (store *PostgresStore) IngestAt(ctx context.Context, stream string, row map[string]any, receivedAt time.Time) error {
	if store == nil || store.db == nil {
		return fmt.Errorf("postgres hot store is not configured")
	}
	statement, err := buildPostgresIngestStatement(stream, row, receivedAt)
	if err != nil {
		return err
	}
	_, err = store.db.ExecContext(ctx, statement.SQL, statement.Args...)
	return err
}

func (store *PostgresStore) ExportRows(ctx context.Context, query SearchQuery, yield RowHandler) (ExportResult, error) {
	if store == nil || store.db == nil {
		return ExportResult{}, fmt.Errorf("postgres hot store is not configured")
	}
	if yield == nil {
		return ExportResult{}, fmt.Errorf("hot store export row handler is required")
	}
	statement, err := buildPostgresSearchStatement(query)
	if err != nil {
		return ExportResult{}, err
	}
	rows, err := store.db.QueryContext(ctx, statement.SQL, statement.Args...)
	if err != nil {
		return ExportResult{}, err
	}
	defer rows.Close()

	totalMatches := 0
	rowsExported := 0
	for rows.Next() {
		var payload []byte
		if err := rows.Scan(&payload, &totalMatches); err != nil {
			return ExportResult{}, err
		}
		var row map[string]any
		if err := json.Unmarshal(payload, &row); err != nil {
			return ExportResult{}, fmt.Errorf("decode hot event payload: %w", err)
		}
		if err := yield(row); err != nil {
			return ExportResult{}, err
		}
		rowsExported++
	}
	if err := rows.Err(); err != nil {
		return ExportResult{}, err
	}
	filters := copyFilters(query.Filters)
	filters["tenant_id"] = strings.TrimSpace(query.TenantID)
	var oldestMatched time.Time
	if query.IncludeOldestMatched {
		if oldestMatched, err = store.oldestEventAt(ctx, query); err != nil {
			return ExportResult{}, err
		}
	}
	return ExportResult{
		Stream:          strings.TrimSpace(query.Stream),
		Limit:           query.Limit,
		Filters:         filters,
		Query:           strings.ToLower(strings.TrimSpace(query.Text)),
		TotalScanned:    totalMatches,
		TotalMatches:    totalMatches,
		RowsExported:    rowsExported,
		OldestMatchedAt: oldestMatched,
	}, nil
}

// oldestEventAt is the earliest event held for a tenant+stream, ignoring the query's time bounds. Its own tiny
// statement, NOT a change to buildPostgresSearchStatement: that builder must keep emitting the payload +
// count(*) OVER() + ORDER BY + LIMIT shape its two callers depend on. hot_events_search_idx leads with
// (tenant_id, stream, occurred_at), so this is an index scan to the first row, not an aggregate over the table.
func (store *PostgresStore) oldestEventAt(ctx context.Context, query SearchQuery) (time.Time, error) {
	tenantID := strings.TrimSpace(query.TenantID)
	stream := strings.TrimSpace(query.Stream)
	if tenantID == "" || stream == "" {
		return time.Time{}, nil
	}
	var oldest sql.NullTime
	err := store.db.QueryRowContext(ctx,
		`SELECT MIN(occurred_at) FROM hot_events WHERE tenant_id = $1 AND stream = $2`,
		tenantID, stream).Scan(&oldest)
	if err != nil {
		return time.Time{}, fmt.Errorf("read oldest hot event: %w", err)
	}
	if !oldest.Valid {
		return time.Time{}, nil
	}
	return oldest.Time.UTC(), nil
}

func (store *PostgresStore) RelatedByAccessDecisionID(ctx context.Context, query RelatedLogQuery) (RelatedLogResult, error) {
	if store == nil || store.db == nil {
		return RelatedLogResult{}, fmt.Errorf("postgres hot store is not configured")
	}
	statement, err := buildPostgresRelatedByAccessDecisionIDStatement(query)
	if err != nil {
		return RelatedLogResult{}, err
	}
	rows, err := store.db.QueryContext(ctx, statement.SQL, statement.Args...)
	if err != nil {
		return RelatedLogResult{}, err
	}
	defer rows.Close()

	result := RelatedLogResult{
		AccessDecisionID: strings.TrimSpace(query.AccessDecisionID),
		RowsByStream:     map[string][]map[string]any{},
	}
	for rows.Next() {
		var stream string
		var payload []byte
		if err := rows.Scan(&stream, &payload); err != nil {
			return RelatedLogResult{}, err
		}
		var row map[string]any
		if err := json.Unmarshal(payload, &row); err != nil {
			return RelatedLogResult{}, fmt.Errorf("decode related hot event payload: %w", err)
		}
		result.RowsByStream[stream] = append(result.RowsByStream[stream], row)
		result.TotalRows++
	}
	if err := rows.Err(); err != nil {
		return RelatedLogResult{}, err
	}
	return result, nil
}

func buildPostgresIngestStatement(stream string, row map[string]any, receivedAt time.Time) (postgresIngestStatement, error) {
	stream = strings.TrimSpace(stream)
	if stream == "" {
		return postgresIngestStatement{}, fmt.Errorf("stream is required")
	}
	if row == nil {
		return postgresIngestStatement{}, fmt.Errorf("hot event row is required")
	}
	tenantID := strings.TrimSpace(stringValue(row["tenant_id"]))
	if tenantID == "" {
		return postgresIngestStatement{}, fmt.Errorf("tenant_id is required")
	}
	eventID := firstNonEmptyString(row["event_id"], row["id"])
	payload, err := json.Marshal(row)
	if err != nil {
		return postgresIngestStatement{}, fmt.Errorf("encode hot event payload: %w", err)
	}
	if eventID == "" {
		sum := sha256.Sum256(payload)
		eventID = "evt_" + hex.EncodeToString(sum[:16])
	}
	occurredAt := receivedAt.UTC()
	if receivedAt.IsZero() {
		occurredAt = time.Now().UTC()
		receivedAt = occurredAt
	}
	if raw := firstNonEmptyString(row["occurred_at"], row["timestamp"], row["created_at"]); raw != "" {
		parsed, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			return postgresIngestStatement{}, fmt.Errorf("parse hot event occurred_at: %w", err)
		}
		occurredAt = parsed.UTC()
	}
	accessDecisionID := strings.TrimSpace(stringValue(row["access_decision_id"]))
	var accessDecisionArg any
	if accessDecisionID != "" {
		accessDecisionArg = accessDecisionID
	}
	statement := strings.Join([]string{
		"INSERT INTO hot_events",
		"(tenant_id, edge_region_id, stream, event_id, access_decision_id, occurred_at, received_at, payload)",
		"VALUES ($1, $2, $3, $4, $5, $6::timestamptz, $7::timestamptz, $8::jsonb)",
		"ON CONFLICT (tenant_id, stream, event_id) DO UPDATE SET",
		"edge_region_id = EXCLUDED.edge_region_id,",
		"access_decision_id = EXCLUDED.access_decision_id,",
		"occurred_at = EXCLUDED.occurred_at,",
		"received_at = EXCLUDED.received_at,",
		"payload = EXCLUDED.payload",
	}, " ")
	return postgresIngestStatement{
		SQL: statement,
		Args: []any{tenantID, noteAndReturnRegion(row), stream, eventID, accessDecisionArg, occurredAt,
			receivedAt.UTC(), string(payload)},
	}, nil
}

// substringFilterFields are matched as case-insensitive PARTIAL matches instead of exact equality — the
// human-meaningful identity / host / resource fields an operator types partially (e.g. "alice", "web-01").
// Enum and ID fields (decision, policy_id, session_id, event ids, tenant_id, …) stay exact.
var substringFilterFields = map[string]bool{
	"user_id":         true,
	"subject_user_id": true,
	"destination":     true,
	"device_id":       true,
	"application_id":  true,
	"actor_nhi_id":    true,
	"tool_id":         true,
}

func isSubstringFilterField(key string) bool { return substringFilterFields[key] }

// likeEscape escapes LIKE/ILIKE wildcards so a filter value is matched as a literal substring, not a pattern.
func likeEscape(s string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s)
}

func buildPostgresSearchStatement(query SearchQuery) (postgresSearchStatement, error) {
	tenantID := strings.TrimSpace(query.TenantID)
	if tenantID == "" {
		return postgresSearchStatement{}, fmt.Errorf("tenant_id is required")
	}
	stream := strings.TrimSpace(query.Stream)
	if stream == "" {
		return postgresSearchStatement{}, fmt.Errorf("stream is required")
	}
	if query.Limit < 1 {
		return postgresSearchStatement{}, fmt.Errorf("limit must be greater than or equal to 1")
	}
	offset, err := decodeSearchCursorOffset(query)
	if err != nil {
		return postgresSearchStatement{}, err
	}

	args := []any{tenantID, stream}
	conditions := []string{"tenant_id = $1", "stream = $2"}
	nextArg := 3
	filters := copyFilters(query.Filters)
	if query.countUnknownRegion {
		delete(filters, "edge_region_id")
		conditions = append(conditions, "edge_region_id = ''")
	}
	filterKeys := make([]string, 0, len(filters))
	for key := range filters {
		if key != "tenant_id" {
			filterKeys = append(filterKeys, key)
		}
	}
	sort.Strings(filterKeys)
	for _, key := range filterKeys {
		value := filters[key]
		if key == "edge_region_id" {
			// ★ THE COLUMN, NOT THE PAYLOAD (2026-08-24). Filtering through payload ->> would miss every
			// record whose producer spelled the region differently — device_state writes "<region>/<cluster>"
			// under another name — and would not use the index. The column carries what EventRegion derived at
			// ingest, so the filter answers for all of them and answers quickly.
			conditions = append(conditions, fmt.Sprintf("edge_region_id = $%d", nextArg))
			args = append(args, value)
			nextArg++
			continue
		}
		if isSubstringFilterField(key) {
			// Partial match for the human-typed identity/host fields: an operator filters "alice" or "web-01",
			// not the exact string. Wildcards in the value are escaped so it matches as a literal substring.
			conditions = append(conditions, fmt.Sprintf("payload ->> $%d ILIKE $%d", nextArg, nextArg+1))
			args = append(args, key, "%"+likeEscape(value)+"%")
		} else {
			conditions = append(conditions, fmt.Sprintf("payload ->> $%d = $%d", nextArg, nextArg+1))
			args = append(args, key, value)
		}
		nextArg += 2
	}
	if text := strings.ToLower(strings.TrimSpace(query.Text)); text != "" {
		conditions = append(conditions, fmt.Sprintf("lower(payload::text) LIKE $%d", nextArg))
		args = append(args, "%"+text+"%")
		nextArg++
	}
	if query.From != nil {
		conditions = append(conditions, fmt.Sprintf("occurred_at >= $%d", nextArg))
		args = append(args, query.From.UTC())
		nextArg++
	}
	if query.To != nil {
		conditions = append(conditions, fmt.Sprintf("occurred_at <= $%d", nextArg))
		args = append(args, query.To.UTC())
		nextArg++
	}
	if query.countUnknownRegion {
		return postgresSearchStatement{SQL: "SELECT count(*) FROM hot_events WHERE " + strings.Join(conditions, " AND "), Args: args}, nil
	}
	limitArg := nextArg
	args = append(args, query.Limit)
	nextArg++
	offsetClause := ""
	if offset > 0 {
		offsetArg := nextArg
		args = append(args, offset)
		offsetClause = fmt.Sprintf(" OFFSET $%d", offsetArg)
	}
	statement := fmt.Sprintf(
		"SELECT payload, count(*) OVER() AS total_matches FROM hot_events WHERE %s ORDER BY occurred_at DESC, received_at DESC, event_id DESC LIMIT $%d%s",
		strings.Join(conditions, " AND "),
		limitArg,
		offsetClause,
	)
	return postgresSearchStatement{SQL: statement, Args: args, Offset: offset}, nil
}

func buildPostgresRelatedByAccessDecisionIDStatement(query RelatedLogQuery) (postgresRelatedStatement, error) {
	tenantID := strings.TrimSpace(query.TenantID)
	if tenantID == "" {
		return postgresRelatedStatement{}, fmt.Errorf("tenant_id is required")
	}
	decisionID := strings.TrimSpace(query.AccessDecisionID)
	if decisionID == "" {
		return postgresRelatedStatement{}, fmt.Errorf("access_decision_id is required")
	}
	statement := "SELECT stream, payload FROM hot_events WHERE tenant_id = $1 AND access_decision_id = $2 ORDER BY occurred_at DESC, received_at DESC, event_id DESC"
	return postgresRelatedStatement{SQL: statement, Args: []any{tenantID, decisionID}}, nil
}

// CountUnknownRegion preserves every scope/filter except region, and ignores pagination.
func (store *PostgresStore) CountUnknownRegion(ctx context.Context, query SearchQuery) (int64, error) {
	if store == nil || store.db == nil {
		return 0, fmt.Errorf("postgres hot store is not configured")
	}
	query.countUnknownRegion = true
	query.Cursor = ""
	statement, err := buildPostgresSearchStatement(query)
	if err != nil {
		return 0, err
	}
	var count int64
	err = store.db.QueryRowContext(ctx, statement.SQL, statement.Args...).Scan(&count)
	return count, err
}
