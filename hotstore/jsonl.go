package hotstore

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/lantern-networks/dsse-core/logs"
)

type Store interface {
	Search(ctx context.Context, query SearchQuery) (SearchResult, error)
	ExportRows(ctx context.Context, query SearchQuery, yield RowHandler) (ExportResult, error)
	RelatedByAccessDecisionID(ctx context.Context, query RelatedLogQuery) (RelatedLogResult, error)
}

type JSONLStore struct {
	writer  *logs.Writer
	streams map[string]string
}

type RowHandler func(row map[string]any) error

type SearchQuery struct {
	TenantID string
	Stream   string
	Filters  map[string]string
	Text     string
	From     *time.Time
	To       *time.Time
	Limit    int
	Cursor   string
	// IncludeOldestMatched asks ExportRows to also report the earliest event held for this tenant+stream,
	// ignoring From/To (see ExportResult.OldestMatchedAt). Opt-in because it is free on the JSONL backend (that
	// scan already visits every row) but an extra statement on Postgres — the callers that do not need to state
	// their coverage should not pay for it.
	IncludeOldestMatched bool
}

type SearchResult struct {
	Stream       string
	Limit        int
	Filters      map[string]string
	Query        string
	TotalScanned int
	TotalMatches int
	NextCursor   *string
	Rows         []map[string]any
}

type ExportResult struct {
	Stream       string
	Limit        int
	Filters      map[string]string
	Query        string
	TotalScanned int
	TotalMatches int
	RowsExported int
	// OldestMatchedAt is the earliest event time held for this tenant+stream+filters IGNORING From/To, and is
	// populated only when SearchQuery.IncludeOldestMatched asked for it. It answers a question the windowed
	// rows cannot: an empty first half of a window means either "nothing happened" or "we no longer hold it",
	// and a report that cannot tell those apart implies coverage it does not have. Zero when unknown — a
	// backend that cannot answer cheaply is expected to leave it zero rather than guess.
	OldestMatchedAt time.Time
}

type RelatedLogQuery struct {
	TenantID         string
	AccessDecisionID string
}

type RelatedLogResult struct {
	AccessDecisionID string
	TotalRows        int
	RowsByStream     map[string][]map[string]any
}

type searchCursor struct {
	Version          int    `json:"v"`
	Offset           int    `json:"offset"`
	QueryChecksum    string `json:"query_checksum"`
	CreatedAt        string `json:"created_at"`
	LastReturnedHint string `json:"last_returned_hint,omitempty"`
	Signature        string `json:"signature,omitempty"`
}

var (
	searchCursorSigningKeyMu sync.RWMutex
	searchCursorSigningKey   = newSearchCursorSigningKey()
)

func ConfigureSearchCursorSigningSecret(secret string) {
	trimmed := strings.TrimSpace(secret)
	if trimmed == "" {
		return
	}
	sum := sha256.Sum256([]byte("dsse-search-cursor:" + trimmed))
	setSearchCursorSigningKey(sum[:])
}

func NewJSONLStore(writer *logs.Writer, streams map[string]string) *JSONLStore {
	copied := map[string]string{}
	for stream, filename := range streams {
		if strings.TrimSpace(stream) != "" && strings.TrimSpace(filename) != "" {
			copied[strings.TrimSpace(stream)] = strings.TrimSpace(filename)
		}
	}
	return &JSONLStore{writer: writer, streams: copied}
}

func (store *JSONLStore) Search(ctx context.Context, query SearchQuery) (SearchResult, error) {
	if store == nil || store.writer == nil {
		return SearchResult{}, fmt.Errorf("hot store is not configured")
	}
	tenantID := strings.TrimSpace(query.TenantID)
	if tenantID == "" {
		return SearchResult{}, fmt.Errorf("tenant_id is required")
	}
	filename, ok := store.streams[strings.TrimSpace(query.Stream)]
	if !ok {
		return SearchResult{}, fmt.Errorf("unknown hot store stream %q", query.Stream)
	}
	filters := copyFilters(query.Filters)
	filters["tenant_id"] = tenantID
	textQuery := strings.ToLower(strings.TrimSpace(query.Text))
	offset, err := decodeSearchCursorOffset(query)
	if err != nil {
		return SearchResult{}, err
	}
	rows, err := store.writer.ReadJSONL(filename)
	if err != nil {
		return SearchResult{}, err
	}
	matches := []map[string]any{}
	totalMatches := 0
	skipped := 0
	for i := len(rows) - 1; i >= 0; i-- {
		if err := ctx.Err(); err != nil {
			return SearchResult{}, err
		}
		row := rows[i]
		if !rowMatches(row, filters, textQuery) {
			continue
		}
		if !rowWithinTimeRange(row, query.From, query.To) {
			continue
		}
		totalMatches++
		if skipped < offset {
			skipped++
			continue
		}
		if len(matches) < query.Limit {
			matches = append(matches, row)
		}
	}
	nextCursor := nextSearchCursor(query, offset, totalMatches, matches)
	return SearchResult{
		Stream:       query.Stream,
		Limit:        query.Limit,
		Filters:      filters,
		Query:        textQuery,
		TotalScanned: len(rows),
		TotalMatches: totalMatches,
		NextCursor:   nextCursor,
		Rows:         matches,
	}, nil
}

func (store *JSONLStore) ExportRows(ctx context.Context, query SearchQuery, yield RowHandler) (ExportResult, error) {
	if store == nil || store.writer == nil {
		return ExportResult{}, fmt.Errorf("hot store is not configured")
	}
	if yield == nil {
		return ExportResult{}, fmt.Errorf("hot store export row handler is required")
	}
	tenantID := strings.TrimSpace(query.TenantID)
	if tenantID == "" {
		return ExportResult{}, fmt.Errorf("tenant_id is required")
	}
	filename, ok := store.streams[strings.TrimSpace(query.Stream)]
	if !ok {
		return ExportResult{}, fmt.Errorf("unknown hot store stream %q", query.Stream)
	}
	if query.Limit < 1 {
		return ExportResult{}, fmt.Errorf("limit must be greater than or equal to 1")
	}
	filters := copyFilters(query.Filters)
	filters["tenant_id"] = tenantID
	textQuery := strings.ToLower(strings.TrimSpace(query.Text))
	offset, err := decodeSearchCursorOffset(query)
	if err != nil {
		return ExportResult{}, err
	}
	// Phase 1 JSONL export keeps the adapter simple and reads the lab log file in memory.
	// Alpha PostgreSQL exports stream database rows through this same callback boundary.
	rows, err := store.writer.ReadJSONL(filename)
	if err != nil {
		return ExportResult{}, err
	}
	totalMatches := 0
	rowsExported := 0
	skipped := 0
	var oldestMatched time.Time
	for i := len(rows) - 1; i >= 0; i-- {
		if err := ctx.Err(); err != nil {
			return ExportResult{}, err
		}
		row := rows[i]
		if !rowMatches(row, filters, textQuery) {
			continue
		}
		// Before the time filter, so this sees rows OUTSIDE the window — that is the whole point. Free here:
		// this loop already visits every row in the file.
		if query.IncludeOldestMatched {
			if t, ok := rowEventTime(row); ok && (oldestMatched.IsZero() || t.Before(oldestMatched)) {
				oldestMatched = t
			}
		}
		if !rowWithinTimeRange(row, query.From, query.To) {
			continue
		}
		totalMatches++
		if skipped < offset {
			skipped++
			continue
		}
		if rowsExported >= query.Limit {
			continue
		}
		if err := yield(row); err != nil {
			return ExportResult{}, err
		}
		rowsExported++
	}
	return ExportResult{
		Stream:          query.Stream,
		Limit:           query.Limit,
		Filters:         filters,
		Query:           textQuery,
		TotalScanned:    len(rows),
		TotalMatches:    totalMatches,
		RowsExported:    rowsExported,
		OldestMatchedAt: oldestMatched,
	}, nil
}

// rowEventTime reads a row's event time, accepting every spelling the backends write. Shared with
// rowWithinTimeRange so the two cannot disagree about which field is the timestamp.
func rowEventTime(row map[string]any) (time.Time, bool) {
	raw := firstNonEmptyString(row["timestamp"], row["occurred_at"], row["created_at"])
	if raw == "" {
		return time.Time{}, false
	}
	if t, err := time.Parse(time.RFC3339, raw); err == nil {
		return t, true
	}
	t, err := time.Parse(time.RFC3339Nano, raw)
	return t, err == nil
}

func (store *JSONLStore) RelatedByAccessDecisionID(ctx context.Context, query RelatedLogQuery) (RelatedLogResult, error) {
	if store == nil || store.writer == nil {
		return RelatedLogResult{}, fmt.Errorf("hot store is not configured")
	}
	tenantID := strings.TrimSpace(query.TenantID)
	if tenantID == "" {
		return RelatedLogResult{}, fmt.Errorf("tenant_id is required")
	}
	decisionID := strings.TrimSpace(query.AccessDecisionID)
	if decisionID == "" {
		return RelatedLogResult{}, fmt.Errorf("access_decision_id is required")
	}
	result := RelatedLogResult{
		AccessDecisionID: decisionID,
		RowsByStream:     map[string][]map[string]any{},
	}
	streams := make([]string, 0, len(store.streams))
	for stream := range store.streams {
		streams = append(streams, stream)
	}
	sort.Strings(streams)
	for _, stream := range streams {
		if err := ctx.Err(); err != nil {
			return RelatedLogResult{}, err
		}
		rows, err := store.writer.ReadJSONL(store.streams[stream])
		if err != nil {
			return RelatedLogResult{}, err
		}
		matches := rowsWithAccessDecisionID(rows, tenantID, decisionID)
		result.RowsByStream[stream] = matches
		result.TotalRows += len(matches)
	}
	return result, nil
}

func decodeSearchCursorOffset(query SearchQuery) (int, error) {
	rawCursor := strings.TrimSpace(query.Cursor)
	if rawCursor == "" {
		return 0, nil
	}
	decoded, err := base64.RawURLEncoding.DecodeString(rawCursor)
	if err != nil {
		return 0, fmt.Errorf("decode search cursor: %w", err)
	}
	var cursor searchCursor
	if err := json.Unmarshal(decoded, &cursor); err != nil {
		return 0, fmt.Errorf("parse search cursor: %w", err)
	}
	if cursor.Version != 1 {
		return 0, fmt.Errorf("unsupported search cursor version %d", cursor.Version)
	}
	if cursor.Offset < 0 {
		return 0, fmt.Errorf("search cursor offset must be non-negative")
	}
	if cursor.QueryChecksum != searchCursorChecksum(query) {
		return 0, fmt.Errorf("search cursor does not match query")
	}
	if !searchCursorSignatureValid(cursor) {
		return 0, fmt.Errorf("search cursor signature is invalid")
	}
	return cursor.Offset, nil
}

func nextSearchCursor(query SearchQuery, offset, totalMatches int, rows []map[string]any) *string {
	nextOffset := offset + len(rows)
	if len(rows) == 0 || nextOffset >= totalMatches {
		return nil
	}
	cursor := searchCursor{
		Version:          1,
		Offset:           nextOffset,
		QueryChecksum:    searchCursorChecksum(query),
		CreatedAt:        time.Now().UTC().Format(time.RFC3339),
		LastReturnedHint: rowCursorHint(rows[len(rows)-1]),
	}
	cursor.Signature = signSearchCursor(cursor)
	encoded, err := json.Marshal(cursor)
	if err != nil {
		return nil
	}
	raw := base64.RawURLEncoding.EncodeToString(encoded)
	return &raw
}

func newSearchCursorSigningKey() []byte {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		panic(fmt.Sprintf("generate search cursor signing key: %v", err))
	}
	return key
}

func currentSearchCursorSigningKey() []byte {
	searchCursorSigningKeyMu.RLock()
	defer searchCursorSigningKeyMu.RUnlock()
	return append([]byte(nil), searchCursorSigningKey...)
}

func setSearchCursorSigningKey(key []byte) {
	searchCursorSigningKeyMu.Lock()
	defer searchCursorSigningKeyMu.Unlock()
	searchCursorSigningKey = append([]byte(nil), key...)
}

func signSearchCursor(cursor searchCursor) string {
	payload, err := searchCursorSignaturePayload(cursor)
	if err != nil {
		return ""
	}
	mac := hmac.New(sha256.New, currentSearchCursorSigningKey())
	mac.Write(payload)
	return "hmac-sha256:" + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func searchCursorSignatureValid(cursor searchCursor) bool {
	if strings.TrimSpace(cursor.Signature) == "" {
		return false
	}
	expected := signSearchCursor(cursor)
	return hmac.Equal([]byte(expected), []byte(cursor.Signature))
}

func searchCursorSignaturePayload(cursor searchCursor) ([]byte, error) {
	cursor.Signature = ""
	return json.Marshal(cursor)
}

func searchCursorChecksum(query SearchQuery) string {
	filters := copyFilters(query.Filters)
	filters["tenant_id"] = strings.TrimSpace(query.TenantID)
	keys := make([]string, 0, len(filters))
	for key := range filters {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := []string{
		"tenant=" + strings.TrimSpace(query.TenantID),
		"stream=" + strings.TrimSpace(query.Stream),
		"text=" + strings.ToLower(strings.TrimSpace(query.Text)),
		"from=" + timePtrString(query.From),
		"to=" + timePtrString(query.To),
	}
	for _, key := range keys {
		parts = append(parts, "filter."+key+"="+filters[key])
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "\n")))
	return "sha256:" + base64.RawURLEncoding.EncodeToString(sum[:])
}

func rowCursorHint(row map[string]any) string {
	return firstNonEmptyString(row["event_id"], row["id"], row["access_decision_id"], row["timestamp"], row["occurred_at"], row["created_at"])
}

func timePtrString(value *time.Time) string {
	if value == nil {
		return ""
	}
	return value.UTC().Format(time.RFC3339Nano)
}

func rowMatches(row map[string]any, filters map[string]string, textQuery string) bool {
	for field, expected := range filters {
		got := stringValue(row[field])
		if isSubstringFilterField(field) {
			// Partial match (case-insensitive) — mirrors the postgres store's ILIKE for these fields.
			if !strings.Contains(strings.ToLower(got), strings.ToLower(expected)) {
				return false
			}
		} else if got != expected {
			return false
		}
	}
	if textQuery == "" {
		return true
	}
	encoded, err := json.Marshal(row)
	if err != nil {
		return false
	}
	return strings.Contains(strings.ToLower(string(encoded)), textQuery)
}

func rowWithinTimeRange(row map[string]any, from, to *time.Time) bool {
	if from == nil && to == nil {
		return true
	}
	raw := firstNonEmptyString(row["timestamp"], row["occurred_at"], row["created_at"])
	if raw == "" {
		return false
	}
	timestamp, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return false
	}
	if from != nil && timestamp.Before(*from) {
		return false
	}
	if to != nil && timestamp.After(*to) {
		return false
	}
	return true
}

func rowsWithAccessDecisionID(rows []map[string]any, tenantID, decisionID string) []map[string]any {
	matches := []map[string]any{}
	for _, row := range rows {
		if stringValue(row["tenant_id"]) == tenantID && stringValue(row["access_decision_id"]) == decisionID {
			matches = append(matches, row)
		}
	}
	return matches
}

func firstNonEmptyString(values ...any) string {
	for _, value := range values {
		if text := strings.TrimSpace(stringValue(value)); text != "" {
			return text
		}
	}
	return ""
}

func stringValue(value any) string {
	switch typed := value.(type) {
	case nil:
		return ""
	case string:
		return typed
	case fmt.Stringer:
		return typed.String()
	default:
		return fmt.Sprint(typed)
	}
}

func copyFilters(filters map[string]string) map[string]string {
	copied := map[string]string{}
	for key, value := range filters {
		if strings.TrimSpace(key) != "" && strings.TrimSpace(value) != "" {
			copied[strings.TrimSpace(key)] = strings.TrimSpace(value)
		}
	}
	return copied
}
