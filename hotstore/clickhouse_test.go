package hotstore

import (
	"context"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

func sampleInspectionRow() map[string]any {
	return map[string]any{
		"id":             "ie_1",
		"tenant_id":      "acme",
		"timestamp":      "2026-07-16T02:20:00Z",
		"finding_type":   "dlp_match",
		"application_id": "com.apple.curl",
		"user_id":        "alice",
		"device_id":      "mac-dev-1",
		"metadata": map[string]any{
			"dlp_action":           "block",
			"dlp_destination":      "postman-echo.com",
			"dlp_identifier_types": []any{"my_number", "credit_card"},
			"dlp_instance_class":   "corporate",
			"dlp_rule_id":          "dlpp_abc",
		},
	}
}

func TestClickHouseBuildWhereKnownColumn(t *testing.T) {
	s := NewClickHouseStore("http://x:8123", "u", "p", "dsse", "events")
	where, params := s.buildWhere(SearchQuery{TenantID: "acme", Stream: "inspection_events", Filters: map[string]string{"finding_type": "dlp_match"}})
	if !strings.Contains(where, "tenant_id = {tenant:String}") || !strings.Contains(where, "stream = {stream:String}") {
		t.Fatalf("where missing tenant/stream: %q", where)
	}
	if !strings.Contains(where, "finding_type = {f0:String}") {
		t.Fatalf("known filter should map to a column: %q", where)
	}
	if params["tenant"] != "acme" || params["stream"] != "inspection_events" || params["f0"] != "dlp_match" {
		t.Fatalf("params wrong: %+v", params)
	}
	// Injection safety: values live in params, never in the SQL text.
	if strings.Contains(where, "dlp_match") || strings.Contains(where, "acme") {
		t.Fatalf("value interpolated into SQL (injection risk): %q", where)
	}
}

func TestClickHouseBuildWhereUnknownKeyUsesJSONExtract(t *testing.T) {
	s := NewClickHouseStore("http://x:8123", "u", "p", "dsse", "events")
	where, params := s.buildWhere(SearchQuery{TenantID: "acme", Filters: map[string]string{"custom_field": "v"}})
	if !strings.Contains(where, "JSONExtractString(raw, {k0:String}) = {f0:String}") {
		t.Fatalf("unknown key should use JSONExtract: %q", where)
	}
	if params["k0"] != "custom_field" || params["f0"] != "v" {
		t.Fatalf("params wrong: %+v", params)
	}
	if strings.Contains(where, "custom_field") {
		t.Fatalf("filter key interpolated into SQL: %q", where)
	}
}

func TestClickHouseBuildWhereTimeAndText(t *testing.T) {
	s := NewClickHouseStore("http://x:8123", "u", "p", "dsse", "events")
	from := time.Date(2026, 7, 16, 1, 0, 0, 0, time.UTC)
	to := time.Date(2026, 7, 16, 3, 0, 0, 0, time.UTC)
	where, params := s.buildWhere(SearchQuery{TenantID: "acme", Text: "postman", From: &from, To: &to})
	if !strings.Contains(where, "positionCaseInsensitive(raw, {txt:String}) > 0") {
		t.Fatalf("text filter missing: %q", where)
	}
	if !strings.Contains(where, "ts >= parseDateTime64BestEffort({fromts:String})") || !strings.Contains(where, "ts <= parseDateTime64BestEffort({tots:String})") {
		t.Fatalf("time range missing: %q", where)
	}
	if params["txt"] != "postman" || params["fromts"] == "" || params["tots"] == "" {
		t.Fatalf("params wrong: %+v", params)
	}
}

func TestClickHouseRowFromEvent(t *testing.T) {
	rec := clickHouseRowFromEvent("inspection_events", sampleInspectionRow(), time.Now())
	if rec["event_id"] != "ie_1" || rec["tenant_id"] != "acme" || rec["stream"] != "inspection_events" {
		t.Fatalf("core columns wrong: %+v", rec)
	}
	if rec["finding_type"] != "dlp_match" || rec["action"] != "block" || rec["destination"] != "postman-echo.com" {
		t.Fatalf("metadata-derived columns wrong: %+v", rec)
	}
	if rec["instance_class"] != "corporate" || rec["rule_id"] != "dlpp_abc" {
		t.Fatalf("instance/rule wrong: %+v", rec)
	}
	ids, _ := rec["identifier_types"].([]string)
	if len(ids) != 2 || ids[0] != "my_number" {
		t.Fatalf("identifier_types wrong: %+v", rec["identifier_types"])
	}
	// ★★ NO OFFSET ON THE INSERT PATH, AND THIS TEST WAS CHANGED THE WRONG WAY ONCE (2026-08-13). The
	// twenty-ninth review's fix added "+00:00" here; the test failed, correctly, and I rewrote the TEST to
	// demand the offset instead of asking why. Reproduced against the reference ClickHouse afterwards:
	//
	//	Code: 6. DB::Exception: Cannot parse string '2026-07-16 02:20:00.000+00:00' as DateTime64(3)
	//
	// Every INSERT failed. A VALUES literal is parsed by the column under date_time_input_format=basic, which
	// does not read an offset; only the query parameters go through parseDateTime64BestEffort, which does. The
	// zone is now carried by the COLUMN (DateTime64(3,'UTC')), where it is unambiguous on any server.
	if rec["ts"] != "2026-07-16 02:20:00.000" {
		t.Fatalf("ts must be the naive form the column's parser accepts, got %v", rec["ts"])
	}
	if raw, _ := rec["raw"].(string); !strings.Contains(raw, "\"id\":\"ie_1\"") {
		t.Fatalf("raw did not carry the full record: %v", rec["raw"])
	}
}

func TestParseClickHouseRawRows(t *testing.T) {
	body := []byte(`{"raw":"{\"id\":\"e1\",\"tenant_id\":\"acme\"}"}` + "\n" + `{"raw":"{\"id\":\"e2\"}"}` + "\n")
	rows, err := parseClickHouseRawRows(body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(rows) != 2 || rows[0]["id"] != "e1" || rows[0]["tenant_id"] != "acme" || rows[1]["id"] != "e2" {
		t.Fatalf("rows wrong: %+v", rows)
	}
}

func TestInsertDedupToken(t *testing.T) {
	if got := insertDedupToken("inspection_events", "e1"); got != "inspection_events\x1fe1" {
		t.Fatalf("token = %q, want stream+US+id", got)
	}
	if got := insertDedupToken("inspection_events", ""); got != "" {
		t.Fatalf("keyless token = %q, want empty (plain insert, no collapse)", got)
	}
	if got := insertDedupToken("inspection_events", "   "); got != "" {
		t.Fatalf("whitespace-only id token = %q, want empty", got)
	}
	// Different streams with the same id must produce different tokens (mirrors the Postgres PK's stream scope).
	if insertDedupToken("access", "e1") == insertDedupToken("audit", "e1") {
		t.Fatalf("same id across streams collided")
	}
}

// TestClickHouseStoreIngestIdempotent proves the retain-and-replay invariant: re-ingesting the same event_id is a
// storage no-op (no duplicate row), while keyless records are never collapsed. Guarded by CLICKHOUSE_TEST_ENDPOINT.
func TestClickHouseStoreIngestIdempotent(t *testing.T) {
	endpoint := os.Getenv("CLICKHOUSE_TEST_ENDPOINT")
	if endpoint == "" {
		t.Skip("set CLICKHOUSE_TEST_ENDPOINT to run the ClickHouse integration test")
	}
	user := valueOr(os.Getenv("CLICKHOUSE_TEST_USER"), "dsse")
	pass := valueOr(os.Getenv("CLICKHOUSE_TEST_PASSWORD"), "dsse-lab")
	ctx := context.Background()
	store := NewClickHouseStore(endpoint, user, pass, "dsse", "events_ckdedup")

	// The dedup window setting is what makes insert_deduplication_token take effect.
	ddl := `CREATE TABLE IF NOT EXISTS dsse.events_ckdedup (event_id String, tenant_id LowCardinality(String), ts DateTime64(3), stream LowCardinality(String), finding_type LowCardinality(String), action LowCardinality(String), application_id String, user_id String, device_id String, destination String, identifier_types Array(String), instance_class LowCardinality(String), rule_id String, raw String) ENGINE = MergeTree PARTITION BY (tenant_id, toYYYYMMDD(ts)) ORDER BY (tenant_id, ts, event_id) SETTINGS non_replicated_deduplication_window = 1000`
	if _, err := store.exec(ctx, ddl, nil); err != nil {
		t.Fatalf("create table: %v", err)
	}
	defer store.exec(ctx, "DROP TABLE IF EXISTS dsse.events_ckdedup", nil)
	if _, err := store.exec(ctx, "TRUNCATE TABLE dsse.events_ckdedup", nil); err != nil {
		t.Fatalf("truncate: %v", err)
	}

	// Ship the SAME keyed event three times (as a lost-ack retry / spool replay would).
	keyed := sampleInspectionRow()
	keyed["id"] = "e_replay_1"
	keyed["timestamp"] = "2026-07-16T03:00:00Z"
	for i := 0; i < 3; i++ {
		if err := store.Ingest(ctx, "inspection_events", keyed); err != nil {
			t.Fatalf("ingest attempt %d: %v", i, err)
		}
	}
	// Two keyless records with DISTINCT content must both survive (different destinations → different blocks). A
	// keyless record falls back to ClickHouse's default block-content-hash dedup, which only collapses byte-identical
	// re-ships (still replay-safe) — genuinely-distinct events differ in content and are not collapsed.
	for i, dest := range []string{"a.example", "b.example"} {
		if err := store.Ingest(ctx, "inspection_events", map[string]any{"tenant_id": "acme", "timestamp": "2026-07-16T03:01:00Z", "finding_type": "dlp_match", "metadata": map[string]any{"dlp_destination": dest}}); err != nil {
			t.Fatalf("keyless ingest %d: %v", i, err)
		}
	}
	// A byte-identical keyless re-ship collapses (content-hash replay safety).
	dup := map[string]any{"tenant_id": "acme", "timestamp": "2026-07-16T03:02:00Z", "finding_type": "dlp_match", "metadata": map[string]any{"dlp_destination": "dup.example"}}
	for i := 0; i < 2; i++ {
		if err := store.Ingest(ctx, "inspection_events", dup); err != nil {
			t.Fatalf("keyless dup ingest %d: %v", i, err)
		}
	}

	count := func(where string) int {
		body, err := store.exec(ctx, "SELECT count() FROM dsse.events_ckdedup WHERE "+where+" FORMAT TabSeparatedRaw", map[string]string{"tenant": "acme", "a": "a.example", "b": "b.example"})
		if err != nil {
			t.Fatalf("count(%s): %v", where, err)
		}
		n, _ := strconv.Atoi(strings.TrimSpace(string(body)))
		return n
	}
	if got := count("event_id = 'e_replay_1'"); got != 1 {
		t.Fatalf("keyed event replayed 3x landed %d rows, want 1 (idempotent)", got)
	}
	if got := count("destination IN ({a:String}, {b:String})"); got != 2 {
		t.Fatalf("2 distinct keyless records landed %d rows, want 2 (distinct content not collapsed)", got)
	}
	if got := count("destination = 'dup.example'"); got != 1 {
		t.Fatalf("byte-identical keyless re-ship landed %d rows, want 1 (content-hash replay safety)", got)
	}
}

// Integration test against a live ClickHouse. Guarded by CLICKHOUSE_TEST_ENDPOINT so unit CI stays hermetic:
//
//	CLICKHOUSE_TEST_ENDPOINT=http://127.0.0.1:8123 CLICKHOUSE_TEST_USER=dsse CLICKHOUSE_TEST_PASSWORD=dsse-lab \
//	  go test ./oss/hotstore/ -run Integration -count=1
func TestClickHouseStoreIntegration(t *testing.T) {
	endpoint := os.Getenv("CLICKHOUSE_TEST_ENDPOINT")
	if endpoint == "" {
		t.Skip("set CLICKHOUSE_TEST_ENDPOINT to run the ClickHouse integration test")
	}
	user := valueOr(os.Getenv("CLICKHOUSE_TEST_USER"), "dsse")
	pass := valueOr(os.Getenv("CLICKHOUSE_TEST_PASSWORD"), "dsse-lab")
	ctx := context.Background()
	store := NewClickHouseStore(endpoint, user, pass, "dsse", "events_cktest")

	ddl := `CREATE TABLE IF NOT EXISTS dsse.events_cktest (event_id String, tenant_id LowCardinality(String), ts DateTime64(3), stream LowCardinality(String), finding_type LowCardinality(String), action LowCardinality(String), application_id String, user_id String, device_id String, destination String, identifier_types Array(String), instance_class LowCardinality(String), rule_id String, raw String) ENGINE = MergeTree PARTITION BY (tenant_id, toYYYYMMDD(ts)) ORDER BY (tenant_id, ts, event_id)`
	if _, err := store.exec(ctx, ddl, nil); err != nil {
		t.Fatalf("create table: %v", err)
	}
	defer store.exec(ctx, "DROP TABLE IF EXISTS dsse.events_cktest", nil)
	if _, err := store.exec(ctx, "TRUNCATE TABLE dsse.events_cktest", nil); err != nil {
		t.Fatalf("truncate: %v", err)
	}

	// A match, a second match, and a scan_skipped — with an access_decision_id for the Related test.
	m1 := sampleInspectionRow()
	m1["id"] = "e_match_1"
	m1["access_decision_id"] = "dec_42"
	m2 := sampleInspectionRow()
	m2["id"] = "e_match_2"
	m2["timestamp"] = "2026-07-16T02:25:00Z"
	skip := map[string]any{"id": "e_skip_1", "tenant_id": "acme", "timestamp": "2026-07-16T02:22:00Z", "finding_type": "dlp_scan_skipped", "metadata": map[string]any{}}
	for _, r := range []map[string]any{m1, m2, skip} {
		if err := store.Ingest(ctx, "inspection_events", r); err != nil {
			t.Fatalf("ingest %v: %v", r["id"], err)
		}
	}

	// Search: filter to dlp_match — expect 2, newest-first, original record shape, no raw secret leak of note.
	res, err := store.Search(ctx, SearchQuery{TenantID: "acme", Stream: "inspection_events", Filters: map[string]string{"finding_type": "dlp_match"}, Limit: 10})
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if res.TotalMatches != 2 || len(res.Rows) != 2 {
		t.Fatalf("search dlp_match: total=%d rows=%d, want 2/2", res.TotalMatches, len(res.Rows))
	}
	if res.Rows[0]["id"] != "e_match_2" {
		t.Fatalf("not newest-first: %v", res.Rows[0]["id"])
	}
	// The returned row is the ORIGINAL record (metadata intact).
	if meta, _ := res.Rows[0]["metadata"].(map[string]any); meta == nil || meta["dlp_action"] != "block" {
		t.Fatalf("row is not the original record shape: %+v", res.Rows[0])
	}

	// Search including the skip.
	all, err := store.Search(ctx, SearchQuery{TenantID: "acme", Stream: "inspection_events", Limit: 10})
	if err != nil || all.TotalMatches != 3 {
		t.Fatalf("search all: total=%d err=%v, want 3", all.TotalMatches, err)
	}

	// RelatedByAccessDecisionID.
	rel, err := store.RelatedByAccessDecisionID(ctx, RelatedLogQuery{TenantID: "acme", AccessDecisionID: "dec_42"})
	if err != nil {
		t.Fatalf("related: %v", err)
	}
	if rel.TotalRows != 1 || len(rel.RowsByStream["inspection_events"]) != 1 {
		t.Fatalf("related: total=%d byStream=%+v, want 1 in inspection_events", rel.TotalRows, rel.RowsByStream)
	}

	// ExportRows.
	exported := 0
	exp, err := store.ExportRows(ctx, SearchQuery{TenantID: "acme", Stream: "inspection_events"}, func(row map[string]any) error { exported++; return nil })
	if err != nil || exp.RowsExported != 3 || exported != 3 {
		t.Fatalf("export: rows=%d exported=%d err=%v, want 3", exp.RowsExported, exported, err)
	}
}

// TestClickHouseStoreTrends drives the full ingest-time rollup path — base table + AggregatingMergeTree rollup + the
// materialized view — then asserts Trends reads correct per-bucket aggregates from the rollup. Guarded by
// CLICKHOUSE_TEST_ENDPOINT.
func TestClickHouseStoreTrends(t *testing.T) {
	endpoint := os.Getenv("CLICKHOUSE_TEST_ENDPOINT")
	if endpoint == "" {
		t.Skip("set CLICKHOUSE_TEST_ENDPOINT to run the ClickHouse integration test")
	}
	user := valueOr(os.Getenv("CLICKHOUSE_TEST_USER"), "dsse")
	pass := valueOr(os.Getenv("CLICKHOUSE_TEST_PASSWORD"), "dsse-lab")
	ctx := context.Background()
	store := NewClickHouseStore(endpoint, user, pass, "dsse", "events_trendtest")

	base := `CREATE TABLE IF NOT EXISTS dsse.events_trendtest (event_id String, tenant_id LowCardinality(String), ts DateTime64(3), stream LowCardinality(String), finding_type LowCardinality(String), action LowCardinality(String), application_id String, user_id String, device_id String, destination String, identifier_types Array(String), instance_class LowCardinality(String), rule_id String, raw String) ENGINE = MergeTree PARTITION BY (tenant_id, toYYYYMMDD(ts)) ORDER BY (tenant_id, ts, event_id)`
	rollup := `CREATE TABLE IF NOT EXISTS dsse.events_trendtest_rollup_5m (tenant_id LowCardinality(String), bucket DateTime, stream LowCardinality(String), finding_type LowCardinality(String), action LowCardinality(String), events SimpleAggregateFunction(sum, UInt64), users AggregateFunction(uniq, String), destinations AggregateFunction(uniq, String), devices AggregateFunction(uniq, String)) ENGINE = AggregatingMergeTree PARTITION BY (tenant_id, toYYYYMMDD(bucket)) ORDER BY (tenant_id, bucket, stream, finding_type, action)`
	mv := `CREATE MATERIALIZED VIEW IF NOT EXISTS dsse.events_trendtest_mv TO dsse.events_trendtest_rollup_5m AS SELECT tenant_id, toStartOfFiveMinutes(ts) AS bucket, stream, finding_type, action, toUInt64(count()) AS events, uniqState(user_id) AS users, uniqState(destination) AS destinations, uniqState(device_id) AS devices FROM dsse.events_trendtest GROUP BY tenant_id, bucket, stream, finding_type, action`
	for _, ddl := range []string{base, rollup, mv} {
		if _, err := store.exec(ctx, ddl, nil); err != nil {
			t.Fatalf("ddl: %v", err)
		}
	}
	defer store.exec(ctx, "DROP TABLE IF EXISTS dsse.events_trendtest_mv", nil)
	defer store.exec(ctx, "DROP TABLE IF EXISTS dsse.events_trendtest_rollup_5m", nil)
	defer store.exec(ctx, "DROP TABLE IF EXISTS dsse.events_trendtest", nil)
	_, _ = store.exec(ctx, "TRUNCATE TABLE dsse.events_trendtest", nil)
	_, _ = store.exec(ctx, "TRUNCATE TABLE dsse.events_trendtest_rollup_5m", nil)

	mk := func(id, ts, u, dev, dest, action string) map[string]any {
		return map[string]any{"id": id, "tenant_id": "trendco", "timestamp": ts, "finding_type": "dlp_match",
			"user_id": u, "device_id": dev, "metadata": map[string]any{"dlp_action": action, "dlp_destination": dest}}
	}
	// Two events in the 05:00 bucket (block, 2 users, 1 dest, 2 devices) and one in the 05:10 bucket (observe).
	for _, r := range []map[string]any{
		mk("t1", "2026-07-16T05:00:00Z", "alice", "d1", "box.com", "block"),
		mk("t2", "2026-07-16T05:03:00Z", "bob", "d2", "box.com", "block"),
		mk("t3", "2026-07-16T05:10:00Z", "alice", "d1", "drive.google.com", "observe"),
	} {
		if err := store.Ingest(ctx, "inspection_events", r); err != nil {
			t.Fatalf("ingest %v: %v", r["id"], err)
		}
	}

	from := time.Date(2026, 7, 16, 4, 55, 0, 0, time.UTC)
	to := time.Date(2026, 7, 16, 5, 15, 0, 0, time.UTC)
	res, err := store.Trends(ctx, TrendsQuery{TenantID: "trendco", From: &from, To: &to, Granularity: "5m"})
	if err != nil {
		t.Fatalf("trends: %v", err)
	}
	byAction := map[string]TrendBucket{}
	for _, b := range res.Buckets {
		byAction[b.Action] = b
	}
	if blk := byAction["block"]; blk.Events != 2 || blk.Users != 2 || blk.Destinations != 1 || blk.Devices != 2 {
		t.Fatalf("block bucket = %+v, want events=2 users=2 dests=1 devices=2", blk)
	}
	if obs := byAction["observe"]; obs.Events != 1 || obs.Users != 1 || obs.Destinations != 1 || obs.Devices != 1 {
		t.Fatalf("observe bucket = %+v, want events=1 users=1 dests=1 devices=1", obs)
	}
	// 1h granularity collapses both 5-min buckets of the same (stream,finding_type,action) — block stays 2 events.
	hourly, err := store.Trends(ctx, TrendsQuery{TenantID: "trendco", From: &from, To: &to, Granularity: "1h"})
	if err != nil {
		t.Fatalf("trends 1h: %v", err)
	}
	var hblock int64
	for _, b := range hourly.Buckets {
		if b.Action == "block" {
			hblock = b.Events
		}
	}
	if hblock != 2 {
		t.Fatalf("1h block events = %d, want 2", hblock)
	}
	// Tenant isolation + unsupported granularity.
	if other, err := store.Trends(ctx, TrendsQuery{TenantID: "someone_else", From: &from, To: &to}); err != nil || len(other.Buckets) != 0 {
		t.Fatalf("cross-tenant trends should be empty, got %d buckets err=%v", len(other.Buckets), err)
	}
	if _, err := store.Trends(ctx, TrendsQuery{TenantID: "trendco", Granularity: "7m"}); err == nil {
		t.Fatal("unsupported granularity should error")
	}
}

func valueOr(v, fallback string) string {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	return v
}
