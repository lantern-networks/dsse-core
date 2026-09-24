package hotstore

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// ClickHouseStore is a hotstore.Store backed by ClickHouse over its HTTP interface — NO Go client dependency,
// matching the codebase's near-zero-dep philosophy. Each record is one row with the full original JSON in `raw`;
// queries filter on an indexed column when the key is known and fall back to JSONExtract on `raw` for arbitrary
// keys, and return the parsed `raw` so callers see the original record shape exactly as the JSONL/Postgres stores
// do. All user values are bound via ClickHouse HTTP `param_` binding ({name:Type} placeholders) — never
// string-interpolated — so the query builder is injection-safe.
type ClickHouseStore struct {
	client   *http.Client
	endpoint string
	user     string
	password string
	database string
	table    string
}

// NewClickHouseStore builds a store against the ClickHouse HTTP endpoint (e.g. http://clickhouse:8123).
func NewClickHouseStore(endpoint, user, password, database, table string) *ClickHouseStore {
	return &ClickHouseStore{
		client:   &http.Client{Timeout: 30 * time.Second},
		endpoint: strings.TrimRight(strings.TrimSpace(endpoint), "/"),
		user:     user,
		password: password,
		database: strings.TrimSpace(database),
		table:    strings.TrimSpace(table),
	}
}

func (s *ClickHouseStore) qualified() string { return s.database + "." + s.table }

// clickHouseKnownColumns maps a filter key to an indexed column; an unknown key falls back to
// JSONExtractString(raw, key) so any record field remains filterable.
var clickHouseKnownColumns = map[string]string{
	"event_id":       "event_id",
	"edge_region_id": "edge_region_id",
	"finding_type":   "finding_type",
	"action":         "action",
	"application_id": "application_id",
	"user_id":        "user_id",
	"device_id":      "device_id",
	"destination":    "destination",
	"instance_class": "instance_class",
	"rule_id":        "rule_id",
}

// exec runs a SQL statement with named parameters bound safely via ClickHouse HTTP `param_<name>` query params.
func (s *ClickHouseStore) exec(ctx context.Context, sql string, params map[string]string) ([]byte, error) {
	return s.execWithSettings(ctx, sql, params, nil)
}

// execWithSettings is exec plus optional per-request ClickHouse settings (plain query params, e.g.
// insert_deduplication_token). Settings are distinct from bound params, which carry the `param_` prefix.
func (s *ClickHouseStore) execWithSettings(ctx context.Context, sql string, params, settings map[string]string) ([]byte, error) {
	if s == nil || s.endpoint == "" {
		return nil, fmt.Errorf("clickhouse hot store is not configured")
	}
	u, err := url.Parse(s.endpoint + "/")
	if err != nil {
		return nil, err
	}
	qp := u.Query()
	if s.database != "" {
		qp.Set("database", s.database)
	}
	for k, v := range params {
		qp.Set("param_"+k, v)
	}
	for k, v := range settings {
		qp.Set(k, v)
	}
	u.RawQuery = qp.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), strings.NewReader(sql))
	if err != nil {
		return nil, err
	}
	if s.user != "" {
		req.SetBasicAuth(s.user, s.password)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("clickhouse http %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return body, nil
}

// buildWhere renders the WHERE clause + the bound parameters for a query (tenant + stream + filters + text +
// time range). Filter values and the JSONExtract keys are all bound parameters (injection-safe).
func (s *ClickHouseStore) buildWhere(query SearchQuery) (string, map[string]string) {
	conds := []string{"tenant_id = {tenant:String}"}
	params := map[string]string{"tenant": strings.TrimSpace(query.TenantID)}
	if stream := strings.TrimSpace(query.Stream); stream != "" {
		conds = append(conds, "stream = {stream:String}")
		params["stream"] = stream
	}
	i := 0
	for k, v := range query.Filters {
		vk := fmt.Sprintf("f%d", i)
		params[vk] = v
		if col, ok := clickHouseKnownColumns[k]; ok {
			conds = append(conds, fmt.Sprintf("%s = {%s:String}", col, vk))
		} else {
			kk := fmt.Sprintf("k%d", i)
			params[kk] = k
			conds = append(conds, fmt.Sprintf("JSONExtractString(raw, {%s:String}) = {%s:String}", kk, vk))
		}
		i++
	}
	if t := strings.TrimSpace(query.Text); t != "" {
		params["txt"] = t
		conds = append(conds, "positionCaseInsensitive(raw, {txt:String}) > 0")
	}
	if query.From != nil {
		params["fromts"] = clickHouseQueryBound(query.From)
		conds = append(conds, "ts >= parseDateTime64BestEffort({fromts:String})")
	}
	if query.To != nil {
		params["tots"] = clickHouseQueryBound(query.To)
		conds = append(conds, "ts <= parseDateTime64BestEffort({tots:String})")
	}
	return strings.Join(conds, " AND "), params
}

// Search returns the newest-first matching records (paginated) plus the total match count for the cursor.
func (s *ClickHouseStore) Search(ctx context.Context, query SearchQuery) (SearchResult, error) {
	if strings.TrimSpace(query.TenantID) == "" {
		return SearchResult{}, fmt.Errorf("tenant_id is required")
	}
	offset, err := decodeSearchCursorOffset(query)
	if err != nil {
		return SearchResult{}, err
	}
	where, params := s.buildWhere(query)
	countBody, err := s.exec(ctx, "SELECT count() FROM "+s.qualified()+" WHERE "+where+" FORMAT TabSeparatedRaw", params)
	if err != nil {
		return SearchResult{}, err
	}
	totalMatches, err := strconv.Atoi(strings.TrimSpace(string(countBody)))
	if err != nil || totalMatches < 0 {
		return SearchResult{}, fmt.Errorf("invalid ClickHouse search count")
	}
	limit := query.Limit
	if limit < 0 {
		limit = 0
	}
	rowParams := cloneParams(params)
	rowParams["lim"] = strconv.Itoa(limit)
	rowParams["off"] = strconv.Itoa(offset)
	rowsBody, err := s.exec(ctx, "SELECT raw FROM "+s.qualified()+" WHERE "+where+" ORDER BY ts DESC, event_id DESC LIMIT {lim:UInt64} OFFSET {off:UInt64} FORMAT JSONEachRow", rowParams)
	if err != nil {
		return SearchResult{}, err
	}
	rows, err := parseClickHouseRawRows(rowsBody)
	if err != nil {
		return SearchResult{}, err
	}
	filters := copyFilters(query.Filters)
	filters["tenant_id"] = strings.TrimSpace(query.TenantID)
	return SearchResult{
		Stream:       strings.TrimSpace(query.Stream),
		Limit:        query.Limit,
		Filters:      filters,
		Query:        strings.ToLower(strings.TrimSpace(query.Text)),
		TotalScanned: totalMatches,
		TotalMatches: totalMatches,
		NextCursor:   nextSearchCursor(query, offset, totalMatches, rows),
		Rows:         rows,
	}, nil
}

// ExportRows streams all matching records (up to Limit, newest-first) to yield.
func (s *ClickHouseStore) ExportRows(ctx context.Context, query SearchQuery, yield RowHandler) (ExportResult, error) {
	if strings.TrimSpace(query.TenantID) == "" {
		return ExportResult{}, fmt.Errorf("tenant_id is required")
	}
	where, params := s.buildWhere(query)
	limit := query.Limit
	if limit <= 0 {
		limit = 1000000
	}
	params = cloneParams(params)
	params["lim"] = strconv.Itoa(limit)
	body, err := s.exec(ctx, "SELECT raw FROM "+s.qualified()+" WHERE "+where+" ORDER BY ts DESC LIMIT {lim:UInt64} FORMAT JSONEachRow", params)
	if err != nil {
		return ExportResult{}, err
	}
	rows, err := parseClickHouseRawRows(body)
	if err != nil {
		return ExportResult{}, err
	}
	exported := 0
	for _, row := range rows {
		if err := yield(row); err != nil {
			return ExportResult{}, err
		}
		exported++
	}
	filters := copyFilters(query.Filters)
	filters["tenant_id"] = strings.TrimSpace(query.TenantID)
	return ExportResult{
		Stream:       strings.TrimSpace(query.Stream),
		Limit:        query.Limit,
		Filters:      filters,
		Query:        strings.ToLower(strings.TrimSpace(query.Text)),
		TotalScanned: exported,
		TotalMatches: exported,
		RowsExported: exported,
	}, nil
}

// RelatedByAccessDecisionID returns every record carrying the given access_decision_id, grouped by stream.
func (s *ClickHouseStore) RelatedByAccessDecisionID(ctx context.Context, query RelatedLogQuery) (RelatedLogResult, error) {
	if strings.TrimSpace(query.TenantID) == "" {
		return RelatedLogResult{}, fmt.Errorf("tenant_id is required")
	}
	params := map[string]string{"tenant": strings.TrimSpace(query.TenantID), "adid": strings.TrimSpace(query.AccessDecisionID)}
	body, err := s.exec(ctx, "SELECT stream, raw FROM "+s.qualified()+" WHERE tenant_id = {tenant:String} AND JSONExtractString(raw, 'access_decision_id') = {adid:String} ORDER BY ts DESC FORMAT JSONEachRow", params)
	if err != nil {
		return RelatedLogResult{}, err
	}
	byStream := map[string][]map[string]any{}
	total := 0
	sc := bufio.NewScanner(bytes.NewReader(body))
	sc.Buffer(make([]byte, 0, 1024*1024), 16*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var wrap struct {
			Stream string `json:"stream"`
			Raw    string `json:"raw"`
		}
		if err := json.Unmarshal([]byte(line), &wrap); err != nil {
			return RelatedLogResult{}, fmt.Errorf("decode clickhouse related row: %w", err)
		}
		var row map[string]any
		if err := json.Unmarshal([]byte(wrap.Raw), &row); err != nil {
			return RelatedLogResult{}, fmt.Errorf("decode raw payload: %w", err)
		}
		byStream[wrap.Stream] = append(byStream[wrap.Stream], row)
		total++
	}
	return RelatedLogResult{AccessDecisionID: strings.TrimSpace(query.AccessDecisionID), TotalRows: total, RowsByStream: byStream}, sc.Err()
}

// Ingest writes one record (the audit-ingest receiver / a stream hook calls this to mirror events into the hot
// OLAP tier). The structured columns are best-effort-extracted from the record; the full original JSON lives in
// `raw` so Search returns the record unchanged.
func (s *ClickHouseStore) Ingest(ctx context.Context, stream string, row map[string]any) error {
	return s.IngestAt(ctx, stream, row, time.Now().UTC())
}

// IngestRecord is one record waiting to be written, as the batching ingestor holds it.
type IngestRecord struct {
	Stream     string
	Row        map[string]any
	ReceivedAt time.Time
}

// IngestBatch writes MANY records as one INSERT — which is the only shape ClickHouse is built to take.
//
// ★ WHY THIS EXISTS (2026-08-12, measured on the reference lab). Every record used to arrive as its own HTTP
// INSERT, and every INSERT creates a PART that has to be merged. Over three hours on a lab holding 2.4M rows —
// a trivial volume — that produced 12,428 inserts averaging ONE row each and 10,158 merges costing 3,604
// seconds: an hour of CPU spent merging per three hours of a nearly idle system. It ended with ClickHouse at
// 429% CPU, its own ingest timing out, and the control plane refusing to start because its hot-store health
// check could not complete. The store was not overloaded by data; it was overloaded by the SHAPE of the writes.
//
// ★ THE DEDUP TOKEN COVERS THE BATCH, and that is a deliberate narrowing of what it guaranteed. Per record it
// meant "this exact record can be re-shipped forever and appear once". Per batch it means "this exact batch can
// be retried and appear once" — which is what the retry path actually does, because a batch is assembled once
// and retried as itself. What it no longer covers is a DIFFERENT batch containing the same record; the caller
// that could produce that (the Edge→CP shipper's replay) is upstream of here and is de-duplicated before this
// point, by the receiver that records each event id.
func (s *ClickHouseStore) IngestBatch(ctx context.Context, records []IngestRecord) error {
	if len(records) == 0 {
		return nil
	}
	var body strings.Builder
	body.WriteString("INSERT INTO " + s.qualified() + " FORMAT JSONEachRow\n")
	sum := sha256.New()
	keyless := false
	for _, record := range records {
		rec := clickHouseRowFromEvent(record.Stream, record.Row, record.ReceivedAt)
		payload, err := json.Marshal(rec)
		if err != nil {
			// One unencodable record must not lose the batch around it.
			continue
		}
		body.Write(payload)
		body.WriteByte('\n')
		eventID, _ := rec["event_id"].(string)
		if strings.TrimSpace(eventID) == "" {
			// ★ A TOKEN OVER NOTHING IS A TOKEN TWO DIFFERENT BATCHES SHARE (2026-08-13). The hash is built
			// from (stream, event_id) pairs, so a batch whose records carry NO event id hashes to a function of
			// the stream names and the count — and the next batch with the same shape produces the SAME token,
			// which ClickHouse then drops as a replay. Silently, and in the mirror an operator reads.
			//
			// The single-row path already gets this right and says why: "a record with no event_id gets no
			// token, so it falls back to ClickHouse's default block-content-hash dedup" — a byte-identical
			// re-ship still collapses, and genuinely distinct events differ in content and are kept. The batch
			// path is held to the same rule: one keyless record and the whole batch relies on content.
			keyless = true
		}
		sum.Write([]byte(record.Stream + "\x00" + eventID + "\x00"))
	}
	settings := map[string]string{
		// async_insert still helps: several batches arriving together become one part rather than several.
		// wait_for_async_insert=1 because the caller reports failures and a fire-and-forget write would report
		// none.
		"async_insert":             "1",
		"wait_for_async_insert":    "1",
		"async_insert_deduplicate": "1",
	}
	if !keyless {
		settings["insert_deduplication_token"] = "batch:" + hex.EncodeToString(sum.Sum(nil))[:32]
	}
	_, err := s.execWithSettings(ctx, body.String(), nil, settings)
	return err
}

func (s *ClickHouseStore) IngestAt(ctx context.Context, stream string, row map[string]any, receivedAt time.Time) error {
	rec := clickHouseRowFromEvent(stream, row, receivedAt)
	payload, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	// Idempotent ingest so the Edge→CP retain-and-replay spool's at-least-once retries never double-count —
	// "replay after recovery does not duplicate". Each single-row INSERT carries an insert_deduplication_token
	// keyed like the Postgres hot store's PK (stream + event_id); ClickHouse drops a re-insert whose token it has
	// seen within the table's non_replicated_deduplication_window — no duplicate row is ever stored, and queries
	// need no FINAL. A record with no event_id gets no token, so it falls back to ClickHouse's default
	// block-content-hash dedup: a byte-identical re-ship still collapses (replay-safe), while genuinely-distinct
	// events differ in content and are kept. In the target design every event carries a ULID, so the keyless path
	// is only a safety fallback.
	// ★ ASYNC INSERT, BECAUSE ONE ROW PER INSERT IS THE ONE THING CLICKHOUSE CANNOT TAKE (2026-08-12, measured
	// on the reference lab).
	//
	// Every record arrived as its own HTTP INSERT, and every INSERT creates a PART that then has to be merged.
	// Measured over three hours on a lab holding 2.4M rows / 423 MiB — a trivial volume:
	//
	//     12,428 inserts, average 1 row each (min 1, max 1)
	//     10,158 merges, 3,604 seconds of merge time
	//
	// An hour of CPU spent merging per three hours of a nearly idle lab. It ended with ClickHouse at 429% CPU,
	// its own ingest timing out, and the control plane refusing to start because its hot-store health check
	// could not complete. The store was not overloaded by data; it was overloaded by the SHAPE of the writes.
	//
	// async_insert lets the SERVER batch many concurrent single-row inserts into one part — which is exactly
	// what this caller cannot do for itself, because it is called once per appended record from a hook that
	// has no view of the next one.
	//
	// wait_for_async_insert=1 DELIBERATELY: the caller is the Edge→CP ingest path, and this whole subsystem
	// answers "accepted" to a shipper that then drops its copy. Returning before the flush would make that
	// acknowledgement a guess. The batching still happens; only this caller's return waits for it.
	//
	// async_insert_deduplicate keeps the replay-safety the token was added for.
	eventID, _ := rec["event_id"].(string)
	settings := map[string]string{
		"async_insert":             "1",
		"wait_for_async_insert":    "1",
		"async_insert_deduplicate": "1",
	}
	if token := insertDedupToken(stream, eventID); token != "" {
		settings["insert_deduplication_token"] = token
	}
	_, err = s.execWithSettings(ctx, "INSERT INTO "+s.qualified()+" FORMAT JSONEachRow\n"+string(payload), nil, settings)
	return err
}

// insertDedupToken builds the ClickHouse insert-deduplication token for a record — scoped to (stream, event_id) so
// it mirrors the Postgres hot store's (tenant, stream, event_id) idempotency key (tenant is already the partition
// key). Empty when event_id is absent, so keyless records fall back to a plain insert instead of all collapsing to
// one. The 0x1f unit separator cannot appear in either field.
func insertDedupToken(stream, eventID string) string {
	if strings.TrimSpace(eventID) == "" {
		return ""
	}
	return stream + "\x1f" + eventID
}

// rollupTable is the ingest-time rollup maintained by the materialized view (deploy/reference/clickhouse-init/
// 02-rollups.sql) alongside the base events table.
func (s *ClickHouseStore) rollupTable() string { return s.database + "." + s.table + "_rollup_5m" }

// trendBucketExpr maps an allowed granularity to a ClickHouse bucket expression over the rollup's 5-min `bucket`
// column. It is a fixed whitelist (never interpolated from user input), so the query stays injection-safe.
var trendBucketExpr = map[string]string{
	"5m": "bucket",
	"1h": "toStartOfHour(bucket)",
	"1d": "toStartOfDay(bucket)",
}

// Trends serves a tenant's event-activity time series from the ingest-time rollup (AggregatingMergeTree), reading a
// handful of pre-aggregated rows instead of the raw firehose. Implements TrendsCapable.
func (s *ClickHouseStore) Trends(ctx context.Context, q TrendsQuery) (TrendsResult, error) {
	tenant := strings.TrimSpace(q.TenantID)
	if tenant == "" {
		return TrendsResult{}, fmt.Errorf("tenant_id is required")
	}
	gran := strings.TrimSpace(q.Granularity)
	if gran == "" {
		gran = "5m"
	}
	bucketExpr, ok := trendBucketExpr[gran]
	if !ok {
		return TrendsResult{}, fmt.Errorf("unsupported granularity %q (want 5m, 1h or 1d)", gran)
	}
	to := time.Now().UTC()
	if q.To != nil {
		to = q.To.UTC()
	}
	from := to.Add(-24 * time.Hour)
	if q.From != nil {
		from = q.From.UTC()
	}
	conds := []string{"tenant_id = {tenant:String}", "bucket >= parseDateTimeBestEffort({from:String})", "bucket < parseDateTimeBestEffort({to:String})"}
	params := map[string]string{
		"tenant": tenant,
		"from":   clickHouseQueryBound(from),
		"to":     clickHouseQueryBound(to),
	}
	if st := strings.TrimSpace(q.Stream); st != "" {
		conds = append(conds, "stream = {stream:String}")
		params["stream"] = st
	}
	if ft := strings.TrimSpace(q.FindingType); ft != "" {
		conds = append(conds, "finding_type = {ft:String}")
		params["ft"] = ft
	}
	sql := "SELECT toUnixTimestamp(" + bucketExpr + ") AS bucket_ts, stream, finding_type, action, " +
		"toInt64(sum(events)) AS events, toInt64(uniqMerge(users)) AS users, " +
		"toInt64(uniqMerge(destinations)) AS destinations, toInt64(uniqMerge(devices)) AS devices " +
		"FROM " + s.rollupTable() + " WHERE " + strings.Join(conds, " AND ") +
		" GROUP BY bucket_ts, stream, finding_type, action ORDER BY bucket_ts, stream, finding_type, action FORMAT JSONEachRow"
	// Unquote 64-bit ints so they decode straight into int64 (ClickHouse quotes them as strings by default).
	body, err := s.execWithSettings(ctx, sql, params, map[string]string{"output_format_json_quote_64bit_integers": "0"})
	if err != nil {
		return TrendsResult{}, err
	}
	result := TrendsResult{TenantID: tenant, From: from, To: to, Granularity: gran, Buckets: []TrendBucket{}}
	sc := bufio.NewScanner(bytes.NewReader(body))
	sc.Buffer(make([]byte, 0, 1024*1024), 16*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var row struct {
			BucketTS     int64  `json:"bucket_ts"`
			Stream       string `json:"stream"`
			FindingType  string `json:"finding_type"`
			Action       string `json:"action"`
			Events       int64  `json:"events"`
			Users        int64  `json:"users"`
			Destinations int64  `json:"destinations"`
			Devices      int64  `json:"devices"`
		}
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			return TrendsResult{}, fmt.Errorf("decode trends row: %w", err)
		}
		result.Buckets = append(result.Buckets, TrendBucket{
			Bucket:       time.Unix(row.BucketTS, 0).UTC(),
			Stream:       row.Stream,
			FindingType:  row.FindingType,
			Action:       row.Action,
			Events:       row.Events,
			Users:        row.Users,
			Destinations: row.Destinations,
			Devices:      row.Devices,
		})
	}
	return result, sc.Err()
}

func cloneParams(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// parseClickHouseRawRows parses `SELECT raw FORMAT JSONEachRow` output — each line is {"raw":"<record json>"} —
// into the original record maps.
func parseClickHouseRawRows(body []byte) ([]map[string]any, error) {
	out := []map[string]any{}
	sc := bufio.NewScanner(bytes.NewReader(body))
	sc.Buffer(make([]byte, 0, 1024*1024), 16*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var wrap struct {
			Raw string `json:"raw"`
		}
		if err := json.Unmarshal([]byte(line), &wrap); err != nil {
			return nil, fmt.Errorf("decode clickhouse row: %w", err)
		}
		var row map[string]any
		if err := json.Unmarshal([]byte(wrap.Raw), &row); err != nil {
			return nil, fmt.Errorf("decode raw payload: %w", err)
		}
		out = append(out, row)
	}
	return out, sc.Err()
}

// clickHouseRowFromEvent maps a record to the dsse.events column shape (best-effort) plus the full JSON in `raw`.
func clickHouseRowFromEvent(stream string, row map[string]any, receivedAt time.Time) map[string]any {
	str := func(k string) string {
		if v, ok := row[k].(string); ok {
			return v
		}
		return ""
	}
	meta, _ := row["metadata"].(map[string]any)
	mstr := func(k string) string {
		if meta != nil {
			if v, ok := meta[k].(string); ok {
				return v
			}
		}
		return ""
	}
	idTypes := []string{}
	if meta != nil {
		if arr, ok := meta["dlp_identifier_types"].([]any); ok {
			for _, x := range arr {
				if v, ok := x.(string); ok {
					idTypes = append(idTypes, v)
				}
			}
		}
	}
	ts := clickHouseIngestTimestamp(receivedAt)
	if t := str("timestamp"); t != "" {
		if parsed, err := time.Parse(time.RFC3339, t); err == nil {
			ts = clickHouseIngestTimestamp(parsed)
		}
	}
	eventID := str("id")
	if eventID == "" {
		eventID = str("event_id")
	}
	raw, _ := json.Marshal(row)
	return map[string]any{
		"event_id":         eventID,
		"tenant_id":        str("tenant_id"),
		"edge_region_id":   noteAndReturnRegion(row),
		"ts":               ts,
		"stream":           stream,
		"finding_type":     str("finding_type"),
		"action":           mstr("dlp_action"),
		"application_id":   str("application_id"),
		"user_id":          str("user_id"),
		"device_id":        str("device_id"),
		"destination":      mstr("dlp_destination"),
		"identifier_types": idTypes,
		"instance_class":   mstr("dlp_instance_class"),
		"rule_id":          mstr("dlp_rule_id"),
		"raw":              string(raw),
	}
}

// clickHouseQueryBound renders an instant for a QUERY PARAMETER, with its offset written out.
//
// ★ A NAIVE STRING IS READ IN THE SERVER'S TIMEZONE (2026-08-13, twenty-ninth review). The bounds are handed to
// parseDateTime64BestEffort, which applies the SERVER's zone to a string that carries no offset — so a
// ClickHouse in Asia/Tokyo shifted every window by nine hours, and a report that states the window it covers
// was covering a different one.
//
// Measured on the reference server (24.10.2.80) rather than assumed:
//
//	parseDateTime64BestEffort('2026-07-16 02:20:00.000+00:00', 3)  →  1784168400000   correct, offset honoured
//
// This is the QUERY side only. The insert side must NOT use it — see clickHouseIngestTimestamp.
func clickHouseQueryBound(t interface{ UTC() time.Time }) string {
	return t.UTC().Format("2006-01-02 15:04:05.000") + "+00:00"
}

// clickHouseIngestTimestamp renders an instant for an INSERT, with no offset.
//
// ★★ THE OFFSET FORM BREAKS EVERY INSERT, AND THE TWENTY-NINTH REVIEW'S FIX SHIPPED IT (2026-08-13, thirtieth
// review, reproduced live against the reference ClickHouse before this was written):
//
//	INSERT … VALUES ('2026-07-16 02:20:00.000+00:00')
//	Code: 6. DB::Exception: Cannot parse string '2026-07-16 02:20:00.000+00:00' as DateTime64(3):
//	syntax error at position 23 (parsed just '2026-07-16 02:20:00.000')
//
// Two different parsers, and only one of them was checked. A query parameter goes through
// parseDateTime64BestEffort, which reads an offset; a VALUES literal goes through the column's own parser under
// date_time_input_format=basic, which does not. So the fix for a nine-hour skew on a hypothetical non-UTC
// server stopped every event reaching the durable log plane on the UTC servers actually deployed — the spool
// grows and the lane stops, which is worse than the skew it was fixing.
//
// ★ AND THE REAL FIX IS IN THE COLUMN, NOT THE STRING. `ts DateTime64(3)` with no timezone is parsed in the
// SERVER's zone, which is what made a naive string ambiguous in the first place. Measured on the same server:
//
//	DateTime64(3,'Asia/Tokyo')  ← '2026-07-16 02:20:00.000'  stored 2026-07-15 17:20:00 UTC   (the skew)
//	DateTime64(3,'UTC')         ← '2026-07-16 02:20:00.000'  stored 2026-07-16 02:20:00 UTC   (correct)
//
// So the column is declared UTC (clickhouse-init/01-events.sql, and an ALTER for tables already created), and
// a naive string is then unambiguous on a server in any zone. That is the guarantee the twenty-ninth review
// wanted, made where it can actually hold.
func clickHouseIngestTimestamp(t interface{ UTC() time.Time }) string {
	return t.UTC().Format("2006-01-02 15:04:05.000")
}

// EventRegion answers which region a record is from, which is the question a residency decision starts with.
//
// ★★★ THE SAME FACT WAS SPELLED TWO WAYS (2026-08-24, measured on 3,085,761 rows). Access and audit records
// carry edge_region_id. device_state carried only "edge" as "<region>/<cluster>", and config_generations
// carried nothing — 29,859 rows from which no region could be read without knowing how ANOTHER field was
// punctuated, in a store whose schema had no region column at all. Both producers now emit edge_region_id;
// this fallback is what makes the rows already written answerable, and what keeps a producer nobody has fixed
// yet from being invisible rather than merely wrong.
//
// ★ IT RETURNS EMPTY RATHER THAN GUESSING. A record with no region is a defect to be counted, not a row to be
// assigned to whichever region is asking.
func EventRegion(row map[string]any) string {
	if v, ok := row["edge_region_id"].(string); ok {
		if v = strings.TrimSpace(v); v != "" {
			return v
		}
	}
	// device_state's "<region>/<cluster>": the region is the part before the slash.
	if v, ok := row["edge"].(string); ok {
		if v = strings.TrimSpace(v); v != "" {
			if i := strings.Index(v, "/"); i > 0 {
				return strings.TrimSpace(v[:i])
			}
		}
	}
	return ""
}
