package hotstore

import (
	"context"
	"database/sql"
	"fmt"
	"strconv"
	"strings"
)

// GroupRowsByFields groups in the database rather than shipping rows to be grouped in Go. Its own statement
// builder, deliberately not buildPostgresSearchStatement: that one must keep emitting payload + count(*) OVER()
// + ORDER BY + LIMIT for its two callers, none of which this needs, and it rejects Limit < 1 which is
// meaningless here.
//
// No new index is needed, and one would not help. hot_events_search_idx leads with (tenant_id, stream,
// occurred_at), which is exactly this WHERE, so the window is an index range scan; the GROUP BY itself is a hash
// aggregate over those rows, and an index on the grouped JSON expressions would not be used for it — it would
// cost every write and buy nothing.
func (store *PostgresStore) GroupRowsByFields(ctx context.Context, query FieldGroupQuery) (FieldGroupResult, error) {
	if store == nil || store.db == nil {
		return FieldGroupResult{}, fmt.Errorf("postgres hot store is not configured")
	}
	if err := query.validate(); err != nil {
		return FieldGroupResult{}, err
	}
	args := []any{query.TenantID, query.Stream}
	where := []string{"tenant_id = $1", "stream = $2"}
	if query.From != nil {
		args = append(args, query.From.UTC())
		where = append(where, fmt.Sprintf("occurred_at >= $%d", len(args)))
	}
	if query.To != nil {
		args = append(args, query.To.UTC())
		where = append(where, fmt.Sprintf("occurred_at <= $%d", len(args)))
	}

	fieldSelects := make([]string, 0, len(query.Fields))
	fieldOrdinals := make([]string, 0, len(query.Fields))
	for i, spec := range query.Fields {
		fieldSelects = append(fieldSelects, payloadFieldExpr(spec)+" AS g"+strconv.Itoa(i))
		fieldOrdinals = append(fieldOrdinals, strconv.Itoa(i+1))
	}
	matchedExpr := "0"
	if len(query.MatchCount.Paths) > 0 {
		matchedExpr = fmt.Sprintf("COALESCE(sum(CASE WHEN upper(%s) = upper(%s) THEN 1 ELSE 0 END), 0)",
			payloadFieldExpr(query.MatchCount), quoteSQLLiteral(query.MatchValue))
	}

	var statement string
	if query.BucketSeconds > 0 {
		// TWO levels, not one aggregate with DISTINCT inside it. The session buckets have to come back as a SET
		// (the caller unions them at coarser granularities, so a per-group count would double-count a bucket two
		// groups share), and `string_agg(DISTINCT …)` makes Postgres sort every row of every group to dedupe.
		// Grouping by (fields, bucket) first makes each pair unique by construction, so the outer aggregate is a
		// plain concatenation over a set that is already small.
		//
		// Measured at 100k rows against the same grouping WITHOUT the bucket set as a control, because absolute
		// timings on the lab's containerised disk move by nearly an order of magnitude with cache and autovacuum
		// state (the same query has read 16.9s and 1.8s on different runs) — only the within-run comparison is
		// worth quoting. The DISTINCT form cost 20.0s on top of a 16.9s base; this form costs 1.3s on top of a
		// 1.8s base. Re-measurable via cmd/edge/ai_usage_postgres_scale_test.go, which prints both.
		bucketExpr := fmt.Sprintf("floor(extract(epoch from occurred_at) / %d)::bigint", query.BucketSeconds)
		inner := "SELECT " + strings.Join(fieldSelects, ", ") +
			", " + bucketExpr + " AS bucket" +
			", count(*) AS row_count" +
			", " + sumNumberFieldExpr(query.BytesSent) + " AS bytes_sent" +
			", " + sumNumberFieldExpr(query.BytesReceived) + " AS bytes_received" +
			", " + matchedExpr + " AS matched" +
			" FROM hot_events WHERE " + strings.Join(where, " AND ") +
			" GROUP BY " + strings.Join(append(append([]string{}, fieldOrdinals...), strconv.Itoa(len(query.Fields)+1)), ", ")
		outerFields := make([]string, 0, len(query.Fields))
		for i := range query.Fields {
			outerFields = append(outerFields, "g"+strconv.Itoa(i))
		}
		statement = "SELECT " + strings.Join(outerFields, ", ") +
			", sum(row_count)::bigint AS row_count, sum(bytes_sent)::bigint AS bytes_sent, sum(bytes_received)::bigint AS bytes_received" +
			", sum(matched)::bigint AS matched" +
			// string_agg rather than array_agg so the result crosses the driver boundary as text: this package
			// talks to database/sql only, and a driver-specific array type to move a list of integers would tie
			// the hot store to lib/pq for no gain. No DISTINCT — the inner grouping already made each unique.
			", COALESCE(string_agg(bucket::text, ','), '') AS buckets" +
			" FROM (" + inner + ") t" +
			" GROUP BY " + strings.Join(fieldOrdinals, ", ") +
			" ORDER BY row_count DESC"
	} else {
		selects := append(append([]string{}, fieldSelects...),
			"count(*) AS row_count",
			sumNumberFieldExpr(query.BytesSent)+" AS bytes_sent",
			sumNumberFieldExpr(query.BytesReceived)+" AS bytes_received",
			matchedExpr+" AS matched",
			"'' AS buckets")
		statement = "SELECT " + strings.Join(selects, ", ") +
			" FROM hot_events WHERE " + strings.Join(where, " AND ") +
			" GROUP BY " + strings.Join(fieldOrdinals, ", ") +
			" ORDER BY row_count DESC"
	}
	// One more than the cap, so hitting it is distinguishable from landing exactly on it.
	if query.MaxGroups > 0 {
		statement += fmt.Sprintf(" LIMIT %d", query.MaxGroups+1)
	}

	rows, err := store.db.QueryContext(ctx, statement, args...)
	if err != nil {
		return FieldGroupResult{}, fmt.Errorf("group hot events: %w", err)
	}
	defer rows.Close()

	result := FieldGroupResult{}
	for rows.Next() {
		values := make([]sql.NullString, len(query.Fields))
		scan := make([]any, 0, len(query.Fields)+5)
		for i := range values {
			scan = append(scan, &values[i])
		}
		var rowCount, matched, bytesSent, bytesReceived int64
		var buckets string
		scan = append(scan, &rowCount, &bytesSent, &bytesReceived, &matched, &buckets)
		if err := rows.Scan(scan...); err != nil {
			return FieldGroupResult{}, err
		}
		group := FieldGroup{
			Fields:        make(map[string]string, len(query.Fields)),
			Rows:          int(rowCount),
			MatchedRows:   int(matched),
			BytesSent:     bytesSent,
			BytesReceived: bytesReceived,
			Buckets:       parseBucketList(buckets),
		}
		for i, spec := range query.Fields {
			group.Fields[spec.Name] = values[i].String
		}
		result.TotalRows += group.Rows
		result.Groups = append(result.Groups, group)
	}
	if err := rows.Err(); err != nil {
		return FieldGroupResult{}, err
	}
	if query.IncludeOldestMatched {
		oldest, err := store.oldestEventAt(ctx, SearchQuery{TenantID: query.TenantID, Stream: query.Stream})
		if err != nil {
			return FieldGroupResult{}, err
		}
		result.OldestMatchedAt = oldest
	}
	if query.MaxGroups > 0 && len(result.Groups) > query.MaxGroups {
		result.Groups = result.Groups[:query.MaxGroups]
		result.Truncated = true
		// TotalRows would otherwise count rows from a group that was dropped.
		result.TotalRows = 0
		for _, g := range result.Groups {
			result.TotalRows += g.Rows
		}
	}
	return result, nil
}

// payloadFieldExpr reads a value from the FIRST of the spec's paths that is present — exactly the order the
// caller's own reader tries them in. It does not add depths the caller did not ask for: a store that looked
// under "metadata" for a field the caller only reads at the top level would attribute rows the caller never
// would, and nothing would say so.
func payloadFieldExpr(spec FieldSpec) string {
	if len(spec.Paths) == 0 {
		return "NULL"
	}
	if len(spec.Paths) == 1 {
		return jsonPathTextExpr(spec.Paths[0])
	}
	parts := make([]string, 0, len(spec.Paths))
	for _, path := range spec.Paths {
		parts = append(parts, jsonPathTextExpr(path))
	}
	return "COALESCE(" + strings.Join(parts, ", ") + ")"
}

// jsonPathTextExpr renders one dot-separated path as a JSONB text extraction: "metadata.ai_app" becomes
// payload -> 'metadata' ->> 'ai_app'. Segment shapes are validated before we get here.
func jsonPathTextExpr(path string) string {
	segments := strings.Split(path, ".")
	expr := "payload"
	for i, segment := range segments {
		if i == len(segments)-1 {
			expr += fmt.Sprintf(" ->> '%s'", segment)
			continue
		}
		expr += fmt.Sprintf(" -> '%s'", segment)
	}
	return expr
}

// jsonPathValueExpr is jsonPathTextExpr's sibling that stops one step short, yielding the JSONB value rather
// than its text — needed to ask what TYPE a value is.
func jsonPathValueExpr(path string) string {
	segments := strings.Split(path, ".")
	expr := "payload"
	for _, segment := range segments {
		expr += fmt.Sprintf(" -> '%s'", segment)
	}
	return expr
}

// sumNumberFieldExpr sums a field that holds a JSON NUMBER, and only that. A value stored as a string counts
// zero and a fractional one truncates toward zero, because that is what a caller decoding JSON into Go sees —
// its byte reader takes a number or gives up. Being more generous here (accepting "100") or less (rejecting
// 10.9) would make the aggregate disagree with the row-loading path on exactly the rows nobody writes a test
// for. Not a bare cast either: that raises on the first malformed value and would blank a whole report.
func sumNumberFieldExpr(spec FieldSpec) string {
	if len(spec.Paths) == 0 {
		return "0"
	}
	terms := make([]string, 0, len(spec.Paths))
	for _, path := range spec.Paths {
		terms = append(terms, fmt.Sprintf("WHEN jsonb_typeof(%s) = 'number' THEN trunc((%s)::numeric)",
			jsonPathValueExpr(path), jsonPathTextExpr(path)))
	}
	return fmt.Sprintf("COALESCE(sum(CASE %s ELSE 0 END)::bigint, 0)", strings.Join(terms, " "))
}

// quoteSQLLiteral is for the ONE value that cannot be a bind parameter here (it sits inside an aggregate's CASE
// alongside interpolated field names). Doubling quotes is the whole of SQL string escaping for a value that has
// already been shape-checked by the caller's whitelist.
func quoteSQLLiteral(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "''") + "'"
}

func parseBucketList(raw string) []int64 {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	buckets := make([]int64, 0, len(parts))
	for _, p := range parts {
		if n, err := strconv.ParseInt(strings.TrimSpace(p), 10, 64); err == nil {
			buckets = append(buckets, n)
		}
	}
	return buckets
}
