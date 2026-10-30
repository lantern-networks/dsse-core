package hotstore

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type RetentionStream struct {
	Tenant string `json:"tenant"`
	Stream string `json:"stream"`
}
type RetentionRecord struct {
	ID        string `json:"id"`
	Raw       string `json:"raw"`
	Timestamp string `json:"timestamp"`
}
type RetentionCandidate struct {
	ID        string `json:"id"`
	Timestamp string `json:"timestamp"`
}

var retentionUUID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
var manualDeleteJobID = regexp.MustCompile(`^hot_delete_[a-z0-9_]{1,80}$`)

type ManualDeleteMutation struct {
	ID        string `json:"mutation_id"`
	Done      uint8  `json:"is_done"`
	PartsToDo uint64 `json:"parts_to_do"`
	Failed    uint8  `json:"failed"`
}

// ManualDeleteNotSubmitted distinguishes a known rejection from an ambiguous
// lost response. Only the former permits a failed job to release its hold fence.
type ManualDeleteNotSubmitted struct{ Err error }

func (e *ManualDeleteNotSubmitted) Error() string { return e.Err.Error() }
func (e *ManualDeleteNotSubmitted) Unwrap() error { return e.Err }

// The ClickHouse clock and an insertion timestamp freeze a predicate without
// copying millions of individual row receipts into PostgreSQL.
func (s *ClickHouseStore) ManualDeletePreview(ctx context.Context, tenant, stream string, cutoff time.Time) (int64, time.Time, error) {
	if err := s.manualDeleteReady(ctx); err != nil {
		return 0, time.Time{}, err
	}
	// PostgreSQL timestamptz stores microseconds. Capture exactly that precision
	// before counting, so the confirmed predicate cannot drift on round-trip.
	b, err := s.exec(ctx, `SELECT toString(now64(6, 'UTC'), 'UTC') FORMAT TabSeparatedRaw`, nil)
	if err != nil {
		return 0, time.Time{}, err
	}
	previewAt, err := time.Parse("2006-01-02 15:04:05.999999999", strings.TrimSpace(string(b)))
	if err != nil {
		return 0, time.Time{}, err
	}
	count, err := s.ManualDeleteCount(ctx, tenant, stream, cutoff, previewAt)
	return count, previewAt.UTC(), err
}

func (s *ClickHouseStore) manualDeleteReady(ctx context.Context) error {
	if err := s.RetentionReady(ctx); err != nil {
		return err
	}
	b, err := s.exec(ctx, `SELECT count() FROM system.columns WHERE database={db:String} AND table={table:String} AND name='inserted_at' AND type LIKE 'DateTime64(9%' FORMAT TabSeparatedRaw`, map[string]string{"db": s.database, "table": s.table})
	if err != nil {
		return err
	}
	if strings.TrimSpace(string(b)) != "1" {
		return fmt.Errorf("ClickHouse manual deletion requires inserted_at DateTime64(9, UTC)")
	}
	b, err = s.exec(ctx, `SELECT count() FROM system.parts WHERE active AND database={db:String} AND table={table:String}
		AND name NOT IN (SELECT name FROM system.parts_columns WHERE active AND database={db:String} AND table={table:String} AND column='inserted_at') FORMAT TabSeparatedRaw`, map[string]string{"db": s.database, "table": s.table})
	if err != nil {
		return err
	}
	if strings.TrimSpace(string(b)) != "0" {
		return fmt.Errorf("ClickHouse inserted_at must be materialized before manual deletion starts")
	}
	return nil
}

func (s *ClickHouseStore) ManualDeleteCount(ctx context.Context, tenant, stream string, cutoff, previewAt time.Time) (int64, error) {
	if tenant == "" || stream == "" || cutoff.IsZero() || previewAt.IsZero() {
		return 0, fmt.Errorf("invalid manual deletion scope")
	}
	b, err := s.exec(ctx, `SELECT count() FROM `+s.qualified()+` WHERE tenant_id={tenant:String} AND stream={stream:String} AND ts<parseDateTime64BestEffort({cutoff:String}, 3) AND inserted_at<parseDateTime64BestEffort({preview:String}, 9) FORMAT TabSeparatedRaw`, map[string]string{
		"tenant": tenant, "stream": stream, "cutoff": cutoff.UTC().Format(time.RFC3339Nano), "preview": previewAt.UTC().Format(time.RFC3339Nano),
	})
	if err != nil {
		return 0, err
	}
	return strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
}

func (s *ClickHouseStore) ManualDeleteStart(ctx context.Context, jobID, tenant, stream string, cutoff, previewAt time.Time) error {
	if !manualDeleteJobID.MatchString(jobID) || tenant == "" || stream == "" || cutoff.IsZero() || previewAt.IsZero() {
		return fmt.Errorf("invalid manual deletion job")
	}
	if err := s.manualDeleteReady(ctx); err != nil {
		return &ManualDeleteNotSubmitted{Err: err}
	}
	// The constant marker survives mutation-command serialization. It identifies
	// this one async mutation after a CP process or leader change.
	where := `tenant_id={tenant:String} AND stream={stream:String} AND ts<parseDateTime64BestEffort({cutoff:String}, 3) AND inserted_at<parseDateTime64BestEffort({preview:String}, 9) AND cityHash64('` + jobID + `') != 0`
	_, err := s.execWithSettings(ctx, `ALTER TABLE `+s.qualified()+` DELETE WHERE `+where, map[string]string{
		"tenant": tenant, "stream": stream, "cutoff": cutoff.UTC().Format(time.RFC3339Nano), "preview": previewAt.UTC().Format(time.RFC3339Nano),
	}, map[string]string{"mutations_sync": "0", "query_id": jobID, "replace_running_query": "0"})
	var response *ClickHouseHTTPError
	if errors.As(err, &response) && response.StatusCode >= 400 && response.StatusCode < 500 {
		return &ManualDeleteNotSubmitted{Err: err}
	}
	return err
}

// ManualDeleteQueryRunning checks the ALTER before looking for its asynchronous
// mutation. A disconnected HTTP request can still be waiting for a table lock
// and has not necessarily registered a mutation yet. Call this first: an ALTER
// can move from system.processes to system.mutations between the two reads.
// Both reads must address the same single-server MergeTree authority.
func (s *ClickHouseStore) ManualDeleteQueryRunning(ctx context.Context, jobID string) (bool, error) {
	if !manualDeleteJobID.MatchString(jobID) {
		return false, fmt.Errorf("invalid manual deletion job")
	}
	b, err := s.exec(ctx, `SELECT count() FROM system.processes WHERE query_id={job:String} FORMAT TabSeparatedRaw`, map[string]string{"job": jobID})
	if err != nil {
		return false, err
	}
	count, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
	if err != nil {
		return false, fmt.Errorf("invalid ClickHouse running deletion query count")
	}
	return count != 0, nil
}

func (s *ClickHouseStore) ManualDeleteMutationState(ctx context.Context, jobID string) (ManualDeleteMutation, bool, error) {
	if !manualDeleteJobID.MatchString(jobID) {
		return ManualDeleteMutation{}, false, fmt.Errorf("invalid manual deletion job")
	}
	b, err := s.execWithSettings(ctx, `SELECT mutation_id, is_done, parts_to_do, (latest_fail_reason != '') AS failed FROM system.mutations WHERE database={db:String} AND table={table:String} AND position(command,{marker:String})>0 ORDER BY create_time DESC, mutation_id DESC LIMIT 1 FORMAT JSONEachRow`, map[string]string{
		// Include the SQL literal boundaries so one job cannot match a longer
		// job ID with the same prefix. The validated alphabet contains no quote.
		"db": s.database, "table": s.table, "marker": "'" + jobID + "'",
	}, map[string]string{"output_format_json_quote_64bit_integers": "0"})
	if err != nil {
		return ManualDeleteMutation{}, false, err
	}
	if strings.TrimSpace(string(b)) == "" {
		return ManualDeleteMutation{}, false, nil
	}
	var state ManualDeleteMutation
	if err := json.Unmarshal(b, &state); err != nil || state.ID == "" {
		return ManualDeleteMutation{}, false, fmt.Errorf("invalid ClickHouse mutation state")
	}
	return state, true, nil
}

// ManualDeleteKill is an operator recovery action for a stalled asynchronous
// mutation. ClickHouse does not roll back already rewritten parts; callers keep
// the legal-hold fence until subsequent state reconciliation confirms it ended.
func (s *ClickHouseStore) ManualDeleteKill(ctx context.Context, jobID string) error {
	state, found, err := s.ManualDeleteMutationState(ctx, jobID)
	if err != nil {
		return err
	}
	if !found {
		// KILL MUTATION cannot cancel an ALTER still queued before mutation
		// registration. Do not report success or imply the hold fence can lift.
		return fmt.Errorf("ClickHouse deletion acceptance is unconfirmed; legal-hold fence retained")
	}
	if state.Done != 0 {
		return nil
	}
	_, err = s.exec(ctx, `KILL MUTATION WHERE database={db:String} AND table={table:String} AND mutation_id={mutation:String}`, map[string]string{
		"db": s.database, "table": s.table, "mutation": state.ID,
	})
	return err
}

// A receipt belongs to one physical insertion, not to the producer's reusable
// event ID. Retried deletes must never select a later replay of the event.
func (s *ClickHouseStore) RetentionReady(ctx context.Context) error {
	params := map[string]string{"db": s.database, "table": s.table}
	b, err := s.exec(ctx, `SELECT count() FROM system.columns WHERE database={db:String} AND table={table:String} AND name='retention_id' AND type='UUID' AND default_kind='DEFAULT' AND default_expression='generateUUIDv4()' FORMAT TabSeparatedRaw`, params)
	if err != nil {
		return err
	}
	if strings.TrimSpace(string(b)) != "1" {
		return fmt.Errorf("ClickHouse retention requires the retention_id schema migration")
	}
	b, err = s.exec(ctx, `SELECT count() FROM system.parts WHERE active AND database={db:String} AND table={table:String} AND name NOT IN (SELECT name FROM system.parts_columns WHERE active AND database={db:String} AND table={table:String} AND column='retention_id') FORMAT TabSeparatedRaw`, params)
	if err != nil {
		return err
	}
	if strings.TrimSpace(string(b)) != "0" {
		return fmt.Errorf("ClickHouse retention_id must be materialized before retention starts")
	}
	params["rollup"] = s.table + "_rollup_5m"
	b, err = s.exec(ctx, "SELECT create_table_query FROM system.tables WHERE database={db:String} AND name IN ({table:String}, {rollup:String}) FORMAT TabSeparatedRaw", params)
	if err != nil {
		return err
	}
	if regexp.MustCompile(`\bTTL\b`).Match(b) {
		return fmt.Errorf("ClickHouse independent TTL must be removed before retention starts")
	}
	return nil
}
func (s *ClickHouseStore) RetentionStreams(ctx context.Context) ([]RetentionStream, error) {
	b, err := s.exec(ctx, "SELECT DISTINCT tenant_id AS tenant, stream FROM "+s.qualified()+" ORDER BY tenant, stream FORMAT JSONEachRow", nil)
	if err != nil {
		return nil, err
	}
	var result []RetentionStream
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if line == "" {
			continue
		}
		var row RetentionStream
		if err = json.Unmarshal([]byte(line), &row); err != nil {
			return nil, err
		}
		if row.Tenant == "" || row.Stream == "" {
			return nil, fmt.Errorf("invalid retention stream")
		}
		result = append(result, row)
	}
	return result, nil
}

// RetentionBacklog counts only rows already due for archival. The caller
// supplies each stream's effective cutoff; held tenants are excluded there.
func (s *ClickHouseStore) RetentionBacklog(ctx context.Context, tenant, stream string, cutoff time.Time) (int64, *time.Time, error) {
	if tenant == "" || stream == "" {
		return 0, nil, fmt.Errorf("invalid retention backlog scope")
	}
	b, err := s.exec(ctx, "SELECT count(), if(count()=0, '', toString(min(ts), 'UTC')) FROM "+s.qualified()+" WHERE tenant_id={tenant:String} AND stream={stream:String} AND ts < parseDateTime64BestEffort({cutoff:String}) FORMAT TabSeparatedRaw", map[string]string{
		"tenant": tenant, "stream": stream, "cutoff": cutoff.UTC().Format(time.RFC3339Nano),
	})
	if err != nil {
		return 0, nil, err
	}
	fields := strings.Split(strings.TrimRight(string(b), "\r\n"), "\t")
	if len(fields) != 2 {
		return 0, nil, fmt.Errorf("invalid retention backlog result")
	}
	count, err := strconv.ParseInt(fields[0], 10, 64)
	if err != nil {
		return 0, nil, err
	}
	if count < 0 || (count > 0 && fields[1] == "") {
		return 0, nil, fmt.Errorf("invalid retention backlog result")
	}
	if count == 0 {
		return 0, nil, nil
	}
	oldest, err := time.Parse("2006-01-02 15:04:05.999999999", fields[1])
	if err != nil {
		return 0, nil, err
	}
	return count, &oldest, nil
}

// RetentionCandidates pages immutable insertion receipts without an offset.
func (s *ClickHouseStore) RetentionCandidates(ctx context.Context, tenant, stream string, cutoff time.Time, afterTime, afterID string, limit int) ([]RetentionCandidate, error) {
	if tenant == "" || stream == "" || limit <= 0 || limit > 1000 || (afterTime == "") != (afterID == "") {
		return nil, fmt.Errorf("invalid retention candidate scope")
	}
	if err := s.RetentionReady(ctx); err != nil {
		return nil, err
	}
	params := map[string]string{"tenant": tenant, "stream": stream, "cutoff": cutoff.UTC().Format(time.RFC3339Nano), "limit": strconv.Itoa(limit)}
	filter := ""
	if afterTime != "" {
		if !retentionUUID.MatchString(afterID) {
			return nil, fmt.Errorf("invalid retention cursor")
		}
		params["after_time"], params["after_id"] = afterTime, afterID
		filter = " AND (ts > parseDateTime64BestEffort({after_time:String}) OR (ts = parseDateTime64BestEffort({after_time:String}) AND retention_id > {after_id:UUID}))"
	}
	b, err := s.exec(ctx, "SELECT toString(retention_id) AS id, toString(ts, 'UTC') AS timestamp FROM "+s.qualified()+" WHERE tenant_id={tenant:String} AND stream={stream:String} AND ts < parseDateTime64BestEffort({cutoff:String})"+filter+" ORDER BY ts, retention_id LIMIT {limit:UInt64} FORMAT JSONEachRow", params)
	if err != nil {
		return nil, err
	}
	var result []RetentionCandidate
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if line == "" {
			continue
		}
		var row RetentionCandidate
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			return nil, err
		}
		if !retentionUUID.MatchString(row.ID) {
			return nil, fmt.Errorf("invalid retention candidate")
		}
		if _, err := time.Parse("2006-01-02 15:04:05.999999999", row.Timestamp); err != nil {
			return nil, err
		}
		result = append(result, row)
	}
	return result, nil
}

func (s *ClickHouseStore) RetentionExistingCount(ctx context.Context, tenant, stream string, ids []string) (int64, error) {
	if tenant == "" || stream == "" || len(ids) == 0 || len(ids) > 1000 {
		return 0, fmt.Errorf("invalid retention receipts")
	}
	params := map[string]string{"tenant": tenant, "stream": stream}
	var bound []string
	for i, id := range ids {
		if !retentionUUID.MatchString(id) {
			return 0, fmt.Errorf("invalid retention receipt")
		}
		name := fmt.Sprintf("id%d", i)
		params[name] = id
		bound = append(bound, "{"+name+":UUID}")
	}
	b, err := s.exec(ctx, "SELECT count() FROM "+s.qualified()+" WHERE tenant_id={tenant:String} AND stream={stream:String} AND retention_id IN ("+strings.Join(bound, ",")+") FORMAT TabSeparatedRaw", params)
	if err != nil {
		return 0, err
	}
	return strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
}
func (s *ClickHouseStore) RetentionBatch(ctx context.Context, tenant, stream string, cutoff time.Time, limit int) ([]RetentionRecord, error) {
	if tenant == "" || stream == "" || limit <= 0 || limit > 1000 {
		return nil, fmt.Errorf("invalid retention selection")
	}
	if err := s.RetentionReady(ctx); err != nil {
		return nil, err
	}
	b, err := s.exec(ctx, "SELECT toString(retention_id) AS id, raw, toString(ts, 'UTC') AS timestamp FROM "+s.qualified()+" WHERE tenant_id={tenant:String} AND stream={stream:String} AND ts < parseDateTime64BestEffort({cutoff:String}) ORDER BY ts, retention_id LIMIT {limit:UInt64} FORMAT JSONEachRow", map[string]string{"tenant": tenant, "stream": stream, "cutoff": cutoff.UTC().Format(time.RFC3339Nano), "limit": strconv.Itoa(limit)})
	if err != nil {
		return nil, err
	}
	var result []RetentionRecord
	seen := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if line == "" {
			continue
		}
		var row RetentionRecord
		if err = json.Unmarshal([]byte(line), &row); err != nil {
			return nil, err
		}
		if !retentionUUID.MatchString(row.ID) || seen[row.ID] || !json.Valid([]byte(row.Raw)) {
			return nil, fmt.Errorf("invalid retention record")
		}
		seen[row.ID] = true
		result = append(result, row)
	}
	return result, nil
}
func (s *ClickHouseStore) DeleteRetentionBatch(ctx context.Context, tenant, stream string, ids []string) error {
	if tenant == "" || stream == "" || len(ids) == 0 || len(ids) > 1000 {
		return fmt.Errorf("invalid retention deletion")
	}
	if err := s.RetentionReady(ctx); err != nil {
		return err
	}
	params := map[string]string{"tenant": tenant, "stream": stream}
	var bound []string
	for i, id := range ids {
		if !retentionUUID.MatchString(id) {
			return fmt.Errorf("invalid retention receipt")
		}
		name := fmt.Sprintf("id%d", i)
		params[name] = id
		bound = append(bound, "{"+name+":UUID}")
	}
	where := "tenant_id={tenant:String} AND stream={stream:String} AND retention_id IN (" + strings.Join(bound, ",") + ")"
	_, err := s.execWithSettings(ctx, "ALTER TABLE "+s.qualified()+" DELETE WHERE "+where, params, map[string]string{"mutations_sync": "2"})
	if err != nil {
		return err
	}
	b, err := s.exec(ctx, "SELECT count() FROM "+s.qualified()+" WHERE "+where+" FORMAT TabSeparatedRaw", params)
	if err != nil {
		return err
	}
	if strings.TrimSpace(string(b)) != "0" {
		return fmt.Errorf("ClickHouse retention deletion is unconfirmed")
	}
	return nil
}

func (s *ClickHouseStore) RetentionIdentity() string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(s.endpoint+"\x00"+s.database+"\x00"+s.table)))
}
