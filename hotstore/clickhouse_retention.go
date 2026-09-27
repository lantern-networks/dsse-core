package hotstore

import (
	"context"
	"crypto/sha256"
	"encoding/json"
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

var retentionUUID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

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
