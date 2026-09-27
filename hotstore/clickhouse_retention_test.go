package hotstore

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

func TestClickHouseRetentionReceiptsIntegration(t *testing.T) {
	endpoint := os.Getenv("CLICKHOUSE_TEST_ENDPOINT")
	if endpoint == "" {
		t.Skip("CLICKHOUSE_TEST_ENDPOINT not set")
	}
	table := fmt.Sprintf("retention_receipts_%d", time.Now().UnixNano())
	s := NewClickHouseStore(endpoint, os.Getenv("CLICKHOUSE_TEST_USER"), os.Getenv("CLICKHOUSE_TEST_PASSWORD"), "dsse", table)
	ctx := context.Background()
	run := func(sql string) {
		t.Helper()
		if _, err := s.exec(ctx, sql, nil); err != nil {
			t.Fatal(err)
		}
	}
	run("CREATE TABLE " + s.qualified() + " (event_id String, tenant_id String, stream String, ts DateTime64(3,'UTC'), raw String) ENGINE=MergeTree ORDER BY (tenant_id,ts,event_id)")
	defer s.exec(ctx, "DROP TABLE "+s.qualified(), nil)
	run("INSERT INTO " + s.qualified() + " VALUES ('same-event','a','audit','2020-01-01 00:00:00.123','{}'),('peer','b','audit','2020-01-01 00:00:00.000','{}')")
	if err := s.RetentionReady(ctx); err == nil {
		t.Fatal("old schema accepted")
	}
	run("ALTER TABLE " + s.qualified() + " ADD COLUMN retention_id UUID DEFAULT generateUUIDv4()")
	if err := s.RetentionReady(ctx); err == nil {
		t.Fatal("unmaterialized IDs accepted")
	}
	run("ALTER TABLE " + s.qualified() + " MATERIALIZE COLUMN retention_id SETTINGS mutations_sync=2")
	if err := s.RetentionReady(ctx); err != nil {
		t.Fatal(err)
	}
	rollup := "dsse." + table + "_rollup_5m"
	run("CREATE TABLE " + rollup + " (bucket DateTime) ENGINE=MergeTree ORDER BY bucket TTL bucket + INTERVAL 400 DAY")
	defer s.exec(ctx, "DROP TABLE "+rollup, nil)
	if err := s.RetentionReady(ctx); err == nil {
		t.Fatal("independent rollup expiry accepted")
	}
	run("ALTER TABLE " + rollup + " REMOVE TTL")
	rows, err := s.RetentionBatch(ctx, "a", "audit", time.Now(), 100)
	if err != nil || len(rows) != 1 {
		t.Fatalf("batch=%v err=%v", rows, err)
	}
	if !strings.HasSuffix(rows[0].Timestamp, ".123") {
		t.Fatal("timestamp precision lost", rows[0].Timestamp)
	}
	again, err := s.RetentionBatch(ctx, "a", "audit", time.Now(), 100)
	if err != nil || len(again) != 1 || again[0].ID != rows[0].ID {
		t.Fatal("receipt not stable", again, err)
	}
	if err = s.DeleteRetentionBatch(ctx, "a", "audit", []string{rows[0].ID}); err != nil {
		t.Fatal(err)
	}
	// The same producer ID may arrive again, but it has a new insertion receipt.
	run("INSERT INTO " + s.qualified() + " (event_id,tenant_id,stream,ts,raw) VALUES ('same-event','a','audit','2020-01-01 00:00:00.123','{}')")
	if err = s.DeleteRetentionBatch(ctx, "a", "audit", []string{rows[0].ID}); err != nil {
		t.Fatal(err)
	}
	replay, err := s.RetentionBatch(ctx, "a", "audit", time.Now(), 100)
	if err != nil || len(replay) != 1 || replay[0].ID == rows[0].ID {
		t.Fatal("late delete removed replay", replay, err)
	}
	peer, err := s.RetentionBatch(ctx, "b", "audit", time.Now(), 100)
	if err != nil || len(peer) != 1 {
		t.Fatal("other tenant changed", peer, err)
	}
}
