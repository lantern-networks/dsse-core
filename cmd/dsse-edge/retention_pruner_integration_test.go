package main

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"
)

// Gated postgres E2E: aged rows are pruned, recent rows are kept. Set POSTGRES_QUEUE_E2E_DSN to run.
func TestRetentionPrunerPostgresE2E(t *testing.T) {
	dsn := os.Getenv("POSTGRES_QUEUE_E2E_DSN")
	if dsn == "" {
		t.Skip("POSTGRES_QUEUE_E2E_DSN is not set")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	if err := db.PingContext(ctx); err != nil {
		t.Skipf("postgres unreachable: %v", err)
	}

	ins := `INSERT INTO hot_events (tenant_id, stream, event_id, access_decision_id, occurred_at, received_at, payload)
	        VALUES ('t_ret','access',$1,'d', $2, $2, '{}'::jsonb) ON CONFLICT DO NOTHING`
	if _, err := db.ExecContext(ctx, ins, "ret-old", time.Now().Add(-60*24*time.Hour)); err != nil {
		t.Skipf("hot_events not available: %v", err)
	}
	if _, err := db.ExecContext(ctx, ins, "ret-fresh", time.Now()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), "DELETE FROM hot_events WHERE event_id IN ('ret-old','ret-fresh')")
	})

	// Prune anything older than 30 days.
	runRetentionPrune(ctx, db, retentionConfig{interval: time.Hour, hotEvents: 30 * 24 * time.Hour})

	count := func(id string) int {
		var n int
		_ = db.QueryRowContext(ctx, "SELECT count(*) FROM hot_events WHERE event_id=$1", id).Scan(&n)
		return n
	}
	if count("ret-old") != 0 {
		t.Fatal("aged hot_events row must be pruned")
	}
	if count("ret-fresh") != 1 {
		t.Fatal("recent hot_events row must be kept")
	}
}
