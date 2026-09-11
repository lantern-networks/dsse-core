package main

import (
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/hotstore"
)

func TestPostgresHotStoreAppendHookIsBestEffortOnIngestError(t *testing.T) {
	monitor := newHotStoreAppendMirrorMonitor()
	hook := postgresHotStoreAppendHook((*hotstore.PostgresStore)(nil), adminLogStreamFilenameMap(), monitor)
	err := hook("access.log.jsonl", []byte(`{"id":"alog_best_effort_001","tenant_id":"tenant_lab_001","timestamp":"2026-05-23T05:00:00Z"}`))
	if err != nil {
		t.Fatalf("hook returned error for best-effort ingest failure: %v", err)
	}
	health := monitor.Health(time.Date(2026, 5, 23, 5, 1, 0, 0, time.UTC))
	if health.Status != "degraded" || health.Stats["ingest_failures"] != 1 {
		t.Fatalf("health = %#v, want degraded ingest failure", health)
	}
}

func TestPostgresHotStoreAppendHookIgnoresMalformedMirrorRows(t *testing.T) {
	monitor := newHotStoreAppendMirrorMonitor()
	hook := postgresHotStoreAppendHook((*hotstore.PostgresStore)(nil), adminLogStreamFilenameMap(), monitor)
	if err := hook("access.log.jsonl", []byte(`{bad json`)); err != nil {
		t.Fatalf("hook returned error for malformed mirror row: %v", err)
	}
	health := monitor.Health(time.Date(2026, 5, 23, 5, 1, 0, 0, time.UTC))
	if health.Status != "degraded" || health.Stats["decode_failures"] != 1 {
		t.Fatalf("health = %#v, want degraded decode failure", health)
	}
}
