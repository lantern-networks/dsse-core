package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/logs"
)

func TestObservedReportReplayPostgresPreservesNewerEvidence(t *testing.T) {
	dsn := os.Getenv("POSTGRES_QUEUE_E2E_DSN")
	if dsn == "" {
		t.Skip("POSTGRES_QUEUE_E2E_DSN is not set")
	}
	base, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer base.Close()
	schema := fmt.Sprintf("observed_delivery_%d", time.Now().UnixNano())
	if _, err := base.Exec("CREATE SCHEMA " + schema); err != nil {
		t.Fatal(err)
	}
	defer base.Exec("DROP SCHEMA " + schema + " CASCADE")
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	store, closeStore, err := setupPostgresObservedExclusionStore(context.Background(), u.String(), filepath.Join("..", "..", "migrations"), true)
	if err != nil {
		t.Fatal(err)
	}
	defer closeStore()
	newer := sampleReport()
	newer.AdoptedTrustSerial = 5
	if err := store.Record(newer); err != nil {
		t.Fatal(err)
	}
	older := newer
	older.ReportedAt = newer.ReportedAt.Add(-time.Minute)
	older.AdoptedTrustSerial = 100
	if err := store.Record(older); err != nil {
		t.Fatal(err)
	}
	// Same timestamp is a replay too; it must not rewrite committed facts.
	older.ReportedAt = newer.ReportedAt
	if err := store.Record(older); err != nil {
		t.Fatal(err)
	}
	rows := store.Query(newer.TenantID, observedQueryFilter{Limit: 10}).Entries
	if len(rows) != 1 || rows[0].AdoptedTrustSerial != 5 {
		t.Fatalf("out-of-order report replaced evidence: %+v", rows)
	}
	newer.ReportedAt = newer.ReportedAt.Add(time.Second)
	newer.AdoptedTrustSerial = 6
	if err := store.Record(newer); err != nil {
		t.Fatal(err)
	}
	rows = store.Query(newer.TenantID, observedQueryFilter{Limit: 10}).Entries
	if len(rows) != 1 || rows[0].AdoptedTrustSerial != 6 {
		t.Fatal("new report was not adopted")
	}
}

func TestObservedReportDeliveryDoesNotAcknowledgeDatabaseFailure(t *testing.T) {
	db, err := sql.Open("postgres", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	registerAuditIngestReceiver(mux, writer, "ship-test", nil, &postgresObservedExclusionStore{db: db}, nil, true, observationReportSink{})
	raw, _ := json.Marshal(sampleReport())
	r := httptest.NewRequest(http.MethodPost, "/audit-ingest", strings.NewReader(string(raw)))
	r.Header.Set("Authorization", "Bearer ship-test")
	r.Header.Set("X-Audit-Stream", observedExclusionShipStream)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("uncommitted report acknowledged: %d", w.Code)
	}
}

func TestObservedReportReplayCannotReplaceNewerEvidence(t *testing.T) {
	s := newObservedExclusionStore(0)
	newer := sampleReport()
	newer.AdoptedTrustSerial = 5
	s.Record(newer)
	older := newer
	older.ReportedAt = newer.ReportedAt.Add(-time.Minute)
	older.AdoptedTrustSerial = 100
	s.Record(older)
	got := s.List(newer.TenantID)
	if len(got) != 1 || got[0].AdoptedTrustSerial != 5 {
		t.Fatalf("old report replaced current evidence: %+v", got)
	}
}
