package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/usagemeter"
)

func TestUsageSummaryDoesNotReportSuccessWhenDurableReadFails(t *testing.T) {
	store := &postgresUsageMeterStore{SpoolDir: t.TempDir()}
	mux := http.NewServeMux()
	registerUsageEventsRoutes(mux, func(_ string, h http.HandlerFunc) http.HandlerFunc { return h }, nil, store, nil, nil, nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest("GET", "/admin/usage/summary?period_start=2020-01-01T00:00:00Z&period_end=2020-02-01T00:00:00Z", nil))
	if rec.Code != 503 {
		t.Fatalf("unavailable usage became a valid zero: %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), store.SpoolDir) {
		t.Fatal("private spool path exposed")
	}
}

func TestUsageSpoolCorruptionCannotHideNewRecords(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, postgresUsageMeterSpoolFile)
	bad := []byte(`{"interrupted":`)
	if err := os.WriteFile(path, bad, 0600); err != nil {
		t.Fatal(err)
	}
	store := &postgresUsageMeterStore{SpoolDir: dir}
	record := readUsageMeterSampleForTest(t, "usage_meter_nhi_decision_lab.json")
	store.bufferPending(record)
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, bad) {
		t.Fatal("new record appended behind corrupt spool; original must remain unchanged")
	}
	if len(store.pending) != 1 || store.pending[0].ID != record.ID {
		t.Fatal("new record was not retained in fallback memory")
	}
}

func TestUsageSpoolAcceptsCompleteLastRecordWithoutNewline(t *testing.T) {
	dir := t.TempDir()
	record := readUsageMeterSampleForTest(t, "usage_meter_nhi_decision_lab.json")
	raw, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, postgresUsageMeterSpoolFile), raw, 0600); err != nil {
		t.Fatal(err)
	}
	store := &postgresUsageMeterStore{SpoolDir: dir}
	record.ID += "-next"
	if err = store.appendSpool(record); err != nil {
		t.Fatal(err)
	}
	got, err := store.spooledPending()
	if err != nil || len(got) != 2 {
		t.Fatalf("valid unterminated last line joined to next record: count=%d err=%v", len(got), err)
	}
}

func TestUsageHealthRetainsTenantSpecificDataLossAfterPendingDrains(t *testing.T) {
	store := &postgresUsageMeterStore{MaxPending: 1}
	record := readUsageMeterSampleForTest(t, "usage_meter_nhi_decision_lab.json")
	record.TenantID = "Acme"
	store.bufferPending(record)
	record.TenantID = "acme"
	record.ID += "-next"
	store.bufferPending(record)
	store.takePending()
	for _, tc := range []struct {
		tenant string
		loss   bool
	}{{"Acme", true}, {"acme", false}, {"Other", false}} {
		h := usagemeter.UsageMeterHealthFor(store, tc.tenant, "postgres", time.Now())
		found := false
		for _, reason := range h.Reasons {
			if reason == "usage_meter_data_loss" {
				found = true
			}
		}
		if found != tc.loss {
			t.Fatalf("tenant=%s loss=%t health=%+v", tc.tenant, tc.loss, h)
		}
	}
}

func TestUsageFailedReadOnlyReturnsOwnPendingWindow(t *testing.T) {
	store := &postgresUsageMeterStore{}
	r := readUsageMeterSampleForTest(t, "usage_meter_nhi_decision_lab.json")
	r.TenantID = "Acme"
	store.bufferPending(r)
	r.TenantID = "acme"
	store.bufferPending(r)
	rows, err := store.UsageMeterRecords("Acme", r.PeriodStart, r.PeriodEnd)
	if err == nil {
		t.Fatal("missing database was not reported")
	}
	if len(rows) != 1 || rows[0].TenantID != "Acme" {
		t.Fatal("partial read exposed another tenant's pending usage")
	}
	rows, _ = store.UsageMeterRecords("Acme", r.PeriodEnd.Add(time.Hour), r.PeriodEnd.Add(2*time.Hour))
	if len(rows) != 0 {
		t.Fatal("partial read returned records outside requested period")
	}
}
