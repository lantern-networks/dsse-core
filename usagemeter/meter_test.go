package usagemeter

import (
	"testing"
	"time"
)

func TestRecordAndSummary(t *testing.T) {
	store := NewUsageMeterStore()
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	end := start.Add(24 * time.Hour)
	store.Record(UsageMeterRecord{ID: "r1", TenantID: "acme", MeterType: "active_devices", PeriodStart: start, PeriodEnd: end, Quantity: 5, Unit: "devices"})

	if sum := store.Summary("acme", start, end); sum.Records != 1 {
		t.Fatalf("summary records = %d, want 1", sum.Records)
	}
	recs, err := store.UsageMeterRecords("acme", start, end)
	if err != nil || len(recs) != 1 {
		t.Fatalf("records: %v len=%d", err, len(recs))
	}
}
