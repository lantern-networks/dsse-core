package usagemeter

import (
	"testing"
	"time"
)

func snapshotPeriod() (time.Time, time.Time, time.Time) {
	start := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	end := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	return start, end, time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
}

func recordedSeat(t *testing.T, store *UsageMeterStore, tenantID string, start, end time.Time) (float64, string) {
	t.Helper()
	record, found := usageMeterGovernanceSnapshot(store, "human_seat", tenantID, start, end)
	if !found {
		t.Fatalf("no human_seat snapshot recorded for %s", tenantID)
	}
	return record.Quantity, StringUsageMeterDimension(record.Dimensions, "measurement_scope")
}

// The defect, demonstrated live before it was fixed: the directory went from 43 active people to 42 and the
// recorded seat count stayed at 43 for the rest of the billing period, because the snapshot was written only
// when the period had none.
func TestTheSeatCountFollowsTheDirectory(t *testing.T) {
	start, end, now := snapshotPeriod()
	store := NewUsageMeterStore()

	RecordUsageMeterGovernanceSnapshot(store, "tenant_northwind", 43, "identity_directory_active_humans", 1, start, end, now)
	if quantity, _ := recordedSeat(t, store, "tenant_northwind", start, end); quantity != 43 {
		t.Fatalf("first snapshot recorded %v seats, want 43", quantity)
	}

	RecordUsageMeterGovernanceSnapshot(store, "tenant_northwind", 42, "identity_directory_active_humans", 1, start, end, now)
	quantity, _ := recordedSeat(t, store, "tenant_northwind", start, end)
	if quantity != 42 {
		t.Fatalf("somebody left and the recorded seat count is still %v — the number a customer is measured on "+
			"is frozen at whatever the first node to answer this period happened to see", quantity)
	}

	// And the refresh must REPLACE, not accumulate. The summary SUMS a meter's records, so a second row would
	// bill 43+42 for one month. Checked through the summary — the number a customer is actually shown — rather
	// than through the record lookup, which would find one of two rows and call it fine.
	summary := store.Summary("tenant_northwind", start, end)
	if got := summary.Meters["human_seat"].Quantity; got != 42 {
		t.Fatalf("the period's summary reports %v seats after one change, want 42 — the refresh added a row "+
			"instead of replacing one, and the summary sums them", got)
	}
}

// The other half, and without it the fix is a new defect wearing the opposite mask: two nodes answer for the
// same tenant and they do not know the same things. A node counting admin principals as a stand-in must never
// overwrite a count taken from the directory itself.
func TestAProxyCountNeverOverwritesAMeasuredOne(t *testing.T) {
	start, end, now := snapshotPeriod()
	store := NewUsageMeterStore()

	RecordUsageMeterGovernanceSnapshot(store, "tenant_northwind", 43, "identity_directory_active_humans", 1, start, end, now)
	RecordUsageMeterGovernanceSnapshot(store, "tenant_northwind", 90, "admin_auth_principals_proxy_until_identity_directory", 1, start, end, now)

	quantity, scope := recordedSeat(t, store, "tenant_northwind", start, end)
	if quantity != 43 || scope != "identity_directory_active_humans" {
		t.Fatalf("a proxy count overwrote a measured one: %v seats, scope %q", quantity, scope)
	}

	// The reverse direction must work, or an Edge that has just received the directory would never be able to
	// correct the guess it made before the directory arrived.
	fresh := NewUsageMeterStore()
	RecordUsageMeterGovernanceSnapshot(fresh, "tenant_northwind", 90, "admin_auth_principals_proxy_until_identity_directory", 1, start, end, now)
	RecordUsageMeterGovernanceSnapshot(fresh, "tenant_northwind", 43, "identity_directory_active_humans", 1, start, end, now)
	quantity, scope = recordedSeat(t, fresh, "tenant_northwind", start, end)
	if quantity != 43 || scope != "identity_directory_active_humans" {
		t.Fatalf("a measured count could not replace a proxy: %v seats, scope %q — a node that has just "+
			"received the directory would go on reporting the number it guessed", quantity, scope)
	}
}
