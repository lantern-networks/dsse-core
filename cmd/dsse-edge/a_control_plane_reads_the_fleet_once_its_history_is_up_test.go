package main

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/hotstore"
)

// historyThatStartsLate refuses the first reads, the way ClickHouse did while it was still starting beside a
// control plane that had started first.
type historyThatStartsLate struct {
	refusals int32
	calls    atomic.Int32
	rows     []map[string]any
}

func (h *historyThatStartsLate) Search(_ context.Context, q hotstore.SearchQuery) (hotstore.SearchResult, error) {
	if h.calls.Add(1) <= h.refusals {
		return hotstore.SearchResult{}, errors.New("clickhouse dsse-clickhouse:8123: dial tcp: connect: connection refused")
	}
	return hotstore.SearchResult{Stream: q.Stream, Rows: h.rows}, nil
}

func (h *historyThatStartsLate) ExportRows(context.Context, hotstore.SearchQuery, hotstore.RowHandler) (hotstore.ExportResult, error) {
	return hotstore.ExportResult{}, nil
}

func (h *historyThatStartsLate) RelatedByAccessDecisionID(context.Context, hotstore.RelatedLogQuery) (hotstore.RelatedLogResult, error) {
	return hotstore.RelatedLogResult{}, nil
}

// Found 2026-11-08 on acceptance C: the control plane that held leadership had tried to read the shipped device
// history once, a moment before its history store accepted connections, and never again. For the whole run the
// device page said every device's operating system was unknown and its posture unreported, while the device was
// reporting; it read correctly the moment leadership moved to a control plane whose one attempt had succeeded.
func TestAControlPlaneReadsTheFleetOnceItsHistoryStoreIsUp(t *testing.T) {
	var pauses []time.Duration
	restore := fleetProjectionSeedSleep
	fleetProjectionSeedSleep = func(d time.Duration) { pauses = append(pauses, d) }
	t.Cleanup(func() { fleetProjectionSeedSleep = restore })

	now := time.Now().UTC().Format(time.RFC3339Nano)
	history := &historyThatStartsLate{refusals: 7, rows: []map[string]any{{
		"tenant_id": "tenant", "device_id": "win-1", "os": "Windows 11", "timestamp": now,
		"disk_encryption_enabled": true, "firewall_enabled": true,
	}}}
	p := newFleetDeviceProjection()
	seedFleetDeviceProjection(p, history, "tenant")

	devices, seeded := p.Devices("tenant")
	if !seeded {
		t.Fatalf("the projection stayed unseeded after %d reads; the fleet view would answer for one node forever", history.calls.Load())
	}
	if len(devices) != 1 || devices[0].OS != "Windows 11" {
		t.Fatalf("seeded with %+v, want the device the history holds", devices)
	}
	if got := history.calls.Load(); got != 8 {
		t.Fatalf("read the history %d times, want 7 refusals and the read that succeeded", got)
	}
	// The pause grows and stops growing; a history store that is down for an hour costs one line a minute.
	if len(pauses) != 7 || pauses[0] != fleetProjectionSeedFirstPause || pauses[len(pauses)-1] != fleetProjectionSeedMaxPause {
		t.Fatalf("pauses = %v, want a growing pause capped at %s", pauses, fleetProjectionSeedMaxPause)
	}
	for i := 1; i < len(pauses); i++ {
		if pauses[i] < pauses[i-1] {
			t.Fatalf("pause shrank: %v", pauses)
		}
	}
}
