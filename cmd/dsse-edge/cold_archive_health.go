package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/lantern-networks/dsse-core/archive"
)

// The health record belongs to the deployment, not to a customer. Pending
// transitions stay in the shared CP database until the existing signed domain
// event outbox accepts them. Retrying an accepted transition is harmless: its
// outbox ID is deterministic.
type coldArchiveHealthEvent struct {
	Sequence int64      `json:"sequence"`
	Type     string     `json:"type"`
	At       time.Time  `json:"at"`
	Reason   string     `json:"reason"`
	Backlog  int64      `json:"backlog"`
	OldestAt *time.Time `json:"oldest_at,omitempty"`
}

type coldArchiveHealthState struct {
	Version        int                      `json:"version"`
	Status         string                   `json:"status"`
	Reason         string                   `json:"reason"`
	Backlog        int64                    `json:"backlog"`
	OldestAt       *time.Time               `json:"oldest_at,omitempty"`
	OldestDueAt    *time.Time               `json:"oldest_due_at,omitempty"`
	CheckedAt      time.Time                `json:"checked_at"`
	AlertAfterSecs int64                    `json:"alert_after_seconds"`
	Sequence       int64                    `json:"sequence"`
	Pending        []coldArchiveHealthEvent `json:"pending"`
}

type coldArchiveHealthMonitor struct {
	state      postgresBlobPersister
	outbox     domainEventOutboxWriter
	alertAfter time.Duration
}

type coldArchiveDeliveryState struct {
	PendingCount int64      `json:"pending_count"`
	DeadCount    int64      `json:"dead_count"`
	LastSuccess  *time.Time `json:"last_success_at,omitempty"`
}

func (m *coldArchiveHealthMonitor) deliveryState(ctx context.Context) (coldArchiveDeliveryState, error) {
	if m == nil || m.state.db == nil {
		return coldArchiveDeliveryState{}, fmt.Errorf("archive delivery state is unavailable")
	}
	var state coldArchiveDeliveryState
	var published sql.NullTime
	err := m.state.db.QueryRowContext(ctx, `SELECT count(*) FILTER (WHERE status IN ('pending','publishing')),
		count(*) FILTER (WHERE status='dead'),max(published_at) FROM domain_event_outbox
		WHERE tenant_id=$1 AND stream='cold_archive_health_events'`, agentUpdateCatalogueScope).Scan(&state.PendingCount, &state.DeadCount, &published)
	if published.Valid {
		state.LastSuccess = &published.Time
	}
	return state, err
}

func (m *coldArchiveHealthMonitor) read() (coldArchiveHealthState, error) {
	if m == nil {
		return coldArchiveHealthState{}, fmt.Errorf("cold archive health is unavailable")
	}
	raw, err := m.state.Load()
	if err != nil {
		return coldArchiveHealthState{}, err
	}
	var state coldArchiveHealthState
	if len(raw) == 0 {
		return state, nil
	}
	if err := json.Unmarshal(raw, &state); err != nil || state.Version != 1 || state.Sequence < 0 || state.Backlog < 0 || (state.Status != "ok" && state.Status != "degraded") {
		return coldArchiveHealthState{}, fmt.Errorf("invalid shared cold archive health state")
	}
	return state, nil
}

func (m *coldArchiveHealthMonitor) observe(ctx context.Context, now time.Time, reason string, backlog int64, oldest, oldestDue *time.Time) error {
	if m == nil {
		return nil
	}
	if backlog < 0 {
		return fmt.Errorf("invalid cold archive backlog")
	}
	if reason != "" {
		reason = coldArchiveHealthReason(reason)
	}
	now = now.UTC()
	if oldest != nil {
		v := oldest.UTC()
		oldest = &v
	}
	if reason == "" && oldestDue != nil && now.Sub(*oldestDue) > m.alertAfter {
		reason = "backlog_stale"
	}
	if err := m.state.UpdateContext(ctx, func(raw []byte) ([]byte, error) {
		var state coldArchiveHealthState
		if len(raw) > 0 {
			if err := json.Unmarshal(raw, &state); err != nil || state.Version != 1 || state.Sequence < 0 {
				return nil, fmt.Errorf("invalid shared cold archive health state")
			}
		}
		state = nextColdArchiveHealthState(state, now, reason, backlog, oldest, oldestDue, m.alertAfter)
		return json.Marshal(state)
	}); err != nil {
		return err
	}
	return m.flush(ctx)
}

func nextColdArchiveHealthState(state coldArchiveHealthState, now time.Time, reason string, backlog int64, oldest, oldestDue *time.Time, alertAfter time.Duration) coldArchiveHealthState {
	status := "ok"
	if reason != "" {
		status = "degraded"
	}
	changed := state.Version != 0 && (state.Status != status || state.Reason != reason)
	if state.Version == 0 && status == "degraded" {
		changed = true
	}
	state.Version, state.Status, state.Reason = 1, status, reason
	state.Backlog, state.OldestAt, state.OldestDueAt, state.CheckedAt = backlog, oldest, oldestDue, now
	state.AlertAfterSecs = int64(alertAfter.Seconds())
	if changed {
		state.Sequence++
		typeName := "cold_archive_recovered"
		if status == "degraded" {
			typeName = "cold_archive_degraded"
		}
		state.Pending = append(state.Pending, coldArchiveHealthEvent{Sequence: state.Sequence, Type: typeName, At: now, Reason: reason, Backlog: backlog, OldestAt: oldest})
	}
	return state
}

func (m *coldArchiveHealthMonitor) flush(ctx context.Context) error {
	if m == nil || m.outbox == nil {
		return nil
	}
	state, err := m.read()
	if err != nil {
		return err
	}
	for _, event := range state.Pending {
		id := fmt.Sprintf("cold_archive_%d", event.Sequence)
		envelope, err := domainEventOutboxEnvelopeFromModel("cold_archive_health_events", event.Type, id, agentUpdateCatalogueScope, event.At.Format(time.RFC3339), event, event.At)
		if err != nil {
			return err
		}
		if err := m.outbox.InsertEvent(ctx, envelope, event.At); err != nil {
			return err
		}
		if err := m.state.UpdateContext(ctx, func(raw []byte) ([]byte, error) {
			var latest coldArchiveHealthState
			if err := json.Unmarshal(raw, &latest); err != nil || latest.Version != 1 {
				return nil, fmt.Errorf("invalid shared cold archive health state")
			}
			remaining := latest.Pending[:0]
			for _, pending := range latest.Pending {
				if pending.Sequence > event.Sequence {
					remaining = append(remaining, pending)
				}
			}
			latest.Pending = remaining
			return json.Marshal(latest)
		}); err != nil {
			return err
		}
	}
	return nil
}

// observedColdArchive records only operation classes. It never persists an S3
// error string because SDK errors can include endpoints, request IDs or keys.
type observedColdArchive struct {
	backend archive.ColdArchive
	mu      sync.Mutex
	failure string
}

func (a *observedColdArchive) reset()         { a.mu.Lock(); a.failure = ""; a.mu.Unlock() }
func (a *observedColdArchive) failed() string { a.mu.Lock(); defer a.mu.Unlock(); return a.failure }
func (a *observedColdArchive) mark(reason string, err error) {
	if err != nil {
		a.mu.Lock()
		if a.failure == "" {
			a.failure = reason
		}
		a.mu.Unlock()
	}
}
func (a *observedColdArchive) Put(ctx context.Context, key string, r io.Reader, size int64, opts archive.PutOptions) (archive.PutResult, error) {
	result, err := a.backend.Put(ctx, key, r, size, opts)
	a.mark("put_failed", err)
	return result, err
}
func (a *observedColdArchive) Get(ctx context.Context, key string) (io.ReadCloser, error) {
	result, err := a.backend.Get(ctx, key)
	a.mark("get_failed", err)
	return result, err
}
func (a *observedColdArchive) List(ctx context.Context, prefix string, limit int) ([]archive.ObjectInfo, error) {
	result, err := a.backend.List(ctx, prefix, limit)
	a.mark("list_failed", err)
	return result, err
}
func (a *observedColdArchive) Backend() string { return a.backend.Backend() }

func coldArchiveHealthReason(reason string) string {
	switch strings.TrimSpace(reason) {
	case "put_failed", "get_failed", "list_failed", "backlog_query_failed", "backlog_stale":
		return reason
	default:
		return "archive_operation_failed"
	}
}

type coldArchiveBacklog struct {
	Count     int64
	Oldest    *time.Time
	OldestDue *time.Time
}

func measureColdArchiveBacklog(ctx context.Context, db *sql.DB, cfg retentionConfig, now time.Time) (coldArchiveBacklog, error) {
	var result coldArchiveBacklog
	if cfg.clickhouse != nil {
		pairs, err := cfg.clickhouse.hot.RetentionStreams(ctx)
		if err != nil {
			return result, err
		}
		for _, pair := range pairs {
			if cfg.legalHold != nil && cfg.legalHold.IsHeld(pair.Tenant) {
				continue
			}
			ret := cfg.retentionForStream(pair.Stream)
			if ret <= 0 {
				continue
			}
			count, oldest, err := cfg.clickhouse.hot.RetentionBacklog(ctx, pair.Tenant, pair.Stream, now.Add(-ret))
			if err != nil {
				return result, err
			}
			result.Count += count
			if oldest != nil {
				if result.Oldest == nil || oldest.Before(*result.Oldest) {
					result.Oldest = oldest
				}
				due := oldest.Add(ret)
				if result.OldestDue == nil || due.Before(*result.OldestDue) {
					result.OldestDue = &due
				}
			}
		}
		return result, nil
	}
	rows, err := db.QueryContext(ctx, "SELECT DISTINCT tenant_id, stream FROM hot_events")
	if err != nil {
		return result, err
	}
	type pair struct{ tenant, stream string }
	var pairs []pair
	for rows.Next() {
		var p pair
		if err := rows.Scan(&p.tenant, &p.stream); err != nil {
			rows.Close()
			return result, err
		}
		pairs = append(pairs, p)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return result, err
	}
	for _, p := range pairs {
		if cfg.legalHold != nil && cfg.legalHold.IsHeld(p.tenant) {
			continue
		}
		ret := cfg.retentionForStream(p.stream)
		if ret <= 0 {
			continue
		}
		var count int64
		var oldest sql.NullTime
		if err := db.QueryRowContext(ctx, "SELECT count(*), min(received_at) FROM hot_events WHERE tenant_id=$1 AND stream=$2 AND received_at<$3", p.tenant, p.stream, now.Add(-ret)).Scan(&count, &oldest); err != nil {
			return result, err
		}
		result.Count += count
		if oldest.Valid {
			if result.Oldest == nil || oldest.Time.Before(*result.Oldest) {
				at := oldest.Time
				result.Oldest = &at
			}
			due := oldest.Time.Add(ret)
			if result.OldestDue == nil || due.Before(*result.OldestDue) {
				result.OldestDue = &due
			}
		}
	}
	return result, nil
}
