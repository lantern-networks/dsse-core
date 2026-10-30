package main

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/archive"
)

func TestColdArchiveHealthTransitionsOnlyOnChange(t *testing.T) {
	now := time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC)
	state := nextColdArchiveHealthState(coldArchiveHealthState{}, now, "", 0, nil, nil, 2*time.Hour)
	if state.Status != "ok" || len(state.Pending) != 0 {
		t.Fatalf("healthy baseline = %+v", state)
	}
	state = nextColdArchiveHealthState(state, now.Add(time.Hour), "put_failed", 7, nil, nil, 2*time.Hour)
	state = nextColdArchiveHealthState(state, now.Add(2*time.Hour), "put_failed", 9, nil, nil, 2*time.Hour)
	if state.Sequence != 1 || len(state.Pending) != 1 || state.Pending[0].Type != "cold_archive_degraded" || state.Backlog != 9 {
		t.Fatalf("outage should emit one transition while counts update: %+v", state)
	}
	state = nextColdArchiveHealthState(state, now.Add(3*time.Hour), "", 0, nil, nil, 2*time.Hour)
	if state.Sequence != 2 || len(state.Pending) != 2 || state.Pending[1].Type != "cold_archive_recovered" {
		t.Fatalf("recovery = %+v", state)
	}
}

func TestColdArchiveHealthBacklogThresholdAndReason(t *testing.T) {
	now := time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC)
	due := now.Add(-time.Hour)
	monitor := &coldArchiveHealthMonitor{alertAfter: 2 * time.Hour}
	state := nextColdArchiveHealthState(coldArchiveHealthState{}, now, "", 3, &due, &due, monitor.alertAfter)
	if state.Status != "ok" {
		t.Fatalf("backlog below alert threshold should be visible but not alert: %+v", state)
	}
	// The observation layer raises the threshold reason using due time, not event age.
	if now.Sub(due) > monitor.alertAfter {
		t.Fatal("invalid fixture")
	}
	state = nextColdArchiveHealthState(state, now.Add(2*time.Hour), "backlog_stale", 3, &due, &due, monitor.alertAfter)
	if state.Status != "degraded" || state.Pending[0].Reason != "backlog_stale" {
		t.Fatalf("stale backlog = %+v", state)
	}
	if got := coldArchiveHealthReason("AccessKey=secret at https://example.test"); got != "archive_operation_failed" {
		t.Fatalf("unsafe reason %q", got)
	}
}

type failingHealthArchive struct{}

func (failingHealthArchive) Put(context.Context, string, io.Reader, int64, archive.PutOptions) (archive.PutResult, error) {
	return archive.PutResult{}, errors.New("secret")
}
func (failingHealthArchive) Get(context.Context, string) (io.ReadCloser, error) {
	return nil, errors.New("secret")
}
func (failingHealthArchive) List(context.Context, string, int) ([]archive.ObjectInfo, error) {
	return nil, errors.New("secret")
}
func (failingHealthArchive) Backend() string { return "secret backend" }

func TestObservedArchiveRecordsOnlyOperationClass(t *testing.T) {
	a := &observedColdArchive{backend: failingHealthArchive{}}
	_, _ = a.List(context.Background(), "", 1)
	if got := a.failed(); got != "list_failed" {
		t.Fatalf("failure reason %q", got)
	}
	a.reset()
	if got := a.failed(); got != "" {
		t.Fatalf("reset reason %q", got)
	}
}

func TestColdArchiveHealthPersistsAcrossCPAndRetriesOutbox(t *testing.T) {
	p, leader, peer := blobWriterPostgresFixture(t)
	p.key = "cold_archive_health"
	now := time.Now().UTC().Truncate(time.Second)
	outbox := &recordingDomainEventOutbox{err: errors.New("temporary webhook outbox failure")}
	monitor := &coldArchiveHealthMonitor{state: p, outbox: outbox, alertAfter: 2 * time.Hour}
	if err := monitor.observe(context.Background(), now, "put_failed", 7, nil, nil); err == nil {
		t.Fatal("outbox failure was hidden")
	}
	state, err := monitor.read()
	if err != nil || state.Status != "degraded" || len(state.Pending) != 1 {
		t.Fatalf("durable failure state=%+v err=%v", state, err)
	}
	// A promoted CP sees the same pending transition; it can retry without
	// synthesizing a second outage notification.
	leader.release()
	peer.tick()
	if !peer.IsLeader() {
		t.Fatal("peer did not promote")
	}
	cpLeaderElectorInstance = peer
	outbox.err = nil
	other := &coldArchiveHealthMonitor{state: postgresBlobPersister{db: p.db, key: p.key}, outbox: outbox, alertAfter: 2 * time.Hour}
	if err := other.observe(context.Background(), now.Add(time.Minute), "put_failed", 9, nil, nil); err != nil {
		t.Fatal(err)
	}
	state, err = other.read()
	if err != nil || state.Sequence != 1 || len(state.Pending) != 0 || state.Backlog != 9 {
		t.Fatalf("retry state=%+v err=%v", state, err)
	}
	if err := other.observe(context.Background(), now.Add(2*time.Minute), "", 0, nil, nil); err != nil {
		t.Fatal(err)
	}
	events := outbox.insertedEvents()
	if len(events) != 3 || events[0].ID != events[1].ID || events[2].EventType != "cold_archive_recovered" || events[2].TenantID != agentUpdateCatalogueScope {
		t.Fatalf("unexpected outbox attempts: %+v", events)
	}
}

func TestColdArchiveHealthEventAcceptedAfterMigration(t *testing.T) {
	p, _, _ := blobWriterPostgresFixture(t)
	for _, name := range []string{"006_domain_event_outbox.sql", "007_domain_event_outbox_stream_check.sql", "054_cold_archive_health_events.sql"} {
		data, err := os.ReadFile(filepath.Join("..", "..", "migrations", name))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := p.db.Exec(string(data)); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	now := time.Now().UTC().Truncate(time.Second)
	event := coldArchiveHealthEvent{Sequence: 1, Type: "cold_archive_degraded", At: now, Reason: "put_failed", Backlog: 3}
	envelope, err := domainEventOutboxEnvelopeFromModel("cold_archive_health_events", event.Type, "health_1", agentUpdateCatalogueScope, now.Format(time.RFC3339), event, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := (postgresDomainEventOutboxStore{DB: p.db}).InsertEvent(context.Background(), envelope, now); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := p.db.QueryRow(`SELECT count(*) FROM domain_event_outbox WHERE tenant_id='deployment' AND stream='cold_archive_health_events'`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("persisted events=%d err=%v", count, err)
	}
}

func TestColdArchiveDeliveryStateReadsActualOutbox(t *testing.T) {
	p, _, _ := blobWriterPostgresFixture(t)
	for _, name := range []string{"006_domain_event_outbox.sql", "054_cold_archive_health_events.sql"} {
		data, err := os.ReadFile(filepath.Join("..", "..", "migrations", name))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := p.db.Exec(string(data)); err != nil {
			t.Fatal(err)
		}
	}
	monitor := &coldArchiveHealthMonitor{state: p}
	state, err := monitor.deliveryState(context.Background())
	if err != nil || state.PendingCount != 0 || state.LastSuccess != nil {
		t.Fatalf("initial delivery state %+v: %v", state, err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	var sentID string
	for _, id := range []string{"health_pending", "health_sent"} {
		event := coldArchiveHealthEvent{Sequence: 1, Type: "cold_archive_degraded", At: now, Reason: "put_failed", Backlog: 2}
		envelope, err := domainEventOutboxEnvelopeFromModel("cold_archive_health_events", event.Type, id, agentUpdateCatalogueScope, now.Format(time.RFC3339), event, now)
		if err != nil {
			t.Fatal(err)
		}
		if id == "health_sent" {
			sentID = envelope.ID
		}
		if err := (postgresDomainEventOutboxStore{DB: p.db}).InsertEvent(context.Background(), envelope, now); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := p.db.Exec(`UPDATE domain_event_outbox SET status='published',published_at=$1 WHERE outbox_id=$2`, now, sentID); err != nil {
		t.Fatal(err)
	}
	state, err = monitor.deliveryState(context.Background())
	if err != nil || state.PendingCount != 1 || state.LastSuccess == nil || !state.LastSuccess.Equal(now) {
		t.Fatalf("outbox delivery state %+v: %v", state, err)
	}
}
