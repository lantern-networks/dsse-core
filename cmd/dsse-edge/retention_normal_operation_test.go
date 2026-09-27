package main

import (
	"context"
	"testing"
	"time"
)

func TestDeletionSafetyDefaultStartupAndExplicitMode(t *testing.T) {
	for _, version := range []int{0, 2, 3} {
		h, r := newLegalHoldStore(nil), newRetentionOverrideStore(nil)
		h.snapshotVersion = version
		if err := configureExistingDeletionSafety(h, r, false); err != nil {
			t.Fatal(err)
		}
		err := h.checkDeletionSafety(context.Background(), nil)
		if (err != nil) != (version == 3) {
			t.Fatalf("version %d gate=%v", version, err)
		}
	}
}

func TestPostgresRetentionBacklogMakesBoundedProgress(t *testing.T) {
	p, _, _ := blobWriterPostgresFixture(t)
	if _, err := p.db.Exec(`CREATE TABLE hot_events(tenant_id text,stream text,event_id text,received_at timestamptz,payload bytea)`); err != nil {
		t.Fatal(err)
	}
	for _, archived := range []bool{false, true} {
		if _, err := p.db.Exec(`TRUNCATE hot_events; INSERT INTO hot_events SELECT 'tenant','access',n::text,now()-interval '10 days',convert_to('{}','UTF8') FROM generate_series(1,2001) n`); err != nil {
			t.Fatal(err)
		}
		cfg := retentionConfig{hotEvents: 24 * time.Hour}
		arc := &fakeArchive{objs: map[string][]byte{}}
		if archived {
			cfg.archive = arc
		}
		now := time.Now()
		for _, want := range []int{1001, 1, 0} {
			if archived {
				archiveThenPruneStream(context.Background(), p.db, cfg, "tenant", "access", now.Add(-24*time.Hour), now)
			} else {
				deleteHotStreamOlderThan(context.Background(), p.db, cfg, "tenant", "access", now.Add(-24*time.Hour), now)
			}
			var n int
			if err := p.db.QueryRow(`SELECT count(*) FROM hot_events`).Scan(&n); err != nil || n != want {
				t.Fatalf("archive=%v remaining=%d want=%d err=%v", archived, n, want, err)
			}
		}
		if archived && len(arc.objs) != 3 {
			t.Fatalf("archive segments=%d", len(arc.objs))
		}
	}
}
