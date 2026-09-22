package main

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/archive"
)

type unavailableListingArchive struct {
	fakeArchive
	lists int
}

func (a *unavailableListingArchive) List(context.Context, string, int) ([]archive.ObjectInfo, error) {
	a.lists++
	return nil, fmt.Errorf("archive listing unavailable")
}

// An unavailable archive must not occupy the CP writer for a stream that
// cannot be pruned. Eligibility still comes from the locked, latest policy.
func TestPostgresArchiveChecksEligibilityBeforeListing(t *testing.T) {
	d, _, leader, peer := trustDistributionPostgresFixture(t)
	p := d.store.(postgresBlobPersister)
	if _, err := p.db.Exec(`CREATE TABLE hot_events(tenant_id text,stream text,event_id text,received_at timestamptz,payload bytea)`); err != nil {
		t.Fatal(err)
	}
	var beforePID int
	if err := leader.conn.QueryRowContext(context.Background(), "SELECT pg_backend_pid()").Scan(&beforePID); err != nil {
		t.Fatal(err)
	}
	term := leader.leaderSince.Load()
	for _, mode := range []string{"held", "forever", "longer", "empty", "eligible"} {
		t.Run(mode, func(t *testing.T) {
			hp, rp, ap := p, p, p
			hp.key, rp.key, ap.key = "hold_"+mode, "retention_"+mode, "chain_"+mode
			h, r := newLegalHoldStore(hp), newRetentionOverrideStore(rp)
			arc := &unavailableListingArchive{fakeArchive: fakeArchive{objs: map[string][]byte{}}}
			now := time.Now()
			wantRows := 0
			if mode != "empty" {
				wantRows = 1
				if _, err := p.db.Exec(`INSERT INTO hot_events VALUES($1,'audit','old',$2,$3)`, mode, now.Add(-10*24*time.Hour), []byte(`{}`)); err != nil {
					t.Fatal(err)
				}
			}
			// Commit through a different Store after the pruning Store was loaded.
			// A stale local map must not trigger List or broaden the cutoff.
			if mode == "held" {
				if err := newLegalHoldStore(hp).Set(mode, "review", "", true, now); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "forever" || mode == "longer" {
				days := 0
				if mode == "longer" {
					days = 30
				}
				if err := newRetentionOverrideStore(rp).Set("audit", days); err != nil {
					t.Fatal(err)
				}
			}
			archiveThenPruneStream(context.Background(), p.db, retentionConfig{legalHold: h, override: r, hotEvents: 24 * time.Hour, archive: arc, auditChain: newAuditChainStore(ap)}, mode, "audit", now.Add(-24*time.Hour), now)
			wantLists := 0
			if mode == "eligible" {
				wantLists = 1
			}
			if arc.lists != wantLists {
				t.Errorf("archive List calls=%d want=%d", arc.lists, wantLists)
			}
			var rows int
			if err := p.db.QueryRow(`SELECT count(*) FROM hot_events WHERE tenant_id=$1`, mode).Scan(&rows); err != nil || rows != wantRows {
				t.Fatalf("hot rows=%d want=%d: %v", rows, wantRows, err)
			}
			if seq, _, err := newAuditChainStore(ap).Next(mode); err != nil || seq != 0 || len(arc.objs) != 0 {
				t.Fatalf("paused archive changed head/objects: seq=%d err=%v", seq, err)
			}
		})
	}
	var afterPID int
	if err := leader.conn.QueryRowContext(context.Background(), "SELECT pg_backend_pid()").Scan(&afterPID); err != nil || afterPID != beforePID || leader.leaderSince.Load() != term {
		t.Fatalf("leader session changed: %d -> %d: %v", beforePID, afterPID, err)
	}
	peer.tick()
	if peer.IsLeader() {
		t.Fatal("peer acquired active leader lock")
	}
}
