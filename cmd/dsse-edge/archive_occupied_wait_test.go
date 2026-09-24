package main

import (
	"context"
	"errors"
	"io"
	"path/filepath"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/archive"
	"github.com/lantern-networks/dsse-core/blobstore"
)

type occupiedArchive struct {
	fakeArchive
	phase   string
	entered chan struct{}
}

func (a *occupiedArchive) List(ctx context.Context, prefix string, limit int) ([]archive.ObjectInfo, error) {
	if a.phase == "list" {
		close(a.entered)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return a.fakeArchive.List(ctx, prefix, limit)
}
func (a *occupiedArchive) Put(ctx context.Context, key string, r io.Reader, n int64, opts archive.PutOptions) (archive.PutResult, error) {
	if a.phase == "put" {
		close(a.entered)
		<-ctx.Done()
		return archive.PutResult{}, ctx.Err()
	}
	return a.fakeArchive.Put(ctx, key, r, n, opts)
}

// Eligible work really enters the external call. Both local and shared policy
// writers, the chain gate and an unrelated CP write must honor shorter deadlines
// without waiting for that call's full budget or discarding the leader session.
func TestPostgresEligibleArchiveOccupiedWait(t *testing.T) {
	for _, storage := range []string{"file", "shared"} {
		for _, phase := range []string{"list", "put"} {
			t.Run(storage+"/"+phase, func(t *testing.T) {
				d, _, leader, peer := trustDistributionPostgresFixture(t)
				p := d.store.(postgresBlobPersister)
				hp, rp, ap := p, p, p
				hp.key = "legal_hold"
				rp.key = "retention_override"
				ap.key = "audit_chain"
				h, r := newLegalHoldStore(hp), newRetentionOverrideStore(rp)
				if storage == "file" {
					h = newLegalHoldStore(blobstore.FilePersister{Path: filepath.Join(t.TempDir(), "holds.json")})
					r = newRetentionOverrideStore(blobstore.FilePersister{Path: filepath.Join(t.TempDir(), "retention.json")})
				}
				now := time.Now()
				if err := h.Set("peer", "review", "", true, now); err != nil {
					t.Fatal(err)
				}
				if err := r.Set("audit", 1); err != nil {
					t.Fatal(err)
				}
				if _, err := p.db.Exec(`CREATE TABLE hot_events(tenant_id text,stream text,event_id text,received_at timestamptz,payload bytea); INSERT INTO hot_events VALUES('target','audit','old',now()-interval '10 days','{}'),('peer','audit','old',now()-interval '10 days','{}')`); err != nil {
					t.Fatal(err)
				}
				var pid int
				if err := leader.conn.QueryRowContext(context.Background(), "SELECT pg_backend_pid()").Scan(&pid); err != nil {
					t.Fatal(err)
				}
				term := leader.leaderSince.Load()
				arc := &occupiedArchive{fakeArchive: fakeArchive{objs: map[string][]byte{}}, phase: phase, entered: make(chan struct{})}
				chain := newAuditChainStore(ap)
				cfg := retentionConfig{legalHold: h, override: r, hotEvents: 24 * time.Hour, archive: arc, auditChain: chain}
				done := make(chan struct{})
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				started := time.Now()
				go func() {
					defer close(done)
					archiveThenPruneStream(ctx, p.db, cfg, "target", "audit", now.Add(-24*time.Hour), now)
				}()
				select {
				case <-arc.entered:
				case <-time.After(7 * time.Second):
					cancel()
					<-done
					t.Fatal("eligible archive did not enter external call")
				}
				for _, gate := range []string{"hold", "retention", "chain", "cp"} {
					wait, stop := context.WithTimeout(context.Background(), 40*time.Millisecond)
					result := make(chan error, 1)
					go func() {
						switch gate {
						case "hold":
							result <- h.SetContext(wait, "target", "review", "", true, now)
						case "retention":
							result <- r.SetContext(wait, "audit", 0)
						case "chain":
							err := chain.operationMu.LockContext(wait)
							if err == nil {
								chain.operationMu.Unlock()
							}
							result <- err
						case "cp":
							q := p
							q.key = "unrelated"
							result <- q.UpdateContext(retentionWriteContext(wait), func([]byte) ([]byte, error) { return []byte(`{}`), nil })
						}
					}()
					select {
					case err := <-result:
						if err == nil {
							t.Errorf("%s unexpectedly passed busy gate", gate)
						} else if gate != "cp" && !errors.Is(err, context.DeadlineExceeded) {
							t.Errorf("%s error %v", gate, err)
						}
					case <-time.After(400 * time.Millisecond):
						t.Errorf("%s ignored short deadline", gate)
						cancel()
						<-done
						<-result
					}
					stop()
				}
				select {
				case <-done:
				case <-time.After(7 * time.Second):
					cancel()
					<-done
					t.Fatal("external call failed to release archive")
				}
				t.Logf("eligible %s/%s occupied for %s", storage, phase, time.Since(started))
				if time.Since(started) < cpStateBlobDBTimeout/2 {
					t.Error("did not exercise default external timeout")
				}
				var afterPID int
				if err := leader.conn.QueryRowContext(context.Background(), "SELECT pg_backend_pid()").Scan(&afterPID); err != nil || afterPID != pid || leader.leaderSince.Load() != term {
					t.Fatalf("leader changed %d -> %d: %v", pid, afterPID, err)
				}
				peer.tick()
				if peer.IsLeader() {
					t.Fatal("peer replaced healthy leader")
				}
				var n int
				if err := p.db.QueryRow(`SELECT count(*) FROM hot_events`).Scan(&n); err != nil || n != 2 {
					t.Fatal("failed archive deleted data", n, err)
				}
				if seq, _, err := newAuditChainStore(ap).Next("target"); err != nil || seq != 0 || len(arc.objs) != 0 {
					t.Fatal("failed archive advanced chain", seq, err)
				}
				if !h.Pending("target") || len(r.PendingForever()) != 1 {
					t.Fatal("pending protection missing")
				}
				// Explicit successful resolution, followed by a normal successful sweep.
				if err := h.Set("target", "review", "", false, now); err != nil {
					t.Fatal(err)
				}
				if err := r.Set("audit", 1); err != nil {
					t.Fatal(err)
				}
				q := p
				q.key = "unrelated"
				if err := q.UpdateContext(retentionWriteContext(context.Background()), func([]byte) ([]byte, error) { return []byte(`{}`), nil }); err != nil {
					t.Fatal(err)
				}
				arc.phase = ""
				archiveThenPruneStream(context.Background(), p.db, cfg, "target", "audit", now.Add(-24*time.Hour), now)
				if seq, _, err := newAuditChainStore(ap).Next("target"); err != nil || seq != 1 || len(arc.objs) != 1 {
					t.Fatal("retry failed", seq, err)
				}
				if err := p.db.QueryRow(`SELECT count(*) FROM hot_events WHERE tenant_id='target'`).Scan(&n); err != nil || n != 0 {
					t.Fatal("retry target count", n, err)
				}
				if err := p.db.QueryRow(`SELECT count(*) FROM hot_events WHERE tenant_id='peer'`).Scan(&n); err != nil || n != 1 || !h.IsHeld("peer") {
					t.Fatal("retry changed peer", n, err)
				}
			})
		}
	}
}
