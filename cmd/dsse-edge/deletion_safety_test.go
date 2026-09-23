package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"github.com/lantern-networks/dsse-core/blobstore"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Failed preservation must survive a new leader even when no individual intent
// reached durable storage. A new process has no authority to resume deletion.
func TestPostgresDeletionSafetyFailover(t *testing.T) {
	for _, protection := range []string{"hold", "forever"} {
		for _, takeover := range []string{"peer", "subprocess"} {
			t.Run(protection+"/"+takeover, func(t *testing.T) {
				d, _, leader, peer := trustDistributionPostgresFixture(t)
				p := d.store.(postgresBlobPersister)
				hp, rp := p, p
				hp.key, rp.key = "legal_hold", "retention_override"
				if err := hp.Save([]byte(`[{"tenant_id":"peer","held_since":"2026-01-01T00:00:00Z"}]`)); err != nil {
					t.Fatal(err)
				}
				if err := rp.Save([]byte(`{"audit":1}`)); err != nil {
					t.Fatal(err)
				}
				h, r := newLegalHoldStore(hp), newRetentionOverrideStore(rp)
				if err := configureDeletionSafety(h, r, true); err != nil {
					t.Fatal(err)
				}
				authorizeDeletionForTest(t, hp, h)
				beforeH, _ := hp.Load()
				beforeR, _ := rp.Load()
				_, err := p.db.Exec(`CREATE TABLE hot_events(tenant_id text,stream text,received_at timestamptz);
				INSERT INTO hot_events VALUES('target','audit',now()-interval '10 days'),('peer','audit',now()-interval '10 days');
				CREATE FUNCTION refuse_preservation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected save refusal'; END $$;
				CREATE TRIGGER refuse_preservation BEFORE UPDATE ON cp_state_blobs FOR EACH ROW EXECUTE FUNCTION refuse_preservation()`)
				if err != nil {
					t.Fatal(err)
				}
				now := time.Now()
				if protection == "hold" {
					err = h.Set("target", "probe", "", true, now)
				} else {
					err = r.Set("audit", 0)
				}
				if err == nil {
					t.Fatal("missing write failure")
				}
				if protection == "hold" && !h.Pending("target") || protection == "forever" && len(r.PendingForever()) != 1 {
					t.Fatal("missing local pending")
				}
				cfg := retentionConfig{legalHold: h, override: r, hotEvents: time.Hour}
				deleteHotStreamOlderThan(context.Background(), p.db, cfg, "target", "audit", now.Add(-time.Hour), now)
				safetyCount(t, p.db, "target", 1)
				afterH, _ := hp.Load()
				afterR, _ := rp.Load()
				if !bytes.Equal(beforeH, afterH) || !bytes.Equal(beforeR, afterR) {
					t.Fatal("failed request altered durable policy")
				}
				if _, err := p.db.Exec(`DROP TRIGGER refuse_preservation ON cp_state_blobs; DROP FUNCTION refuse_preservation()`); err != nil {
					t.Fatal(err)
				}
				if takeover == "peer" {
					var pid int
					if err := leader.conn.QueryRowContext(context.Background(), "SELECT pg_backend_pid()").Scan(&pid); err != nil {
						t.Fatal(err)
					}
					var killed bool
					if err := p.db.QueryRow("SELECT pg_terminate_backend($1)", pid).Scan(&killed); err != nil || !killed {
						t.Fatal("terminate", err)
					}
					leader.release()
					peer.tick()
					if !peer.IsLeader() {
						t.Fatal("peer not leader")
					}
					cpLeaderElectorInstance = peer
					safetyPruneFresh(t, p.db)
				} else {
					leader.release()
					ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
					defer cancel()
					cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestDeletionSafetyChild$", "-test.v")
					cmd.Env = append(os.Environ(), "DSSE_PENDING_CHILD=1")
					out, err := cmd.CombinedOutput()
					t.Logf("child output:\n%s", out)
					if err != nil {
						t.Fatal(err)
					}
				}
				safetyCount(t, p.db, "target", 1)
				safetyCount(t, p.db, "peer", 1)
				t.Logf("PROTECTED protection=%s takeover=%s target=1->1 peer=1->1; successor requires reconciliation", protection, takeover)
			})
		}
	}
}

func TestDeletionSafetyChild(t *testing.T) {
	if os.Getenv("DSSE_PENDING_CHILD") != "1" {
		t.Skip("subprocess helper")
	}
	leader, _ := postgresFailureElectors(t)
	leader.tick()
	if !leader.IsLeader() {
		t.Fatal("child election failed")
	}
	cpLeaderElectorInstance, edgeIsControlPlane = leader, true
	db, err := sql.Open("postgres", os.Getenv("POSTGRES_QUEUE_E2E_DSN"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	safetyPruneFresh(t, db)
	t.Logf("new test process pid=%d acquired leadership and retained unrecorded pending target", os.Getpid())
}

func safetyPruneFresh(t *testing.T, db *sql.DB) {
	t.Helper()
	h := newLegalHoldStore(postgresBlobPersister{db: db, key: "legal_hold"})
	r := newRetentionOverrideStore(postgresBlobPersister{db: db, key: "retention_override"})
	if err := configureDeletionSafety(h, r, true); err != nil {
		t.Fatal(err)
	}
	if h.Pending("target") || len(r.PendingForever()) != 0 {
		t.Fatal("unexpected durable pending")
	}
	now := time.Now()
	cfg := retentionConfig{legalHold: h, override: r, hotEvents: time.Hour}
	for _, tenant := range []string{"target", "peer"} {
		deleteHotStreamOlderThan(context.Background(), db, cfg, tenant, "audit", now.Add(-time.Hour), now)
	}
	if _, _, err := h.beginErasure(context.Background(), "target", "review"); err == nil {
		t.Fatal("unreconciled successor allowed purge")
	}
}

func safetyCount(t *testing.T, db *sql.DB, tenant string, want int) {
	t.Helper()
	var n int
	if err := db.QueryRow("SELECT count(*) FROM hot_events WHERE tenant_id=$1", tenant).Scan(&n); err != nil || n != want {
		t.Fatalf("%s count=%d want=%d err=%v", tenant, n, want, err)
	}
}

// Simulate the documented maintenance CAS, not an automatic product path.
func authorizeDeletionForTest(t *testing.T, p postgresBlobPersister, h *legalHoldStore) {
	t.Helper()
	before, err := p.Load()
	if err != nil {
		t.Fatal(err)
	}
	v, err := decodeHoldSnapshot(before, true)
	if err != nil {
		t.Fatal(err)
	}
	v.Version = 3
	v.DeletionPermit = &deletionSafetyPermit{Process: h.deletionGuard.process, Term: strconv.FormatInt(cpLeaderElectorInstance.leaderSince.Load(), 10)}
	after, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	res, err := p.db.Exec(`UPDATE cp_state_blobs SET payload=$1,updated_at=now() WHERE store_key=$2 AND payload=$3`, after, p.key, before)
	if err != nil {
		t.Fatal(err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		t.Fatal("maintenance CAS did not match")
	}
}

func TestPostgresDeletionSafetyReconciliation(t *testing.T) {
	d, _, leader, peer := trustDistributionPostgresFixture(t)
	p := d.store.(postgresBlobPersister)
	hp, rp := p, p
	hp.key, rp.key = "legal_hold", "retention_override"
	if err := hp.Save([]byte(`[]`)); err != nil {
		t.Fatal(err)
	}
	if err := rp.Save([]byte(`{"audit":1}`)); err != nil {
		t.Fatal(err)
	}
	h, r := newLegalHoldStore(hp), newRetentionOverrideStore(rp)
	if err := configureDeletionSafety(h, r, true); err != nil {
		t.Fatal(err)
	}
	if _, err := p.db.Exec(`CREATE TABLE hot_events(tenant_id text,stream text,received_at timestamptz); INSERT INTO hot_events VALUES('target','audit',now()-interval '10 days')`); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	cfg := retentionConfig{legalHold: h, override: r, hotEvents: time.Hour}
	prune := func() {
		deleteHotStreamOlderThan(context.Background(), p.db, cfg, "target", "audit", now.Add(-time.Hour), now)
	}
	prune()
	safetyCount(t, p.db, "target", 1) // Missing permit, including legacy state, is closed.
	authorizeDeletionForTest(t, hp, h)
	// Restore an unresolved protective request before permitting a successor.
	if err := h.Set("target", "review", "reconciled", true, now); err != nil {
		t.Fatal(err)
	}
	old := captureCPWriteLease(context.Background())
	leader.release()
	peer.tick()
	if !peer.IsLeader() {
		t.Fatal("no peer")
	}
	cpLeaderElectorInstance = peer
	prune()
	safetyCount(t, p.db, "target", 1)
	authorizeDeletionForTest(t, hp, h)
	prune()
	safetyCount(t, p.db, "target", 1) // Authorization does not release a hold.
	if err := h.SetContext(old, "target", "review", "", false, now); err == nil {
		t.Fatal("old term released protection")
	}
	if err := h.Set("target", "review", "", false, now); err != nil {
		t.Fatal(err)
	}
	prune()
	safetyCount(t, p.db, "target", 0)
	// A known authority row deleted after successful work must not be recreated
	// as empty safe state, nor should a v3 permit disappear during ordinary writes.
	raw, err := hp.Load()
	if err != nil {
		t.Fatal(err)
	}
	v, err := decodeHoldSnapshot(raw, true)
	if err != nil || v.Version != 3 || v.DeletionPermit == nil {
		t.Fatal("permit lost", err)
	}
	if _, err := p.db.Exec(`DELETE FROM cp_state_blobs WHERE store_key='legal_hold'; INSERT INTO hot_events VALUES('target','audit',now()-interval '10 days')`); err != nil {
		t.Fatal(err)
	}
	prune()
	safetyCount(t, p.db, "target", 1)
}

func TestLocalDeletionSafetyPermitAndRestart(t *testing.T) {
	hp := blobstore.FilePersister{Path: filepath.Join(t.TempDir(), "hold.json")}
	rp := blobstore.FilePersister{Path: filepath.Join(t.TempDir(), "retention.json")}
	h, r := newLegalHoldStore(hp), newRetentionOverrideStore(rp)
	if err := h.Set("peer", "review", "", true, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := r.Set("audit", 1); err != nil {
		t.Fatal(err)
	}
	if err := configureDeletionSafety(h, r, false); err != nil {
		t.Fatal(err)
	}
	if _, _, err := h.beginErasure(context.Background(), "target", "review"); err == nil {
		t.Fatal("missing permit allowed erasure")
	}
	raw, _ := hp.Load()
	v, err := decodeHoldSnapshot(raw, true)
	if err != nil {
		t.Fatal(err)
	}
	v.Version = 3
	v.DeletionPermit = &deletionSafetyPermit{Process: h.deletionGuard.process, Term: "local"}
	approved, _ := json.Marshal(v)
	if err := hp.Save(approved); err != nil {
		t.Fatal(err)
	}
	_, finish, err := h.beginErasure(context.Background(), "target", "review")
	if err != nil {
		t.Fatal(err)
	}
	if err := finish(); err != nil {
		t.Fatal(err)
	}
	if err := h.Set("another", "review", "", true, time.Now()); err != nil {
		t.Fatal(err)
	}
	fresh := newLegalHoldStore(hp)
	if err := configureDeletionSafety(fresh, newRetentionOverrideStore(rp), false); err != nil {
		t.Fatal(err)
	}
	if _, _, err := fresh.beginErasure(context.Background(), "target", "review"); err == nil {
		t.Fatal("restart reused previous process permit")
	}
	if !fresh.IsHeld("peer") || !fresh.IsHeld("another") {
		t.Fatal("confirmed policy lost")
	}
}

func TestDeletionSafetyConfigurationAndFormat(t *testing.T) {
	h, r := newLegalHoldStore(nil), newRetentionOverrideStore(nil)
	if err := configureDeletionSafety(h, r, true); err != nil {
		t.Fatal(err)
	}
	if err := h.checkDeletionSafety(context.Background(), nil); err == nil || !strings.Contains(err.Error(), "same PostgreSQL authority") {
		t.Fatal(err)
	}
	for _, raw := range []string{
		`{"version":2,"holds":[],"erasures":{},"deletion_permit":{"process":"00000000000000000000000000000000","term":"local"}}`,
		`{"version":3,"holds":[],"erasures":{},"deletion_permit":{"process":"short","term":"local"}}`,
		`{"version":3,"holds":[],"erasures":{},"deletion_permit":{"process":"00000000000000000000000000000000","term":"0"}}`,
	} {
		if _, err := decodeHoldSnapshot([]byte(raw), true); err == nil {
			t.Fatal("accepted invalid permit", raw)
		}
	}
}
