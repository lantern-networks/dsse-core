package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/archive"
	migrationstore "github.com/lantern-networks/dsse-core/migrations"
)

type archiveWriteProbe struct {
	fakeArchive
	putHook func()
	fail    bool
	puts    int
}

func (a *archiveWriteProbe) Put(ctx context.Context, key string, r io.Reader, size int64, opts archive.PutOptions) (archive.PutResult, error) {
	a.puts++
	if a.fail {
		return archive.PutResult{}, errors.New("injected put failure")
	}
	result, err := a.fakeArchive.Put(ctx, key, r, size, opts)
	if a.putHook != nil {
		a.putHook()
	}
	return result, err
}

func TestAuditChainStateFailuresStopAdvancement(t *testing.T) {
	for _, data := range []string{`null`, `{`, `{"t":null}`, `{"t":{}}`, `{"t":{"seq":0,"last_hash":""},"t":{"seq":0,"last_hash":""}}`, `{"t":{"seq":-1}}`, `{"t":{"seq":1,"last_hash":"bad"}}`} {
		s := newAuditChainStore(&unreadableHoldPersister{data: []byte(data)})
		if _, _, err := s.Next("t"); err == nil {
			t.Fatal("invalid state usable")
		}
		archiveThenPruneStream(context.Background(), nil, retentionConfig{auditChain: s}, "t", "audit", time.Now(), time.Now())
	}
	p := &holdOutcomePersister{}
	s := newAuditChainStore(p)
	hash := hashObjectBytes([]byte("first"))
	if err := s.Commit("t", 0, hash); err != nil {
		t.Fatal(err)
	}
	p.fail = true
	if err := s.Commit("t", 1, hashObjectBytes([]byte("next"))); err == nil {
		t.Fatal("save failure swallowed")
	}
	if s.per["t"].Seq != 1 || s.per["t"].LastHash != hash {
		t.Fatal("failed save published")
	}
	if _, _, err := s.Next("t"); err == nil {
		t.Fatal("failed commit allowed fork")
	}
}

func TestPostgresArchiveWriteFailuresPreserveHotRows(t *testing.T) {
	dsn := os.Getenv("POSTGRES_QUEUE_E2E_DSN")
	if dsn == "" {
		t.Skip("POSTGRES_QUEUE_E2E_DSN is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	admin, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	schema := fmt.Sprintf("archive_write_%d", time.Now().UnixNano())
	if _, err := admin.ExecContext(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	defer admin.ExecContext(context.Background(), "DROP SCHEMA "+schema+" CASCADE")
	scoped := dsn + " search_path=" + schema
	if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
		u, err := url.Parse(dsn)
		if err != nil {
			t.Fatal(err)
		}
		q := u.Query()
		q.Set("search_path", schema)
		u.RawQuery = q.Encode()
		scoped = u.String()
	}
	db, err := sql.Open("postgres", scoped)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	all, err := migrationstore.LoadDir("../../migrations")
	if err != nil {
		t.Fatal(err)
	}
	selected, err := selectPostgresComponentMigrations(all, "archive fixture", "003")
	if err != nil {
		t.Fatal(err)
	}
	if err := migrationstore.Apply(ctx, db, selected); err != nil {
		t.Fatal(err)
	}
	insert := func(tenant, id string) {
		t.Helper()
		_, err := db.ExecContext(ctx, `INSERT INTO hot_events(tenant_id,stream,event_id,occurred_at,received_at,payload) VALUES($1,'audit',$2,now()-interval '10 days',now()-interval '10 days','{"event":"test"}')`, tenant, id)
		if err != nil {
			t.Fatal(err)
		}
	}
	count := func(tenant string) int {
		t.Helper()
		var n int
		if err := db.QueryRowContext(ctx, "SELECT count(*) FROM hot_events WHERE tenant_id=$1", tenant).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	cutoff := time.Now().Add(-24 * time.Hour)
	for _, mode := range []string{"success", "put_failure", "state_failure", "delete_failure"} {
		t.Run(mode, func(t *testing.T) {
			tenant := mode
			insert(tenant, "old")
			insert(tenant+"_other", "unrelated")
			p := &holdOutcomePersister{fail: mode == "state_failure"}
			chain := newAuditChainStore(p)
			arc := &archiveWriteProbe{fakeArchive: fakeArchive{objs: map[string][]byte{}}, fail: mode == "put_failure"}
			cfg := retentionConfig{archive: arc, auditChain: chain}
			if mode == "success" {
				arc.putHook = func() { insert(tenant, "late") }
			}
			if mode == "delete_failure" {
				_, err := db.ExecContext(ctx, `CREATE FUNCTION refuse_archive_delete() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected delete failure'; END $$; CREATE TRIGGER refuse_archive_delete BEFORE DELETE ON hot_events FOR EACH ROW EXECUTE FUNCTION refuse_archive_delete()`)
				if err != nil {
					t.Fatal(err)
				}
			}
			archiveThenPruneStream(ctx, db, cfg, tenant, "audit", cutoff, time.Now())
			if count(tenant) != 1 || count(tenant+"_other") != 1 {
				t.Fatal("unarchived or failed rows removed")
			}
			if mode == "success" {
				var id string
				if err := db.QueryRowContext(ctx, "SELECT event_id FROM hot_events WHERE tenant_id=$1", tenant).Scan(&id); err != nil || id != "late" {
					t.Fatal("late arrival was erased")
				}
			}
			if mode == "state_failure" {
				if chain.Health() == nil || len(arc.objs) != 1 {
					t.Fatal("state failure hidden")
				}
				p.fail = false
				archiveThenPruneStream(ctx, db, cfg, tenant, "audit", cutoff, time.Now())
				cfg.auditChain = newAuditChainStore(p) // Simulate restart with old persisted head.
				archiveThenPruneStream(ctx, db, cfg, tenant, "audit", cutoff, time.Now())
				if arc.puts != 1 || count(tenant) != 1 {
					t.Fatal("orphan object was silently forked on retry/restart")
				}
			}
			if mode == "delete_failure" {
				if _, err := db.ExecContext(ctx, "DROP TRIGGER refuse_archive_delete ON hot_events; DROP FUNCTION refuse_archive_delete()"); err != nil {
					t.Fatal(err)
				}
				archiveThenPruneStream(ctx, db, cfg, tenant, "audit", cutoff, time.Now())
				if count(tenant) != 0 || len(arc.objs) != 2 {
					t.Fatal("retry lost or overwrote archive")
				}
				verified, err := verifyAuditChain(ctx, arc, tenant)
				if err != nil || !verified.OK {
					t.Fatalf("retry chain %+v %v", verified, err)
				}
			}
		})
	}
	// Console-only retention must activate a sweep even when all startup TTLs are zero.
	override := newRetentionOverrideStore(nil)
	if err := override.Set("audit", 1); err != nil {
		t.Fatal(err)
	}
	cfg := retentionConfig{interval: time.Hour, override: override}
	if !cfg.enabled() {
		t.Fatal("Console-only pruner not enabled")
	}
	runRetentionPrune(ctx, db, cfg)
	if count("success") != 0 {
		t.Fatal("Console-only override ignored")
	}
}
