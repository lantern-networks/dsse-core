package main

import (
	"bytes"
	"context"
	"fmt"
	"github.com/lantern-networks/dsse-core/archive"
	"io"
	"sync"
	"testing"
	"time"
)

func TestAuditChainSharedPreservesPeerHead(t *testing.T) {
	p := &transactionalCAFixture{}
	a, b := newAuditChainStore(p), newAuditChainStore(p)
	if err := a.Commit("a", 0, hashObjectBytes([]byte("a"))); err != nil {
		t.Fatal(err)
	}
	if err := b.Commit("b", 0, hashObjectBytes([]byte("b"))); err != nil {
		t.Fatal(err)
	}
	fresh := newAuditChainStore(p)
	if n, _, err := fresh.Next("a"); err != nil || n != 1 {
		t.Fatal("stale writer erased peer head")
	}
}
func TestAuditChainSharedRejectsStaleGeneration(t *testing.T) {
	p := &transactionalCAFixture{}
	a, b := newAuditChainStore(p), newAuditChainStore(p)
	if err := a.Commit("a", 0, hashObjectBytes([]byte("first"))); err != nil {
		t.Fatal(err)
	}
	if err := b.Commit("a", 0, hashObjectBytes([]byte("fork"))); err == nil {
		t.Fatal("stale generation fork accepted")
	}
}

func TestPostgresAuditArchiveSharedTransaction(t *testing.T) {
	d, _, leader, peer := trustDistributionPostgresFixture(t)
	p := d.store.(postgresBlobPersister)
	p.key = "audit_chain"
	if _, err := p.db.Exec(`CREATE TABLE hot_events(tenant_id text,stream text,event_id text,received_at timestamptz,payload bytea)`); err != nil {
		t.Fatal(err)
	}
	insert := func(tenant, id string) {
		t.Helper()
		if _, err := p.db.Exec(`INSERT INTO hot_events VALUES($1,'audit',$2,now()-interval '10 days',$3)`, tenant, id, []byte(`{"event":"retained"}`)); err != nil {
			t.Fatal(err)
		}
	}
	count := func(tenant string) int {
		t.Helper()
		var n int
		if err := p.db.QueryRow(`SELECT count(*) FROM hot_events WHERE tenant_id=$1`, tenant).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	arc := &lockedAuditArchive{fakeArchive: fakeArchive{objs: map[string][]byte{}}}
	a, b := newAuditChainStore(p), newAuditChainStore(p)
	now := time.Now()
	cutoff := now.Add(-time.Hour)
	prune := func(chain *auditChainStore, tenant string) {
		archiveThenPruneStream(context.Background(), p.db, retentionConfig{archive: arc, auditChain: chain}, tenant, "audit", cutoff, time.Now())
	}
	insert("a", "1")
	prune(a, "a")
	insert("b", "1")
	prune(b, "b")
	insert("a", "2")
	prune(b, "a") // b was stale before a's first archive.
	for tenant, want := range map[string]int{"a": 2, "b": 1} {
		n, _, err := newAuditChainStore(p).Next(tenant)
		if err != nil || n != want || count(tenant) != 0 {
			t.Fatalf("peer head/hot mismatch %s: %d %v", tenant, n, err)
		}
		verified, err := verifyAuditChain(context.Background(), arc, tenant)
		if err != nil || !verified.OK || verified.Segments != want {
			t.Fatal("invalid archived chain", verified, err)
		}
	}
	// Competing Store instances with no process-local leader mutex: row locking
	// must cover the head read, object write, head update and deletion.
	cpLeaderElectorInstance = nil
	insert("parallel", "1")
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); prune(newAuditChainStore(p), "parallel") }()
	}
	wg.Wait()
	cpLeaderElectorInstance = leader
	n, _, err := newAuditChainStore(p).Next("parallel")
	if err != nil || n != 1 || count("parallel") != 0 {
		t.Fatal("parallel archive duplicated/lost rows", n, err)
	}
	old := retentionWriteContext(context.Background())
	leader.release()
	peer.tick()
	peer.release()
	leader.tick()
	insert("oldterm", "1")
	before, _ := p.Load()
	archiveThenPruneStream(old, p.db, retentionConfig{archive: arc, auditChain: newAuditChainStore(p)}, "oldterm", "audit", cutoff, time.Now())
	after, _ := p.Load()
	if !bytes.Equal(before, after) || count("oldterm") != 1 {
		t.Fatal("old term archived/deleted")
	}
	for _, mode := range []string{"put", "head", "commit"} {
		t.Run(mode, func(t *testing.T) {
			tenant := "refuse_" + mode
			insert(tenant, "1")
			chain := newAuditChainStore(p)
			if mode == "put" {
				arc.fail = true
			}
			if mode == "head" {
				if _, err := p.db.Exec(`CREATE FUNCTION reject_chain_update() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'reject head'; END $$; CREATE TRIGGER reject_chain_update BEFORE UPDATE ON cp_state_blobs FOR EACH ROW EXECUTE FUNCTION reject_chain_update()`); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "commit" {
				if _, err := p.db.Exec(`CREATE FUNCTION reject_delete_commit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'reject commit'; END $$; CREATE CONSTRAINT TRIGGER reject_delete_commit AFTER DELETE ON hot_events DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_delete_commit()`); err != nil {
					t.Fatal(err)
				}
			}
			before, _ := p.Load()
			prune(chain, tenant)
			after, _ := p.Load()
			if !bytes.Equal(before, after) || count(tenant) != 1 {
				t.Fatal("failure advanced head or erased hot rows")
			}
			if mode == "head" {
				p.db.Exec(`DROP TRIGGER reject_chain_update ON cp_state_blobs; DROP FUNCTION reject_chain_update()`)
			}
			if mode == "commit" {
				p.db.Exec(`DROP TRIGGER reject_delete_commit ON hot_events; DROP FUNCTION reject_delete_commit()`)
			}
			arc.fail = false
			if mode == "put" {
				prune(chain, tenant)
				if count(tenant) != 0 {
					t.Fatal("put retry failed")
				}
			} else {
				puts := arc.puts
				prune(chain, tenant)
				prune(newAuditChainStore(p), tenant)
				if count(tenant) != 1 || arc.puts != puts {
					t.Fatal("orphan silently continued after retry/reload")
				}
			}
		})
	}
}

type lockedAuditArchive struct {
	mu sync.Mutex
	fakeArchive
	fail bool
	puts int
}

func (a *lockedAuditArchive) Put(ctx context.Context, key string, r io.Reader, size int64, opts archive.PutOptions) (archive.PutResult, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.puts++
	if a.fail {
		return archive.PutResult{}, fmt.Errorf("refused PUT")
	}
	return a.fakeArchive.Put(ctx, key, r, size, opts)
}
func (a *lockedAuditArchive) Get(ctx context.Context, key string) (io.ReadCloser, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.fakeArchive.Get(ctx, key)
}
func (a *lockedAuditArchive) List(ctx context.Context, prefix string, limit int) ([]archive.ObjectInfo, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.fakeArchive.List(ctx, prefix, limit)
}

func TestAuditChainSharedReadAndCommitFailures(t *testing.T) {
	p := &retentionReadFailure{transactionalCAFixture: &transactionalCAFixture{}}
	s := newAuditChainStore(p)
	if err := s.Commit("a", 0, hashObjectBytes([]byte("first"))); err != nil {
		t.Fatal(err)
	}
	valid, _ := p.Load()
	p.failRead = true
	if s.Health() == nil {
		t.Fatal("shared read failure reported healthy")
	}
	if _, _, err := s.Next("a"); err == nil {
		t.Fatal("stale head returned after read failure")
	}
	p.failRead = false
	for _, raw := range [][]byte{nil, []byte(`null`), []byte(`broken`)} {
		p.Save(raw)
		if s.Health() == nil {
			t.Fatal("missing/corrupt shared head accepted")
		}
		if _, _, err := s.Next("a"); err == nil {
			t.Fatal("missing/corrupt head used")
		}
	}
	p.Save(valid)
	if n, _, err := s.Next("a"); err != nil || n != 1 {
		t.Fatal("checked read did not recover")
	}
	p.failCommit = true
	if err := s.Commit("a", 1, hashObjectBytes([]byte("next"))); err == nil {
		t.Fatal("unconfirmed commit accepted")
	}
	after, _ := p.Load()
	if !bytes.Equal(valid, after) {
		t.Fatal("failed commit changed head")
	}
	p.failCommit = false
	if _, _, err := s.Next("a"); err == nil {
		t.Fatal("unconfirmed advance lost reconciliation latch")
	}
}
