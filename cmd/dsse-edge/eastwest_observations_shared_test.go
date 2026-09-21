package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/eastwestobserve"
	"github.com/lantern-networks/dsse-core/policy"
)

func TestPostgresObservationsSharedFlush(t *testing.T) {
	d, _, leader, peer := trustDistributionPostgresFixture(t)
	p := d.store.(postgresBlobPersister)
	p.key = "east_west_observations"
	a, b := eastwestobserve.NewStore(), eastwestobserve.NewStore()
	a.SetPersister(p, 0)
	b.SetPersister(p, 0)
	now := time.Now().UTC()
	a.Observe("a", "dev", "alice", "host", "ssh", 22, now)
	if e := a.PersistIfDirtyContext(captureCPWriteLease(context.Background())); e != nil {
		t.Fatal(e)
	}
	b.Observe("a", "dev", "bob", "host", "ssh", 22, now.Add(time.Second))
	b.Observe("b", "peer", "", "peer", "ssh", 22, now)
	if e := b.PersistIfDirtyContext(captureCPWriteLease(context.Background())); e != nil {
		t.Fatal(e)
	}
	old := captureCPWriteLease(context.Background())
	leader.release()
	peer.tick()
	peer.release()
	leader.tick()
	before, _ := p.Load()
	a.Observe("a", "dev", "bob", "host", "ssh", 22, now.Add(time.Second))
	if e := a.PersistIfDirtyContext(old); e == nil || !errors.Is(e, blobstore.ErrWriteNotCommitted) {
		t.Fatal("old term classification", e)
	}
	after, _ := p.Load()
	if string(before) != string(after) {
		t.Fatal("old term changed row")
	}
	if e := a.PersistIfDirtyContext(captureCPWriteLease(context.Background())); e != nil {
		t.Fatal(e)
	}
	cpLeaderElectorInstance = nil
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s := eastwestobserve.NewStore()
			if e := s.SetPersister(p, 0); e != nil {
				errs <- e
				return
			}
			s.Observe("a", "dev", "bob", "host", "ssh", 22, now.Add(time.Second))
			errs <- s.PersistIfDirtyContext(context.Background())
		}()
	}
	wg.Wait()
	close(errs)
	cpLeaderElectorInstance = leader
	for e := range errs {
		if e != nil {
			t.Fatal(e)
		}
	}
	fresh := eastwestobserve.NewStore()
	if e := fresh.SetPersister(p, 0); e != nil || fresh.List("a")[0].Count != 11 || len(fresh.List("b")) != 1 {
		t.Fatal("parallel count/peer lost", e, fresh.List("a"))
	}
	if _, e := p.db.Exec(`CREATE FUNCTION refuse_observation_flush() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'refuse'; END $$; CREATE TRIGGER refuse_observation_flush BEFORE UPDATE ON cp_state_blobs FOR EACH ROW EXECUTE FUNCTION refuse_observation_flush()`); e != nil {
		t.Fatal(e)
	}
	a.Observe("a", "dev", "bob", "host", "ssh", 22, now.Add(time.Second))
	before, _ = p.Load()
	if e := a.PersistIfDirtyContext(captureCPWriteLease(context.Background())); !errors.Is(e, blobstore.ErrWriteNotCommitted) {
		t.Fatal("write refusal classification", e)
	}
	after, _ = p.Load()
	if string(before) != string(after) {
		t.Fatal("refused row changed")
	}
	if _, e := p.db.Exec(`DROP TRIGGER refuse_observation_flush ON cp_state_blobs; DROP FUNCTION refuse_observation_flush()`); e != nil {
		t.Fatal(e)
	}
	if e := a.PersistIfDirtyContext(captureCPWriteLease(context.Background())); e != nil {
		t.Fatal(e)
	}
	fresh = eastwestobserve.NewStore()
	if e := fresh.SetPersister(p, 0); e != nil || fresh.List("a")[0].Count != 12 {
		t.Fatal("retry count", e)
	}
	// A deferred trigger fails inside COMMIT, which must remain unclassified.
	if _, e := p.db.Exec(`CREATE FUNCTION refuse_observation_commit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'commit refusal'; END $$; CREATE CONSTRAINT TRIGGER refuse_observation_commit AFTER UPDATE ON cp_state_blobs DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION refuse_observation_commit()`); e != nil {
		t.Fatal(e)
	}
	before, _ = p.Load()
	a.Observe("a", "dev", "bob", "host", "ssh", 22, now.Add(time.Second))
	if e := a.PersistIfDirtyContext(captureCPWriteLease(context.Background())); e == nil || errors.Is(e, blobstore.ErrWriteNotCommitted) {
		t.Fatal("COMMIT failure classified as safe retry", e)
	}
	after, _ = p.Load()
	if string(before) != string(after) {
		t.Fatal("deferred refusal changed row")
	}
	if _, e := p.db.Exec(`DROP TRIGGER refuse_observation_commit ON cp_state_blobs; DROP FUNCTION refuse_observation_commit()`); e != nil {
		t.Fatal(e)
	}
	if a.PersistIfDirtyContext(captureCPWriteLease(context.Background())) == nil || a.RefreshShared() == nil {
		t.Fatal("uncertain additive commit replayed")
	}
	after, _ = p.Load()
	if string(before) != string(after) {
		t.Fatal("uncertain retry changed row")
	}

}
func TestSharedObservationUnavailableBlocksListAndAdoption(t *testing.T) {
	p := &transactionalCAFixture{}
	s := eastwestobserve.NewStore()
	s.SetPersister(p, 0)
	s.Observe("a", "dev", "", "host", "ssh", 22, time.Now())
	if e := s.PersistIfDirty(); e != nil {
		t.Fatal(e)
	}
	p.Save([]byte(`null`))
	mux := http.NewServeMux()
	identity := func(_ string, h http.HandlerFunc) http.HandlerFunc { return h }
	policies := policy.NewStore(nil)
	registerEastWestRoutes(mux, identity, policies, nil, nil, s, "")
	registerEffectivePolicyRoutes(mux, identity, serverConfig{EastWestObserveStore: s}, testEvaluator(), nil, policies, nil, nil, nil, func() { t.Fatal("unavailable inventory reached compiler") })
	for _, method := range []string{"GET", "POST"} {
		path := "/admin/east-west/observations"
		if method == "POST" {
			path += "/adopt"
		}
		req := httptest.NewRequest(method, path, strings.NewReader(`{"observation_ids":["one"]}`))
		out := httptest.NewRecorder()
		mux.ServeHTTP(out, req)
		if out.Code != 503 || strings.Contains(out.Body.String(), "host") {
			t.Fatal(fmt.Sprint(method, out.Code, out.Body.String()))
		}
	}
}
