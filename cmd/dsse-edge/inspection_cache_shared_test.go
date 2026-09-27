package main

import (
	"context"
	"fmt"
	"github.com/lantern-networks/dsse-core/inspection"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestPostgresInspectionCacheSharedFlush(t *testing.T) {
	d, _, leader, peer := trustDistributionPostgresFixture(t)
	p := d.store.(postgresBlobPersister)
	p.key = "inspection_events"
	a, b := inspection.NewStore(0), inspection.NewStore(0)
	for _, s := range []*inspection.Store{a, b} {
		if e := s.SetPersister(p, 0); e != nil {
			t.Fatal(e)
		}
	}
	a.Upsert(model.InspectionEvent{ID: "a", TenantID: "a"})
	if e := a.PersistIfDirtyContext(captureCPWriteLease(context.Background())); e != nil {
		t.Fatal(e)
	}
	b.Upsert(model.InspectionEvent{ID: "b", TenantID: "b"})
	if e := b.PersistIfDirtyContext(captureCPWriteLease(context.Background())); e != nil {
		t.Fatal(e)
	}
	old := captureCPWriteLease(context.Background())
	leader.release()
	peer.tick()
	peer.release()
	leader.tick()
	before, _ := p.Load()
	a.Upsert(model.InspectionEvent{ID: "oldterm", TenantID: "a"})
	if a.PersistIfDirtyContext(old) == nil {
		t.Fatal("old term accepted")
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
		go func(i int) {
			defer wg.Done()
			s := inspection.NewStore(0)
			if e := s.SetPersister(p, 0); e != nil {
				errs <- e
				return
			}
			s.Upsert(model.InspectionEvent{ID: fmt.Sprint("parallel-", i), TenantID: "parallel"})
			errs <- s.PersistIfDirtyContext(context.Background())
		}(i)
	}
	wg.Wait()
	close(errs)
	cpLeaderElectorInstance = leader
	for e := range errs {
		if e != nil {
			t.Fatal(e)
		}
	}
	fresh := inspection.NewStore(0)
	if e := fresh.SetPersister(p, 0); e != nil || fresh.Count() != 11 {
		t.Fatal("lost parallel/peer event", fresh.Count(), e)
	}
	if _, e := p.db.Exec(`CREATE FUNCTION refuse_inspection_flush() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'refuse'; END $$; CREATE TRIGGER refuse_inspection_flush BEFORE UPDATE ON cp_state_blobs FOR EACH ROW EXECUTE FUNCTION refuse_inspection_flush()`); e != nil {
		t.Fatal(e)
	}
	before, _ = p.Load()
	a.Upsert(model.InspectionEvent{ID: "retry", TenantID: "a"})
	if a.PersistIfDirtyContext(captureCPWriteLease(context.Background())) == nil {
		t.Fatal("DB failure accepted")
	}
	after, _ = p.Load()
	if string(before) != string(after) {
		t.Fatal("refusal changed row")
	}
	if _, e := p.db.Exec(`DROP TRIGGER refuse_inspection_flush ON cp_state_blobs; DROP FUNCTION refuse_inspection_flush()`); e != nil {
		t.Fatal(e)
	}
	if e := a.PersistIfDirtyContext(captureCPWriteLease(context.Background())); e != nil {
		t.Fatal(e)
	}
	fresh = inspection.NewStore(0)
	if e := fresh.SetPersister(p, 0); e != nil || fresh.Count() != 12 {
		t.Fatal("retry/reload", fresh.Count(), e)
	}
}

func TestAdminSharedInspectionFailureDoesNotReturnCachedFindings(t *testing.T) {
	p := &transactionalCAFixture{}
	s := inspection.NewStore(0)
	if e := s.SetPersister(p, 0); e != nil {
		t.Fatal(e)
	}
	s.Upsert(model.InspectionEvent{ID: "cached", TenantID: testEvaluator().PolicyBundle.TenantID, FindingType: stringPtr("dlp_match"), Timestamp: time.Now().UTC().Format(time.RFC3339), Metadata: map[string]any{"dlp_action": "block", "dlp_identifier_types": []string{"email"}}})
	if e := s.PersistIfDirty(); e != nil {
		t.Fatal(e)
	}
	w, e := logs.NewWriter(filepath.Join(t.TempDir(), "logs"))
	if e != nil {
		t.Fatal(e)
	}
	defer w.Close()
	h := findingsTestHandler(t, w, nil, s)
	if r := findingsTestRead(h, ""); r.Code != 200 || !strings.Contains(r.Body.String(), "cached") {
		t.Fatal("finding missing", r.Code, r.Body.String())
	}
	good, _ := p.Load()
	p.Save([]byte(`null`))
	if r := findingsTestRead(h, ""); r.Code != 503 || strings.Contains(r.Body.String(), "cached") {
		t.Fatal("stale cache accepted", r.Code, r.Body.String())
	}
	p.Save(good)
	if r := findingsTestRead(h, ""); r.Code != 200 {
		t.Fatal("failed to recover", r.Code)
	}
}
