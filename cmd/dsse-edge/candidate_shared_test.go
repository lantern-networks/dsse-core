package main

import (
	"context"
	"errors"
	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/policycandidate"
	"sync"
	"testing"
	"time"
)

func TestPostgresCandidateSharedLifecycle(t *testing.T) {
	d, _, leader, peer := trustDistributionPostgresFixture(t)
	p := d.store.(postgresBlobPersister)
	p.key = "policy_candidates"
	a, b := policycandidate.NewStore(), policycandidate.NewStore()
	if e := a.SetPersister(p); e != nil {
		t.Fatal(e)
	}
	if e := b.SetPersister(p); e != nil {
		t.Fatal(e)
	}
	now := time.Now()
	ctx := candidateWriteContext(context.Background())
	c, e := a.ObserveCertPinFailure(ctx, "own", "named.example", "", 443, "pin", now)
	if e != nil {
		t.Fatal(e)
	}
	if _, _, e = a.Review(ctx, "own", c.CandidateID, policycandidate.ReviewRequest{Decision: "suppressed"}, now); e != nil {
		t.Fatal(e)
	}
	if _, e = b.ObserveCertPinFailure(ctx, "own", "named.example", "", 443, "pin", now); e != nil {
		t.Fatal(e)
	}
	if _, e = b.AddManualCertPinBypass(ctx, "peer", "other.example", now); e != nil {
		t.Fatal(e)
	}
	got, _, e := a.Get(ctx, "own", c.CandidateID)
	if e != nil || got.Status != "suppressed" || got.FailureCount != 2 {
		t.Fatal("peer review/count", got, e)
	}
	old := captureCPWriteLease(context.Background())
	leader.release()
	peer.tick()
	peer.release()
	leader.tick()
	if candidateWriteContext(old) != old {
		t.Fatal("observation recaptured old request term")
	}
	before, _ := p.Load()
	if _, _, e = a.Review(old, "own", c.CandidateID, policycandidate.ReviewRequest{Decision: "approved"}, now); !errors.Is(e, blobstore.ErrWriteNotCommitted) {
		t.Fatal("old review term", e)
	}
	if _, e = a.RemoveTenantContext(old, "peer"); !errors.Is(e, blobstore.ErrWriteNotCommitted) {
		t.Fatal("old erasure term", e)
	}
	after, _ := p.Load()
	if string(before) != string(after) {
		t.Fatal("old term changed row")
	}
	cpLeaderElectorInstance = nil
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s := policycandidate.NewStore()
			if e := s.SetPersister(p); e != nil {
				errs <- e
				return
			}
			_, e := s.ObserveCertPinFailure(context.Background(), "own", "named.example", "", 443, "pin", now)
			errs <- e
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
	got, _, e = a.Get(context.Background(), "own", c.CandidateID)
	if e != nil || got.FailureCount != 10 || got.Status != "suppressed" {
		t.Fatal("concurrent observations", got, e)
	}
	if _, e = p.db.Exec(`CREATE FUNCTION refuse_candidate() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'refused'; END $$; CREATE TRIGGER refuse_candidate BEFORE UPDATE ON cp_state_blobs FOR EACH ROW EXECUTE FUNCTION refuse_candidate()`); e != nil {
		t.Fatal(e)
	}
	ctx = captureCPWriteLease(context.Background())
	before, _ = p.Load()
	if _, _, e = a.Review(ctx, "own", c.CandidateID, policycandidate.ReviewRequest{Decision: "approved"}, now); !errors.Is(e, blobstore.ErrWriteNotCommitted) {
		t.Fatal("write failure", e)
	}
	after, _ = p.Load()
	if string(before) != string(after) {
		t.Fatal("failed row changed")
	}
	if _, e = p.db.Exec(`DROP TRIGGER refuse_candidate ON cp_state_blobs; DROP FUNCTION refuse_candidate()`); e != nil {
		t.Fatal(e)
	}
	if _, _, e = a.Review(ctx, "own", c.CandidateID, policycandidate.ReviewRequest{Decision: "approved"}, now); e != nil {
		t.Fatal(e)
	}
	if _, _, e = b.Materialize(ctx, "own", c.CandidateID, false, now); e != nil {
		t.Fatal(e)
	}
	if _, e = a.RemoveTenantContext(ctx, "own"); e != nil {
		t.Fatal(e)
	}
	if _, e = b.ObserveConnectorDiscovered(ctx, "peer", "app.example", 443, "web", "conn", "site", "ns", nil, now); e != nil {
		t.Fatal(e)
	}
	fresh := policycandidate.NewStore()
	if e = fresh.SetPersister(p); e != nil {
		t.Fatal(e)
	}
	own, e := fresh.List(ctx, "own", policycandidate.ListOptions{})
	if e != nil || own.Count != 0 {
		t.Fatal("resurrected", own, e)
	}
	other, e := fresh.List(ctx, "peer", policycandidate.ListOptions{})
	if e != nil || other.Count != 2 {
		t.Fatal("peer lost", other, e)
	}
	// A real COMMIT-time refusal is conservatively unclassified. Do not replay
	// observations or serve that store's old snapshot after the unknown outcome.
	if _, e = p.db.Exec(`CREATE FUNCTION refuse_candidate_commit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'refused commit'; END $$; CREATE CONSTRAINT TRIGGER refuse_candidate_commit AFTER UPDATE ON cp_state_blobs DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION refuse_candidate_commit()`); e != nil {
		t.Fatal(e)
	}
	if _, e = b.ObserveCertPinFailure(ctx, "peer", "pin.example", "", 443, "pin", now); e == nil || errors.Is(e, blobstore.ErrWriteNotCommitted) {
		t.Fatal("commit classification", e)
	}
	if _, e = p.db.Exec(`DROP TRIGGER refuse_candidate_commit ON cp_state_blobs; DROP FUNCTION refuse_candidate_commit()`); e != nil {
		t.Fatal(e)
	}
	if _, e = b.List(ctx, "peer", policycandidate.ListOptions{}); !errors.Is(e, policycandidate.ErrUnavailable) {
		t.Fatal("unknown state read", e)
	}
	if _, e = b.ObserveCertPinFailure(ctx, "peer", "pin.example", "", 443, "pin", now); e == nil {
		t.Fatal("unknown increment replayed")
	}
}
