package policycandidate

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"github.com/lantern-networks/dsse-core/blobstore"
	"sync"
	"testing"
	"time"
)

type candidateSharedFixture struct {
	mu                     sync.Mutex
	data                   []byte
	fail, unknown, badRead bool
}

func (p *candidateSharedFixture) Load() ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.badRead {
		return nil, fmt.Errorf("read refused")
	}
	return bytes.Clone(p.data), nil
}
func (p *candidateSharedFixture) Save(b []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.data = bytes.Clone(b)
	return nil
}
func (p *candidateSharedFixture) UpdateContext(ctx context.Context, f func([]byte) ([]byte, error)) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if e := ctx.Err(); e != nil {
		return e
	}
	b, e := f(p.data)
	if e != nil {
		return e
	}
	if p.fail {
		return fmt.Errorf("%w: refused", blobstore.ErrWriteNotCommitted)
	}
	p.data = bytes.Clone(b)
	if p.unknown {
		return fmt.Errorf("commit response lost")
	}
	return nil
}
func TestSharedCandidatePreservesPeerReview(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	p := &candidateSharedFixture{}
	a, b := NewStore(), NewStore()
	if e := a.SetPersister(p); e != nil {
		t.Fatal(e)
	}
	if e := b.SetPersister(p); e != nil {
		t.Fatal(e)
	}
	c, e := a.ObserveCertPinFailure(ctx, "own", "named.example", "", 443, "pin", now)
	if e != nil {
		t.Fatal(e)
	}
	if _, _, e = a.Review(ctx, "own", c.CandidateID, ReviewRequest{Decision: "suppressed"}, now); e != nil {
		t.Fatal(e)
	}
	if _, e = b.ObserveCertPinFailure(ctx, "own", "named.example", "", 443, "pin", now); e != nil {
		t.Fatal(e)
	}
	if _, e = b.ObserveUnmatchedFlow(ctx, "peer", "other.example", "", 443, "", now); e != nil {
		t.Fatal(e)
	}
	fresh := NewStore()
	if e = fresh.SetPersister(p); e != nil {
		t.Fatal(e)
	}
	got, ok, e := fresh.Get(ctx, "own", c.CandidateID)
	if e != nil || !ok || got.Status != "suppressed" || got.FailureCount != 2 {
		t.Fatalf("peer review/count lost: %+v %v", got, e)
	}
	if _, e = a.RemoveTenant("own"); e != nil {
		t.Fatal(e)
	}
	if _, e = b.ObserveConnectorDiscovered(ctx, "peer", "discovery.example", 443, "web", "conn", "site", "ns", nil, now); e != nil {
		t.Fatal(e)
	}
	fresh = NewStore()
	if e = fresh.SetPersister(p); e != nil {
		t.Fatal(e)
	}
	own, _ := fresh.List(ctx, "own", ListOptions{})
	peer, _ := fresh.List(ctx, "peer", ListOptions{})
	if own.Count != 0 || peer.Count != 2 {
		t.Fatalf("erasure resurrected or peer lost: %d %d", own.Count, peer.Count)
	}
}

func TestSharedCandidateLifecycleRefusalAndCurrentRead(t *testing.T) {
	for _, op := range []string{"upsert", "review", "manual", "materialize", "observe", "dns", "learning", "discovery", "erase"} {
		t.Run(op, func(t *testing.T) {
			ctx := context.Background()
			now := time.Now()
			p := &candidateSharedFixture{}
			a, b := NewStore(), NewStore()
			if e := a.SetPersister(p); e != nil {
				t.Fatal(e)
			}
			if e := b.SetPersister(p); e != nil {
				t.Fatal(e)
			}
			c, e := a.AddManualCertPinBypass(ctx, "own", "named.example", now)
			if e != nil {
				t.Fatal(e)
			}
			peer, e := a.ObserveUnmatchedFlow(ctx, "peer", "other.example", "", 443, "", now)
			if e != nil {
				t.Fatal(e)
			}
			mutate := func() error {
				var e error
				switch op {
				case "upsert":
					c.Status = "rejected"
					_, e = b.Upsert(ctx, c, "own", now)
				case "review":
					_, _, e = b.Review(ctx, "own", c.CandidateID, ReviewRequest{Decision: "rejected"}, now)
				case "manual":
					_, e = b.AddManualCertPinBypass(ctx, "own", "second.example", now)
				case "materialize":
					_, _, e = b.Materialize(ctx, "own", c.CandidateID, false, now)
				case "observe":
					_, e = b.ObserveCertPinFailure(ctx, "own", "pin.example", "", 443, "pin", now)
				case "dns":
					_, e = b.ObserveCertPinFailureDNSCorrelated(ctx, "own", "dns.example", "192.0.2.1", 443, "pin", now)
				case "learning":
					_, e = b.ObserveUnmatchedFlow(ctx, "own", "learn.example", "", 443, "", now)
				case "discovery":
					_, e = b.ObserveConnectorDiscovered(ctx, "own", "discovery.example", 443, "web", "c", "s", "n", nil, now)
				case "erase":
					_, e = b.RemoveTenant("own")
				}
				return e
			}
			before, _ := p.Load()
			p.fail = true
			if e = mutate(); e == nil {
				t.Fatal("save refusal accepted")
			}
			after, _ := p.Load()
			if !bytes.Equal(before, after) {
				t.Fatal("refused write changed row")
			}
			p.fail = false
			if e = mutate(); e != nil {
				t.Fatal("retry", e)
			}
			got, found, e := b.Get(ctx, "peer", peer.CandidateID)
			if e != nil || !found || got.CandidateID != peer.CandidateID {
				t.Fatal("peer lost", e)
			}
			p.badRead = true
			if _, e = b.List(ctx, "own", ListOptions{}); e == nil {
				t.Fatal("stale list on failed read")
			}
			if _, _, e = b.Get(ctx, "own", c.CandidateID); e == nil {
				t.Fatal("stale get on failed read")
			}
			p.badRead = false
			if _, e = b.List(ctx, "own", ListOptions{}); e != nil {
				t.Fatal("read retry", e)
			}
		})
	}
}
func TestSharedCandidateUnknownCommitStopsReplay(t *testing.T) {
	ctx := context.Background()
	p := &candidateSharedFixture{}
	s := NewStore()
	if e := s.SetPersister(p); e != nil {
		t.Fatal(e)
	}
	p.unknown = true
	if _, e := s.ObserveCertPinFailure(ctx, "own", "named.example", "", 443, "pin", time.Now()); e == nil {
		t.Fatal("unknown commit accepted")
	}
	before, _ := p.Load()
	p.unknown = false
	if _, e := s.ObserveCertPinFailure(ctx, "own", "named.example", "", 443, "pin", time.Now()); e == nil {
		t.Fatal("replayed increment")
	}
	if _, e := s.List(ctx, "own", ListOptions{}); e == nil {
		t.Fatal("uncertain store read allowed")
	}
	if e := s.SetPersister(p); e == nil {
		t.Fatal("uncertain writer replaced")
	}
	after, _ := p.Load()
	if !bytes.Equal(before, after) {
		t.Fatal("row changed after unknown commit")
	}
	fresh := NewStore()
	if e := fresh.SetPersister(p); e != nil {
		t.Fatal(e)
	}
	rows, e := fresh.List(ctx, "own", ListOptions{})
	if e != nil || rows.Count != 1 || rows.Candidates[0].FailureCount != 1 {
		t.Fatal(rows, e)
	}
}
func TestSharedCandidateRejectsMissingInvalidAndCancelled(t *testing.T) {
	ctx := context.Background()
	p := &candidateSharedFixture{}
	s := NewStore()
	if e := s.SetPersister(p); e != nil {
		t.Fatal(e)
	}
	c, e := s.AddManualCertPinBypass(ctx, "own", "named.example", time.Now())
	if e != nil {
		t.Fatal(e)
	}
	for _, raw := range [][]byte{nil, []byte("null"), []byte(`{"own":null}`)} {
		p.data = bytes.Clone(raw)
		if _, e := s.List(ctx, "own", ListOptions{}); e == nil {
			t.Fatal("invalid shared read accepted")
		}
		if _, _, e := s.Review(ctx, "own", c.CandidateID, ReviewRequest{Decision: "approved"}, time.Now()); e == nil {
			t.Fatal("invalid shared row overwritten")
		}
		if !bytes.Equal(p.data, raw) {
			t.Fatal("invalid raw changed")
		}
	}
	p.data = []byte("{}")
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, e = s.AddManualCertPinBypass(cancelled, "own", "named.example", time.Now()); e == nil {
		t.Fatal("cancelled write accepted")
	}
	if string(p.data) != "{}" {
		t.Fatal("cancelled write changed row")
	}
}

// An unknown COMMIT stops the store. The stop must be observable (accessor and a
// dedicated error) so the Console does not advise a retry that cannot succeed.
func TestSharedCandidateUnknownCommitIsReportedAsReconciliation(t *testing.T) {
	ctx := context.Background()
	p := &candidateSharedFixture{}
	s := NewStore()
	if e := s.SetPersister(p); e != nil {
		t.Fatal(e)
	}
	if s.ReconciliationRequired() {
		t.Fatal("fresh store reports reconciliation")
	}
	p.unknown = true
	if _, err := s.ObserveUnmatchedFlow(ctx, "tenant_a", "unknown.example", "unknown.example", 443, "", time.Now()); err == nil {
		t.Fatal("unknown commit reported success")
	}
	if !s.ReconciliationRequired() {
		t.Fatal("unknown commit did not stop the store")
	}
	p.unknown = false
	_, err := s.ObserveUnmatchedFlow(ctx, "tenant_a", "other.example", "other.example", 443, "", time.Now())
	if !errors.Is(err, ErrReconciliationRequired) || !errors.Is(err, ErrPersistence) {
		t.Fatalf("stopped write not identified: %v", err)
	}
	if _, err := s.List(ctx, "tenant_a", ListOptions{}); !errors.Is(err, ErrReconciliationRequired) || !errors.Is(err, ErrUnavailable) {
		t.Fatalf("stopped read not identified: %v", err)
	}
}
