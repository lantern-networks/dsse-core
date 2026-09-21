package eastwestobserve

import (
	"context"
	"fmt"
	"github.com/lantern-networks/dsse-core/blobstore"
	"sync"
	"testing"
	"time"
)

type sharedFixture struct {
	mu                                sync.Mutex
	raw                               []byte
	fail, committedError, failUnknown bool
}

func (p *sharedFixture) Load() ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]byte(nil), p.raw...), nil
}
func (p *sharedFixture) Save(b []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.raw = append([]byte(nil), b...)
	return nil
}
func (p *sharedFixture) UpdateContext(ctx context.Context, f func([]byte) ([]byte, error)) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if e := ctx.Err(); e != nil {
		return e
	}
	b, e := f(p.raw)
	if e != nil {
		return e
	}
	if p.failUnknown {
		return fmt.Errorf("unknown transaction outcome")
	}
	if p.fail {
		return fmt.Errorf("%w: refused", blobstore.ErrWriteNotCommitted)
	}
	p.raw = b
	if p.committedError {
		return fmt.Errorf("commit response lost")
	}
	return nil
}
func TestSharedObservationPreservesPeerCounts(t *testing.T) {
	p := &sharedFixture{}
	a, b := NewStore(), NewStore()
	a.SetPersister(p, 0)
	b.SetPersister(p, 0)
	now := time.Now()
	a.Observe("a", "dev", "alice", "host", "ssh", 22, now)
	a.PersistIfDirty()
	b.Observe("b", "dev", "", "peer", "ssh", 22, now)
	b.Observe("a", "dev", "bob", "host", "ssh", 22, now.Add(time.Second))
	if e := b.PersistIfDirty(); e != nil {
		t.Fatal(e)
	}
	fresh := NewStore()
	fresh.SetPersister(p, 0)
	got := fresh.List("a")
	if len(got) != 1 || got[0].Count != 2 || got[0].User != "bob" || len(fresh.List("b")) != 1 {
		t.Fatalf("peer count lost: %+v", got)
	}
}

func TestSharedObservationRefusalRetryAndRefresh(t *testing.T) {
	p := &sharedFixture{}
	a, b := NewStore(), NewStore()
	a.SetPersister(p, 0)
	b.SetPersister(p, 0)
	now := time.Now().UTC()
	a.Observe("a", "dev", "alice", "host", "ssh", 22, now)
	a.PersistIfDirty()
	b.Observe("a", "dev", "bob", "host", "ssh", 22, now.Add(time.Second))
	p.fail = true
	before, _ := p.Load()
	if b.PersistIfDirty() == nil {
		t.Fatal("refusal accepted")
	}
	after, _ := p.Load()
	if string(before) != string(after) {
		t.Fatal("row changed")
	}
	if e := b.RefreshShared(); e != nil || b.List("a")[0].Count != 2 {
		t.Fatal("pending view", e)
	}
	if e := b.RefreshShared(); e != nil || b.List("a")[0].Count != 2 {
		t.Fatal("refresh doubled pending", e)
	}
	a.Observe("peer", "d", "", "peer", "ssh", 22, now)
	p.fail = false
	a.PersistIfDirty()
	if e := b.PersistIfDirty(); e != nil {
		t.Fatal(e)
	}
	fresh := NewStore()
	fresh.SetPersister(p, 0)
	if fresh.List("a")[0].Count != 2 || len(fresh.List("peer")) != 1 {
		t.Fatal("lost pending or peer")
	}
}
func TestSharedObservationUncertainCommitStopsReplay(t *testing.T) {
	for _, commit := range []bool{false, true} {
		t.Run(fmt.Sprint(commit), func(t *testing.T) {
			p := &sharedFixture{}
			s := NewStore()
			s.SetPersister(p, 0)
			s.Observe("a", "dev", "", "host", "ssh", 22, time.Now())
			p.committedError = true
			p.failUnknown = !commit
			if s.PersistIfDirty() == nil {
				t.Fatal("uncertain accepted")
			}
			before, _ := p.Load()
			p.committedError = false
			p.failUnknown = false
			s.Observe("a", "dev", "", "host", "ssh", 22, time.Now())
			if s.PersistIfDirty() == nil || s.RefreshShared() == nil {
				t.Fatal("uncertain retry/read accepted")
			}
			after, _ := p.Load()
			if string(before) != string(after) {
				t.Fatal("uncertain count replayed")
			}
			if !s.dirty || len(s.sharedPending) == 0 {
				t.Fatal("pending lost")
			}
		})
	}
}
func TestSharedObservationInvalidAndMissingRows(t *testing.T) {
	p := &sharedFixture{}
	s := NewStore()
	s.SetPersister(p, 0)
	s.Observe("a", "dev", "", "host", "ssh", 22, time.Now())
	s.PersistIfDirty()
	valid, _ := p.Load()
	for _, raw := range [][]byte{nil, []byte(`null`), []byte(`broken`), []byte(`{"a":null}`), []byte(`{"a":{"bad":{"count":1}}}`)} {
		p.Save(raw)
		s.Observe("a", "new", "", "new", "ssh", 22, time.Now())
		if s.RefreshShared() == nil || s.PersistIfDirty() == nil {
			t.Fatal("bad row accepted")
		}
		got, _ := p.Load()
		if string(got) != string(raw) {
			t.Fatal("bad row replaced")
		}
	}
	p.Save(valid)
	if e := s.PersistIfDirty(); e != nil {
		t.Fatal("recovery", e)
	}
}
func TestSharedObservationDeltaMetadataAndNoResurrection(t *testing.T) {
	p := &sharedFixture{}
	s := NewStore()
	s.SetPersister(p, 0)
	now := time.Now().UTC()
	s.Observe("a", "d", "latest", "host", "ssh", 22, now)
	s.Observe("a", "d", "older", "host", "ssh", 22, now.Add(-time.Minute))
	if e := s.PersistIfDirty(); e != nil {
		t.Fatal(e)
	}
	got := s.List("a")[0]
	if got.Count != 2 || got.User != "latest" || got.FirstSeen != now.Add(-time.Minute).Format(time.RFC3339) {
		t.Fatal(got)
	}
	p.Save([]byte(`{}`))
	s.Observe("b", "other", "", "peer", "ssh", 22, now)
	if e := s.PersistIfDirty(); e != nil {
		t.Fatal(e)
	}
	if len(s.List("a")) != 0 {
		t.Fatal("peer removal resurrected")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s.Observe("b", "new", "", "new", "ssh", 22, now)
	if s.PersistIfDirtyContext(ctx) == nil {
		t.Fatal("canceled accepted")
	}
}
