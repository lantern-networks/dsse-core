package inspection

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/lantern-networks/dsse-core/model"
	"strings"
	"sync"
	"testing"
)

type sharedFixture struct {
	mu       sync.Mutex
	raw      []byte
	fail     bool
	failRead bool
}

func (p *sharedFixture) Load() ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.failRead {
		return nil, fmt.Errorf("read unavailable")
	}
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
	if err := ctx.Err(); err != nil {
		return err
	}
	b, e := f(p.raw)
	if e != nil {
		return e
	}
	if p.fail {
		return fmt.Errorf("commit refused")
	}
	p.raw = b
	return nil
}
func TestSharedInspectionPreservesPeerEvents(t *testing.T) {
	p := &sharedFixture{}
	a, b := NewStore(0), NewStore(0)
	for _, s := range []*Store{a, b} {
		if e := s.SetPersister(p, 0); e != nil {
			t.Fatal(e)
		}
	}
	a.Upsert(model.InspectionEvent{ID: "a", TenantID: "a"})
	if e := a.PersistIfDirty(); e != nil {
		t.Fatal(e)
	}
	b.Upsert(model.InspectionEvent{ID: "b", TenantID: "b"})
	if e := b.PersistIfDirty(); e != nil {
		t.Fatal(e)
	}
	raw, _ := p.Load()
	var snap storeSnapshot
	json.Unmarshal(raw, &snap)
	if len(snap.Events) != 2 {
		t.Fatal("stale writer erased peer finding")
	}
}

func TestSharedInspectionFailureRetryAndCheckedRefresh(t *testing.T) {
	p := &sharedFixture{}
	a, b := NewStore(0), NewStore(0)
	a.SetPersister(p, 0)
	b.SetPersister(p, 0)
	a.Upsert(model.InspectionEvent{ID: "a", TenantID: "a"})
	a.PersistIfDirty()
	b.Upsert(model.InspectionEvent{ID: "b", TenantID: "b"})
	p.fail = true
	before, _ := p.Load()
	if b.PersistIfDirty() == nil {
		t.Fatal("failure accepted")
	}
	after, _ := p.Load()
	if string(after) != string(before) {
		t.Fatal("failed flush changed row")
	}
	if e := b.RefreshShared(); e != nil {
		t.Fatal(e)
	}
	if len(b.ListByTenant("a")) != 1 || len(b.ListByTenant("b")) != 1 {
		t.Fatal("refresh lost peer or pending")
	}
	p.fail = false
	if e := b.PersistIfDirty(); e != nil {
		t.Fatal(e)
	}
	if e := a.RefreshShared(); e != nil {
		t.Fatal(e)
	}
	if a.Count() != 2 {
		t.Fatal("stale read")
	}
	valid, _ := p.Load()
	for _, bad := range [][]byte{nil, []byte(`null`), []byte(`{}`), []byte(`broken`), []byte(`{"events":{"a":{"id":"a","tenant_id":"a"}},"order":[]}`)} {
		p.Save(bad)
		a.Upsert(model.InspectionEvent{ID: "new", TenantID: "a"})
		if a.PersistIfDirty() == nil || a.RefreshShared() == nil {
			t.Fatal("invalid row accepted")
		}
		after, _ := p.Load()
		if string(after) != string(bad) {
			t.Fatal("invalid row overwritten")
		}
	}
	p.Save(valid)
	if e := a.PersistIfDirty(); e != nil {
		t.Fatal(e)
	}
	if a.Count() != 3 {
		t.Fatal("retry lost pending")
	}
	fresh := NewStore(0)
	if e := fresh.SetPersister(p, 0); e != nil || fresh.Count() != 3 {
		t.Fatal("reload", e)
	}
}
func TestSharedInspectionPendingIsIdempotentAndTenantBound(t *testing.T) {
	p := &sharedFixture{}
	s := NewStore(0)
	s.SetPersister(p, 0)
	s.Upsert(model.InspectionEvent{ID: "same", TenantID: "a"})
	s.PersistIfDirty()
	s.Upsert(model.InspectionEvent{ID: "same", TenantID: "a"})
	s.PersistIfDirty()
	if s.Count() != 1 {
		t.Fatal("duplicate retry")
	}
	before, _ := p.Load()
	s.Upsert(model.InspectionEvent{ID: "same", TenantID: "b"})
	if s.PersistIfDirty() == nil {
		t.Fatal("event ownership changed")
	}
	after, _ := p.Load()
	if string(before) != string(after) {
		t.Fatal("foreign finding overwritten")
	}
}
func TestSharedInspectionDoesNotResurrectCachedPeer(t *testing.T) {
	p := &sharedFixture{}
	s := NewStore(0)
	s.SetPersister(p, 0)
	s.Upsert(model.InspectionEvent{ID: "old", TenantID: "a"})
	s.PersistIfDirty()
	p.Save([]byte(`{"events":{},"order":[]}`))
	s.Upsert(model.InspectionEvent{ID: "new", TenantID: "b"})
	if e := s.PersistIfDirty(); e != nil {
		t.Fatal(e)
	}
	if s.Count() != 1 || len(s.ListByTenant("a")) != 0 {
		t.Fatal("cached event resurrected")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s.Upsert(model.InspectionEvent{ID: "later", TenantID: "b"})
	if s.PersistIfDirtyContext(ctx) == nil {
		t.Fatal("canceled flush committed")
	}
}

func TestSharedInspectionInitialReadFailureAndBound(t *testing.T) {
	p := &sharedFixture{failRead: true}
	s := NewStore(2)
	if s.SetPersister(p, 0) == nil {
		t.Fatal("initial read accepted")
	}
	p.failRead = false
	s.Upsert(model.InspectionEvent{ID: "one", TenantID: "a"})
	// A boot read failure is not knowledge of the row. With no row, the first
	// flush creates it from the unsaved observation instead of failing forever.
	if e := s.PersistIfDirty(); e != nil {
		t.Fatalf("absent row after a boot read failure blocked every flush: %v", e)
	}
	if !strings.Contains(string(p.raw), `"one"`) {
		t.Fatalf("unsaved observation not persisted: %s", p.raw)
	}
	for _, id := range []string{"two", "three"} {
		s.Upsert(model.InspectionEvent{ID: id, TenantID: "b"})
	}
	if e := s.PersistIfDirty(); e != nil {
		t.Fatal(e)
	}
	if s.Count() != 2 {
		t.Fatal("FIFO bound")
	}
	p.failRead = true
	if s.RefreshShared() == nil {
		t.Fatal("read failure accepted")
	}
	p.failRead = false
	fresh := NewStore(2)
	if e := fresh.SetPersister(p, 0); e != nil || fresh.Count() != 2 || len(fresh.ListByTenant("a")) != 0 {
		t.Fatal("bound reload", e)
	}
}
