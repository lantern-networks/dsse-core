package idpregistry

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
)

type sharedMemory struct {
	mu   sync.Mutex
	raw  []byte
	fail bool
}

func (p *sharedMemory) Load() ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]byte(nil), p.raw...), nil
}
func (p *sharedMemory) Save(b []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.fail {
		return errors.New("save failed")
	}
	p.raw = append([]byte(nil), b...)
	return nil
}
func (p *sharedMemory) UpdateContext(ctx context.Context, f func([]byte) ([]byte, error)) error {
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
		return errors.New("save failed")
	}
	p.raw = b
	return nil
}
func TestSharedIdPPreservesPeerDefaultAndSecret(t *testing.T) {
	p := &sharedMemory{}
	a, b := NewStore(), NewStore()
	a.SetPersister(p)
	b.SetPersister(p)
	c := sampleConn("own", "a")
	c.ClientSecret = "new-secret"
	if _, e := b.Upsert(c); e != nil {
		t.Fatal(e)
	}
	if _, e := b.Upsert(sampleConn("other", "keep")); e != nil {
		t.Fatal(e)
	}
	if _, e := a.Upsert(sampleConn("own", "a")); e != nil {
		t.Fatal(e)
	}
	r := NewStore()
	if e := r.SetPersister(p); e != nil {
		t.Fatal(e)
	}
	got, _ := r.Get("own", "a")
	if got.ClientSecret != "new-secret" {
		t.Fatal("stale edit erased peer secret")
	}
	if _, ok := r.Get("other", "keep"); !ok {
		t.Fatal("stale edit erased foreign tenant")
	}
	b.Upsert(sampleConn("own", "b"))
	b.SetDefault("own", "b")
	if _, e := a.Delete("own", "b"); e == nil {
		t.Fatal("stale delete bypassed latest default guard")
	}
	if _, e := a.Delete("own", "a"); e != nil {
		t.Fatal(e)
	}
	r.SetPersister(p)
	d, ok := r.Default("own")
	if !ok || d.IdPID != "b" {
		t.Fatal("peer default lost")
	}
	p.fail = true
	if _, e := a.Upsert(sampleConn("own", "failed")); !errors.Is(e, ErrPersistence) {
		t.Fatal(e)
	}
	p.fail = false
	if _, e := b.Upsert(sampleConn("own", "next")); e != nil {
		t.Fatal(e)
	}
	r.SetPersister(p)
	if _, ok := r.Get("own", "failed"); ok {
		t.Fatal("failed candidate revived")
	}
}
func TestIdPAttachmentRejectsPartialSnapshot(t *testing.T) {
	s := NewStore()
	good := &sharedMemory{}
	s.SetPersister(good)
	s.Upsert(sampleConn("own", "a"))
	for _, raw := range []string{`null`, `{}`, `{"connections":{},"defaults":{"own":"missing"}}`} {
		bad := &sharedMemory{raw: []byte(raw)}
		if e := s.SetPersister(bad); e == nil {
			t.Fatalf("accepted %s", raw)
		}
		if _, e := s.Upsert(sampleConn("own", "b")); e != nil {
			t.Fatal(e)
		}
		var snap persistedRegistry
		json.Unmarshal(good.raw, &snap)
		if _, ok := snap.Connections["own"]["b"]; !ok {
			t.Fatal("failed attachment switched writer")
		}
	}
}

func TestSharedIdPErasureUsesLatestRow(t *testing.T) {
	p := &sharedMemory{}
	a, b := NewStore(), NewStore()
	a.SetPersister(p)
	b.SetPersister(p)
	b.Upsert(sampleConn("erase", "later"))
	b.Upsert(sampleConn("foreign", "keep"))
	if n, err := a.RemoveTenantContext(context.Background(), "erase"); err != nil || n != 1 {
		t.Fatalf("erase latest %d %v", n, err)
	}
	r := NewStore()
	r.SetPersister(p)
	if _, ok := r.Get("foreign", "keep"); !ok {
		t.Fatal("erasure lost foreign")
	}
	if len(r.List("erase")) != 0 {
		t.Fatal("erasure missed peer record")
	}
	p.raw = nil
	if _, err := a.Upsert(sampleConn("own", "new")); !errors.Is(err, ErrPersistence) {
		t.Fatal("missing known authority accepted")
	}
}
