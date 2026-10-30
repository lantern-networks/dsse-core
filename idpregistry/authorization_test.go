package idpregistry

import (
	"errors"
	"sync"
	"testing"
	"time"
)

type authReadAuthority struct {
	sharedMemory
	countMu sync.Mutex
	reads   int
	broken  bool
}

func (p *authReadAuthority) Load() ([]byte, error) {
	p.countMu.Lock()
	defer p.countMu.Unlock()
	p.reads++
	if p.broken {
		return nil, errors.New("offline")
	}
	return p.sharedMemory.Load()
}
func TestAuthorizationReadsCoalesceAndFailClosed(t *testing.T) {
	p := &authReadAuthority{}
	s := NewStore()
	if e := s.SetPersister(p); e != nil {
		t.Fatal(e)
	}
	if _, e := s.Upsert(sampleConn("own", "provider")); e != nil {
		t.Fatal(e)
	}
	p.countMu.Lock()
	before := p.reads
	p.countMu.Unlock()
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, ok := s.ResolveForAuthorization("own", ""); !ok {
				t.Error("missing provider")
			}
		}()
	}
	wg.Wait()
	p.countMu.Lock()
	delta := p.reads - before
	p.broken = true
	p.countMu.Unlock()
	if delta != 1 {
		t.Fatalf("pollers made %d authority reads", delta)
	}
	s.authReadMu.Lock()
	s.authReadAt = time.Time{}
	s.authReadMu.Unlock()
	if _, ok := s.ResolveForAuthorization("own", ""); ok {
		t.Fatal("authority error used stale provider")
	}
	p.countMu.Lock()
	p.broken = false
	p.countMu.Unlock()
	s.authReadMu.Lock()
	s.authReadAt = time.Time{}
	s.authReadMu.Unlock()
	if _, ok := s.ResolveForAuthorization("own", ""); !ok {
		t.Fatal("did not recover")
	}
	if _, err := s.Delete("own", "provider"); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.ResolveForAuthorization("own", ""); ok {
		t.Fatal("local deletion hidden by read coalescing")
	}
}
