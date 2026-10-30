package grantstore

import (
	"encoding/json"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

type countedShared struct {
	grantSharedFixture
	loads atomic.Int64
}

func (p *countedShared) Load() ([]byte, error) { p.loads.Add(1); return p.grantSharedFixture.Load() }
func TestAuthorizationReadsBoundSharedLoads(t *testing.T) {
	p := &countedShared{}
	s := NewStore()
	if e := s.SetPersister(p); e != nil {
		t.Fatal(e)
	}
	now := time.Now()
	s.Mint(grantFixture("one", now), time.Hour, now)
	p.loads.Store(0)
	for i := 0; i < 100; i++ {
		if !s.ValidForAuthorization("one", now) {
			t.Fatal("missing grant")
		}
		if len(s.ListForAuthorization("tenant")) != 1 {
			t.Fatal("missing list")
		}
	}
	if p.loads.Load() != 0 {
		t.Fatalf("a confirmed local commit triggered redundant I/O: loads=%d", p.loads.Load())
	}
	p.mu.Lock()
	p.loadFail = true
	p.mu.Unlock()
	s.mu.Lock()
	s.readRefreshAt = time.Time{}
	s.mu.Unlock()
	if s.ValidForAuthorization("one", now) {
		t.Fatal("failed refresh allowed cached grant")
	}
	until := time.Now().Add(time.Second)
	for p.loads.Load() == 0 && time.Now().Before(until) {
		time.Sleep(time.Millisecond)
	}
	if p.loads.Load() != 1 {
		t.Fatal("single background refresh not attempted")
	}
	s.readRefreshMu.Lock()
	running := s.readRefreshRunning
	s.readRefreshMu.Unlock()
	for running && time.Now().Before(until) {
		time.Sleep(time.Millisecond)
		s.readRefreshMu.Lock()
		running = s.readRefreshRunning
		s.readRefreshMu.Unlock()
	}
	if s.ValidForAuthorization("one", now) {
		t.Fatal("failed refresh allowed cached grant")
	}
}

func TestCheckedAuthorizationReadSeparatesEmptyFromUnavailable(t *testing.T) {
	p := &grantSharedFixture{}
	s := NewStore()
	if err := s.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	if rows, err := s.ListForAuthorizationChecked("tenant"); err != nil || len(rows) != 0 {
		t.Fatalf("fresh empty authority: rows=%d err=%v", len(rows), err)
	}
	p.mu.Lock()
	p.loadFail = true
	p.mu.Unlock()
	s.mu.Lock()
	s.readRefreshAt = time.Time{}
	s.mu.Unlock()
	if rows, err := s.ListForAuthorizationChecked("tenant"); !errors.Is(err, ErrPersistence) || len(rows) != 0 {
		t.Fatalf("unavailable authority: rows=%d err=%v", len(rows), err)
	}
	if fresh, err := s.AuthorizationFreshChecked(Grant{}, "app:22"); fresh || !errors.Is(err, ErrPersistence) {
		t.Fatalf("unavailable freshness: fresh=%v err=%v", fresh, err)
	}
}
func TestConflictDoesNotBlockOtherGrantRevocation(t *testing.T) {
	for _, shared := range []bool{false, true} {
		s := NewStore()
		if shared {
			s.SetPersister(&grantSharedFixture{})
		}
		now := time.Now()
		g1, _ := s.Mint(grantFixture("one", now), time.Hour, now)
		g2, _ := s.Mint(grantFixture("two", now), time.Hour, now)
		g1.Scope = "different"
		g2.Revoked = true
		_, _, e := s.MergeChecked([]Grant{g1, g2}, now)
		if !errors.Is(e, ErrConflict) || s.Valid("two", now) || !s.Valid("one", now) {
			t.Fatalf("shared=%v err=%v", shared, e)
		}
	}
}
func TestLegacyInvalidGrantSkippedWithoutRewriting(t *testing.T) {
	now := time.Now()
	good := grantFixture("good", now)
	bad := grantFixture("bad", now)
	bad.ExpiresAt = "legacy-invalid"
	raw, _ := json.Marshal(map[string]Grant{"good": good, "bad": bad})
	p := &rejectedGrantLoader{data: raw}
	s := NewStore()
	if e := s.SetPersister(p); e != nil {
		t.Fatal(e)
	}
	if !s.Valid("good", now) || s.Valid("bad", now) || p.saves != 0 {
		t.Fatal("legacy load lost valid grant or rewrote storage")
	}
}
