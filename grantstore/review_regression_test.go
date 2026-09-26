package grantstore

import (
	"encoding/json"
	"errors"
	"testing"
	"time"
)

type countedShared struct {
	grantSharedFixture
	loads int
}

func (p *countedShared) Load() ([]byte, error) { p.loads++; return p.grantSharedFixture.Load() }
func TestAuthorizationReadsBoundSharedLoads(t *testing.T) {
	p := &countedShared{}
	s := NewStore()
	if e := s.SetPersister(p); e != nil {
		t.Fatal(e)
	}
	now := time.Now()
	s.Mint(grantFixture("one", now), time.Hour, now)
	p.loads = 0
	for i := 0; i < 100; i++ {
		if !s.ValidForAuthorization("one", now) {
			t.Fatal("missing grant")
		}
		if len(s.ListForAuthorization("tenant")) != 1 {
			t.Fatal("missing list")
		}
	}
	if p.loads != 1 {
		t.Fatalf("loads=%d", p.loads)
	}
	p.loadFail = true
	s.readRefreshAt = time.Time{}
	if s.ValidForAuthorization("one", now) {
		t.Fatal("failed refresh allowed cached grant")
	}
	if p.loads != 2 {
		t.Fatal("refresh not attempted")
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
