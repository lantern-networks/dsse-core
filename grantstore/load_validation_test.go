package grantstore

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

type rejectedGrantLoader struct {
	data  []byte
	err   error
	saves int
}

func (p *rejectedGrantLoader) Load() ([]byte, error) { return p.data, p.err }
func (p *rejectedGrantLoader) Save([]byte) error     { p.saves++; return nil }
func TestGrantLoadFailurePreservesStateAndWriter(t *testing.T) {
	now := time.Now().UTC()
	s := NewStore()
	path := filepath.Join(t.TempDir(), "grants.json")
	if e := s.SetStatePath(path); e != nil {
		t.Fatal(e)
	}
	g, _ := s.Mint(grantFixture("revoked", now), time.Hour, now)
	s.Revoke(g.GrantID)
	wrong, _ := json.Marshal(map[string]Grant{"wrong": g})
	badTime := g
	badTime.ExpiresAt = "not-time"
	bad, _ := json.Marshal(map[string]Grant{g.GrantID: badTime})
	for i, p := range []*rejectedGrantLoader{{err: errors.New("unavailable")}, {data: []byte{}}, {data: []byte("null")}, {data: []byte("{bad")}, {data: wrong}, {data: bad}} {
		snapshot := s.ListAll()
		gen := s.ConfigGeneration()
		if e := s.SetPersister(p); e == nil {
			t.Fatal("invalid snapshot accepted")
		}
		if !reflect.DeepEqual(snapshot, s.ListAll()) || gen != s.ConfigGeneration() {
			t.Fatal("failed load replaced state")
		}
		if _, e := s.Mint(grantFixture(fmt.Sprint("next-", i), now), time.Hour, now); e != nil {
			t.Fatal(e)
		}
		if p.saves != 0 {
			t.Fatal("rejected writer used")
		}
		reloaded := NewStore()
		if e := reloaded.SetStatePath(path); e != nil {
			t.Fatal(e)
		}
		if len(reloaded.ListAll()) != len(s.ListAll()) || reloaded.Valid("revoked", now) {
			t.Fatal("old writer or denial lost")
		}
	}
}
func TestGrantLoadAllowsMissingAndExplicitEmptySnapshots(t *testing.T) {
	s := NewStore()
	p := &rejectedGrantLoader{}
	if e := s.SetPersister(p); e != nil {
		t.Fatal(e)
	}
	if _, e := s.Mint(grantFixture("one", time.Now()), time.Hour, time.Now()); e != nil {
		t.Fatal(e)
	}
	if p.saves != 1 {
		t.Fatal("missing writer not attached")
	}
	if e := s.SetPersister(&rejectedGrantLoader{data: []byte("{}")}); e != nil || len(s.ListAll()) != 0 {
		t.Fatal("explicit empty snapshot refused")
	}
	if e := s.SetPersister(nil); e != nil {
		t.Fatal(e)
	}
}
