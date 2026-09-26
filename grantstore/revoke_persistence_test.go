package grantstore

import (
	"errors"
	"github.com/lantern-networks/dsse-core/blobstore"
	"path/filepath"
	"testing"
	"time"
)

type revokeSaveGate struct {
	blobstore.FilePersister
	fail  bool
	saves int
}

func (p *revokeSaveGate) Save(b []byte) error {
	p.saves++
	if p.fail {
		return errors.New("private fixture unavailable")
	}
	return p.FilePersister.Save(b)
}
func TestScopedRevokePreservesDenialAndRetriesPersistence(t *testing.T) {
	now := time.Now()
	s := NewStore()
	p := &revokeSaveGate{FilePersister: blobstore.FilePersister{Path: filepath.Join(t.TempDir(), "grants.json")}}
	if e := s.SetPersister(p); e != nil {
		t.Fatal(e)
	}
	for _, g := range []Grant{{GrantID: "own-cookie", TenantID: "tenant"}, {GrantID: "foreign-cookie", TenantID: "Tenant"}} {
		if _, e := s.Mint(g, time.Hour, now); e != nil {
			t.Fatal(e)
		}
	}
	gen := s.ConfigGeneration()
	before, _ := p.Load()
	p.fail = true
	if _, found, e := s.RevokeForTenant("tenant", "foreign-cookie"); e != nil || found {
		t.Fatal("case-folded tenant revocation")
	}
	for i := 0; i < 2; i++ {
		saves := p.saves
		g, found, e := s.RevokeForTenant("tenant", "own-cookie")
		if !found || !g.Revoked || !errors.Is(e, ErrPersistence) || s.Valid("own-cookie", now) || p.saves != saves+1 {
			t.Fatalf("retry: %+v %v %v", g, found, e)
		}
		if s.ConfigGeneration() != gen+1 {
			t.Fatal("repeated denial changed generation")
		}
	}
	after, _ := p.Load()
	if string(before) != string(after) {
		t.Fatal("refused save changed disk")
	}
	reload := NewStore()
	if e := reload.SetPersister(p); e != nil {
		t.Fatal(e)
	}
	if !reload.Valid("own-cookie", now) {
		t.Fatal("fixture must demonstrate older saved approval until retry")
	}
	p.fail = false
	if _, found, e := s.RevokeForTenant("tenant", "own-cookie"); e != nil || !found {
		t.Fatal(e)
	}
	reload = NewStore()
	if e := reload.SetPersister(p); e != nil {
		t.Fatal(e)
	}
	if reload.Valid("own-cookie", now) || !reload.Valid("foreign-cookie", now) {
		t.Fatal("retry or isolation lost on restart")
	}
}
