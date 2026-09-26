package delegatedgrant

import (
	"errors"
	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/model"
	"path/filepath"
	"testing"
	"time"
)

type unconfirmedPersister struct {
	blobstore.FilePersister
	err   error
	saves int
}

func (p *unconfirmedPersister) Save(b []byte) error {
	p.saves++
	if e := p.FilePersister.Save(b); e != nil {
		return e
	}
	return p.err
}
func TestUnconfirmedRevokeIsNotSuccessful(t *testing.T) {
	for _, tc := range []struct {
		name      string
		err       error
		confirmed bool
	}{
		{"synced_nonatomic", blobstore.ErrSavedWithoutAtomicity, true},
		{"unconfirmed", blobstore.ErrDurabilityUnconfirmed, false},
		{"joined", errors.Join(blobstore.ErrSavedWithoutAtomicity, blobstore.ErrDurabilityUnconfirmed), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := &unconfirmedPersister{FilePersister: blobstore.FilePersister{Path: filepath.Join(t.TempDir(), "state.json")}}
			s := NewStore(0)
			if e := s.SetPersister(p); e != nil {
				t.Fatal(e)
			}
			if _, e := s.Upsert(model.DelegatedAccessGrant{ID: "one", TenantID: "tenant", ActorNHIID: "agent", SubjectUserID: "person", Status: "active", ExpiresAt: time.Now().Add(time.Hour).Format(time.RFC3339)}); e != nil {
				t.Fatal(e)
			}
			gen := s.ConfigGeneration()
			p.err = tc.err
			for attempt := 0; attempt < 2; attempt++ {
				before := p.saves
				_, e := s.RevokeForTenant("tenant", "one", "review", time.Now())
				if tc.confirmed {
					if e != nil {
						t.Fatal(e)
					}
				} else {
					if !errors.Is(e, ErrPersistence) {
						t.Fatalf("unconfirmed revoke reported success: %v", e)
					}
					if p.saves != before+1 {
						t.Fatal("retry skipped save")
					}
				}
				g, _ := s.GetForTenant("tenant", "one")
				want := "revoked"
				if tc.confirmed {
					want = "revoked"
				}
				if g.Status != want {
					t.Fatal("wrong live state")
				}
				if !tc.confirmed && s.ConfigGeneration() != gen+1 {
					t.Fatal("local denial did not advance generation")
				}
			}
			// The candidate bytes were replaced before the error: neither error means disk stayed unchanged.
			loaded := NewStore(0)
			if e := loaded.SetPersister(p); e != nil {
				t.Fatal(e)
			}
			g, _ := loaded.GetForTenant("tenant", "one")
			if g.Status != "revoked" {
				t.Fatal("fixture did not replace saved candidate")
			}
			p.err = nil
			_, e := s.RevokeForTenant("tenant", "one", "review", time.Now())
			if e != nil {
				t.Fatal(e)
			}
			loaded = NewStore(0)
			if e := loaded.SetPersister(p); e != nil {
				t.Fatal(e)
			}
			g, _ = loaded.GetForTenant("tenant", "one")
			if g.Status != "revoked" {
				t.Fatal("confirmed retry missing")
			}
		})
	}
}
