package nhi

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/blobstore"
)

type uncertainSavePersister struct {
	blobstore.FilePersister
	err   error
	saves int
}

func (p *uncertainSavePersister) Save(b []byte) error {
	p.saves++
	if e := p.FilePersister.Save(b); e != nil {
		return e
	}
	return p.err
}
func TestUnconfirmedSaveCannotReportSuccess(t *testing.T) {
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
			p := &uncertainSavePersister{FilePersister: blobstore.FilePersister{Path: filepath.Join(t.TempDir(), "state.json")}}
			s := NewStore()
			if e := s.SetPersister(p); e != nil {
				t.Fatal(e)
			}
			candidate := testIdentity("target")
			_, err := s.Upsert(context.Background(), candidate, "tenant_a", time.Now())
			if err != nil {
				t.Fatal(err)
			}
			candidate.Status = "revoked"
			mutate := func() error { _, err := s.Upsert(context.Background(), candidate, "tenant_a", time.Now()); return err }
			view := func(s *Store) string { rows, _ := s.List(context.Background(), "tenant_a"); return rows[0].Status }
			gen := s.ConfigGeneration()
			p.err = tc.err
			for attempt := 0; attempt < 2; attempt++ {
				n := p.saves
				err := mutate()
				if tc.confirmed {
					if err != nil {
						t.Fatal(err)
					}
				} else {
					if err == nil {
						t.Fatal("unconfirmed save reported success")
					}
					if p.saves != n+1 {
						t.Fatal("retry skipped persistence")
					}
				}
				want := "revoked"
				if !tc.confirmed {
					want = "active"
				}
				if view(s) != want {
					t.Fatal("wrong live state", view(s), want)
				}
				if !tc.confirmed && s.ConfigGeneration() != gen {
					t.Fatal("unconfirmed generation advanced")
				}
			}
			// A rejected acknowledgement is not evidence that the candidate never reached disk.
			loaded := NewStore()
			if e := loaded.SetPersister(p); e != nil {
				t.Fatal(e)
			}
			if view(loaded) != "revoked" {
				t.Fatal("fixture did not replace candidate")
			}
			p.err = nil
			if e := mutate(); e != nil {
				t.Fatal(e)
			}
			loaded = NewStore()
			if e := loaded.SetPersister(p); e != nil {
				t.Fatal(e)
			}
			if view(loaded) != "revoked" {
				t.Fatal("retry not durable")
			}
		})
	}
}
