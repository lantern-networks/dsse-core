package humanidentity

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/model"
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
			s := NewHumanIdentityDirectoryStore()
			if e := s.SetPersister(p); e != nil {
				t.Fatal(e)
			}
			candidate := model.HumanIdentity{ID: "target", Subject: "target", Status: "active", Source: "manual"}
			_, err := s.Upsert(context.Background(), candidate, "tenant_a", time.Now())
			if err != nil {
				t.Fatal(err)
			}
			candidate.Status = "deleted"
			mutate := func() error { _, err := s.Upsert(context.Background(), candidate, "tenant_a", time.Now()); return err }
			view := func(s *HumanIdentityDirectoryStore) string {
				rows, _ := s.List(context.Background(), "tenant_a")
				return rows[0].Status
			}
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
				want := "deleted"
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
			loaded := NewHumanIdentityDirectoryStore()
			if e := loaded.SetPersister(p); e != nil {
				t.Fatal(e)
			}
			if view(loaded) != "deleted" {
				t.Fatal("fixture did not replace candidate")
			}
			p.err = nil
			if e := mutate(); e != nil {
				t.Fatal(e)
			}
			loaded = NewHumanIdentityDirectoryStore()
			if e := loaded.SetPersister(p); e != nil {
				t.Fatal(e)
			}
			if view(loaded) != "deleted" {
				t.Fatal("retry not durable")
			}
		})
	}
}
