package device

import (
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
			s := NewStore()
			if e := s.SetPersister(p); e != nil {
				t.Fatal(e)
			}
			if _, err := s.Register(testDevice("target"), model.PolicyBundle{}, time.Now()); err != nil {
				t.Fatal(err)
			}
			mutate := func() error {
				_, _, _, err := s.ApplyRiskSignal("target", model.RiskSignal{EntityID: "target", Severity: "high", Source: "test"}, time.Now())
				return err
			}
			view := func(s *Store) string {
				d, _ := s.Get("target")
				if b, _ := d.Metadata["admin_high_risk"].(bool); b {
					return "high"
				}
				return "normal"
			}

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
				if view(s) != "high" {
					t.Fatal("applied live risk lost", view(s))
				}

			}
			// A rejected acknowledgement is not evidence that the candidate never reached disk.
			loaded := NewStore()
			if e := loaded.SetPersister(p); e != nil {
				t.Fatal(e)
			}
			if view(loaded) != "high" {
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
			if view(loaded) != "high" {
				t.Fatal("retry not durable")
			}
		})
	}
}
