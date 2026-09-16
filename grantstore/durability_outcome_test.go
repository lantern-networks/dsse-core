package grantstore

import (
	"encoding/json"
	"errors"
	"github.com/lantern-networks/dsse-core/blobstore"
	"testing"
	"time"
)

type outcomeWriter struct {
	data         []byte
	outcome      error
	saves, loads int
}

func (p *outcomeWriter) Load() ([]byte, error) { p.loads++; return append([]byte(nil), p.data...), nil }
func (p *outcomeWriter) Save(b []byte) error {
	p.saves++
	if p.outcome == nil || errors.Is(p.outcome, blobstore.ErrSavedWithoutAtomicity) {
		p.data = append([]byte(nil), b...)
	}
	return p.outcome
}

func TestGrantSaveOutcomesPreserveDenialAndRetryOnlyUnconfirmed(t *testing.T) {
	for _, tc := range []struct {
		name    string
		outcome error
		pending bool
	}{
		{"synced-in-place", blobstore.ErrSavedWithoutAtomicity, false},
		{"unconfirmed-flush", errors.Join(blobstore.ErrSavedWithoutAtomicity, blobstore.ErrDurabilityUnconfirmed), true},
		{"refused", errors.New("fixture rejected save"), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			now := time.Now()
			p := &outcomeWriter{}
			s := NewStore()
			if err := s.SetPersister(p); err != nil {
				t.Fatal(err)
			}
			g, err := s.Mint(grantFixture("one", now), time.Hour, now)
			if err != nil {
				t.Fatal(err)
			}
			p.outcome = tc.outcome
			revoked, found, err := s.RevokeForTenant(g.TenantID, g.GrantID)
			if !found || !revoked.Revoked || s.Valid(g.GrantID, now) || s.dirty != tc.pending || errors.Is(err, ErrPersistence) != tc.pending {
				t.Fatalf("outcome: found=%v grant=%+v err=%v dirty=%v", found, revoked, err, s.dirty)
			}
			if !tc.pending && !errors.Is(err, blobstore.ErrSavedWithoutAtomicity) {
				t.Fatalf("warning lost: %v", err)
			}
			saves, gen := p.saves, s.ConfigGeneration()
			_, _, err = s.MergeChecked([]Grant{g}, now)
			if tc.pending {
				if !errors.Is(err, ErrPersistence) || p.saves != saves+1 {
					t.Fatalf("missing retry: %v", err)
				}
			} else if err != nil || p.saves != saves {
				t.Fatal("synced write retried unnecessarily")
			}
			if s.ConfigGeneration() != gen {
				t.Fatal("retry changed generation")
			}
			p.outcome = nil
			if _, _, err = s.RevokeForTenant(g.TenantID, g.GrantID); err != nil {
				t.Fatal(err)
			}
			restarted := NewStore()
			if err = restarted.SetPersister(p); err != nil {
				t.Fatal(err)
			}
			if restarted.Valid(g.GrantID, now) || s.dirty {
				t.Fatal("revocation did not persist")
			}
			// Even an already revoked, previously clean grant needs a retry if a
			// later replacement cannot confirm its final flush.
			p.outcome = errors.Join(blobstore.ErrSavedWithoutAtomicity, blobstore.ErrDurabilityUnconfirmed)
			if _, _, err := s.RevokeForTenant(g.TenantID, g.GrantID); !errors.Is(err, ErrPersistence) || !s.dirty {
				t.Fatalf("clean revocation lost retry requirement: %v", err)
			}
		})
	}
}

func TestGrantPendingDenialRefusesWriterReplacementOrDetachment(t *testing.T) {
	now := time.Now()
	p := &outcomeWriter{}
	s := NewStore()
	if err := s.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	g, err := s.Mint(grantFixture("one", now), time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	old := append([]byte(nil), p.data...)
	p.outcome = errors.New("fixture rejected save")
	s.RevokeForTenant(g.TenantID, g.GrantID)
	gen := s.ConfigGeneration()
	for _, next := range []blobstore.Persister{nil, &outcomeWriter{data: old}, &outcomeWriter{data: []byte("{}")}, &outcomeWriter{}} {
		if err := s.SetPersister(next); !errors.Is(err, ErrPendingPersistence) {
			t.Fatalf("replacement allowed: %v", err)
		}
		if s.Valid(g.GrantID, now) || s.ConfigGeneration() != gen || s.persister != p || !s.dirty {
			t.Fatal("pending denial/writer changed")
		}
	}
	p.outcome = nil
	if _, _, err := s.RevokeForTenant(g.TenantID, g.GrantID); err != nil {
		t.Fatal(err)
	}
	next := &outcomeWriter{data: append([]byte(nil), p.data...)}
	if err := s.SetPersister(next); err != nil {
		t.Fatal(err)
	}
	if s.Valid(g.GrantID, now) {
		t.Fatal("denial lost after confirmed save")
	}
}

func TestGrantAdmissionRejectsUnconfirmedFlushButAcceptsSyncedInPlace(t *testing.T) {
	for _, mint := range []bool{false, true} {
		for _, uncertain := range []bool{false, true} {
			now := time.Now()
			p := &outcomeWriter{outcome: blobstore.ErrSavedWithoutAtomicity}
			if uncertain {
				p.outcome = errors.Join(p.outcome, blobstore.ErrDurabilityUnconfirmed)
			}
			s := NewStore()
			if err := s.SetPersister(p); err != nil {
				t.Fatal(err)
			}
			g := grantFixture("one", now)
			var err error
			if mint {
				_, err = s.Mint(g, time.Hour, now)
			} else {
				_, _, err = s.MergeChecked([]Grant{g}, now)
			}
			if errors.Is(err, ErrPersistence) != uncertain || s.Valid(g.GrantID, now) == uncertain {
				t.Fatalf("mint=%v uncertain=%v err=%v", mint, uncertain, err)
			}
			var saved map[string]Grant
			if e := json.Unmarshal(p.data, &saved); e != nil {
				t.Fatal(e)
			}
			if _, ok := saved[g.GrantID]; !ok {
				t.Fatal("fixture must complete replacement before reporting uncertainty")
			}
		}
	}
}
