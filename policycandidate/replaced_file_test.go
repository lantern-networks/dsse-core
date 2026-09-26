package policycandidate

import (
	"context"
	"errors"
	"github.com/lantern-networks/dsse-core/blobstore"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

type replacementWriter struct {
	blobstore.FilePersister
	unconfirmed bool
}

func (p *replacementWriter) Save(raw []byte) error {
	if err := p.FilePersister.Save(raw); err != nil {
		return err
	}
	if p.unconfirmed {
		return blobstore.ErrDurabilityUnconfirmed
	}
	return nil
}

func TestReplacedCandidateMatchesReloadAndSurvivesNextEdit(t *testing.T) {
	ctx, now := context.Background(), time.Now()
	p := &replacementWriter{FilePersister: blobstore.FilePersister{Path: filepath.Join(t.TempDir(), "candidates.json")}}
	s := NewStore()
	if err := s.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	c, err := s.ObserveCertPinFailure(ctx, "own", "named.example", "", 443, "rejected", now)
	if err != nil {
		t.Fatal(err)
	}
	p.unconfirmed = true
	if _, _, err := s.Review(ctx, "own", c.CandidateID, ReviewRequest{Decision: "suppressed"}, now); !errors.Is(err, ErrPersistence) {
		t.Fatal("unconfirmed save acknowledged", err)
	}
	fresh := NewStore()
	if err := fresh.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	expected, _, err := fresh.Get(ctx, "own", c.CandidateID)
	if err != nil || expected.Status != "suppressed" {
		t.Fatal("replacement not saved", err)
	}
	live, _, _ := s.Get(ctx, "own", c.CandidateID)
	if !reflect.DeepEqual(live, expected) {
		t.Fatal("live/reload differ")
	}
	p.unconfirmed = false
	if _, err := s.ObserveCertPinFailure(ctx, "other", "other.example", "", 443, "rejected", now); err != nil {
		t.Fatal(err)
	}
	final := NewStore()
	if err := final.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	got, _, _ := final.Get(ctx, "own", c.CandidateID)
	if !reflect.DeepEqual(got, expected) {
		t.Fatal("next edit undid review")
	}
}
