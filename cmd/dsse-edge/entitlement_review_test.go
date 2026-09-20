package main

import (
	"context"
	"errors"
	"github.com/lantern-networks/dsse-core/blobstore"
	"testing"
)

type entitlementReviewFile struct {
	raw     []byte
	saveErr error
}

func (p *entitlementReviewFile) Load() ([]byte, error) { return p.raw, nil }
func (p *entitlementReviewFile) Save(raw []byte) error {
	p.raw = append([]byte{}, raw...)
	return p.saveErr
}

type entitlementReviewShared struct{ entitlementReviewFile }

func (p *entitlementReviewShared) UpdateContext(_ context.Context, edit func([]byte) ([]byte, error)) error {
	raw, err := edit(p.raw)
	if err != nil {
		return err
	}
	return p.Save(raw)
}

func TestEntitlementMissingSharedAuthorityKeepsAcknowledgedState(t *testing.T) {
	for _, missing := range [][]byte{nil, {}} {
		p := &entitlementReviewShared{entitlementReviewFile{raw: []byte(`{"features":{"one":{"dlp":true}}}`)}}
		s := newEntitlementStore(nil)
		if err := s.SetPersister(p); err != nil {
			t.Fatal(err)
		}
		p.raw = missing
		if err := s.RefreshShared(); err == nil {
			t.Fatal("missing authority silently cleared grants")
		}
		if !s.Entitled("one", featureDLP) {
			t.Fatal("missing authority changed live")
		}
		if err := s.SetFeaturesContext(context.Background(), "two", map[string]bool{featureDLP: true}); err == nil {
			t.Fatal("write recreated missing authority and erased peer grants")
		}
		p.raw = []byte(`{"features":{}}`)
		if err := s.RefreshShared(); err != nil {
			t.Fatal(err)
		}
		if s.Entitled("one", featureDLP) {
			t.Fatal("explicit empty authority not adopted")
		}
	}
}

func TestEntitlementWeakSaveAndUnconfirmedDurability(t *testing.T) {
	for _, tc := range []struct {
		name     string
		err      error
		accepted bool
	}{
		{"confirmed in place", blobstore.ErrSavedWithoutAtomicity, true},
		{"not flushed", blobstore.ErrDurabilityUnconfirmed, false},
		{"both warnings", errors.Join(blobstore.ErrSavedWithoutAtomicity, blobstore.ErrDurabilityUnconfirmed), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := &entitlementReviewFile{raw: []byte(`{"features":{"one":{"dlp":false}}}`), saveErr: tc.err}
			s := newEntitlementStore(nil)
			if err := s.SetPersister(p); err != nil {
				t.Fatal(err)
			}
			err := s.SetFeaturesContext(context.Background(), "one", map[string]bool{featureDLP: true})
			if (err == nil) != tc.accepted || s.Entitled("one", featureDLP) != tc.accepted {
				t.Fatalf("err=%v live=%v accepted=%v", err, s.Entitled("one", featureDLP), tc.accepted)
			}
			restored := newEntitlementStore(nil)
			if err := restored.SetPersister(p); err != nil {
				t.Fatal(err)
			}
			if !restored.Entitled("one", featureDLP) {
				t.Fatal("fixture did not write before returning warning")
			}
		})
	}
}

func TestEntitlementAbsentAndEmptyAuthorityRemainDistinct(t *testing.T) {
	s := newEntitlementStore(nil)
	if err := s.SetPersister(&entitlementReviewFile{}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetPersister(&entitlementReviewFile{raw: []byte{}}); err == nil {
		t.Fatal("truncated file treated as first install")
	}
	p := &entitlementReviewShared{}
	if err := s.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	if err := s.SetFeaturesContext(context.Background(), "one", map[string]bool{featureDLP: true}); err != nil {
		t.Fatal(err)
	}
}
