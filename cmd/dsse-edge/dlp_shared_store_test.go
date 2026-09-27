package main

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/model"
	"strings"
	"testing"
)

type dlpPeerFixture struct {
	attach  func(blobstore.Persister) error
	write   func(string) error
	present func(string) bool
	refresh func() error
	flush   func() error
	stage   func()
}

func dlpPeerFactories() map[string]func() dlpPeerFixture {
	return map[string]func() dlpPeerFixture{
		"allowlist": func() dlpPeerFixture {
			s := newDLPAllowlistRuntimeStore("salt")
			return dlpPeerFixture{s.SetPersister, func(t string) error { return s.SetValuesDurable(t, []string{"safe-" + t}) }, func(t string) bool { return len(s.ValuesForTenant(t)) == 1 }, s.RefreshShared, s.PersistIfDirty, func() { s.SetValues("staged", []string{"safe"}) }}
		},
		"classifiers": func() dlpPeerFixture {
			s := newDLPClassifierRuntimeStore()
			return dlpPeerFixture{s.SetPersister, func(t string) error { return s.SetSpecsDurable(t, classifierFixtureSpecs(t)) }, func(t string) bool { return len(s.SpecsForTenant(t)) == 1 }, s.RefreshShared, s.PersistIfDirty, func() { s.SetSpecs("staged", classifierFixtureSpecs("staged")) }}
		},
		"fingerprints": func() dlpPeerFixture {
			s := newDLPFingerprintRuntimeStore("salt")
			return dlpPeerFixture{s.SetPersister, func(t string) error { _, e := s.SetDatasetDurable(t, "dataset", []string{"sample-" + t}); return e }, func(t string) bool { return len(s.DatasetsForTenant(t)) == 1 }, s.RefreshShared, s.PersistIfDirty, func() { s.SetDataset("staged", "dataset", []string{"sample-staged"}) }}
		},
		"policies": func() dlpPeerFixture {
			s := newDLPPolicyObjectStore()
			return dlpPeerFixture{s.SetPersister, func(t string) error {
				return s.UpsertDurable(model.DLPPolicyObject{ID: "policy", TenantID: t, Name: t, Identifiers: []string{"email"}, OnMatch: "observe"})
			}, func(t string) bool { _, ok := s.Get(t, "policy"); return ok }, s.RefreshShared, s.PersistIfDirty, func() {
				s.Upsert(model.DLPPolicyObject{ID: "policy", TenantID: "staged", Name: "Staged", Identifiers: []string{"email"}, OnMatch: "observe"})
			}}
		},
	}
}
func TestDLPSharedPeerPreservation(t *testing.T) {
	for name, factory := range dlpPeerFactories() {
		t.Run(name, func(t *testing.T) {
			p := &entitlementReviewPersister{}
			a, b := factory(), factory()
			for _, s := range []dlpPeerFixture{a, b} {
				if e := s.attach(p); e != nil {
					t.Fatal(e)
				}
			}
			if e := a.write("one"); e != nil {
				t.Fatal(e)
			}
			if e := b.write("two"); e != nil {
				t.Fatal(e)
			}
			restored := factory()
			if e := restored.attach(p); e != nil {
				t.Fatal(e)
			}
			if !restored.present("one") || !restored.present("two") {
				t.Fatal("acknowledged peer configuration lost")
			}
			if name == "fingerprints" && strings.Contains(string(p.raw), "sample-") {
				t.Fatal("raw EDM values persisted")
			}
		})
	}
}

func TestDLPSharedFailureRefreshAndAuthority(t *testing.T) {
	for name, factory := range dlpPeerFactories() {
		t.Run(name, func(t *testing.T) {
			p := &entitlementReviewPersister{}
			a, b := factory(), factory()
			if e := a.attach(p); e != nil {
				t.Fatal(e)
			}
			if e := b.attach(p); e != nil {
				t.Fatal(e)
			}
			if e := a.write("one"); e != nil {
				t.Fatal(e)
			}
			if e := b.refresh(); e != nil || !b.present("one") {
				t.Fatal("peer refresh missing", e)
			}
			before := append([]byte(nil), p.raw...)
			p.fail = true
			if e := b.write("two"); e == nil {
				t.Fatal("failed persistence acknowledged")
			}
			if b.present("two") || !bytes.Equal(p.raw, before) {
				t.Fatal("failed write changed live/durable state")
			}
			p.fail = false
			for _, bad := range [][]byte{nil, []byte(`{}`)} {
				p.raw = bad
				if e := a.refresh(); e == nil {
					t.Fatal("missing/corrupt authority accepted")
				}
				if e := a.write("two"); e == nil {
					t.Fatal("missing/corrupt authority overwritten")
				}
				if !a.present("one") || a.present("two") {
					t.Fatal("authority error replaced acknowledged state")
				}
			}
			p.raw = before
			a.stage()
			if e := a.flush(); e == nil {
				t.Fatal("staged snapshot overwrote shared row")
			}
			if !bytes.Equal(before, p.raw) {
				t.Fatal("staged state persisted")
			}
			if e := a.refresh(); e == nil {
				t.Fatal("staged state silently discarded")
			}
		})
	}
}
func TestDLPSharedGranularDeleteAndFingerprintSalt(t *testing.T) {
	p := &entitlementReviewPersister{}
	a, b := newDLPFingerprintRuntimeStore("authority"), newDLPFingerprintRuntimeStore("stale")
	if e := a.SetPersister(p); e != nil {
		t.Fatal(e)
	}
	if e := b.SetPersister(p); e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if _, e := a.SetDatasetContext(ctx, "one", "first", []string{"sample-one"}); e != nil {
		t.Fatal(e)
	}
	if _, e := b.SetDatasetContext(ctx, "one", "second", []string{"sample-two"}); e != nil {
		t.Fatal(e)
	}
	if p.ctx != ctx {
		t.Fatal("request context lost")
	}
	restored := newDLPFingerprintRuntimeStore("other")
	if e := restored.SetPersister(p); e != nil {
		t.Fatal(e)
	}
	if restored.salt != "authority" || len(restored.DatasetsForTenant("one")) != 2 {
		t.Fatal("salt or peer dataset lost")
	}
	expected := newDLPFingerprintRuntimeStore("authority")
	expected.SetDataset("one", "second", []string{"sample-two"})
	x, _ := json.Marshal(restored.datasets["one"]["second"])
	y, _ := json.Marshal(expected.datasets["one"]["second"])
	if !bytes.Equal(x, y) {
		t.Fatal("EDM hashed with stale local salt")
	}
	if removed, e := a.RemoveDatasetContext(ctx, "one", "second"); e != nil || !removed {
		t.Fatal("peer dataset not deleted", e)
	}
	if len(a.DatasetsForTenant("one")) != 1 {
		t.Fatal("delete removed unrelated dataset")
	}
	q := &entitlementReviewPersister{}
	pa, pb := newDLPPolicyObjectStore(), newDLPPolicyObjectStore()
	pa.SetPersister(q)
	pb.SetPersister(q)
	for i, s := range []*dlpPolicyObjectStore{pa, pb} {
		if e := s.UpsertContext(ctx, model.DLPPolicyObject{ID: []string{"first", "second"}[i], TenantID: "one", Name: "Fixture", Identifiers: []string{"email"}, OnMatch: "observe"}); e != nil {
			t.Fatal(e)
		}
	}
	if removed, e := pa.DeleteContext(ctx, "one", "second"); e != nil || !removed {
		t.Fatal("peer policy not deleted", e)
	}
	if len(pa.List("one")) != 1 {
		t.Fatal("delete erased unrelated policy")
	}
}
