package main

import (
	"reflect"
	"testing"

	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/dlp"
	"github.com/lantern-networks/dsse-core/model"
)

// ErrSavedWithoutAtomicity is what FilePersister returns, every time, when the
// store is a bind-mounted single file: the bytes ARE on disk. Treating it as a
// failure made every DLP change on such a deployment "fail" forever while the
// file took it, so the change appeared only after the next restart. It is a
// confirmed save; only an unconfirmed-durability error is a failure.
func TestDLPStoresTreatInPlaceSaveAsSaved(t *testing.T) {
	weak := blobstore.ErrSavedWithoutAtomicity

	t.Run("allowlist", func(t *testing.T) {
		p := &checkedClassifierPersister{err: weak}
		s := newDLPAllowlistRuntimeStore("salt")
		if err := s.SetPersister(p); err != nil {
			t.Fatal(err)
		}
		if err := s.SetValuesDurable("own", []string{"4242424242424242"}); err != nil {
			t.Fatalf("in-place save reported as failure: %v", err)
		}
		restarted := newDLPAllowlistRuntimeStore("salt")
		restarted.SetPersister(&checkedClassifierPersister{data: p.data})
		if !s.AllowlistForTenant("own").Allowed(dlp.CreditCard, []byte("4242424242424242")) || !restarted.AllowlistForTenant("own").Allowed(dlp.CreditCard, []byte("4242424242424242")) || s.dirty {
			t.Fatal("live state and file disagree after an in-place save")
		}
	})
	t.Run("classifier", func(t *testing.T) {
		p := &checkedClassifierPersister{err: weak}
		s := newDLPClassifierRuntimeStore()
		if err := s.SetPersister(p); err != nil {
			t.Fatal(err)
		}
		if err := s.SetSpecsDurable("own", classifierFixtureSpecs("NEW")); err != nil {
			t.Fatalf("in-place save reported as failure: %v", err)
		}
		restarted := newDLPClassifierRuntimeStore()
		restarted.SetPersister(&checkedClassifierPersister{data: p.data})
		if !reflect.DeepEqual(s.SpecsForTenant("own"), classifierFixtureSpecs("NEW")) || !reflect.DeepEqual(restarted.SpecsForTenant("own"), classifierFixtureSpecs("NEW")) || s.dirty {
			t.Fatal("live state and file disagree after an in-place save")
		}
	})
	t.Run("fingerprint", func(t *testing.T) {
		p := &checkedClassifierPersister{err: weak}
		s := newDLPFingerprintRuntimeStore("salt")
		if err := s.SetPersister(p); err != nil {
			t.Fatal(err)
		}
		if _, err := s.SetDatasetDurable("own", "customer_record", []string{"NEW-994400"}); err != nil {
			t.Fatalf("in-place save reported as failure: %v", err)
		}
		restarted := newDLPFingerprintRuntimeStore("salt")
		restarted.SetPersister(&checkedClassifierPersister{data: p.data})
		if edmFixtureCount(s, "own", "NEW-994400") != 1 || edmFixtureCount(restarted, "own", "NEW-994400") != 1 || s.dirty {
			t.Fatal("live state and file disagree after an in-place save")
		}
	})
}

func TestPolicyObjectAndDomainStoresTreatInPlaceSaveAsSaved(t *testing.T) {
	weak := blobstore.ErrSavedWithoutAtomicity
	t.Run("dlp_policy_object", func(t *testing.T) {
		p := &checkedClassifierPersister{err: weak}
		s := newDLPPolicyObjectStore()
		if err := s.SetPersister(p); err != nil {
			t.Fatal(err)
		}
		obj := model.DLPPolicyObject{ID: "protect", TenantID: "own", Name: "Protect", Identifiers: []string{"credit_card"}, OnMatch: "block", Status: "active"}
		if err := s.UpsertDurable(obj); err != nil {
			t.Fatalf("in-place save reported as failure: %v", err)
		}
		restarted := newDLPPolicyObjectStore()
		restarted.SetPersister(&checkedClassifierPersister{data: p.data})
		if _, ok := s.Get("own", "protect"); !ok {
			t.Fatal("confirmed in-place save not published")
		}
		if _, ok := restarted.Get("own", "protect"); !ok {
			t.Fatal("live state and file disagree after an in-place save")
		}
	})
	t.Run("organization_domains", func(t *testing.T) {
		p := &checkedClassifierPersister{err: weak}
		s := newOrganizationDomainsStore()
		if err := s.SetPersister(p); err != nil {
			t.Fatal(err)
		}
		if _, err := s.SetDomainsDurable("own", []string{"example.com"}); err != nil {
			t.Fatalf("in-place save reported as failure: %v", err)
		}
		restarted := newOrganizationDomainsStore()
		restarted.SetPersister(&checkedClassifierPersister{data: p.data})
		if !reflect.DeepEqual(s.Domains("own"), []string{"example.com"}) || !reflect.DeepEqual(restarted.Domains("own"), []string{"example.com"}) {
			t.Fatalf("live state and file disagree: live=%v file=%v", s.Domains("own"), restarted.Domains("own"))
		}
	})
}
