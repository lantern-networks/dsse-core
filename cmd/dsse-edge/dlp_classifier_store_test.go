package main

import (
	"testing"

	"github.com/lantern-networks/dsse-core/dlp"
)

func TestDLPClassifierStoreSetAndScan(t *testing.T) {
	s := newDLPClassifierRuntimeStore()
	errs := s.SetSpecs("acme", []dlp.ClassifierSpec{
		{Name: "employee_id", Kind: dlp.ClassifierRegex, Pattern: `EMP-[0-9]{6}`},
		{Name: "bad", Kind: dlp.ClassifierRegex, Pattern: `[a-`}, // invalid, reported but rest survives
	})
	if len(errs) != 1 {
		t.Fatalf("errs = %d, want 1 (the invalid regex)", len(errs))
	}
	set := s.ClassifierSetForTenant("acme")
	if !set.Has("employee_id") {
		t.Fatal("employee_id not published to the live set")
	}
	got := dlp.DetectWith([]byte("ticket EMP-004217"), "text/plain", set)
	if len(got) != 1 || got[0].Type != "employee_id" || got[0].Count != 1 {
		t.Fatalf("scan findings = %v, want one employee_id", got)
	}
	// Tenant isolation.
	if s.ClassifierSetForTenant("other").Has("employee_id") {
		t.Fatal("classifier leaked across tenants")
	}
	// Empty clears.
	s.SetSpecs("acme", nil)
	if s.ClassifierSetForTenant("acme").Has("employee_id") {
		t.Fatal("classifiers not cleared on empty SetSpecs")
	}
}

type memClassifierPersister struct{ data []byte }

func (m *memClassifierPersister) Load() ([]byte, error) { return m.data, nil }
func (m *memClassifierPersister) Save(b []byte) error   { m.data = append([]byte(nil), b...); return nil }

func TestDLPClassifierStorePersistence(t *testing.T) {
	p := &memClassifierPersister{}
	s1 := newDLPClassifierRuntimeStore()
	if err := s1.SetPersister(p); err != nil {
		t.Fatalf("SetPersister: %v", err)
	}
	s1.SetSpecs("acme", []dlp.ClassifierSpec{{Name: "employee_id", Kind: dlp.ClassifierRegex, Pattern: `EMP-[0-9]{6}`}})
	if err := s1.PersistIfDirty(); err != nil {
		t.Fatalf("PersistIfDirty: %v", err)
	}
	// Restart: rehydrate from the same persister and confirm the live set recompiled.
	s2 := newDLPClassifierRuntimeStore()
	if err := s2.SetPersister(p); err != nil {
		t.Fatalf("SetPersister (rehydrate): %v", err)
	}
	set := s2.ClassifierSetForTenant("acme")
	if set == nil || !set.Has("employee_id") {
		t.Fatal("custom classifier did not survive restart")
	}
	if got := dlp.DetectWith([]byte("EMP-123456"), "text/plain", set); len(got) != 1 {
		t.Fatalf("rehydrated classifier does not detect: %v", got)
	}
}
