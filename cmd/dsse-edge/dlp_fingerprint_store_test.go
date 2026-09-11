package main

import (
	"testing"

	"github.com/lantern-networks/dsse-core/dlp"
)

func TestDLPFingerprintStoreSetDetectAndIsolate(t *testing.T) {
	s := newDLPFingerprintRuntimeStore("edge-salt")
	if n := s.SetDataset("acme", "customer_record", []string{"CUST-100482", "ACME-7741-XZ"}); n != 2 {
		t.Fatalf("SetDataset count = %d, want 2", n)
	}
	set := s.FingerprintSetForTenant("acme")
	if set == nil || set.Empty() {
		t.Fatal("fingerprint set not published")
	}
	got := 0
	for _, f := range dlp.DetectWithOptions([]byte("record CUST-100482 attached"), "text/plain", dlp.Options{Fingerprints: set}) {
		if f.Type == "customer_record" {
			got = f.Count
		}
	}
	if got != 1 {
		t.Errorf("EDM detection = %d, want 1", got)
	}
	// Non-secret listing: name + count, never the values.
	ds := s.DatasetsForTenant("acme")
	if len(ds) != 1 || ds[0].Name != "customer_record" || ds[0].Count != 2 {
		t.Errorf("datasets = %+v, want [{customer_record 2}]", ds)
	}
	// Tenant isolation + remove.
	if s.FingerprintSetForTenant("other") != nil {
		t.Error("EDM set leaked across tenants")
	}
	if !s.RemoveDataset("acme", "customer_record") {
		t.Error("RemoveDataset should report true")
	}
	if s.FingerprintSetForTenant("acme") != nil {
		t.Error("set not cleared after removing the last dataset")
	}
}

func TestDLPFingerprintStorePersistenceHashesOnly(t *testing.T) {
	p := &memClassifierPersister{}
	s1 := newDLPFingerprintRuntimeStore("edge-salt")
	if err := s1.SetPersister(p); err != nil {
		t.Fatalf("SetPersister: %v", err)
	}
	s1.SetDataset("acme", "secret_ds", []string{"TOPSECRETVALUE123"})
	if err := s1.PersistIfDirty(); err != nil {
		t.Fatalf("PersistIfDirty: %v", err)
	}
	// The persisted bytes must NOT contain the raw value (hashes only).
	if data, _ := p.Load(); containsSubstring(string(data), "TOPSECRETVALUE123") {
		t.Fatal("persisted snapshot leaked the raw dataset value")
	}
	// Restart: rehydrate + recompile from hashes, still detects.
	s2 := newDLPFingerprintRuntimeStore("edge-salt")
	if err := s2.SetPersister(p); err != nil {
		t.Fatalf("rehydrate: %v", err)
	}
	set := s2.FingerprintSetForTenant("acme")
	if set == nil {
		t.Fatal("dataset did not survive restart")
	}
	got := 0
	for _, f := range dlp.DetectWithOptions([]byte("leak TOPSECRETVALUE123"), "text/plain", dlp.Options{Fingerprints: set}) {
		if f.Type == "secret_ds" {
			got = f.Count
		}
	}
	if got != 1 {
		t.Fatalf("rehydrated EDM does not detect: %d", got)
	}
}

func containsSubstring(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
