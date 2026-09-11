package main

import (
	"testing"

	"github.com/lantern-networks/dsse-core/dlp"
)

func TestDLPAllowlistStoreSetAndSuppress(t *testing.T) {
	s := newDLPAllowlistRuntimeStore("edge-salt")
	s.SetValues("acme", []string{"4111 1111 1111 1111"})
	al := s.AllowlistForTenant("acme")
	if al == nil || al.Empty() {
		t.Fatal("allowlist not published to the live set")
	}
	// The allowlisted card is suppressed; a different card still fires.
	if got := dlp.DetectWithOptions([]byte("card 4111-1111-1111-1111"), "text/plain", dlp.Options{Allowlist: al}); len(got) != 0 {
		t.Errorf("allowlisted card not suppressed: %v", got)
	}
	if got := dlp.DetectWithOptions([]byte("card 4242 4242 4242 4242"), "text/plain", dlp.Options{Allowlist: al}); len(got) == 0 {
		t.Errorf("a non-allowlisted card should still fire")
	}
	// Tenant isolation + clear.
	if s.AllowlistForTenant("other") != nil {
		t.Error("allowlist leaked across tenants")
	}
	s.SetValues("acme", nil)
	if s.AllowlistForTenant("acme") != nil {
		t.Error("allowlist not cleared on empty SetValues")
	}
}

func TestDLPAllowlistStorePersistence(t *testing.T) {
	p := &memClassifierPersister{} // reuse the in-memory persister from the classifier store test
	s1 := newDLPAllowlistRuntimeStore("edge-salt")
	if err := s1.SetPersister(p); err != nil {
		t.Fatalf("SetPersister: %v", err)
	}
	s1.SetValues("acme", []string{"123456789018"})
	if err := s1.PersistIfDirty(); err != nil {
		t.Fatalf("PersistIfDirty: %v", err)
	}
	s2 := newDLPAllowlistRuntimeStore("edge-salt")
	if err := s2.SetPersister(p); err != nil {
		t.Fatalf("rehydrate: %v", err)
	}
	al := s2.AllowlistForTenant("acme")
	if al == nil || al.Empty() {
		t.Fatal("allowlist did not survive restart")
	}
	if got := dlp.DetectWithOptions([]byte("my number 123456789018"), "text/plain", dlp.Options{Allowlist: al}); len(got) != 0 {
		t.Errorf("rehydrated allowlist does not suppress: %v", got)
	}
}
