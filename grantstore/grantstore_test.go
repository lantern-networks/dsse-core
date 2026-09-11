package grantstore

import (
	"path/filepath"
	"testing"
	"time"
)

func TestMintValidExpiryRevoke(t *testing.T) {
	s := NewStore()
	now := time.Now().UTC()
	if _, err := s.Mint(Grant{TenantID: "t1", UserID: "u1", IdPID: "idp_a"}, time.Hour, now); err == nil {
		t.Fatal("missing grant_id must fail")
	}
	g, err := s.Mint(Grant{GrantID: "g1", TenantID: "t1", UserID: "u1", IdPID: "idp_a"}, time.Hour, now)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if !s.Valid("g1", now) {
		t.Fatal("fresh grant should be valid")
	}
	// expired by ttl
	if s.Valid("g1", g.expiresAtTime().Add(time.Second)) {
		t.Fatal("grant past expiry should be invalid")
	}
	// revoke -> invalid
	if !s.Revoke("g1") || s.Valid("g1", now) {
		t.Fatal("revoked grant should be invalid")
	}
}

func TestGrantPersistAcrossRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "grants.json")
	now := time.Now().UTC()
	s1 := NewStore()
	if err := s1.SetStatePath(path); err != nil {
		t.Fatalf("SetStatePath: %v", err)
	}
	_, _ = s1.Mint(Grant{GrantID: "g1", TenantID: "t1", UserID: "u1", IdPID: "idp_a"}, time.Hour, now)
	_ = s1.Revoke("g1") // a revocation must survive a restart (no silent un-revoke)

	s2 := NewStore()
	if err := s2.SetStatePath(path); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if _, ok := s2.Get("g1"); !ok {
		t.Fatal("grant did not survive restart")
	}
	if s2.Valid("g1", now) {
		t.Fatal("a revoked grant must stay revoked across a restart")
	}
}

func (g Grant) expiresAtTime() time.Time {
	tm, _ := time.Parse(time.RFC3339, g.ExpiresAt)
	return tm
}
