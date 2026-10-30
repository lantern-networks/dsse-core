package grantstore

import (
	"path/filepath"
	"testing"
	"time"
)

func TestTenantFootprintAndErasurePreserveCaseDistinctOwnerAcrossRestart(t *testing.T) {
	for _, tc := range []struct {
		name string
		bind func(*Store) error
	}{
		{name: "file", bind: func(s *Store) error { return s.SetStatePath(filepath.Join(t.TempDir(), "grants.json")) }},
		{name: "shared", bind: func(s *Store) error { return s.SetPersister(&grantSharedFixture{}) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := NewStore()
			if err := tc.bind(s); err != nil {
				t.Fatal(err)
			}
			writer := s.persister
			now := time.Now().UTC()
			for _, g := range []Grant{
				{GrantID: "upper-grant", TenantID: "Tenant", UserID: "upper"},
				{GrantID: "lower-grant", TenantID: "tenant", UserID: "lower"},
			} {
				if _, err := s.Mint(g, time.Hour, now); err != nil {
					t.Fatal(err)
				}
			}
			if s.CountForTenant("Tenant") != 1 || s.CountForTenant("tenant") != 1 {
				t.Fatalf("case-distinct tenant footprint merged: upper=%d lower=%d", s.CountForTenant("Tenant"), s.CountForTenant("tenant"))
			}
			if removed, err := s.RemoveTenantChecked("Tenant"); err != nil || removed != 1 {
				t.Fatalf("upper tenant erasure removed another owner's grant: removed=%d err=%v", removed, err)
			}
			restarted := NewStore()
			if err := restarted.SetPersister(writer); err != nil {
				t.Fatal(err)
			}
			if restarted.Valid("upper-grant", now) || !restarted.Valid("lower-grant", now) || restarted.CountForTenant("tenant") != 1 {
				t.Fatal("case-distinct tenant grant was erased or restored across restart")
			}
		})
	}
}
