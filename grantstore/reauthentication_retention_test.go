package grantstore

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"
)

func TestReauthenticationFenceSurvivesPruneAndRestart(t *testing.T) {
	for _, shared := range []bool{false, true} {
		t.Run(fmt.Sprint(shared), func(t *testing.T) {
			s := NewStore()
			path := filepath.Join(t.TempDir(), "grants.json")
			p := &grantSharedFixture{}
			load := func(store *Store) error {
				if shared {
					return store.SetPersister(p)
				}
				return store.SetStatePath(path)
			}
			if err := load(s); err != nil {
				t.Fatal(err)
			}
			now := time.Now().UTC().Truncate(time.Second)
			g := rollingGrant("old", now)
			g.AuthTime = now.Add(-time.Hour).Format(time.RFC3339)
			if _, err := s.Mint(g, time.Minute, now); err != nil {
				t.Fatal(err)
			}
			if _, _, err := s.RequireReauthenticationForTenantContext(context.Background(), g.TenantID, g.GrantID, now); err != nil {
				t.Fatal(err)
			}
			later := now.Add(30 * 24 * time.Hour)
			if n, err := s.PruneExpired(context.Background(), later); n != 0 || err != nil {
				t.Fatal(n, err)
			}
			r := NewStore()
			if err := load(r); err != nil {
				t.Fatal(err)
			}
			g.GrantID = "replacement"
			if _, err := r.Mint(g, time.Minute, later); !errors.Is(err, ErrReauthenticationRequired) {
				t.Fatal("old SSO accepted after prune/restart", err)
			}
			g.AuthTime = later.Format(time.RFC3339)
			if _, err := r.Mint(g, time.Minute, later); err != nil {
				t.Fatal("fresh authentication refused", err)
			}
		})
	}
}

func TestFenceCompactionKeepsNewestExactSelectorAndWildcard(t *testing.T) {
	s := NewStore()
	now := time.Now().UTC().Truncate(time.Second)
	for i, scope := range []string{"app:22", "app:22", ""} {
		g := rollingGrant(fmt.Sprint(i), now)
		g.Scope = scope
		g.AuthTime = now.Add(time.Duration(i) * time.Second).Format(time.RFC3339)
		if _, err := s.Mint(g, time.Minute, now.Add(time.Duration(i)*time.Second)); err != nil {
			t.Fatal(err)
		}
		if _, _, err := s.RequireReauthenticationForTenantContext(context.Background(), g.TenantID, g.GrantID, now.Add(time.Duration(i)*time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	if n, err := s.PruneExpired(context.Background(), now.Add(time.Hour)); n != 2 || err != nil {
		t.Fatal(n, err)
	}
	if _, ok := s.Get("0"); ok {
		t.Fatal("redundant fence retained")
	}
	for _, id := range []string{"2"} {
		if _, ok := s.Get(id); !ok {
			t.Fatal("distinct or newest fence removed", id)
		}
	}
}

func TestFenceCapacityConsolidatesAndNeverRejectsRevocation(t *testing.T) {
	for _, shared := range []bool{false, true} {
		t.Run(fmt.Sprint(shared), func(t *testing.T) {
			s := NewStore()
			now := time.Now().UTC().Truncate(time.Second)
			for i := 0; i < MaxReauthenticationFencesPerTenant; i++ {
				g := rollingGrant(fmt.Sprint(i), now)
				g.Scope = fmt.Sprintf("app:%d", i)
				g.IssuedAt = now.Format(time.RFC3339)
				g.ExpiresAt = now.Add(time.Minute).Format(time.RFC3339)
				g.Revoked = true
				g.ReauthenticateAfter = now.Format(time.RFC3339Nano)
				s.grants[g.GrantID] = g
			}
			s.rebuildReauthenticationIndexLocked()
			var load func(*Store) error
			if shared {
				p := &grantSharedFixture{}
				load = func(r *Store) error { return r.SetPersister(p) }
			} else {
				path := filepath.Join(t.TempDir(), "grants.json")
				load = func(r *Store) error { return r.SetStatePath(path) }
			}
			if err := load(s); err != nil {
				t.Fatal(err)
			}
			for _, tenant := range []string{"tenant", "other"} {
				g := rollingGrant(tenant, now)
				g.TenantID, g.Scope = tenant, "new:22"
				if _, err := s.Mint(g, time.Hour, now); err != nil {
					t.Fatal(err)
				}
				revoked, found, err := s.RequireReauthenticationForTenantContext(context.Background(), tenant, g.GrantID, now.Add(time.Second))
				if err != nil || !found || !revoked.Revoked || s.Valid(g.GrantID, now.Add(2*time.Second)) {
					t.Fatal("revocation refused", tenant, found, err)
				}
				if tenant == "tenant" && s.ReauthenticationScope(revoked) != "tenant" {
					t.Fatal("capacity did not broaden safely")
				}
			}
			if s.fences.count("tenant") != 1 {
				t.Fatal("canonical boundaries not consolidated", s.fences.count("tenant"))
			}
			later := now.Add(365 * 24 * time.Hour)
			if _, err := s.PruneExpired(context.Background(), later); err != nil {
				t.Fatal(err)
			}
			r := NewStore()
			if err := load(r); err != nil {
				t.Fatal(err)
			}
			if r.fences.count("tenant") != 1 {
				t.Fatal("tenant-wide denial lost at restart")
			}
			g := rollingGrant("after-capacity", later)
			g.Scope = "newest:22"
			g.AuthTime = now.Format(time.RFC3339)
			if _, err := r.Mint(g, time.Hour, later); !errors.Is(err, ErrReauthenticationRequired) {
				t.Fatal("old SSO bypassed consolidated boundary", err)
			}
			g.AuthTime = later.Format(time.RFC3339)
			if _, err := r.Mint(g, time.Hour, later); err != nil {
				t.Fatal(err)
			}
			if _, found, err := r.RequireReauthenticationForTenantContext(context.Background(), g.TenantID, g.GrantID, later.Add(time.Second)); err != nil || !found {
				t.Fatal("revocation permanently exhausted", err)
			}
		})
	}
}
