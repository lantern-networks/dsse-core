package grantstore

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestPendingDenialDoesNotBlockOtherTenantOrUndoErasure(t *testing.T) {
	for _, replacement := range []bool{false, true} {
		name := "erased"
		if replacement {
			name = "reassigned"
		}
		t.Run(name, func(t *testing.T) {
			p := &grantSharedFixture{}
			a, b := NewStore(), NewStore()
			now := time.Now().UTC()
			for _, s := range []*Store{a, b} {
				if err := s.SetPersister(p); err != nil {
					t.Fatal(err)
				}
			}
			original, err := a.Mint(Grant{GrantID: "target", TenantID: "a"}, time.Hour, now)
			if err != nil {
				t.Fatal(err)
			}
			p.fail = true
			if _, found, err := a.RevokeForTenant("a", "target"); !found || !errors.Is(err, ErrPersistence) {
				t.Fatal(found, err)
			}
			p.fail = false
			if _, err = b.RemoveTenantChecked("a"); err != nil {
				t.Fatal(err)
			}
			if replacement {
				if _, err = b.Mint(Grant{GrantID: "target", TenantID: "b"}, time.Hour, now); err != nil {
					t.Fatal(err)
				}
			}
			if rows, err := a.ListChecked("a"); err != nil || len(rows) != 0 {
				t.Fatalf("erasure/tenant boundary: %v %v", rows, err)
			}
			if replacement && !a.Valid("target", now) {
				t.Fatal("unrelated tenant blocked by pending denial")
			}
			if _, err = a.Mint(Grant{GrantID: "unrelated", TenantID: "b"}, time.Hour, now); err != nil {
				t.Fatal(err)
			}
			if rows, err := b.ListChecked("a"); err != nil || len(rows) != 0 {
				t.Fatal("write resurrected erased tenant", rows, err)
			}
			if replacement {
				if _, err = b.RemoveTenantChecked("b"); err != nil {
					t.Fatal(err)
				}
			}
			// A report of the erased, latched grant is left out, not admitted.
			if _, _, err = a.MergeChecked([]Grant{original}, now); err != nil {
				t.Fatalf("report of a latched erased grant refused instead of skipped: %v", err)
			}
			if a.Valid(original.GrantID, now) {
				t.Fatal("absent pending identity reauthorized by local ingestion")
			}
			if _, err = b.Mint(Grant{GrantID: "target", TenantID: "a"}, time.Hour, now); err != nil {
				t.Fatal(err)
			}
			if a.Valid("target", now) {
				t.Fatal("unrelated commit discarded absent denial")
			}
			if _, found, err := a.RevokeForTenant("a", "target"); err != nil || !found {
				t.Fatal(found, err)
			}
			restored := NewStore()
			if err := restored.SetPersister(p); err != nil || restored.Valid("target", now) {
				t.Fatal("retry not durable", err)
			}
		})
	}
}

func TestGrantRevokeBeforeCallbackRetainsTenantDenial(t *testing.T) {
	p := &grantSharedFixture{}
	s := NewStore()
	if err := s.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if _, err := s.Mint(Grant{GrantID: "own", TenantID: "a"}, time.Hour, now); err != nil {
		t.Fatal(err)
	}
	gen := s.ConfigGeneration()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, found, err := s.RevokeForTenantContext(ctx, "b", "own"); found || !errors.Is(err, ErrPersistence) {
		t.Fatal("foreign fallback", found, err)
	}
	if !s.Valid("own", now) || s.ConfigGeneration() != gen {
		t.Fatal("foreign fallback changed grant")
	}
	g, found, err := s.RevokeForTenantContext(ctx, "a", "own")
	if !found || !g.Revoked || !errors.Is(err, ErrPersistence) {
		t.Fatal("known revoke lost before callback", g, found, err)
	}
	if s.Valid("own", now) || s.ConfigGeneration() != gen+1 {
		t.Fatal("local denial missing")
	}
	if _, _, err = s.RevokeForTenant("a", "own"); err != nil {
		t.Fatal(err)
	}
	r := NewStore()
	if err = r.SetPersister(p); err != nil || r.Valid("own", now) {
		t.Fatal("retry not durable", err)
	}
}

func TestPendingGrantConflictDoesNotReportUnappliedDenials(t *testing.T) {
	p := &grantSharedFixture{}
	a, b := NewStore(), NewStore()
	a.SetPersister(p)
	b.SetPersister(p)
	now := time.Now()
	original, err := a.Mint(Grant{GrantID: "pending", TenantID: "a"}, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	p.fail = true
	a.RevokeForTenant("a", "pending")
	p.fail = false
	b.RemoveTenantChecked("a")
	other, err := b.Mint(Grant{GrantID: "other", TenantID: "b"}, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	other.Revoked = true
	// The latched, erased grant is skipped; the denial reported alongside it is a
	// restriction and applies. Counts cover only what applied.
	added, updated, err := a.MergeChecked([]Grant{original, other}, now)
	if err != nil || added+updated != 1 {
		t.Fatal("batch with a latched grant misreported", added, updated, err)
	}
	if a.Valid("other", now) || a.Valid("pending", now) {
		t.Fatal("reported denial not applied, or latched grant revived")
	}
	for _, g := range b.ListAll() {
		if g.GrantID == "pending" {
			t.Fatal("erased grant revived by a report")
		}
	}
}
