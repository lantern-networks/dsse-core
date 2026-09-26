package delegatedgrant

import (
	"context"
	"errors"
	"testing"
	"time"
)

type denialGate struct {
	*sharedApprovalFixture
	before, after bool
}

func (p *denialGate) UpdateContext(ctx context.Context, edit func([]byte) ([]byte, error)) error {
	if p.before {
		return errors.New("lease lost before callback")
	}
	return p.sharedApprovalFixture.UpdateContext(ctx, func(raw []byte) ([]byte, error) {
		next, err := edit(raw)
		if err == nil && p.after {
			return nil, errors.New("commit rejected")
		}
		return next, err
	})
}
func TestFailedRevocationRemainsDeniedThroughRefreshAndRetry(t *testing.T) {
	for _, before := range []bool{false, true} {
		name := "commit"
		if before {
			name = "lease"
		}
		t.Run(name, func(t *testing.T) {
			p := &denialGate{sharedApprovalFixture: &sharedApprovalFixture{}}
			s := NewStore(0)
			if err := s.SetPersister(p); err != nil {
				t.Fatal(err)
			}
			for _, tenant := range []string{"own", "foreign"} {
				if _, err := s.Upsert(sampleGrant(tenant, "same")); err != nil {
					t.Fatal(err)
				}
			}
			gen := s.ConfigGeneration()
			p.before, p.after = before, !before
			g, err := s.RevokeForTenant("own", "same", "review", time.Now())
			if !errors.Is(err, ErrPersistence) || g.Status != "revoked" {
				t.Fatalf("failed revoke lost denial result: %s %v", g.Status, err)
			}
			for i := 0; i < 2; i++ {
				g, ok := s.GetForTenant("own", "same")
				if !ok || IsActive(g, time.Now()) {
					t.Fatal("refresh revived failed revocation")
				}
			}
			if g, ok := s.GetForTenant("foreign", "same"); !ok || !IsActive(g, time.Now()) {
				t.Fatal("denial crossed tenants")
			}
			if s.ConfigGeneration() != gen+1 {
				t.Fatal("local denial not distributed")
			}
			p.before, p.after = false, false
			// A peer erases the record. A local pending denial must neither resurrect it
			// nor disappear merely because an unrelated mutation committed.
			peer := NewStore(0)
			if err := peer.SetPersister(p); err != nil {
				t.Fatal(err)
			}
			if _, err := peer.RemoveTenantChecked("own"); err != nil {
				t.Fatal(err)
			}
			if _, ok := s.GetForTenant("own", "same"); ok {
				t.Fatal("pending denial resurrected erased grant")
			}
			if _, err := s.Upsert(sampleGrant("foreign", "other")); err != nil {
				t.Fatal(err)
			}
			if _, err := s.Upsert(sampleGrant("own", "same")); err == nil {
				t.Fatal("unrelated write cleared pending denial")
			}
			if _, err := peer.Upsert(sampleGrant("own", "same")); err != nil {
				t.Fatal(err)
			}
			if g, ok := s.GetForTenant("own", "same"); !ok || IsActive(g, time.Now()) {
				t.Fatal("peer recreation escaped denial")
			}
			if _, err := s.RevokeForTenant("own", "same", "review", time.Now()); err != nil {
				t.Fatal(err)
			}
			restored := NewStore(0)
			if err := restored.SetPersister(p); err != nil {
				t.Fatal(err)
			}
			if g, ok := restored.GetForTenant("own", "same"); !ok || IsActive(g, time.Now()) {
				t.Fatal("retry did not persist denial")
			}
		})
	}
}
