package humanapproval

import (
	"context"
	"errors"
	"github.com/lantern-networks/dsse-core/model"
	"testing"
)

func TestAbsentApprovalDenialSurvivesUnrelatedWrite(t *testing.T) {
	p := &sharedApprovalFixture{}
	a, b := NewStore(0), NewStore(0)
	for _, s := range []*Store{a, b} {
		if err := s.SetPersister(p); err != nil {
			t.Fatal(err)
		}
	}
	original := model.HumanApprovalEvent{ID: "target", TenantID: "a", ApprovalResult: "approved"}
	if _, err := a.Upsert(original); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, found, err := a.RevokeForTenantContext(ctx, "a", "target", "deny"); !found || !errors.Is(err, ErrPersistence) {
		t.Fatal(found, err)
	}
	if _, err := b.RemoveTenantChecked("a"); err != nil {
		t.Fatal(err)
	}
	if _, ok := a.GetForTenant("a", "target"); ok {
		t.Fatal("erasure undone")
	}
	if _, err := a.Upsert(model.HumanApprovalEvent{ID: "peer", TenantID: "b", ApprovalResult: "approved"}); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Upsert(original); err == nil {
		t.Fatal("local recreation bypassed absent denial")
	}
	if _, err := b.Upsert(original); err != nil {
		t.Fatal(err)
	}
	if g, ok := a.GetForTenant("a", "target"); !ok || g.ApprovalResult != "revoked" {
		t.Fatal("unrelated write dropped denial", g)
	}
	if _, _, err := a.RevokeForTenant("a", "target", "deny"); err != nil {
		t.Fatal(err)
	}
	r := NewStore(0)
	if err := r.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	if g, ok := r.GetForTenant("a", "target"); !ok || g.ApprovalResult != "revoked" {
		t.Fatal("retry not durable")
	}
	if _, err := a.RemoveTenantChecked("a"); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Upsert(original); err != nil {
		t.Fatal("explicit erasure did not release denial", err)
	}
}
