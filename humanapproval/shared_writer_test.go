package humanapproval

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/lantern-networks/dsse-core/model"
	"sync"
	"testing"
	"time"
)

type sharedApprovalFixture struct {
	mu  sync.Mutex
	raw []byte
}

func (p *sharedApprovalFixture) Load() ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]byte(nil), p.raw...), nil
}
func (p *sharedApprovalFixture) Save(raw []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.raw = append([]byte(nil), raw...)
	return nil
}
func (p *sharedApprovalFixture) UpdateContext(ctx context.Context, f func([]byte) ([]byte, error)) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	raw, err := f(p.raw)
	if err == nil {
		p.raw = append([]byte(nil), raw...)
	}
	return err
}
func TestSharedWritersPreservePeerAndTerminalState(t *testing.T) {
	p := &sharedApprovalFixture{}
	a, b := NewStore(8), NewStore(8)
	for _, s := range []*Store{a, b} {
		if err := s.SetPersister(p); err != nil {
			t.Fatal(err)
		}
	}
	first := model.HumanApprovalEvent{TenantID: "tenant-a", ID: "same", ApprovalResult: "approved"}
	second := model.HumanApprovalEvent{TenantID: "tenant-b", ID: "same", ApprovalResult: "approved"}
	if _, err := a.Upsert(first); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Upsert(second); err != nil {
		t.Fatal(err)
	}
	raw, _ := p.Load()
	var saved map[string]model.HumanApprovalEvent
	if err := json.Unmarshal(raw, &saved); err != nil {
		t.Fatal(err)
	}
	if len(saved) != 2 {
		t.Errorf("peer record lost: rows=%d", len(saved))
	}
	c := NewStore(8)
	if err := c.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.RevokeForTenant("tenant-b", "same", "review"); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Upsert(second); err == nil {
		t.Error("stale writer revived revoked record")
	}
	raw, _ = p.Load()
	if err := json.Unmarshal(raw, &saved); err != nil {
		t.Fatal(err)
	}
	if saved[approvalKey("tenant-b", "same")].ApprovalResult != "revoked" {
		t.Error("durable revocation lost")
	}
	_ = time.Now()
}

func TestSharedAuthorizationRefreshCapacityErasure(t *testing.T) {
	p := &sharedApprovalFixture{}
	a, b := NewStore(2), NewStore(2)
	for _, s := range []*Store{a, b} {
		if err := s.SetPersister(p); err != nil {
			t.Fatal(err)
		}
	}
	for _, id := range []string{"one", "two"} {
		if _, err := a.Upsert(model.HumanApprovalEvent{ID: id, TenantID: id, ApprovalResult: "approved"}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := b.Upsert(model.HumanApprovalEvent{ID: "three", TenantID: "three", ApprovalResult: "approved"}); !errors.Is(err, ErrCapacity) {
		t.Fatalf("shared capacity: %v", err)
	}
	if n, err := b.RemoveTenantContext(context.Background(), "two"); err != nil || n != 1 {
		t.Fatalf("latest erasure: %d %v", n, err)
	}
	if _, ok := a.GetForTenant("two", "two"); ok {
		t.Fatal("erased record remains authorized")
	}
	if _, ok := a.GetForTenant("one", "one"); !ok {
		t.Fatal("unrelated record lost")
	}
	saved, _ := p.Load()
	for _, bad := range [][]byte{nil, {}, []byte(`null`), []byte(`{"bad":{}}`)} {
		p.Save(bad)
		if _, _, err := a.GetForTenantContext(context.Background(), "one", "one"); err == nil {
			t.Fatal("bad authority reported as healthy")
		}
		if _, ok := a.GetForTenant("one", "one"); ok {
			t.Fatal("bad authority authorizes cached record")
		}
		if _, err := a.Upsert(model.HumanApprovalEvent{ID: "new", TenantID: "one", ApprovalResult: "approved"}); !errors.Is(err, ErrPersistence) {
			t.Fatalf("bad authority mutation: %v", err)
		}
	}
	p.Save(saved)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := a.UpsertContext(ctx, model.HumanApprovalEvent{ID: "new", TenantID: "one", ApprovalResult: "approved"}); err == nil {
		t.Fatal("cancelled update committed")
	}
	raw, _ := p.Load()
	if !bytes.Equal(raw, saved) {
		t.Fatal("cancelled write changed authority")
	}
}

type refusedSharedApproval struct {
	*sharedApprovalFixture
	fail       bool
	beforeEdit bool
}

func (p *refusedSharedApproval) UpdateContext(ctx context.Context, f func([]byte) ([]byte, error)) error {
	if p.fail && p.beforeEdit {
		return errors.New("transaction refused")
	}
	if !p.fail {
		return p.sharedApprovalFixture.UpdateContext(ctx, f)
	}
	raw, _ := p.Load()
	if _, err := f(raw); err != nil {
		return err
	}
	return errors.New("save refused")
}
func TestSharedApprovalUnconfirmedDenialSurvivesRefresh(t *testing.T) {
	p := &refusedSharedApproval{sharedApprovalFixture: &sharedApprovalFixture{}}
	a := NewStore(10)
	if err := a.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	event := model.HumanApprovalEvent{ID: "one", TenantID: "own", ApprovalResult: "approved"}
	if _, err := a.Upsert(event); err != nil {
		t.Fatal(err)
	}
	p.fail = true
	p.beforeEdit = true
	if _, ok, err := a.RevokeForTenant("own", "one", "deny"); !ok || !errors.Is(err, ErrPersistence) {
		t.Fatal("expected unconfirmed revoke")
	}
	if got, ok := a.GetForTenant("own", "one"); !ok || got.ApprovalResult != "revoked" {
		t.Fatal("refresh revived unconfirmed revoke")
	}
	if _, err := a.Upsert(event); err == nil {
		t.Fatal("upsert revived local denial")
	}
	p.fail = false
	b := NewStore(10)
	if err := b.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	if _, err := b.RemoveTenantChecked("own"); err != nil {
		t.Fatal(err)
	}
	if _, ok := a.GetForTenant("own", "one"); ok {
		t.Fatal("local denial resurrected erased record")
	}
	if _, err := a.Upsert(model.HumanApprovalEvent{ID: "two", TenantID: "peer", ApprovalResult: "approved"}); err != nil {
		t.Fatal(err)
	}
	if err := b.RefreshShared(); err != nil || b.Count() != 1 {
		t.Fatalf("erasure overwritten: %v", err)
	}
}
