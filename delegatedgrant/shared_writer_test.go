package delegatedgrant

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
	first := model.DelegatedAccessGrant{TenantID: "tenant-a", ID: "same", Status: "active"}
	second := model.DelegatedAccessGrant{TenantID: "tenant-b", ID: "same", Status: "active"}
	if _, err := a.Upsert(first); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Upsert(second); err != nil {
		t.Fatal(err)
	}
	raw, _ := p.Load()
	var saved map[string]model.DelegatedAccessGrant
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
	if _, err := c.RevokeForTenant("tenant-b", "same", "review", time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Upsert(second); err == nil {
		t.Error("stale writer revived revoked record")
	}
	raw, _ = p.Load()
	if err := json.Unmarshal(raw, &saved); err != nil {
		t.Fatal(err)
	}
	if saved[grantKey("tenant-b", "same")].Status != "revoked" {
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
		if _, err := a.Upsert(model.DelegatedAccessGrant{ID: id, TenantID: id, Status: "active"}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := b.Upsert(model.DelegatedAccessGrant{ID: "three", TenantID: "three", Status: "active"}); !errors.Is(err, ErrCapacity) {
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
		if _, err := a.Upsert(model.DelegatedAccessGrant{ID: "new", TenantID: "one", Status: "active"}); !errors.Is(err, ErrPersistence) {
			t.Fatalf("bad authority mutation: %v", err)
		}
	}
	p.Save(saved)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := a.UpsertContext(ctx, model.DelegatedAccessGrant{ID: "new", TenantID: "one", Status: "active"}); err == nil {
		t.Fatal("cancelled update committed")
	}
	raw, _ := p.Load()
	if !bytes.Equal(raw, saved) {
		t.Fatal("cancelled write changed authority")
	}
}
