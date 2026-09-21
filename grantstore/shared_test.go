package grantstore

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"
)

type grantSharedFixture struct {
	mu       sync.Mutex
	raw      []byte
	fail     bool
	loadFail bool
}

func (p *grantSharedFixture) Load() ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.loadFail {
		return nil, errors.New("read failed")
	}
	return append([]byte(nil), p.raw...), nil
}
func (p *grantSharedFixture) Save(raw []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.raw = append([]byte(nil), raw...)
	return nil
}
func (p *grantSharedFixture) UpdateContext(ctx context.Context, f func([]byte) ([]byte, error)) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	raw, err := f(p.raw)
	if err == nil && p.fail {
		return errors.New("commit refused")
	}
	if err == nil {
		p.raw = append([]byte(nil), raw...)
	}
	return err
}

func TestSharedGrantWritersPreservePeer(t *testing.T) {
	p := &grantSharedFixture{}
	a, b := NewStore(), NewStore()
	for _, s := range []*Store{a, b} {
		if err := s.SetPersister(p); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now().UTC()
	for i, s := range []*Store{a, b} {
		id := []string{"first", "second"}[i]
		if _, err := s.Mint(Grant{GrantID: id, TenantID: id}, time.Hour, now); err != nil {
			t.Fatal(err)
		}
	}
	raw, _ := p.Load()
	var saved map[string]Grant
	json.Unmarshal(raw, &saved)
	if len(saved) != 2 {
		t.Fatalf("stale writer lost peer: %d rows", len(saved))
	}
}

func TestSharedGrantPendingDenialAndCheckedRead(t *testing.T) {
	p := &grantSharedFixture{}
	a, b := NewStore(), NewStore()
	a.SetPersister(p)
	b.SetPersister(p)
	now := time.Now().UTC()
	own, e := a.Mint(Grant{GrantID: "own", TenantID: "t"}, time.Hour, now)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = b.Mint(Grant{GrantID: "foreign", TenantID: "other"}, time.Hour, now); e != nil {
		t.Fatal(e)
	}
	p.fail = true
	if g, found, e := a.RevokeForTenantContext(context.Background(), "t", "own"); !errors.Is(e, ErrPersistence) || !found || !g.Revoked {
		t.Fatalf("denial %v %v %v", g, found, e)
	}
	if a.Valid("own", now) {
		t.Fatal("refresh lost pending denial")
	}
	if !b.Valid("own", now) {
		t.Fatal("failed save claimed shared durability")
	}
	if e = a.SetPersister(p); !errors.Is(e, ErrPendingPersistence) {
		t.Fatal("rebind dropped denial")
	}
	p.fail = false
	if _, e = b.Mint(Grant{GrantID: "peer", TenantID: "other"}, time.Hour, now); e != nil {
		t.Fatal(e)
	}
	if _, _, e = a.RevokeForTenant("t", "own"); e != nil {
		t.Fatal(e)
	}
	if b.Valid("own", now) || len(b.ListAll()) != 3 {
		t.Fatal("retry lost peer or revived grant")
	}
	if _, _, e = b.MergeChecked([]Grant{own}, now); e != nil {
		t.Fatal(e)
	}
	if a.Valid("own", now) {
		t.Fatal("stale report revived grant")
	}
	p.loadFail = true
	if _, e = a.ListChecked("t"); e == nil || a.Valid("peer", now) {
		t.Fatal("failed read accepted")
	}
	p.loadFail = false
	p.raw = nil
	if _, e = a.ListAllChecked(); e == nil {
		t.Fatal("known authority disappearance accepted")
	}
	if _, e = a.Mint(Grant{GrantID: "lost", TenantID: "t"}, time.Hour, now); e == nil {
		t.Fatal("missing authority recreated")
	}
}
func TestSharedGrantFailedMergePublishesOnlyDenials(t *testing.T) {
	p := &grantSharedFixture{}
	s := NewStore()
	s.SetPersister(p)
	now := time.Now().UTC()
	g, _ := s.Mint(Grant{GrantID: "old", TenantID: "t"}, time.Hour, now)
	g.Revoked = true
	fresh := g
	fresh.GrantID = "fresh"
	fresh.Revoked = false
	p.fail = true
	a, u, e := s.MergeChecked([]Grant{g, fresh}, now)
	if a != 0 || u != 1 || !errors.Is(e, ErrPersistence) {
		t.Fatalf("partial counts %d %d %v", a, u, e)
	}
	if s.Valid("old", now) || s.Valid("fresh", now) {
		t.Fatal("unconfirmed allowance")
	}
	p.fail = false
	if _, _, e = s.MergeChecked([]Grant{g, fresh}, now); e != nil {
		t.Fatal(e)
	}
	r := NewStore()
	if e = r.SetPersister(p); e != nil || r.Valid("old", now) || !r.Valid("fresh", now) {
		t.Fatal("replay failed", e)
	}
	if _, found, e := r.RevokeForTenant("other", "fresh"); e != nil || found {
		t.Fatal("foreign revoke")
	}
	if n, e := s.RemoveTenantChecked("t"); n != 2 || e != nil {
		t.Fatal("erase", n, e)
	}
	if rows, e := r.ListAllChecked(); e != nil || len(rows) != 0 {
		t.Fatal("erase refresh", e)
	}
}
