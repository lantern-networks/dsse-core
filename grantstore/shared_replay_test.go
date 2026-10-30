package grantstore

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

type countedGrantPair struct {
	*rollingMemory
	updates  atomic.Int64
	failRead atomic.Bool
}

func (p *countedGrantPair) LoadGrantPair(ctx context.Context) ([]byte, []byte, error) {
	if p.failRead.Load() {
		return nil, nil, errors.New("authority read unavailable")
	}
	return p.rollingMemory.LoadGrantPair(ctx)
}

func (p *countedGrantPair) UpdateGrantPair(ctx context.Context, edit func([]byte, []byte) ([]byte, []byte, error)) error {
	p.updates.Add(1)
	return p.rollingMemory.UpdateGrantPair(ctx, edit)
}

func TestSharedIdenticalReportDoesNotOpenWriteTransaction(t *testing.T) {
	pair := &countedGrantPair{rollingMemory: &rollingMemory{}}
	store := NewStore()
	if err := store.SetPersister(RollingPersister{Backend: pair}); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	grant, err := store.Mint(rollingGrant("repeated", now), time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	before := pair.updates.Load()
	generation := store.ConfigGeneration()
	for i := 0; i < 3; i++ {
		added, updated, err := store.MergeCheckedContext(t.Context(), []Grant{grant}, now)
		if err != nil || added != 0 || updated != 0 {
			t.Fatalf("replay %d: added=%d updated=%d err=%v", i, added, updated, err)
		}
	}
	if pair.updates.Load() != before || store.ConfigGeneration() != generation {
		t.Fatal("unchanged report wrote or advanced the shared authority")
	}
}

func TestSharedReplayRefreshesRevocationBeforeSkipping(t *testing.T) {
	pair := &countedGrantPair{rollingMemory: &rollingMemory{}}
	first, second := NewStore(), NewStore()
	for _, store := range []*Store{first, second} {
		if err := store.SetPersister(RollingPersister{Backend: pair}); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now().UTC().Truncate(time.Second)
	grant, err := first.Mint(rollingGrant("revoked", now), time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := second.Get(grant.GrantID); !ok {
		t.Fatal("peer did not load initial grant")
	}
	if _, found, err := first.RevokeForTenant("tenant", grant.GrantID); err != nil || !found {
		t.Fatalf("revoke: found=%v err=%v", found, err)
	}
	before := pair.updates.Load()
	if _, _, err := second.MergeCheckedContext(t.Context(), []Grant{grant}, now); err != nil {
		t.Fatal(err)
	}
	if pair.updates.Load() == before {
		t.Fatal("stale allow report bypassed transactional merge")
	}
	if second.Valid(grant.GrantID, now) {
		t.Fatal("stale report restored a revoked grant")
	}
}

func TestSharedReplayReadErrorDoesNotClaimUnchangedAuthority(t *testing.T) {
	pair := &countedGrantPair{rollingMemory: &rollingMemory{}}
	store := NewStore()
	if err := store.SetPersister(RollingPersister{Backend: pair}); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	grant, err := store.Mint(rollingGrant("read-error", now), time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	before := pair.updates.Load()
	pair.failRead.Store(true)
	if _, _, err := store.MergeCheckedContext(t.Context(), []Grant{grant}, now); err != nil {
		t.Fatal(err)
	}
	if pair.updates.Load() == before {
		t.Fatal("failed authority read was treated as an unchanged report")
	}
}

func TestSharedIdenticalReportHonorsCanceledContext(t *testing.T) {
	pair := &countedGrantPair{rollingMemory: &rollingMemory{}}
	store := NewStore()
	if err := store.SetPersister(RollingPersister{Backend: pair}); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	grant, err := store.Mint(rollingGrant("canceled", now), time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, _, err := store.MergeCheckedContext(ctx, []Grant{grant}, now); err == nil {
		t.Fatal("canceled report was accepted as a no-op")
	}
}
