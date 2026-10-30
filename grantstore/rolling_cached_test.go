package grantstore

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"
)

type versionedRollingMemory struct {
	mu            sync.Mutex
	legacy        []byte
	evidence      []byte
	revision      GrantPairRevision
	fullReads     int
	revisionReads int
	readErr       error
	versionErr    error
}

func (m *versionedRollingMemory) LoadGrantPair(context.Context) ([]byte, []byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]byte(nil), m.legacy...), append([]byte(nil), m.evidence...), m.readErr
}
func (m *versionedRollingMemory) UpdateGrantPair(ctx context.Context, edit func([]byte, []byte) ([]byte, []byte, error)) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	a, b, err := edit(m.legacy, m.evidence)
	if err != nil {
		return err
	}
	m.legacy, m.evidence = append([]byte(nil), a...), append([]byte(nil), b...)
	m.revision.LegacyPresent, m.revision.EvidencePresent = true, true
	m.revision.Legacy++
	m.revision.Evidence++
	return nil
}
func (m *versionedRollingMemory) GrantPairRevision(context.Context) (GrantPairRevision, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.revisionReads++
	return m.revision, m.versionErr
}
func (m *versionedRollingMemory) LoadGrantPairWithRevision(context.Context) (GrantPairRevision, []byte, []byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.fullReads++
	if m.versionErr != nil {
		return GrantPairRevision{}, nil, nil, m.versionErr
	}
	return m.revision, append([]byte(nil), m.legacy...), append([]byte(nil), m.evidence...), m.readErr
}

func TestCachedRollingGrantReaderSeesPeerDenialAndRefusesReadFailure(t *testing.T) {
	backend := &versionedRollingMemory{}
	store := NewStore()
	if err := store.SetPersister(NewCachedRollingPersister(backend)); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	if _, err := store.Mint(rollingGrant("shared", now), time.Hour, now); err != nil {
		t.Fatal(err)
	}
	if rows, err := store.ListChecked("tenant"); err != nil || len(rows) != 1 {
		t.Fatalf("initial grant read: rows=%d err=%v", len(rows), err)
	}
	backend.mu.Lock()
	fullReads := backend.fullReads
	backend.mu.Unlock()
	for i := 0; i < 4; i++ {
		if rows, err := store.ListChecked("tenant"); err != nil || len(rows) != 1 {
			t.Fatalf("unchanged grant read: rows=%d err=%v", len(rows), err)
		}
	}
	backend.mu.Lock()
	if backend.fullReads != fullReads || backend.revisionReads < 4 {
		t.Fatalf("unchanged reads fetched blobs: full=%d before=%d probes=%d", backend.fullReads, fullReads, backend.revisionReads)
	}
	var legacy map[string]Grant
	if err := json.Unmarshal(backend.legacy, &legacy); err != nil {
		backend.mu.Unlock()
		t.Fatal(err)
	}
	g := legacy["shared"]
	g.Revoked = true
	legacy["shared"] = g
	backend.legacy, _ = json.Marshal(legacy)
	backend.revision.Legacy++ // the database trigger also stamps released writers
	backend.mu.Unlock()
	if store.Valid("shared", now) {
		t.Fatal("released writer's revocation was missed")
	}
	backend.mu.Lock()
	backend.revision.Legacy--
	backend.mu.Unlock()
	if _, err := store.ListChecked("tenant"); err == nil {
		t.Fatal("stale replica revision was accepted")
	}
	backend.mu.Lock()
	backend.revision.Legacy++
	backend.versionErr = ErrGrantRevisionUnavailable
	backend.mu.Unlock()
	if _, err := store.ListChecked("tenant"); err == nil {
		t.Fatal("revision support disappeared after initialization")
	}
	backend.mu.Lock()
	backend.versionErr = errors.New("revision authority unavailable")
	backend.mu.Unlock()
	if _, err := store.ListChecked("tenant"); err == nil {
		t.Fatal("failed revision probe served cached grant authority")
	}
}

func TestCachedRollingGrantReaderFallsBackWhenRevisionSchemaIsAbsent(t *testing.T) {
	backend := &versionedRollingMemory{versionErr: ErrGrantRevisionUnavailable}
	store := NewStore()
	if err := store.SetPersister(NewCachedRollingPersister(backend)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ListAllChecked(); err != nil {
		t.Fatal(err)
	}
	backend.mu.Lock()
	backend.readErr = errors.New("legacy full read unavailable")
	backend.mu.Unlock()
	if _, err := store.ListAllChecked(); err == nil {
		t.Fatal("fallback to the old schema hid a failed full read")
	}
}

func TestCachedRollingGrantReaderRejectsMissingAuthorityAfterRebind(t *testing.T) {
	store := NewStore()
	if err := store.SetPersister(NewCachedRollingPersister(&versionedRollingMemory{})); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	if _, err := store.Mint(rollingGrant("old", now), time.Hour, now); err != nil {
		t.Fatal(err)
	}
	if err := store.SetPersister(NewCachedRollingPersister(&versionedRollingMemory{})); err != nil {
		t.Fatal(err)
	}
	if rows, err := store.ListChecked("tenant"); !errors.Is(err, ErrPersistence) || len(rows) != 0 {
		t.Fatalf("missing rebound authority served old grants: rows=%d err=%v", len(rows), err)
	}
}
