package grantstore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"sync"
)

// ErrGrantRevisionUnavailable allows an older database schema to retain the
// original full-read behavior. Other read errors must fail closed.
var ErrGrantRevisionUnavailable = errors.New("grant blob revision schema is unavailable")

// GrantPairRevision is one consistent observation of both rolling grant keys.
// Presence is part of the identity: deleting and recreating either key must
// never be mistaken for an unchanged snapshot.
type GrantPairRevision struct {
	LegacyPresent   bool
	Legacy          int64
	EvidencePresent bool
	Evidence        int64
}

// VersionedRollingBackend is an optional read optimization. Implementations
// must return both revisions from one database snapshot. The full read must
// likewise return the payloads and revisions from one snapshot. Every write,
// including writes by released binaries, must change the corresponding token.
type VersionedRollingBackend interface {
	RollingBackend
	GrantPairRevision(context.Context) (GrantPairRevision, error)
	LoadGrantPairWithRevision(context.Context) (GrantPairRevision, []byte, []byte, error)
}

// CachedRollingPersister retains only the last verified pair. It never treats
// a failed revision probe as an empty or unchanged authority. Writes continue
// through the existing two-key transaction; its next read sees the new token.
type CachedRollingPersister struct {
	RollingPersister
	mu            sync.Mutex
	revision      GrantPairRevision
	snapshot      []byte
	digest        [32]byte
	initialized   bool
	legacyFloor   int64
	evidenceFloor int64
}

func NewCachedRollingPersister(backend RollingBackend) *CachedRollingPersister {
	return &CachedRollingPersister{RollingPersister: RollingPersister{Backend: backend}}
}

func (p *CachedRollingPersister) Load() ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	raw, err := p.loadLocked()
	return bytes.Clone(raw), err
}

// LoadIfUnchanged confirms authority without copying or hashing the previous
// full snapshot in the Store. An unavailable revision schema uses a full read
// and never reports an unchanged authority; it cannot bless a cached grant.
func (p *CachedRollingPersister) LoadIfUnchanged(digest [32]byte) ([]byte, bool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	raw, err := p.loadLocked()
	if err != nil {
		return nil, false, err
	}
	// Nil means that no durable authority row exists. The Store must still
	// apply its authorityKnown check rather than treating that absence as a
	// successful unchanged read after a persister rebind.
	if p.initialized && p.snapshot != nil && p.digest == digest {
		return nil, true, nil
	}
	return bytes.Clone(raw), false, nil
}

func (p *CachedRollingPersister) loadLocked() ([]byte, error) {
	versioned, ok := p.Backend.(VersionedRollingBackend)
	if !ok {
		return p.RollingPersister.Load()
	}
	if p.initialized {
		revision, err := versioned.GrantPairRevision(context.Background())
		if errors.Is(err, ErrGrantRevisionUnavailable) {
			return nil, ErrPersistence
		}
		if err != nil {
			return nil, err
		}
		if p.regressed(revision) {
			return nil, ErrPersistence
		}
		if revision == p.revision {
			return p.snapshot, nil
		}
	}
	revision, legacy, evidence, err := versioned.LoadGrantPairWithRevision(context.Background())
	if errors.Is(err, ErrGrantRevisionUnavailable) {
		if p.initialized {
			return nil, ErrPersistence
		}
		return p.RollingPersister.Load()
	}
	if err != nil {
		return nil, err
	}
	if p.regressed(revision) {
		return nil, ErrPersistence
	}
	var snapshot []byte
	if legacy != nil || evidence != nil {
		rows, err := joinRolling(legacy, evidence)
		if err != nil {
			return nil, err
		}
		snapshot, err = encodeGrantSnapshot(rows)
		if err != nil {
			return nil, err
		}
	}
	p.revision, p.snapshot, p.digest, p.initialized = revision, snapshot, sha256.Sum256(snapshot), true
	if revision.LegacyPresent && revision.Legacy > p.legacyFloor {
		p.legacyFloor = revision.Legacy
	}
	if revision.EvidencePresent && revision.Evidence > p.evidenceFloor {
		p.evidenceFloor = revision.Evidence
	}
	return p.snapshot, nil
}

func (p *CachedRollingPersister) regressed(next GrantPairRevision) bool {
	if !p.initialized {
		return false
	}
	// Application writes never delete either whole key. Losing a key or reading
	// a lower sequence indicates a stale replica or authority rollback.
	return (p.revision.LegacyPresent && !next.LegacyPresent) ||
		(p.revision.EvidencePresent && !next.EvidencePresent) ||
		(next.LegacyPresent && next.Legacy < p.legacyFloor) ||
		(next.EvidencePresent && next.Evidence < p.evidenceFloor)
}
