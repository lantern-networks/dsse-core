package policycandidate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/lantern-networks/dsse-core/blobstore"
)

// ErrUnavailable means current shared state cannot be used for a decision.
var ErrUnavailable = errors.New("policy candidate shared state unavailable")

type candidateSharedPersister interface {
	blobstore.Persister
	UpdateContext(context.Context, func([]byte) ([]byte, error)) error
}
type candidateLookup struct {
	candidate Candidate
	found     bool
}

// The caller holds mu. Reuse the lifecycle on a detached, memory-only store
// loaded inside the row lock, publishing locally only after confirmed commit.
// No snapshot Save may bypass this transaction for shared candidates.
func sharedCandidateMutation[T any](s *Store, ctx context.Context, edit func(*Store) (T, error)) (T, error) {
	var zero T
	if s.sharedUncertain {
		return zero, fmt.Errorf("%w: shared commit requires reconciliation", ErrPersistence)
	}
	if err := ctx.Err(); err != nil {
		return zero, fmt.Errorf("%w: %w", ErrPersistence, err)
	}
	p := s.persister.(candidateSharedPersister)
	var result T
	var next *Store
	var businessErr error
	prepared := false
	err := p.UpdateContext(ctx, func(raw []byte) ([]byte, error) {
		snapshot, e := s.sharedSnapshotLocked(raw)
		if e != nil {
			return nil, e
		}
		next = &Store{candidates: snapshot}
		result, businessErr = edit(next)
		if businessErr != nil {
			return nil, businessErr
		}
		b, e := json.MarshalIndent(next.candidates, "", "  ")
		prepared = e == nil
		return b, e
	})
	if err != nil {
		if businessErr != nil {
			return zero, businessErr
		}
		// An observation increments a counter: an unknown COMMIT must not be
		// replayed. Stop this store until storage/source reconciliation; comparing
		// payload values cannot prove which writer committed the increment.
		if prepared && !errors.Is(err, blobstore.ErrWriteNotCommitted) {
			s.sharedUncertain = true
		}
		return zero, fmt.Errorf("%w: %w", ErrPersistence, err)
	}
	if next == nil {
		return zero, fmt.Errorf("%w: update callback was not executed", ErrPersistence)
	}
	s.candidates = next.candidates
	s.sharedKnown = true
	s.dirty = false
	return result, nil
}
func (s *Store) sharedSnapshotLocked(raw []byte) (map[string]map[string]Candidate, error) {
	if raw == nil {
		if s.sharedKnown {
			return nil, fmt.Errorf("shared candidate row disappeared")
		}
		return s.cloneLocked(), nil
	}
	return decodeCandidateSnapshot(raw)
}
func (s *Store) refreshSharedLocked(ctx context.Context) error {
	p, ok := s.persister.(candidateSharedPersister)
	if !ok {
		return nil
	}
	if s.sharedUncertain {
		return fmt.Errorf("%w: shared commit requires reconciliation", ErrUnavailable)
	}
	if e := ctx.Err(); e != nil {
		return fmt.Errorf("%w: %w", ErrUnavailable, e)
	}
	raw, e := p.Load()
	if e != nil {
		return fmt.Errorf("%w: %w", ErrUnavailable, e)
	}
	snapshot, e := s.sharedSnapshotLocked(raw)
	if e != nil {
		return fmt.Errorf("%w: %w", ErrUnavailable, e)
	}
	s.candidates = snapshot
	if raw != nil {
		s.sharedKnown = true
	}
	return nil
}
