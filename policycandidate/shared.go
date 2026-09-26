package policycandidate

import (
	"context"
	"errors"
	"fmt"
	"log"

	"github.com/lantern-networks/dsse-core/blobstore"
)

// ErrUnavailable means current shared state cannot be used for a decision.
var ErrUnavailable = errors.New("policy candidate shared state unavailable")

// ErrReconciliationRequired means a shared COMMIT outcome is unknown and this
// store has stopped. A retry from the caller cannot clear it; an operator must
// compare the shared row with the observation sources and restart the process.
var ErrReconciliationRequired = errors.New("policy candidate commit outcome unknown; reconciliation required")

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
	return sharedCandidateMutationLatching(s, ctx, true, edit)
}

// latchOnUnknown is false only for an edit that is safe to repeat after an unknown outcome (a report, which the
// row's receipts recognise when it is delivered again).
func sharedCandidateMutationLatching[T any](s *Store, ctx context.Context, latchOnUnknown bool, edit func(*Store) (T, error)) (T, error) {
	var zero T
	if s.sharedUncertain {
		return zero, fmt.Errorf("%w: %w", ErrPersistence, ErrReconciliationRequired)
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
		snapshot, receipts, e := s.sharedSnapshotLocked(raw)
		if e != nil {
			return nil, e
		}
		// Receipts written by reports are part of the row and survive every other edit.
		next = &Store{candidates: snapshot, receipts: receipts}
		result, businessErr = edit(next)
		if businessErr != nil {
			return nil, businessErr
		}
		b, e := encodeCandidateRow(next.candidates, next.receipts)
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
		if latchOnUnknown && prepared && !errors.Is(err, blobstore.ErrWriteNotCommitted) {
			s.sharedUncertain = true
			// The only trace an operator gets: data-path observers discard the
			// error and Console reads answer a generic 503.
			log.Printf("policy_candidates: shared COMMIT outcome unknown (%v); candidate writes and reads are stopped on this process until the shared row is reconciled and the process restarted", err)
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
func (s *Store) sharedSnapshotLocked(raw []byte) (map[string]map[string]Candidate, map[string]ReportReceipt, error) {
	if raw == nil {
		if s.sharedKnown {
			return nil, nil, fmt.Errorf("shared candidate row disappeared")
		}
		return s.cloneLocked(), nil, nil
	}
	return decodeCandidateRow(raw)
}
func (s *Store) refreshSharedLocked(ctx context.Context) error {
	p, ok := s.persister.(candidateSharedPersister)
	if !ok {
		return nil
	}
	if s.sharedUncertain {
		return fmt.Errorf("%w: %w", ErrUnavailable, ErrReconciliationRequired)
	}
	if e := ctx.Err(); e != nil {
		return fmt.Errorf("%w: %w", ErrUnavailable, e)
	}
	raw, e := p.Load()
	if e != nil {
		return fmt.Errorf("%w: %w", ErrUnavailable, e)
	}
	snapshot, _, e := s.sharedSnapshotLocked(raw)
	if e != nil {
		return fmt.Errorf("%w: %w", ErrUnavailable, e)
	}
	s.candidates = snapshot
	if raw != nil {
		s.sharedKnown = true
	}
	return nil
}

// ReconciliationRequired reports whether an unknown shared COMMIT stopped this
// store, so status surfaces can say so instead of a generic unavailability.
func (s *Store) ReconciliationRequired() bool {
	if s == nil {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.sharedUncertain
}
