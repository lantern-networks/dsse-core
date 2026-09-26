package appcatalog

import (
	"context"
	"errors"
	"reflect"
	"time"
)

var ErrCandidateApplicationConflict = errors.New("application ID is already in use with different settings; reconcile the application before adopting this candidate")

// CandidatePublisher preserves existing applications when adoption is retried
// after only the application half of a multi-store operation was saved.
type CandidatePublisher interface {
	CreateOrMatch(context.Context, Entry, string, time.Time) (Entry, error)
}

// SameCandidatePublication compares authored settings, ignoring save/probe times.
// It does not turn a matching application into proof of candidate approval.
func SameCandidatePublication(current, requested Entry) bool {
	current, requested = copyEntry(current), copyEntry(requested)
	current.UpdatedAt, requested.UpdatedAt = nil, nil
	current.LastProbeAt, requested.LastProbeAt = nil, nil
	return reflect.DeepEqual(current, requested)
}

func (store *Store) CreateOrMatch(ctx context.Context, application Entry, tenantID string, now time.Time) (Entry, error) {
	normalized, err := normalize(application, tenantID, now)
	if err != nil {
		return Entry{}, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return Entry{}, err
	}
	if _, seeded := store.seed[normalized.TenantID][normalized.ApplicationID]; seeded {
		return Entry{}, ErrCandidateApplicationConflict
	}
	if current, found := store.applications[normalized.TenantID][normalized.ApplicationID]; found {
		if !SameCandidatePublication(current, normalized) {
			return Entry{}, ErrCandidateApplicationConflict
		}
		return copyEntry(current), nil
	}
	if err := store.putLocked(normalized); err != nil {
		return Entry{}, err
	}
	return copyEntry(normalized), nil
}
