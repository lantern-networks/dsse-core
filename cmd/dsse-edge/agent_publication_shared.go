package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/lantern-networks/dsse-core/agentpolicy"
)

var errPublicationStore = errors.New("published release storage unavailable")

func publicationWriteContext(ctx context.Context) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	if _, ok := ctx.Value(cpWriteLeaseKey{}).(cpWriteLease); !ok {
		ctx = captureCPWriteLease(ctx)
	}
	return ctx
}

// Candidates have no persister or artifact shelf; edits cannot publish local state
// or remove bytes before the shared transaction commits.
func decodeSharedPublication(raw []byte, known bool) (*publishedAgentUpdateStore, error) {
	candidate := newPublishedAgentUpdateStore()
	if len(raw) == 0 {
		if known {
			return nil, fmt.Errorf("known publication row is missing")
		}
		return candidate, nil
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil, fmt.Errorf("publication state is null")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, err
	}
	if schema, ok := fields["schema"]; ok {
		var value string
		if json.Unmarshal(schema, &value) != nil || value != "published_agent_updates.v2" {
			return nil, fmt.Errorf("unsupported publication schema")
		}
	}
	// Pending/legacy are optional in the existing v2 encoding. Active is required.
	if _, versioned := fields["schema"]; versioned {
		active, ok := fields["active"]
		if !ok || bytes.Equal(bytes.TrimSpace(active), []byte("null")) {
			return nil, fmt.Errorf("publication active set is missing")
		}
	}
	if err := candidate.adopt(raw, "shared publication", ""); err != nil {
		return nil, err
	}
	return candidate, nil
}

// Caller holds s.mu. The callback always sees the current database row.
func (s *publishedAgentUpdateStore) updatePublicationLocked(ctx context.Context, edit func(*publishedAgentUpdateStore) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if shared, ok := s.blob.(interface {
		UpdateContext(context.Context, func([]byte) ([]byte, error)) error
	}); ok {
		var committed *publishedAgentUpdateStore
		err := shared.UpdateContext(ctx, func(raw []byte) ([]byte, error) {
			candidate, err := decodeSharedPublication(raw, s.sharedKnown)
			if err != nil {
				return nil, err
			}
			if err = edit(candidate); err != nil {
				return nil, err
			}
			next, err := json.Marshal(publishedStoreFile{Schema: "published_agent_updates.v2", Active: candidate.envelopes, Pending: candidate.pending, Legacy: candidate.legacy})
			if err == nil {
				committed = candidate
			}
			return next, err
		})
		if err != nil {
			return err
		}
		s.envelopes, s.pending, s.legacy = committed.envelopes, committed.pending, committed.legacy
		s.sharedKnown = true
		return nil
	}
	candidate := newPublishedAgentUpdateStore()
	candidate.envelopes = copyEnvelopes(s.envelopes)
	candidate.pending = copyEnvelopes(s.pending)
	candidate.legacy = copyEnvelopes(s.legacy)
	if err := edit(candidate); err != nil {
		return err
	}
	if err := s.persistLocked(candidate.envelopes, candidate.pending); err != nil {
		return err
	}
	s.envelopes, s.pending = candidate.envelopes, candidate.pending
	return nil
}

// PublicationFor gives management and replication a single confirmed active/pending
// view. A failed shared read is an error rather than an empty or stale catalogue.
func (s *publishedAgentUpdateStore) PublicationFor(ctx context.Context, tenant string) (map[string]agentpolicy.Envelope, map[string]agentpolicy.Envelope, error) {
	if s == nil {
		return map[string]agentpolicy.Envelope{}, map[string]agentpolicy.Envelope{}, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	if _, shared := s.blob.(interface {
		UpdateContext(context.Context, func([]byte) ([]byte, error)) error
	}); shared {
		raw, err := s.blob.Load()
		if err != nil {
			return nil, nil, err
		}
		candidate, err := decodeSharedPublication(raw, s.sharedKnown)
		if err != nil {
			return nil, nil, err
		}
		s.envelopes, s.pending, s.legacy = candidate.envelopes, candidate.pending, candidate.legacy
		s.sharedKnown = s.sharedKnown || len(raw) > 0
	}
	candidate := newPublishedAgentUpdateStore()
	candidate.envelopes = s.envelopes
	candidate.pending = s.pending
	candidate.legacy = s.legacy
	return candidate.ForTenant(tenant), scopedTo(s.pending, tenant), nil
}
