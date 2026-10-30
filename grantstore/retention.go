package grantstore

import (
	"context"
	"reflect"
	"time"
)

// A signed start can be accepted almost two minutes after issue, then its OIDC
// ceremony can last ten more minutes. Keep even a one-second grant's tombstone
// beyond that combined horizon so a restarted Portal cannot reissue the same
// request after the first grant expires. The extra margin covers clock skew and
// second-resolution timestamps. Rolling upgrades must update authority pruners
// before enabling this issuance path on Edges.
const ExpiredRetention = 15 * time.Minute

func expiredBeyondRetention(g Grant, now time.Time) bool {
	at, err := time.Parse(time.RFC3339, g.ExpiresAt)
	return err == nil && !now.Before(at.Add(ExpiredRetention))
}

func prunableGrant(g Grant, index reauthenticationFenceIndex, now time.Time) bool {
	return expiredBeyondRetention(g, now) && (g.ReauthenticateAfter == "" || redundantReauthenticationFence(g, index))
}

func (s *Store) PruneExpired(ctx context.Context, now time.Time) (int, error) {
	// Until the CP has confirmed the complete fleet membership, a rolling
	// authority only prunes rows that legacy readers never see.
	s.mu.RLock()
	_, mixed := s.persister.(RollingPersister)
	s.mu.RUnlock()
	var n int
	handled, err := s.mutateShared(ctx, func(c *Store) error { var e error; n, e = c.pruneExpiredLocal(now, mixed); return e })
	if !handled {
		return s.pruneExpiredLocal(now, false)
	}
	if err != nil {
		return 0, err
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	s.mu.Lock()
	index := indexReauthenticationFences(s.grants)
	for key, g := range s.pending {
		if prunableGrant(g, index, now) && (!mixed || g.RequiresModernReader()) {
			if _, exists := s.grants[g.GrantID]; !exists {
				delete(s.pending, key)
			}
		}
	}
	s.dirty = len(s.pending) > 0
	s.mu.Unlock()
	return n, nil
}

func (s *Store) pruneExpiredLocal(now time.Time, protectedOnly bool) (int, error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	next := cloneGrants(s.grants)
	index := indexReauthenticationFences(s.grants)
	n := 0
	compacted := false
	for id, g := range next {
		if prunableGrant(g, index, now) && (!protectedOnly || g.RequiresModernReader()) {
			delete(next, id)
			n++
			continue
		}
		if expiredBeyondRetention(g, now) && g.Revoked && g.ReauthenticateAfter != "" && g.Supported() && len(g.UnknownFields) == 0 && (!protectedOnly || g.RequiresModernReader()) {
			small := compactExpiredReauthenticationFence(g)
			if !reflect.DeepEqual(small, g) {
				next[id] = small
				compacted = true
			}
		}
	}
	if n == 0 && !compacted {
		return 0, nil
	}
	if err := s.saveLocked(next); err != nil {
		return 0, err
	}
	s.publishLocked(next)
	for k, g := range s.pending {
		if prunableGrant(g, index, now) {
			delete(s.pending, k)
		}
	}
	s.dirty = len(s.pending) > 0
	return n, nil
}

// Once the independent ceremony/replay horizon has elapsed, the denial needs
// selectors and its cutoff, not personal display claims or single-use evidence.
// Keep the existing protected Grant envelope: old modern readers cannot drop a
// new side-table field. Unknown features/fields are never compacted by this path.
func compactExpiredReauthenticationFence(g Grant) Grant {
	g.UserEmail, g.Username, g.UserDisplayName = "", "", ""
	g.ACR, g.AuthTime = "", ""
	g.AMR = nil
	g.AuthenticationRequestID, g.ReauthenticationStartedAt, g.ConsumedAt = "", "", ""
	features := make([]string, 0, len(g.RequiredFeatures))
	for _, f := range g.RequiredFeatures {
		if f != FeatureSingleRequest {
			features = append(features, f)
		}
	}
	g.RequiredFeatures = features
	return cloneGrant(g)
}

type RetentionStats struct {
	Rows          int
	SnapshotBytes int
}

// No subjects, cookies or grant IDs enter capacity metrics.
func (s *Store) RetentionStats() RetentionStats {
	// Keep the snapshot stable without holding an RW reader lock through all
	// encoding: a queued writer would otherwise block new authorization readers.
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	raw, _ := encodeGrantSnapshot(s.grants)
	return RetentionStats{Rows: len(s.grants), SnapshotBytes: len(raw)}
}
