package grantstore

import (
	"errors"
	"reflect"
	"strings"
	"time"
)

var ErrConflict = errors.New("access grant ID or authorization conflicts with an existing record")
var ErrInvalidGrant = errors.New("invalid access grant identity or lifetime")

func cloneGrant(g Grant) Grant { g.AMR = append([]string(nil), g.AMR...); return g }
func cloneGrants(grants map[string]Grant) map[string]Grant {
	out := make(map[string]Grant, len(grants)+1)
	for id, g := range grants {
		out[id] = cloneGrant(g)
	}
	return out
}
func validateGrant(g Grant) error {
	if g.GrantID == "" || g.TenantID == "" || strings.TrimSpace(g.GrantID) != g.GrantID || strings.TrimSpace(g.TenantID) != g.TenantID || strings.ContainsRune(g.GrantID, '\x00') || strings.ContainsRune(g.TenantID, '\x00') {
		return ErrInvalidGrant
	}
	issued, ie := time.Parse(time.RFC3339, g.IssuedAt)
	expires, ee := time.Parse(time.RFC3339, g.ExpiresAt)
	if ie != nil || ee != nil || !expires.After(issued) {
		return ErrInvalidGrant
	}
	return nil
}
func sameAuthorization(a, b Grant) bool {
	a, b = cloneGrant(a), cloneGrant(b)
	a.Revoked, b.Revoked = false, false
	return reflect.DeepEqual(a, b)
}

// MergeChecked validates the complete batch before changing anything. IDs and
// authorization are immutable, while revocation is monotonic. A valid incoming
// revocation keeps the original claims and cannot be undone by a stale active copy.
//
// After validation, denials take effect locally before saving and remain on a save
// error. New active grants are adopted only after a successful save. An unchanged
// replay retries unsaved denials; a clean replay neither writes nor advances generation.
// Counts describe live additions/denials, which can be partial when saving fails.
func (s *Store) MergeChecked(incoming []Grant, now time.Time) (added, updated int, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	proposals := make(map[string]Grant, len(incoming))
	activeConflicts := map[string]bool{}
	for _, raw := range incoming {
		g := cloneGrant(raw)
		if e := validateGrant(g); e != nil {
			return 0, 0, e
		}
		if prev, ok := proposals[g.GrantID]; ok {
			if prev.TenantID != g.TenantID {
				return 0, 0, ErrConflict
			}
			if prev.Revoked {
				continue
			}
			if !g.Revoked && !sameAuthorization(prev, g) {
				activeConflicts[g.GrantID] = true
			}
		}
		proposals[g.GrantID] = g
	}
	for id := range activeConflicts {
		if !proposals[id].Revoked {
			return 0, 0, ErrConflict
		}
	}
	// Check all attribution and active-authorization conflicts before any denial or admission.
	for id, g := range proposals {
		if prev, ok := s.grants[id]; ok {
			if prev.TenantID != g.TenantID {
				return 0, 0, ErrConflict
			}
			if !prev.Revoked && !g.Revoked && !sameAuthorization(prev, g) {
				return 0, 0, ErrConflict
			}
		}
	}
	active := map[string]Grant{}
	for id, g := range proposals {
		if prev, ok := s.grants[id]; ok {
			if !prev.Revoked && g.Revoked {
				prev.Revoked = true
				s.grants[id] = prev
				updated++
			}
			continue
		}
		if g.Revoked {
			s.grants[id] = g
			added++
			continue
		}
		expires, _ := time.Parse(time.RFC3339, g.ExpiresAt)
		if now.Before(expires) {
			active[id] = g
		}
	}
	denialChanged := added > 0 || updated > 0
	if denialChanged {
		s.dirty = true
		s.generation++
	}
	if len(active) == 0 && !s.dirty {
		return added, updated, nil
	}
	candidate := cloneGrants(s.grants)
	for id, g := range active {
		candidate[id] = g
	}
	if err := s.saveLocked(candidate); err != nil && !savedNonAtomically(err) {
		return added, updated, err
	}
	s.grants, s.dirty = candidate, false
	if len(active) > 0 {
		added += len(active)
		if !denialChanged {
			s.generation++
		}
	}
	return added, updated, nil
}
