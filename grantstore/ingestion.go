package grantstore

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/idpregistry"
)

var ErrConflict = errors.New("access grant ID or authorization conflicts with an existing record")
var ErrInvalidGrant = errors.New("invalid access grant identity or lifetime")

func cloneGrant(g Grant) Grant {
	addReauthenticationFeature(&g)
	if g.OSPrincipal != "" || g.OSSession != "" {
		found := false
		for _, f := range g.RequiredFeatures {
			if f == FeatureDeviceUser {
				found = true
			}
		}
		if !found {
			g.RequiredFeatures = append(append([]string(nil), g.RequiredFeatures...), FeatureDeviceUser)
		}
	}

	if g.AuthenticationRequestID != "" {
		found := false
		for _, f := range g.RequiredFeatures {
			if f == FeatureSingleRequest {
				found = true
			}
		}
		if !found {
			g.RequiredFeatures = append(append([]string(nil), g.RequiredFeatures...), FeatureSingleRequest)
		}
	}
	g.AMR = append([]string(nil), g.AMR...)
	g.RequiredFeatures = append([]string(nil), g.RequiredFeatures...)
	if g.UnknownFields != nil {
		m := map[string]json.RawMessage{}
		for k, v := range g.UnknownFields {
			m[k] = append(json.RawMessage(nil), v...)
		}
		g.UnknownFields = m
	}
	return g
}
func cloneGrants(grants map[string]Grant) map[string]Grant {
	out := make(map[string]Grant, len(grants)+1)
	for id, g := range grants {
		out[id] = cloneGrant(g)
	}
	return out
}
func validateGrant(g Grant) error {
	if g.OSPrincipal != "" || g.OSSession != "" {
		if g.DeviceID == "" || g.Issuer == "" || !idpregistry.ValidOSPrincipal(g.OSPrincipal) || !idpregistry.ValidOSSession(g.OSSession) {
			return ErrInvalidGrant
		}
	}

	for _, f := range g.RequiredFeatures {
		if f == "" || len(f) > 128 || (f == FeatureSingleRequest && g.AuthenticationRequestID == "") || (f == FeatureDeviceUser && (g.OSPrincipal == "" || g.OSSession == "")) {
			return ErrInvalidGrant
		}
		if f == FeatureScopedAuthorization && g.Scope == "" {
			return ErrInvalidGrant
		}
	}
	if g.ProviderConfigSHA256 != "" || g.Issuer != "" {
		digest, err := hex.DecodeString(g.ProviderConfigSHA256)
		if err != nil || len(digest) != 32 || g.Issuer == "" || g.UserID == "" || g.IdPID == "" {
			return ErrInvalidGrant
		}
	}
	if g.GrantID == "" || g.TenantID == "" || strings.TrimSpace(g.GrantID) != g.GrantID || strings.TrimSpace(g.TenantID) != g.TenantID || strings.ContainsRune(g.GrantID, '\x00') || strings.ContainsRune(g.TenantID, '\x00') {
		return ErrInvalidGrant
	}
	issued, ie := time.Parse(time.RFC3339, g.IssuedAt)
	expires, ee := time.Parse(time.RFC3339, g.ExpiresAt)
	if ie != nil || ee != nil || !expires.After(issued) {
		return ErrInvalidGrant
	}
	if g.AuthenticationRequestID != "" && (g.ReauthenticationStartedAt == "" || g.DeviceID == "" || len(g.AuthenticationRequestID) > 128) {
		return ErrInvalidGrant
	}
	if g.ConsumedAt != "" {
		consumed, err := time.Parse(time.RFC3339, g.ConsumedAt)
		if err != nil || !g.Revoked || g.AuthenticationRequestID == "" || consumed.Before(issued) || consumed.After(expires) {
			return ErrInvalidGrant
		}
	}
	if g.ReauthenticateAfter != "" {
		after, err := time.Parse(time.RFC3339Nano, g.ReauthenticateAfter)
		if err != nil || !g.Revoked || after.Unix() <= 0 {
			return ErrInvalidGrant
		}
	}
	if g.ReauthenticationStartedAt != "" {
		started, se := time.Parse(time.RFC3339, g.ReauthenticationStartedAt)
		auth, ae := time.Parse(time.RFC3339, g.AuthTime)
		if se != nil || ae != nil || started.Unix() <= 0 || started.After(issued) || auth.Before(started) || auth.After(issued) || g.Issuer == "" || g.Scope == "" {
			return ErrInvalidGrant
		}
	}
	if g.AuthTime != "" {
		auth, err := time.Parse(time.RFC3339, g.AuthTime)
		if err != nil || auth.Unix() <= 0 || auth.After(issued.Add(time.Minute)) {
			return ErrInvalidGrant
		}
	}
	return nil
}
func sameAuthorization(a, b Grant) bool {
	a, b = cloneGrant(a), cloneGrant(b)
	a.Revoked, b.Revoked = false, false
	a.ConsumedAt, b.ConsumedAt = "", ""
	a.ReauthenticateAfter, b.ReauthenticateAfter = "", ""
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
func (s *Store) mergeLocal(incoming []Grant, now time.Time) (added, updated int, err error) {
	return s.mergeLocalWithEvidence(incoming, now, false)
}

func (s *Store) mergeLocalWithEvidence(incoming []Grant, now time.Time, authorityEvidence bool) (added, updated int, err error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	proposals := make(map[string]Grant, len(incoming))
	activeConflicts := map[string]bool{}
	for _, raw := range incoming {
		g := cloneGrant(raw)
		if prev, ok := s.grants[g.GrantID]; ok && !prev.RequiresModernReader() && !g.RequiresModernReader() && g.Issuer == "" && g.ProviderConfigSHA256 == "" {
			a, b := g, prev
			a.Revoked = false
			b.Revoked = false
			x, _ := legacyProjection(a)
			y, _ := legacyProjection(b)
			if string(x) == string(y) {
				revoked := g.Revoked
				g = cloneGrant(prev)
				g.Revoked = g.Revoked || revoked
			}
		}
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
			if !prev.Revoked && !g.Revoked && !sameAuthorization(prev, g) && !(authorityEvidence && authorityEvidenceUpgrade(prev, g)) {
				return 0, 0, ErrConflict
			}
		}
	}
	active := map[string]Grant{}
	enriched := 0
	for id, g := range proposals {
		if prev, ok := s.grants[id]; ok {
			if g.Revoked && (!prev.Revoked || laterBoundary(prev.ReauthenticateAfter, g.ReauthenticateAfter) != prev.ReauthenticateAfter) {
				prev.Revoked = true
				if g.ConsumedAt != "" {
					prev.ConsumedAt = g.ConsumedAt
				}
				prev.ReauthenticateAfter = laterBoundary(prev.ReauthenticateAfter, g.ReauthenticateAfter)
				prev = cloneGrant(prev)
				s.grants[id] = prev
				updated++
			}
			if authorityEvidence && !prev.Revoked && !g.Revoked && authorityEvidenceUpgrade(prev, g) {
				active[id] = g
				enriched++
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
		s.rebuildReauthenticationIndexLocked()
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
		added += len(active) - enriched
		updated += enriched
		if !denialChanged {
			s.generation++
		}
	}
	return added, updated, nil
}

func (s *Store) MergeChecked(incoming []Grant, now time.Time) (int, int, error) {
	return s.MergeCheckedContext(context.Background(), incoming, now)
}

// Only a verified authority may restore evidence omitted by a released decoder.
// Nothing already known, including auth_time and unknown future fields, may be
// replaced. This cannot turn an ordinary grant into a single-request grant.
func authorityEvidenceUpgrade(old, full Grant) bool {
	if old.Revoked || full.Revoked || old.Issuer != "" || old.ProviderConfigSHA256 != "" || old.RequiresModernReader() || full.RequiresModernReader() || len(old.UnknownFields) != 0 || len(full.UnknownFields) != 0 || full.Issuer == "" || full.ProviderConfigSHA256 == "" {
		return false
	}
	if old.AuthTime != "" && old.AuthTime != full.AuthTime {
		return false
	}
	stripped := cloneGrant(full)
	stripped.Issuer, stripped.ProviderConfigSHA256, stripped.AuthTime = "", "", old.AuthTime
	return sameAuthorization(old, stripped)
}
