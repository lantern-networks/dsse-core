package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"github.com/lantern-networks/dsse-core/grantstore"
)

// An acknowledgement may be lost after commit. Read the same grant ID
// once from authority and compare every field; never replay the code exchange or
// mint another grant. A failed read, different row or revocation remains denial.
func mintAuthenticationGrant(ctx context.Context, store *grantstore.Store, candidate grantstore.Grant, ttl time.Duration, now time.Time) (grantstore.Grant, error) {
	if candidate.Scope == "" {
		return grantstore.Grant{}, grantstore.ErrInvalidGrant
	}
	if !slices.Contains(candidate.RequiredFeatures, grantstore.FeatureScopedAuthorization) {
		candidate.RequiredFeatures = append(candidate.RequiredFeatures, grantstore.FeatureScopedAuthorization)
	}
	grant, err := store.MintContext(ctx, candidate, ttl, now)
	if err == nil || !errors.Is(err, grantstore.ErrPersistence) {
		return grant, err
	}
	if ttl <= 0 {
		ttl = 8 * time.Hour
	}
	candidate.IssuedAt = now.UTC().Format(time.RFC3339)
	candidate.ExpiresAt = now.UTC().Add(ttl).Format(time.RFC3339)
	candidate.Revoked = false
	confirmed, ok := store.Get(candidate.GrantID)
	expires, parseErr := time.Parse(time.RFC3339, candidate.ExpiresAt)
	expectedJSON, expectedErr := json.Marshal(candidate)
	actualJSON, actualErr := json.Marshal(confirmed)
	if ok && expectedErr == nil && actualErr == nil && parseErr == nil && time.Now().Before(expires) && bytes.Equal(expectedJSON, actualJSON) {
		return confirmed, nil
	}
	return grantstore.Grant{}, err
}
