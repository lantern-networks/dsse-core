package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/authrollout"
	"github.com/lantern-networks/dsse-core/grantstore"
)

type authenticationGrantRequest struct {
	Grant           grantstore.Grant `json:"grant"`
	TTLSeconds      int64            `json:"ttl_seconds,omitempty"`
	ExpiresNotAfter time.Time        `json:"expires_not_after,omitempty"`
}
type authenticationGrantResponse struct {
	After string            `json:"reauthenticate_after,omitempty"`
	Grant *grantstore.Grant `json:"grant,omitempty"`
}

// Both operations use the existing authenticated Edge->CP management channel.
// The authority checks a revocation and a replacement mint in the same shared
// store transaction. A local Edge mint followed by best-effort reporting cannot
// close the race with an administrator's concurrent revocation.
func registerAuthenticationGrantAuthority(mux *http.ServeMux, store *grantstore.Store, configSourceURL string, authorizeEdge func(*http.Request, string) bool) {
	if store == nil || strings.TrimSpace(configSourceURL) != "" {
		return
	}
	handler := func(mint bool) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			r = r.WithContext(captureCPWriteLease(r.Context()))
			if authorizeEdge == nil {
				writeError(w, 403, fmt.Errorf("verified Edge identity required"))
				return
			}
			var body authenticationGrantRequest
			d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
			d.DisallowUnknownFields()
			if d.Decode(&body) != nil || d.Decode(&struct{}{}) != io.EOF || body.Grant.TenantID == "" {
				writeError(w, 400, fmt.Errorf("invalid authentication authority request"))
				return
			}
			if !authorizeEdge(r, body.Grant.TenantID) {
				writeError(w, 403, fmt.Errorf("Edge is not authorized for this tenant"))
				return
			}
			if !mint {
				after, err := store.ReauthenticationAfterChecked(body.Grant, body.Grant.Scope)
				if err != nil {
					writeError(w, 503, fmt.Errorf("authentication authority unavailable"))
					return
				}
				response := authenticationGrantResponse{}
				if !after.IsZero() {
					response.After = after.UTC().Format(time.RFC3339Nano)
				}
				writeJSON(w, 200, response)
				return
			}
			if body.TTLSeconds < 1 || body.TTLSeconds > 86400 || body.Grant.Scope == "" || body.Grant.UserID == "" || body.Grant.IdPID == "" || body.Grant.Issuer == "" || body.Grant.Revoked || body.Grant.ConsumedAt != "" || body.Grant.ReauthenticateAfter != "" || !body.Grant.Supported() || len(body.Grant.UnknownFields) > 0 {
				writeError(w, 400, fmt.Errorf("invalid authentication grant"))
				return
			}
			now := time.Now().UTC()
			ttl := time.Duration(body.TTLSeconds) * time.Second
			if body.ExpiresNotAfter.IsZero() || !now.Before(body.ExpiresNotAfter) {
				writeError(w, 400, fmt.Errorf("authentication grant deadline elapsed"))
				return
			}
			if remaining := body.ExpiresNotAfter.Sub(now); remaining < ttl {
				ttl = remaining
			}
			grant, err := mintAuthenticationGrant(r.Context(), store, body.Grant, ttl, now)
			if err != nil {
				writeError(w, 409, fmt.Errorf("authentication evidence could not be admitted"))
				return
			}
			writeJSON(w, 200, authenticationGrantResponse{Grant: &grant})
		}
	}
	mux.HandleFunc("POST /authentication-grants/reauthentication", handler(false))
	mux.HandleFunc("POST /authentication-grants/mint", handler(true))
}

func (g *grantCPReporter) authenticationAuthority(ctx context.Context, operation string, body authenticationGrantRequest) (authenticationGrantResponse, error) {
	var result authenticationGrantResponse
	if g == nil || g.client == nil || strings.TrimSpace(g.url) == "" {
		return result, fmt.Errorf("authentication authority unavailable")
	}
	data, err := json.Marshal(body)
	if err != nil {
		return result, err
	}
	base := strings.TrimRight(strings.TrimSpace(g.authorityURL), "/")
	if base == "" {
		base = strings.TrimSuffix(g.url, "/grant-report")
	}
	// Authentication authority is management-only. The data-door selector is
	// used by legacy reports, but its listener deliberately rejects /auth*.
	if current := controlChannelCurrentBaseURL(); current != "" {
		base = strings.TrimSuffix(current, "/")
	}
	req, err := http.NewRequestWithContext(ctx, "POST", base+"/authentication-grants/"+operation, bytes.NewReader(data))
	if err != nil {
		return result, fmt.Errorf("authentication authority request failed")
	}
	req.Header.Set("Content-Type", "application/json")
	client := *g.client
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := client.Do(req)
	if err != nil {
		return result, fmt.Errorf("authentication authority transport failed")
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return result, fmt.Errorf("authentication authority refused the request")
	}
	d := json.NewDecoder(io.LimitReader(response.Body, 64<<10))
	d.DisallowUnknownFields()
	if d.Decode(&result) != nil || d.Decode(&struct{}{}) != io.EOF {
		return result, fmt.Errorf("invalid authentication authority response")
	}
	if (operation == "mint" && (result.Grant == nil || result.After != "")) || (operation == "reauthentication" && result.Grant != nil) {
		return authenticationGrantResponse{}, fmt.Errorf("unexpected authentication authority response")
	}
	return result, nil
}

func (b *clientlessBroker) reauthenticationBoundary(ctx context.Context, selector grantstore.Grant) (time.Time, error) {
	if !b.rollout.featureEnabled(authrollout.RevocationReauthenticationFeature) {
		// Before activation the CP may still be a released binary without these
		// routes. Local denials remain effective; no authority fallback is allowed
		// once the durable activation latch has been observed.
		return b.grants.ReauthenticationAfterChecked(selector, selector.Scope)
	}
	if b.authority != nil {
		ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		r, err := b.authority.authenticationAuthority(ctx, "reauthentication", authenticationGrantRequest{Grant: selector})
		if err != nil {
			return time.Time{}, err
		}
		if r.After == "" {
			return time.Time{}, nil
		}
		return time.Parse(time.RFC3339Nano, r.After)
	}
	if b.authorityRequired {
		return time.Time{}, fmt.Errorf("authentication authority is not configured")
	}
	return b.grants.ReauthenticationAfterChecked(selector, selector.Scope)
}

func (b *clientlessBroker) mintGrant(ctx context.Context, candidate grantstore.Grant, ttl time.Duration, now time.Time) (grantstore.Grant, error) {
	if b.authority == nil || !b.rollout.featureEnabled(authrollout.RevocationReauthenticationFeature) {
		if b.authorityRequired && b.rollout.featureEnabled(authrollout.RevocationReauthenticationFeature) {
			return grantstore.Grant{}, fmt.Errorf("authentication authority is not configured")
		}
		return mintAuthenticationGrant(ctx, b.grants, candidate, ttl, now)
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	r, err := b.authority.authenticationAuthority(ctx, "mint", authenticationGrantRequest{Grant: candidate, TTLSeconds: int64(ttl / time.Second), ExpiresNotAfter: now.Add(ttl)})
	if err != nil || r.Grant == nil {
		return grantstore.Grant{}, fmt.Errorf("authentication authority did not confirm the grant")
	}
	g := *r.Grant
	// An authority response cannot substitute a different owner or resource.
	issued, issuedErr := time.Parse(time.RFC3339, g.IssuedAt)
	expires, expiresErr := time.Parse(time.RFC3339, g.ExpiresAt)
	if g.GrantID != candidate.GrantID || g.TenantID != candidate.TenantID || g.UserID != candidate.UserID || g.IdPID != candidate.IdPID || g.Issuer != candidate.Issuer || g.DeviceID != candidate.DeviceID || g.OSPrincipal != candidate.OSPrincipal || g.OSSession != candidate.OSSession || g.Scope != candidate.Scope || g.AuthTime != candidate.AuthTime || g.ProviderConfigSHA256 != candidate.ProviderConfigSHA256 || g.ACR != candidate.ACR || !slices.Equal(g.AMR, candidate.AMR) || g.AuthenticationRequestID != candidate.AuthenticationRequestID || g.ReauthenticationStartedAt != candidate.ReauthenticationStartedAt || g.Revoked || g.ConsumedAt != "" || g.ReauthenticateAfter != "" || !g.Supported() || !slices.Contains(g.RequiredFeatures, grantstore.FeatureScopedAuthorization) || issuedErr != nil || expiresErr != nil || issued.Before(now.Add(-5*time.Second)) || issued.After(time.Now().Add(5*time.Second)) || !expires.After(issued) || expires.After(issued.Add(ttl)) || expires.After(now.Add(ttl)) {
		return grantstore.Grant{}, fmt.Errorf("authentication authority evidence mismatch")
	}
	if _, _, err := b.grants.MergeAuthorityEvidence([]grantstore.Grant{g}, now); err != nil {
		return grantstore.Grant{}, err
	}
	return g, nil
}
