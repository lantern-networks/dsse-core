package eastwest

import (
	"fmt"
	"github.com/lantern-networks/dsse-core/policy"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/model"
)

// east_west_grant: E3 of the east-west per-hop authorization design. After the out-of-band ceremony (E4)
// proves the user's identity for a held flow, an ephemeral grant is issued against the challenge. The
// grant RELEASES the authenticate-mode hold for its bound (identity x device x destination x protocol)
// until it expires, so re-access within the TTL is silent.
//
// TTL: default 1 day. The maximum is admin-configurable (NOT hard-capped) -- that tiering is E6. Per the
// design, a long TTL is only safe because of continuous revocation (E5): posture/agent-tamper/idp-risk/
// idle revoke the grant immediately. E3 issues + releases; E5 revokes.
const eastWestGrantDefaultTTL = 24 * time.Hour

type grantStore interface {
	IssueEastWestGrant(tenantID string, grant decision.EastWestGrant)
	EastWestGrantsFor(tenantID string, now time.Time) []decision.EastWestGrant
	RevokeEastWestGrants(tenantID, scopeType, scopeID string) int
	EastWestRulesFor(tenantID string) []decision.EastWestRule
	EastWestMaxGrantTTL(tenantID string) int
}

// EffectiveTTL caps a requested grant lifetime by the per-rule sensitivity tier (MaxTTLSeconds of
// the governing east-west rule) and the per-tenant admin maximum (E6). Returns the smallest applicable.
func EffectiveTTL(grantStore grantStore, tenantID string, binding decision.EastWestGrant, requested time.Duration) time.Duration {
	ttl := requested
	req := model.DecisionRequest{
		SubjectUserID: binding.SubjectUserID, UserID: binding.SubjectUserID, DeviceID: binding.DeviceID,
		Destination: binding.Destination, ApplicationID: binding.Destination, ServiceFamily: binding.Protocol,
	}
	if rule, ok := decision.MatchedEastWestRule(grantStore.EastWestRulesFor(tenantID), req); ok && rule.MaxTTLSeconds > 0 {
		if cap := time.Duration(rule.MaxTTLSeconds) * time.Second; cap < ttl {
			ttl = cap
		}
	}
	if tenantMax := grantStore.EastWestMaxGrantTTL(tenantID); tenantMax > 0 {
		if cap := time.Duration(tenantMax) * time.Second; cap < ttl {
			ttl = cap
		}
	}
	return ttl
}

// GrantRevokeRequest revokes east-west grants for a tenant (scope_type ""/"tenant") or a
// device/user scope (E5 continuous revocation / admin).
type GrantRevokeRequest struct {
	ScopeType string `json:"scope_type"`
	ScopeID   string `json:"scope_id"`
}

func RevokeGrants(policyStore policy.RuntimeStore, tenantID string, req GrantRevokeRequest) (map[string]any, error) {
	s, ok := policyStore.(grantStore)
	if !ok {
		return nil, fmt.Errorf("policy store does not support east-west grants")
	}
	revoked := s.RevokeEastWestGrants(tenantID, req.ScopeType, req.ScopeID)
	return map[string]any{
		"schema_version":        "admin_east_west_grant_revoke.v1",
		"tenant_id":             tenantID,
		"revoked_count":         revoked,
		"no_secret_attestation": true,
	}, nil
}

type GrantIssueRequest struct {
	ChallengeID string `json:"challenge_id"`
}

type grantResponse struct {
	SchemaVersion       string `json:"schema_version"`
	TenantID            string `json:"tenant_id"`
	SubjectUserID       string `json:"subject_user_id"`
	DeviceID            string `json:"device_id"`
	Destination         string `json:"destination"`
	Protocol            string `json:"protocol"`
	ExpiresAt           string `json:"expires_at"`
	NoSecretAttestation bool   `json:"no_secret_attestation"`
}

func grantResponseFrom(tenantID string, g decision.EastWestGrant) grantResponse {
	return grantResponse{
		SchemaVersion:       "east_west_grant.v1",
		TenantID:            tenantID,
		SubjectUserID:       g.SubjectUserID,
		DeviceID:            g.DeviceID,
		Destination:         g.Destination,
		Protocol:            g.Protocol,
		ExpiresAt:           g.ExpiresAt.UTC().Format(time.RFC3339),
		NoSecretAttestation: true,
	}
}

// IssueGrantFromChallenge completes a pending challenge and issues an ephemeral grant bound to
// its (identity x device x destination x protocol), hot-applied to the live decision path.
func IssueGrantFromChallenge(policyStore policy.RuntimeStore, challenges *AuthChallengeStore, challengeID string, now time.Time) (grantResponse, error) {
	grantStore, ok := policyStore.(grantStore)
	if !ok {
		return grantResponse{}, fmt.Errorf("policy store does not support east-west grants")
	}
	challenge, ok := challenges.Complete(challengeID, now)
	if !ok {
		return grantResponse{}, fmt.Errorf("challenge is not a pending, unexpired challenge")
	}
	grant := decision.EastWestGrant{
		SubjectUserID: challenge.SubjectUserID,
		DeviceID:      challenge.DeviceID,
		Destination:   challenge.Destination,
		Protocol:      challenge.Protocol,
		LastUsedAt:    now,
	}
	grant.ExpiresAt = now.Add(EffectiveTTL(grantStore, challenge.TenantID, grant, eastWestGrantDefaultTTL))
	grantStore.IssueEastWestGrant(challenge.TenantID, grant)
	return grantResponseFrom(challenge.TenantID, grant), nil
}

// AdminGrantIssueRequest is an admin pre-authorization: issue an east-west grant directly,
// without an OOB ceremony (e.g. break-glass / pre-provisioned access). ttl_seconds defaults to 1 day.
type AdminGrantIssueRequest struct {
	SubjectUserID  string `json:"subject_user_id"`
	DeviceID       string `json:"device_id"`
	Destination    string `json:"destination"`
	Protocol       string `json:"protocol"`
	TTLSeconds     int    `json:"ttl_seconds"`
	IdleTTLSeconds int    `json:"idle_ttl_seconds"`
}

// IssueGrantDirect issues a grant from explicit binding (admin pre-authorization), hot-applied.
func IssueGrantDirect(policyStore policy.RuntimeStore, tenantID string, req AdminGrantIssueRequest, now time.Time) (grantResponse, error) {
	grantStore, ok := policyStore.(grantStore)
	if !ok {
		return grantResponse{}, fmt.Errorf("policy store does not support east-west grants")
	}
	if !decision.IsEastWestProtocol(req.Protocol) {
		return grantResponse{}, fmt.Errorf("protocol %q is not an east-west protocol", req.Protocol)
	}
	if strings.TrimSpace(req.Destination) == "" {
		return grantResponse{}, fmt.Errorf("destination is required")
	}
	requested := eastWestGrantDefaultTTL
	if req.TTLSeconds > 0 {
		requested = time.Duration(req.TTLSeconds) * time.Second
	}
	grant := decision.EastWestGrant{
		SubjectUserID:  strings.TrimSpace(req.SubjectUserID),
		DeviceID:       strings.TrimSpace(req.DeviceID),
		Destination:    strings.TrimSpace(req.Destination),
		Protocol:       strings.ToLower(strings.TrimSpace(req.Protocol)),
		LastUsedAt:     now,
		IdleTTLSeconds: req.IdleTTLSeconds,
	}
	grant.ExpiresAt = now.Add(EffectiveTTL(grantStore, tenantID, grant, requested))
	grantStore.IssueEastWestGrant(tenantID, grant)
	return grantResponseFrom(tenantID, grant), nil
}

// CompleteCeremony is the E4 hook: after the out-of-band browser ceremony authenticates the user
// (OIDC + MFA), this issues the ephemeral grant against the held challenge -- but only when the
// authenticated identity matches the held flow's claimed subject (identity binding). The endpoint is
// untrusted, so the grant is bound to who actually proved themselves in the browser, not to who the held
// flow claimed to be.
func CompleteCeremony(policyStore policy.RuntimeStore, challenges *AuthChallengeStore, challengeID, authenticatedUserID string, now time.Time) (grantResponse, error) {
	challenge, ok := challenges.Get(challengeID)
	if !ok || challenge.Status != "pending" {
		return grantResponse{}, fmt.Errorf("challenge is not a pending challenge")
	}
	// Identity binding (fail-open review #16): when the held flow CLAIMS a subject, the browser ceremony must have
	// PROVEN that same subject. The previous `authenticatedUserID != ""` clause let an EMPTY authenticated identity
	// (the ceremony proved no one) skip the check and issue the grant to the merely-claimed subject. Require the
	// proven identity to non-emptily equal the claim. A userless (empty-subject) challenge still allows an empty
	// authenticated id (device-attested flow).
	if challenge.SubjectUserID != "" && challenge.SubjectUserID != authenticatedUserID {
		return grantResponse{}, fmt.Errorf("authenticated identity does not match the held flow")
	}
	return IssueGrantFromChallenge(policyStore, challenges, challengeID, now)
}

type grantToucher interface {
	TouchEastWestGrant(tenantID string, req model.DecisionRequest, now time.Time)
}

// TouchGrantIfSatisfied bumps the idle timer of the grant that just released a flow (E6), so an
// actively-used grant does not idle-expire. No-op unless the decision was an east-west grant release.
func TouchGrantIfSatisfied(policyStore policy.RuntimeStore, req model.DecisionRequest, dec model.AccessDecision, now time.Time) {
	if dec.Decision != "allow" {
		return
	}
	satisfied := false
	for _, c := range dec.ReasonCodes {
		if c == "east_west_grant_satisfied" {
			satisfied = true
			break
		}
	}
	if !satisfied {
		return
	}
	if t, ok := policyStore.(grantToucher); ok {
		t.TouchEastWestGrant(dec.TenantID, req, now)
	}
}

// AdminGrants lists the active (non-expired) east-west grants for a tenant (observability).
func AdminGrants(policyStore policy.RuntimeStore, tenantID string, now time.Time) map[string]any {
	grants := []grantResponse{}
	if s, ok := policyStore.(grantStore); ok {
		for _, g := range s.EastWestGrantsFor(tenantID, now) {
			grants = append(grants, grantResponseFrom(tenantID, g))
		}
	}
	return map[string]any{
		"schema_version":        "admin_east_west_grants.v1",
		"tenant_id":             tenantID,
		"active_grants":         grants,
		"no_secret_attestation": true,
	}
}
