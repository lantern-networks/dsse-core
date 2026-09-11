package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/lantern-networks/dsse-core/enrolledinventory"
)

// enrolled_identity_claim_remote.go — taking the one-time claim on a device identity where the authority is.
//
// ★★★ THE SEVENTH DEPENDENCY, AND THE ONE THAT WAS NOT A STORE FLAG (2026-08-23). Six postgres-backed stores
// came off the enforcement Edges and the reference compose still handed them a DSN, with this written beside
// it: "The Edge refuses to start with a device CA and no -postgres-dsn." Not a store an operator chose — a
// hard startup requirement, and therefore invisible to a count of -*-store flags.
//
// Its requirement is real and is the same one the enrolment token has: "has this identity already enrolled" is
// a ONE-TIME decision, and a one-time decision taken by more than one process needs one place to take it. The
// interface's own note says the ledger cannot be that place, because it answers from memory and saves as a
// blob, so two processes holding a device CA each decide alone.
//
// And the answer is the same: the decision belongs to the AUTHORITY, not to a database an enforcement node
// happens to reach. The single conditional write stays exactly where it was; the Edge asks.
//
// ★ FAILING TO ASK IS NOT "NOT CLAIMED". A claim that cannot be taken must never read as taken-by-nobody:
// that is the precise shape in which two issuers both mint a certificate for one device name. An unreachable
// authority returns an ERROR, and the enrolment is refused — enrolment is growth, and refusing growth while
// the authority is unreachable is the safe direction.

// remoteEnrolledIdentityClaims takes and releases identity claims through the control plane.
type remoteEnrolledIdentityClaims struct {
	url    string
	token  string
	client *http.Client
}

var _ enrolledinventory.IdentityClaimer = (*remoteEnrolledIdentityClaims)(nil)

func newRemoteEnrolledIdentityClaims(url, token string, client *http.Client) *remoteEnrolledIdentityClaims {
	if strings.TrimSpace(url) == "" || client == nil {
		return nil
	}
	return &remoteEnrolledIdentityClaims{url: strings.TrimRight(strings.TrimSpace(url), "/"),
		token: strings.TrimSpace(token), client: client}
}

type identityClaimRemoteRequest struct {
	TenantID string                            `json:"tenant_id,omitempty"`
	Identity string                            `json:"identity,omitempty"`
	Grant    int                               `json:"grant,omitempty"`
	Claims   []enrolledinventory.IdentityClaim `json:"claims,omitempty"`
}

type identityClaimRemoteResponse struct {
	Claimed  bool   `json:"claimed"`
	Recorded int    `json:"recorded"`
	Error    string `json:"error,omitempty"`
}

func (c *remoteEnrolledIdentityClaims) call(ctx context.Context, path string,
	req identityClaimRemoteRequest) (identityClaimRemoteResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return identityClaimRemoteResponse{}, err
	}
	// The identity claim is the other half of the same act, and follows leadership for the same reason —
	// see enrolment_token_remote.go.
	base := strings.TrimRight(c.url, "/")
	if current := controlChannelCurrentBaseURL(); current != "" {
		base = strings.TrimRight(current, "/")
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, base+path, bytes.NewReader(body))
	if err != nil {
		return identityClaimRemoteResponse{}, err
	}
	httpReq.Header.Set("Authorization", "Bearer "+c.token)
	httpReq.Header.Set("content-type", "application/json")
	resp, err := c.client.Do(httpReq)
	if err != nil {
		return identityClaimRemoteResponse{}, fmt.Errorf("the identity-claim authority is unreachable, so no "+
			"device can enrol here until it is back (devices already enrolled are unaffected): %w", err)
	}
	defer resp.Body.Close()
	var out identityClaimRemoteResponse
	if derr := json.NewDecoder(resp.Body).Decode(&out); derr != nil && resp.StatusCode < 300 {
		return identityClaimRemoteResponse{}, fmt.Errorf("identity-claim authority answered unreadably: %w", derr)
	}
	if resp.StatusCode >= 300 {
		return identityClaimRemoteResponse{}, fmt.Errorf("the identity-claim authority refused: HTTP %d", resp.StatusCode)
	}
	if reason := strings.TrimSpace(out.Error); reason != "" {
		return out, fmt.Errorf("identity claim refused: %s", reason)
	}
	return out, nil
}

func (c *remoteEnrolledIdentityClaims) ClaimIdentity(ctx context.Context, tenantID, identity string, grant int) (bool, error) {
	out, err := c.call(ctx, "/admin/fleet/identity-claim/claim",
		identityClaimRemoteRequest{TenantID: tenantID, Identity: identity, Grant: grant})
	if err != nil {
		// ★ NOT (false, nil). "I could not ask" and "somebody else already has it" are the same VALUE and
		// completely different facts, and only one of them is safe to proceed on. Returning the error is what
		// makes an unreachable authority refuse the enrolment rather than hand out a second certificate for a
		// name already in use.
		return false, err
	}
	return out.Claimed, nil
}

func (c *remoteEnrolledIdentityClaims) ReleaseIdentity(ctx context.Context, tenantID, identity string, grant int) error {
	_, err := c.call(ctx, "/admin/fleet/identity-claim/release",
		identityClaimRemoteRequest{TenantID: tenantID, Identity: identity, Grant: grant})
	return err
}

func (c *remoteEnrolledIdentityClaims) BackfillClaims(ctx context.Context, claims []enrolledinventory.IdentityClaim) (int, error) {
	if len(claims) == 0 {
		return 0, nil
	}
	out, err := c.call(ctx, "/admin/fleet/identity-claim/backfill", identityClaimRemoteRequest{Claims: claims})
	if err != nil {
		return 0, err
	}
	return out.Recorded, nil
}
