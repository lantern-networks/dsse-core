package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/enrolltoken"
)

// enrolment_token_remote.go — spending a one-time enrolment token where the authority is.
//
// ★★★ THE LAST REASON AN ENFORCEMENT EDGE HELD A DATABASE (2026-08-23). Of the six postgres-backed stores an
// Edge carried, five turned out not to need one at all: two were configuration that now travels in the config
// bundle, two were runtime reports that are now shipped, and one was an admin surface the Edge should not have
// been authoritative for. This is the sixth, and it is the only one whose requirement was REAL.
//
// Its own implementation states it: "a token has to be spendable exactly once across EVERY Edge, not once per
// Edge. The in-memory store loads its persister at boot and mutates a copy, so two Edges sharing a blob would
// each have their own idea of what had been spent and could both honour the same token — 'one-time' would
// quietly mean 'once per Edge'." That is true, and a file cannot fix it.
//
// ★ BUT IT IS NOT A REASON FOR AN EDGE TO HOLD A DATABASE. Spending a one-time enrolment token is the act of
// deciding that a device may be issued a certificate. That is an authority act, and the authority is the
// control plane. So the Edge goes on serving POST /enroll — a device must reach an Edge, not a control plane —
// and ASKS whether the token may be spent. The single conditional write stays exactly where it was; only the
// caller moves.
//
// ★★ AND WHEN THE CONTROL PLANE IS UNREACHABLE, ENROLMENT STOPS. That is correct, and it is the same judgement
// the licence seat gate already makes: enrolment is GROWTH, the devices already enrolled are untouched, and
// refusing growth is the safe direction. The alternative — an Edge deciding for itself while it cannot reach
// the authority — is precisely how "one-time" becomes "once per Edge, and once more after every partition".
//
// ★ WHAT IT DOES NOT DO. Issuing, listing, revoking and counting are administrative acts and are already
// refused on a config-pulling Edge; this authority refuses them too rather than silently answering from
// nothing, because an admin surface that returns an empty list is indistinguishable from one that has none.

// remoteEnrolmentTokenAuthority spends and verifies against the control plane.
type remoteEnrolmentTokenAuthority struct {
	url    string // the control plane's admin base, e.g. https://controlplane:9443
	token  string // the same bearer the Edge uses for its other control-plane calls
	client *http.Client
}

var _ enrolltoken.Authority = (*remoteEnrolmentTokenAuthority)(nil)

func newRemoteEnrolmentTokenAuthority(url, token string, client *http.Client) *remoteEnrolmentTokenAuthority {
	if strings.TrimSpace(url) == "" || client == nil {
		return nil
	}
	return &remoteEnrolmentTokenAuthority{url: strings.TrimRight(strings.TrimSpace(url), "/"),
		token: strings.TrimSpace(token), client: client}
}

// enrolmentTokenRemoteRequest is what the Edge asks. deviceID is empty for a verify.
type enrolmentTokenRemoteRequest struct {
	Secret   string `json:"secret,omitempty"`
	ID       string `json:"id,omitempty"`
	TenantID string `json:"tenant_id,omitempty"`
	DeviceID string `json:"device_id,omitempty"`
}

// enrolmentTokenRemoteResponse is what the control plane answers. Error carries the authority's OWN reason,
// which the Edge maps back to the sentinel errors its callers already switch on — so a token that is spent,
// revoked or expired keeps producing the same operator-facing log line it did when the store was local.
type enrolmentTokenRemoteResponse struct {
	Token enrolltoken.Token `json:"token"`
	Error string            `json:"error,omitempty"`
	// UsedBy and UsedAt travel beside Error=="used" so the Edge's operator log can name the machine that
	// spent this token. Without them "already been used" is true and unusable — see AlreadyUsedError. They
	// go no further than that log: the caller still gets its single sentence.
	UsedBy string `json:"used_by,omitempty"`
	UsedAt string `json:"used_at,omitempty"`
}

func (a *remoteEnrolmentTokenAuthority) call(path string, req enrolmentTokenRemoteRequest) (enrolltoken.Token, error) {
	return a.callOnce(path, req, false)
}

// callOnce is one attempt. retried says this is already the second, so a node that still denies leadership is
// reported rather than chased.
func (a *remoteEnrolmentTokenAuthority) callOnce(path string, req enrolmentTokenRemoteRequest, retried bool) (enrolltoken.Token, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	body, err := json.Marshal(req)
	if err != nil {
		return enrolltoken.Token{}, err
	}
	// ★★★ THE AUTHORITY IS WHEREVER LEADERSHIP IS (2026-08-25, measured with leadership in another region).
	// Whether a one-time token may be spent is the deployment's single conditional write, and this asked a
	// FIXED address — this region's own control-plane door. With leadership elsewhere that door has no
	// healthy backend, so every enrolment on this Edge answered "invalid or missing eligibility token": a
	// perfectly good token, refused, in words that send somebody to look at the token.
	base := strings.TrimRight(a.url, "/")
	if current := controlChannelCurrentBaseURL(); current != "" {
		base = strings.TrimRight(current, "/")
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, base+path, bytes.NewReader(body))
	if err != nil {
		return enrolltoken.Token{}, err
	}
	httpReq.Header.Set("Authorization", "Bearer "+a.token)
	httpReq.Header.Set("content-type", "application/json")
	resp, err := a.client.Do(httpReq)
	if err != nil {
		// Unreachable authority. Reported as its own error rather than as "unknown token", because the two
		// call for different things: one is a network to fix, the other is a credential to re-issue.
		return enrolltoken.Token{}, fmt.Errorf("the enrolment-token authority is unreachable, so no device can "+
			"enrol here until it is back (devices already enrolled are unaffected): %w", err)
	}
	// ★★★ THE BODY IS DRAINED AND CLOSED BEFORE ANY DECISION (2026-08-27). A connection only returns to the
	// pool when its response body is finished with, and CloseIdleConnections closes only what is IDLE — so
	// dropping the pool while this response was still open left the bad connection in place and the retry rode
	// it straight back to the same node. The difference between this working and not.
	raw, readErr := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	_ = resp.Body.Close()
	var out enrolmentTokenRemoteResponse
	if err := json.Unmarshal(raw, &out); err != nil && resp.StatusCode < 300 {
		if readErr != nil {
			err = readErr
		}
		return enrolltoken.Token{}, fmt.Errorf("enrolment-token authority answered unreadably: %w", err)
	}
	if reason := strings.TrimSpace(out.Error); reason != "" {
		// ★★★ "I DO NOT LEAD" IS PROOF THIS CONNECTION GOES TO THE WRONG NODE (2026-08-27, measured on a
		// deployment standing itself up). The authority is a PAIR behind a front door whose health check is
		// GET /leader, so a standby is marked down and new connections go to the leader — but a connection
		// already established is kept, and this client pools them. An Edge that first connected while the
		// other node led held that connection FOR EVER: every enrolment through it was refused, while the
		// other Edge behind the same region door worked. Measured at 400 seconds of continuous refusal, and
		// recreating both Edges cleared it instantly — half a fleet unable to enrol anything, indefinitely,
		// with nothing reporting it because the other half was fine.
		//
		// The answer says which side is wrong: this connection. So it is dropped and the call is made once
		// more, which lands on a fresh connection and therefore on whoever leads now. Once, not in a loop —
		// if the second attempt also says this, leadership is genuinely moving and the caller should be told.
		if !retried && enrolmentAuthorityDeniedLeadership(reason) {
			a.dropPooledConnections()
			return a.callOnce(path, req, true)
		}
		return enrolltoken.Token{}, enrolmentTokenSentinel(reason, out.UsedBy, out.UsedAt)
	}
	if resp.StatusCode >= 300 {
		return enrolltoken.Token{}, fmt.Errorf("the enrolment-token authority refused: HTTP %d", resp.StatusCode)
	}
	return out.Token, nil
}

// enrolmentTokenSentinel maps the authority's reason back to the sentinel the local store would have returned.
//
// ★ THE SENTINELS MATTER. /enroll logs "already spent" and "revoked" differently from "never existed", and
// treats an unknown secret as possibly-the-shared-token and falls through. Losing that distinction across the
// wire would turn a spent config file into an unexplained refusal — and would make a valid shared token stop
// working, because the fall-through only happens for ErrUnknownToken.
func enrolmentTokenSentinel(reason, usedBy, usedAt string) error {
	switch strings.TrimSpace(strings.ToLower(reason)) {
	case "unknown":
		return enrolltoken.ErrUnknownToken
	case "used":
		// Rebuilt with the detail, not the bare sentinel: the authority is the only one that holds these two
		// facts, and the Edge is where the operator reads them.
		return &enrolltoken.AlreadyUsedError{UsedBy: usedBy, UsedAt: usedAt}
	case "revoked":
		return enrolltoken.ErrTokenRevoked
	case "expired":
		return enrolltoken.ErrTokenExpired
	case "wrong_tenant":
		return enrolltoken.ErrWrongTenant
	default:
		return fmt.Errorf("enrolment token refused: %s", reason)
	}
}

// enrolmentTokenReason is the inverse, used by the control plane's endpoint so the two halves cannot drift.
func enrolmentTokenReason(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, enrolltoken.ErrUnknownToken):
		return "unknown"
	case errors.Is(err, enrolltoken.ErrTokenUsed):
		return "used"
	case errors.Is(err, enrolltoken.ErrTokenRevoked):
		return "revoked"
	case errors.Is(err, enrolltoken.ErrTokenExpired):
		return "expired"
	case errors.Is(err, enrolltoken.ErrWrongTenant):
		return "wrong_tenant"
	default:
		return "refused"
	}
}

func (a *remoteEnrolmentTokenAuthority) Verify(secret, tenantID string, _ time.Time) (enrolltoken.Token, error) {
	return a.call("/admin/fleet/enrolment-token/verify", enrolmentTokenRemoteRequest{Secret: secret, TenantID: tenantID})
}

func (a *remoteEnrolmentTokenAuthority) Spend(id, tenantID, deviceID string, _ time.Time) (enrolltoken.Token, error) {
	return a.call("/admin/fleet/enrolment-token/spend",
		enrolmentTokenRemoteRequest{ID: id, TenantID: tenantID, DeviceID: deviceID})
}

// The administrative half. An Edge that pulls its config already refuses these routes, so answering them from
// nothing here would only make an empty list look like an answer.
func (a *remoteEnrolmentTokenAuthority) Issue(enrolltoken.Policy, string, string, string, string, string,
	time.Time, time.Time) (enrolltoken.Token, string, error) {
	return enrolltoken.Token{}, "", fmt.Errorf("enrolment tokens are issued on the control plane, not on an Edge")
}

func (a *remoteEnrolmentTokenAuthority) Revoke(string, string, time.Time) (enrolltoken.Token, bool) {
	return enrolltoken.Token{}, false
}

func (a *remoteEnrolmentTokenAuthority) List(string) []enrolltoken.Token { return nil }

func (a *remoteEnrolmentTokenAuthority) Outstanding(string, time.Time) int { return 0 }

func (a *remoteEnrolmentTokenAuthority) ExpiringWithin(string, time.Duration, time.Time) []enrolltoken.Token {
	return nil
}

// enrolmentAuthorityDeniedLeadership recognises the one answer that is about the CONNECTION rather than about
// the token: the node that answered does not hold leadership, so nothing it says about a one-time credential
// can be acted on — and, crucially, nothing was spent.
func enrolmentAuthorityDeniedLeadership(reason string) bool {
	return strings.Contains(strings.ToLower(reason), "does not hold leadership")
}

// dropPooledConnections throws away this client's keep-alive connections so the next request dials again.
//
// ★ IT IS THE WHOLE POINT OF THE RETRY. Without it the second attempt rides the same connection to the same
// wrong node and gets the same answer, which is what made the original failure permanent.
func (a *remoteEnrolmentTokenAuthority) dropPooledConnections() {
	if a == nil || a.client == nil {
		return
	}
	type idleCloser interface{ CloseIdleConnections() }
	if t, ok := a.client.Transport.(idleCloser); ok {
		t.CloseIdleConnections()
		return
	}
	a.client.CloseIdleConnections()
}
