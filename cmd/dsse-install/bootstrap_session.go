package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// bootstrap_session.go — minting this deployment's credentials AS THE ADMINISTRATOR, not as break-glass.
//
// ★★★ THE TOKENS INHERITED THE PRINCIPAL THAT MINTED THEM (2026-08-25, measured on the deployment this
// installer produced, right after it was correctly closed).
//
// The bootstrap creates a named administrator and then mints two API tokens — one for the fleet, one for the
// operator. Both were minted with the BREAK-GLASS bearer, because that is what is armed at that moment. The
// control plane files an act under the principal of the caller, and the break-glass principal is
// admin_legacy_token / legacy-admin-token@example.local — the synthetic owner the whole bootstrap exists to
// replace. So issuing an enrolment token with the operator credential recorded:
//
//	"issued_by": "admin_legacy_token", "issued_by_label": "legacy-admin-token@example.local"
//
// The deployment closed break-glass and then filed everything under it. Every enrolment, every act an Edge
// performs, every question the operator asks — attributed to nobody, for the life of the deployment, in a
// deployment whose entire point was to have a named administrator.
//
// The fix is not a different scope: it is minting them from the ADMINISTRATOR'S OWN SESSION. The bootstrap
// already has everything that needs — it set the password and it holds the second-factor secret, because it
// just completed the second factor itself. So it signs in as them, exactly as a person would, and the tokens
// carry that person's principal.
//
// ★ AND IT PROVES THE ACCOUNT WORKS BY USING IT. The step this replaces was a sign-in whose only purpose was
// to check the account could sign in; now the sign-in is load-bearing, so it cannot pass while being useless.

// adminSession is a signed-in administrator: what the control plane needs to recognise them on the next call.
//
// ★ TWO VALUES, NOT ONE. The session cookie authenticates; the CSRF token authorises a MUTATION. A session
// alone is answered 403 "admin csrf token is invalid or absent" on anything that writes — correct, and the
// reason a first attempt at this failed.
type adminSession struct {
	ID   string
	CSRF string
}

// signInAsAdministrator completes password + second factor and returns the session.
func signInAsAdministrator(client *http.Client, cpAdmin, email, password, totpSecret string) (adminSession, error) {
	cpAdmin = strings.TrimRight(cpAdmin, "/")
	code, raw, err := postJSON(client, cpAdmin+"/admin/login/password",
		map[string]any{"email": email, "password": password})
	if err != nil || code != 200 {
		return adminSession{}, fmt.Errorf("the account was created but cannot sign in -> %d %v: %s",
			code, err, first(raw, 200))
	}
	var challenge struct {
		ChallengeToken string `json:"challenge_token"`
		TOTPRequired   bool   `json:"totp_required"`
	}
	if json.Unmarshal(raw, &challenge) != nil || strings.TrimSpace(challenge.ChallengeToken) == "" {
		return adminSession{}, fmt.Errorf("the control plane returned a sign-in this installer cannot read")
	}
	otp, err := totpNow(totpSecret)
	if err != nil {
		return adminSession{}, fmt.Errorf("compute the second-factor code: %w", err)
	}
	code, raw, err = postJSON(client, cpAdmin+"/admin/login/totp",
		map[string]any{"challenge_token": challenge.ChallengeToken, "code": otp})
	if err != nil || (code != 200 && code != 201) {
		return adminSession{}, fmt.Errorf("the second factor was refused at sign-in -> %d %v: %s",
			code, err, first(raw, 200))
	}
	var signedIn struct {
		Session struct {
			ID       string            `json:"id"`
			Metadata map[string]string `json:"metadata"`
		} `json:"session"`
	}
	if json.Unmarshal(raw, &signedIn) != nil {
		return adminSession{}, fmt.Errorf("the control plane returned a session this installer cannot read")
	}
	s := adminSession{ID: strings.TrimSpace(signedIn.Session.ID),
		CSRF: strings.TrimSpace(signedIn.Session.Metadata["csrf_token"])}
	if s.ID == "" {
		return adminSession{}, fmt.Errorf("the sign-in carried no session")
	}
	if s.CSRF == "" {
		// Said plainly rather than discovered as a 403 three calls later.
		return adminSession{}, fmt.Errorf("the sign-in carried no csrf token, so nothing can be minted with it")
	}
	return s, nil
}

// postAsAdministrator is post() with a session instead of a bearer.
func postAsAdministrator(client *http.Client, url string, session adminSession, body []byte) (int, []byte, error) {
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(string(body)))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cookie", "admin_session="+session.ID)
	req.Header.Set("X-CSRF-Token", session.CSRF)
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, raw, nil
}
