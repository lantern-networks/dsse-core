package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"
)

// First-party admin auth: login-challenge store (between the password factor and the TOTP factor), the lab
// email sink, and helpers that turn a verified credential into the existing admin principal + session.
// See docs/admin_first_party_account_onboarding_design.md.

const loginChallengeTTL = 5 * time.Minute

type loginChallenge struct {
	email  string
	expiry time.Time
}

// loginChallengeStore holds the short-lived token issued after a correct password, redeemed by the TOTP step.
type loginChallengeStore struct {
	mu      sync.Mutex
	byToken map[string]loginChallenge
}

func newLoginChallengeStore() *loginChallengeStore {
	return &loginChallengeStore{byToken: map[string]loginChallenge{}}
}

func (s *loginChallengeStore) Issue(email string, now time.Time) (string, error) {
	token, err := randomToken(24)
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byToken[token] = loginChallenge{email: email, expiry: now.UTC().Add(loginChallengeTTL)}
	return token, nil
}

// Consume redeems a challenge token exactly once, returning the email it was issued for.
func (s *loginChallengeStore) Consume(token string, now time.Time) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.byToken[strings.TrimSpace(token)]
	if !ok {
		return "", false
	}
	delete(s.byToken, strings.TrimSpace(token))
	if now.After(c.expiry) {
		return "", false
	}
	return c.email, true
}

// activationLink builds the URL emailed to a newly invited admin (the Console activation page consumes the
// token from the query string).
func activationLink(consoleOrigin, rawToken string) string {
	origin := strings.TrimRight(strings.TrimSpace(consoleOrigin), "/")
	if origin == "" {
		origin = "https://console.local"
	}
	return origin + "/?activate=" + rawToken
}

// sendActivationEmail writes the activation message to the lab email sink (a file) and logs it. Production
// swaps this for an SMTP/provider transport behind the same call site.
// adminInvitationMessage is the invitation, assembled once and handed to whoever will deliver it.
//
// ★ THIS PRODUCT DOES NOT SEND MAIL, AND SAYING SO IS THE FEATURE (2026-08-15). There is no SMTP; the
// old path appended a line to a file or printed it, and the Console then threw the link away and said
// "invitation sent". Nobody received anything, and the failure was invisible — twenty-three unusable
// accounts accumulated in the lab before anyone noticed. What was missing was never a way to SEND. It was a
// way to HAND OVER: the operator has a channel (their own mail, chat, in person) and needs the words.
type adminInvitationMessage struct {
	To        string `json:"to"`
	Subject   string `json:"subject"`
	Body      string `json:"body"`
	Link      string `json:"link"`
	ExpiresAt string `json:"expires_at"`
	// SingleUse and TTLHours are stated so the screen can say them without knowing the store's constants.
	SingleUse bool `json:"single_use"`
	TTLHours  int  `json:"ttl_hours"`
}

// buildAdminInvitation assembles the text a person can paste into whatever channel they actually use.
//
// ★ IT CARRIES BOTH LANGUAGES, AND THAT IS A DECISION RATHER THAN A HEDGE (2026-08-17). Every screen in this
// console is written in the reader's language, and this message was the one piece of operator-facing text that
// was English only — pasted, as it stands, into a Japanese organization's chat by an administrator who has
// never seen an English screen of this product.
//
// The server cannot pick one: the reader is the person being INVITED, who has no account yet, no session, and
// therefore no stated language — the only preference the deployment holds belongs to the operator composing
// the message, who is not the reader. Guessing from the tenant's timezone would be a guess about a person from
// a fact about an organization. So the message says the same thing twice, which is what a bilingual workplace
// does with a message to somebody it has not met, and it costs a reader four lines.
//
// A per-organization language, alongside Timezone on the tenant model, is the thing that would let this pick
// one. Until that exists this must not silently keep addressing half its readers in a language they may not
// read.
func buildAdminInvitation(email, link string, now time.Time) adminInvitationMessage {
	expires := now.UTC().Add(activationTTL)
	stamp := expires.Format(time.RFC3339)
	hours := int(activationTTL.Hours())
	body := strings.Join([]string{
		"Lantern DSSE の管理者に招待されました。",
		"",
		"次のリンクを開いて、パスワードを設定してサインインしてください:",
		link,
		"",
		fmt.Sprintf("このリンクは1回だけ使えます。%s（%d時間後）に使えなくなります。", stamp, hours),
		"期限が切れていたら、招待した相手に新しいリンクの発行を依頼してください。",
		"",
		"---",
		"",
		"You have been invited to administer a Lantern DSSE organization.",
		"",
		"Open this link to set your password and sign in:",
		link,
		"",
		fmt.Sprintf("The link works once and expires at %s (%d hours).", stamp, hours),
		"If it has expired, ask whoever invited you to issue a new one.",
	}, "\n")
	return adminInvitationMessage{
		To:        email,
		Subject:   "Lantern DSSE 管理者アカウントの有効化 / Activate your Lantern DSSE admin account",
		Body:      body,
		Link:      link,
		ExpiresAt: expires.Format(time.RFC3339),
		SingleUse: true,
		TTLHours:  int(activationTTL.Hours()),
	}
}

func sendActivationEmail(sinkPath, email, link string, now time.Time) error {
	msg := fmt.Sprintf("[%s] to=%s subject=\"Activate your Lantern DSSE admin account\" link=%s\n",
		now.UTC().Format(time.RFC3339), email, link)
	if strings.TrimSpace(sinkPath) == "" {
		// ★ NOT THE LINK. The activation token is a single-use credential that sets an administrator's first
		// password, and this branch — no sink configured, which is the DEFAULT — put it in the process log in
		// plain text, where it outlives the 24-hour window in whatever collects stdout. The invitation is
		// handed over through the API response now, so the log only needs to record that one was made.
		log.Printf("admin invite created for %s (the activation link is in the API response, not here)", email)
		return nil
	}
	f, err := os.OpenFile(sinkPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(msg)
	return err
}

// principalFromCredential maps an activated first-party credential to the admin principal used by sessions +
// audit (the email is the operator's user ID).
// ★ AND THE ID COMES FROM WHOEVER ALREADY EXISTS, when one does. A deployment where the two have already
// diverged — every account invited twice before the fix above — must be able to sign in again without anybody
// editing a database. The person is (organization, IdP, subject); the id is a label the system chose for them
// once, and adopting it is how a label stays stable.
func principalFromCredentialResolved(cred *localAdminCredential, now time.Time,
	existing func(tenantID, subject string) (string, bool)) adminPrincipal {
	principal := principalFromCredential(cred, now)
	if existing == nil {
		return principal
	}
	if id, ok := existing(cred.TenantID, cred.Email); ok && strings.TrimSpace(id) != "" {
		principal.ID = id
	}
	return principal
}

func principalFromCredential(cred *localAdminCredential, now time.Time) adminPrincipal {
	last := now.UTC().Format(time.RFC3339)
	return adminPrincipal{
		ID:          cred.PrincipalID,
		TenantID:    cred.TenantID,
		Subject:     cred.Email,
		Email:       cred.Email,
		Roles:       append([]string(nil), cred.Roles...),
		IDPID:       "first_party",
		Status:      "active",
		CreatedAt:   now.UTC().Format(time.RFC3339),
		LastLoginAt: &last,
		Metadata:    map[string]any{"auth_method": "first_party"},
	}
}

// mintFirstPartyAdminSession persists the principal + a fresh (MFA-satisfied) admin session and returns it so
// the caller can set the session cookie. Mirrors the OIDC session shape.
func mintFirstPartyAdminSession(ctx context.Context, store adminAuthRuntimeStore, principal adminPrincipal, sourceIP, userAgent string, now time.Time) (adminSession, error) {
	csrf, err := randomURLToken(32)
	if err != nil {
		return adminSession{}, fmt.Errorf("generate admin csrf token: %w", err)
	}
	session := adminSession{
		ID:               randomEdgeID("admin_sess_", now),
		TenantID:         principal.TenantID,
		AdminPrincipalID: principal.ID,
		Subject:          principal.Subject,
		Roles:            append([]string(nil), principal.Roles...),
		AuthTime:         now.UTC().Format(time.RFC3339),
		MFAState:         "fresh", // password + TOTP
		SourceIP:         &sourceIP,
		UserAgent:        &userAgent,
		CreatedAt:        now.UTC().Format(time.RFC3339),
		ExpiresAt:        now.UTC().Add(8 * time.Hour).Format(time.RFC3339),
		LastActiveAt:     now.UTC().Format(time.RFC3339),
		Status:           "active",
		Metadata: map[string]any{
			adminCSRFTokenKey: csrf,
			"auth_method":     "first_party",
			"email":           principal.Email,
		},
	}
	if err := store.PersistPrincipal(ctx, principal); err != nil {
		return adminSession{}, err
	}
	if err := store.PersistSession(ctx, session); err != nil {
		return adminSession{}, err
	}
	return session, nil
}
