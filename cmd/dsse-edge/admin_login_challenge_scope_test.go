package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestLoginChallengeCannotSurviveCredentialReplacement(t *testing.T) {
	now := time.Now().UTC()
	store := newLocalAdminCredentialStore("DSSE")
	email := "challenge@example.test"
	seedActiveAdminAccount(t, store, email, "tenant_lab_001", "challenge-admin", []string{"admin"}, now)
	handler, _ := newAdminAccountTestServer(t, store)
	post := func(path, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	first := post("/admin/login/password", `{"email":"challenge@example.test","password":"a-strong-passphrase-123"}`)
	if first.Code != http.StatusOK {
		t.Fatalf("password factor failed: %d", first.Code)
	}
	var issued struct {
		Challenge string `json:"challenge_token"`
	}
	if err := json.Unmarshal(first.Body.Bytes(), &issued); err != nil || issued.Challenge == "" {
		t.Fatal("missing challenge")
	}
	// Re-enrollment changes the password and second factor after the first factor
	// was verified; the old challenge cannot authenticate the replacement account.
	invite, err := store.Invite(email, "tenant_lab_001", "challenge-admin", []string{"admin"}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetActivationPassword(invite, "a-replacement-password-456", now); err != nil {
		t.Fatal(err)
	}
	secret, _, err := store.BeginTOTPEnrollment(invite, now)
	if err != nil {
		t.Fatal(err)
	}
	code, _ := totpCodeForCounter(secret, uint64(now.Unix())/totpPeriod)
	if _, err := store.CompleteActivation(invite, code, now); err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]string{"challenge_token": issued.Challenge, "code": code})
	if w := post("/admin/login/totp", string(body)); w.Code != http.StatusUnauthorized {
		t.Fatalf("old password challenge authenticated replacement credentials: status=%d", w.Code)
	}
	// A newly verified password can still complete with the unspent second factor.
	first = post("/admin/login/password", `{"email":"challenge@example.test","password":"a-replacement-password-456"}`)
	if first.Code != http.StatusOK {
		t.Fatalf("new password rejected: %d", first.Code)
	}
	if err := json.Unmarshal(first.Body.Bytes(), &issued); err != nil {
		t.Fatal(err)
	}
	body, _ = json.Marshal(map[string]string{"challenge_token": issued.Challenge, "code": code})
	if w := post("/admin/login/totp", string(body)); w.Code != http.StatusCreated {
		t.Fatalf("new challenge failed: status=%d", w.Code)
	}
}

func TestLoginChallengeExpiryAndPruning(t *testing.T) {
	s := newLoginChallengeStore()
	now := time.Unix(1700000000, 0)
	cred := &localAdminCredential{Email: "a@example.test", Status: credentialStatusActive, PasswordHash: "hashed", TOTPEnrolled: true}
	first, err := s.Issue(cred, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Consume(first, now.Add(loginChallengeTTL)); ok {
		t.Fatal("challenge accepted at expiry")
	}
	old, err := s.Issue(cred, now)
	if err != nil {
		t.Fatal(err)
	}
	fresh, err := s.Issue(cred, now.Add(loginChallengeTTL))
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := s.byToken[old]; exists {
		t.Fatal("expired unconsumed challenge retained")
	}
	if _, ok := s.Consume(fresh, now.Add(loginChallengeTTL)); !ok {
		t.Fatal("fresh challenge rejected")
	}
	if _, ok := s.Consume(fresh, now.Add(loginChallengeTTL)); ok {
		t.Fatal("challenge replay accepted")
	}
}
