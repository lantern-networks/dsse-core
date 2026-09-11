package main

import (
	"strings"
	"testing"
	"time"
)

// RFC 6238 reference vector (SHA1, secret = ASCII "12345678901234567890"): at counter 1 the 8-digit code is
// 94287082, so the 6-digit code is 287082. This validates the TOTP implementation against the spec.
func TestTOTPRFC6238Vector(t *testing.T) {
	secret := totpBase32.EncodeToString([]byte("12345678901234567890"))
	got, err := totpCodeForCounter(secret, 1)
	if err != nil {
		t.Fatalf("totpCodeForCounter: %v", err)
	}
	if got != "287082" {
		t.Fatalf("RFC6238 code = %q, want 287082", got)
	}
	// verify tolerates +/-1 step skew
	at := time.Unix(59, 0).UTC() // counter 1
	code, _ := totpCodeForCounter(secret, 1)
	if step, ok := totpVerify(secret, code, at); !ok || step != 1 {
		t.Fatalf("totpVerify should accept the current-step code and return step 1, got step=%d ok=%v", step, ok)
	}
	if _, ok := totpVerify(secret, "000000", at); ok {
		t.Fatalf("totpVerify should reject a wrong code")
	}
}

func TestPasswordPolicy(t *testing.T) {
	if err := validatePasswordPolicy("short", "a@b.com"); err == nil {
		t.Fatalf("short password must be rejected")
	}
	if err := validatePasswordPolicy("user@corp.example", "user@corp.example"); err == nil {
		t.Fatalf("password equal to email must be rejected")
	}
	if err := validatePasswordPolicy("a-strong-passphrase-123", "user@corp.example"); err != nil {
		t.Fatalf("valid password rejected: %v", err)
	}
}

// Full first-party lifecycle: invite -> activate (set password, enroll TOTP, complete) -> login with
// password + TOTP. Plus: single-use activation token, password lockout, recovery-code fallback.
func TestFirstPartyAccountLifecycle(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	store := newLocalAdminCredentialStore("Lantern DSSE")
	email := "alice@corp.example.com"

	token, err := store.Invite(email, "tenant_lab_001", "adm_alice", []string{"admin"}, now)
	if err != nil {
		t.Fatalf("Invite: %v", err)
	}
	if got, err := store.ActivationEmail(token, now); err != nil || got != "alice@corp.example.com" {
		t.Fatalf("ActivationEmail = %q,%v", got, err)
	}
	// cannot login before activation
	if _, err := store.VerifyPassword(email, "a-strong-passphrase-123", now); err == nil {
		t.Fatalf("login before activation must fail")
	}

	// activation: weak password rejected, strong accepted
	if err := store.SetActivationPassword(token, "weak", now); err == nil {
		t.Fatalf("weak password must be rejected")
	}
	if err := store.SetActivationPassword(token, "a-strong-passphrase-123", now); err != nil {
		t.Fatalf("SetActivationPassword: %v", err)
	}
	secret, uri, err := store.BeginTOTPEnrollment(token, now)
	if err != nil || secret == "" {
		t.Fatalf("BeginTOTPEnrollment: %v", err)
	}
	if !strings.Contains(uri, "otpauth://totp/") {
		t.Fatalf("otpauth uri = %q", uri)
	}
	// wrong enrollment code rejected
	if _, err := store.CompleteActivation(token, "000000", now); err == nil {
		t.Fatalf("wrong enrollment code must be rejected")
	}
	good, _ := totpCodeForCounter(secret, uint64(now.Unix())/totpPeriod)
	recovery, err := store.CompleteActivation(token, good, now)
	if err != nil || len(recovery) != recoveryCodes {
		t.Fatalf("CompleteActivation: codes=%d err=%v", len(recovery), err)
	}
	// activation token is single-use (consumed)
	if _, err := store.ActivationEmail(token, now); err == nil {
		t.Fatalf("activation token must be single-use")
	}

	// steady-state login (a later time step than activation, as a real login would be): password then TOTP.
	loginAt := now.Add(totpPeriod * time.Second)
	if _, err := store.VerifyPassword(email, "wrong-password", loginAt); err == nil {
		t.Fatalf("wrong password must fail")
	}
	if _, err := store.VerifyPassword(email, "a-strong-passphrase-123", loginAt); err != nil {
		t.Fatalf("correct password must pass: %v", err)
	}
	totpNow, _ := totpCodeForCounter(secret, uint64(loginAt.Unix())/totpPeriod)
	if _, err := store.VerifyTOTP(email, totpNow, loginAt); err != nil {
		t.Fatalf("correct TOTP must pass: %v", err)
	}
	// recovery code works once, then is consumed
	if _, err := store.VerifyTOTP(email, recovery[0], loginAt); err != nil {
		t.Fatalf("recovery code should work once: %v", err)
	}
	if _, err := store.VerifyTOTP(email, recovery[0], loginAt); err == nil {
		t.Fatalf("recovery code must be single-use")
	}
}

// Review #24 (RFC 6238): a TOTP code must be single-use on the login path. Once a step's code has
// authenticated a login, replaying it (or an earlier still-in-window step) must be rejected.
func TestTOTPCodeIsSingleUse(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	store := newLocalAdminCredentialStore("Lantern DSSE")
	email := "carol@corp.example.com"
	token, _ := store.Invite(email, "t1", "adm_carol", []string{"admin"}, now)
	_ = store.SetActivationPassword(token, "a-strong-passphrase-123", now)
	secret, _, _ := store.BeginTOTPEnrollment(token, now)
	activateCode, _ := totpCodeForCounter(secret, uint64(now.Unix())/totpPeriod)
	if _, err := store.CompleteActivation(token, activateCode, now); err != nil {
		t.Fatalf("CompleteActivation: %v", err)
	}

	// First login with the current code succeeds (activation does not consume the login counter, so the
	// legitimate "enroll then log in with the current code" flow works)...
	code, _ := totpCodeForCounter(secret, uint64(now.Unix())/totpPeriod)
	if _, err := store.VerifyTOTP(email, code, now); err != nil {
		t.Fatalf("first login with the current code must pass: %v", err)
	}
	// ...but replaying that exact code within the same window is now rejected.
	if _, err := store.VerifyTOTP(email, code, now); err == nil {
		t.Fatalf("a consumed code must not be replayable")
	}
	// An earlier still-in-window step is also rejected once a newer step was consumed.
	oldCode, _ := totpCodeForCounter(secret, uint64(now.Unix())/totpPeriod-1)
	if _, err := store.VerifyTOTP(email, oldCode, now); err == nil {
		t.Fatalf("an earlier-step code must not be accepted after a newer step was consumed")
	}
	// A genuinely newer step (a later login) is accepted.
	later := now.Add(2 * totpPeriod * time.Second)
	newCode, _ := totpCodeForCounter(secret, uint64(later.Unix())/totpPeriod)
	if _, err := store.VerifyTOTP(email, newCode, later); err != nil {
		t.Fatalf("a fresh code at a later step must log in: %v", err)
	}
}

func TestPasswordLockout(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	store := newLocalAdminCredentialStore("Lantern DSSE")
	email := "bob@corp.example.com"
	token, _ := store.Invite(email, "t1", "adm_bob", []string{"admin"}, now)
	_ = store.SetActivationPassword(token, "a-strong-passphrase-123", now)
	secret, _, _ := store.BeginTOTPEnrollment(token, now)
	good, _ := totpCodeForCounter(secret, uint64(now.Unix())/totpPeriod)
	_, _ = store.CompleteActivation(token, good, now)

	for i := 0; i < maxFailedLogins; i++ {
		if _, err := store.VerifyPassword(email, "nope", now); err == nil {
			t.Fatalf("attempt %d should fail", i)
		}
	}
	// now locked even with the correct password
	if _, err := store.VerifyPassword(email, "a-strong-passphrase-123", now); err == nil {
		t.Fatalf("account should be locked after %d failures", maxFailedLogins)
	}
	// lock clears after the window
	if _, err := store.VerifyPassword(email, "a-strong-passphrase-123", now.Add(loginLockWindow+time.Minute)); err != nil {
		t.Fatalf("login should succeed after lock window: %v", err)
	}
}
