package main

import (
	"os"
	"strings"
	"testing"
)

// ★★★ THE STEP-UP WINDOW VERIFIES THE PORTAL'S CERTIFICATE (2026-09-03).
//
// It used to set --ignore-certificate-errors unconditionally, in a signed shipping binary, on the one surface
// where a user types their corporate password and second factor. The comment defended it with "it does not
// weaken WebAuthn RP binding" — true of passkeys, and not the common case: an Okta, an Entra ID or a Keycloak
// asking for a password and a TOTP hands both to whoever holds the connection.
//
// It also made the operator's decision unenforceable. They chose that the step-up portal's certificate is the
// operator's to provide, and a window that never checks makes providing one worth nothing.
//
// This is a default that will want to drift back — the lab is easier with it on — so it is held here.
func TestTheCertificateBypassIsOffUnlessAskedFor(t *testing.T) {
	body, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(body)

	if !strings.Contains(src, `flag.Bool("insecure-skip-portal-cert-verify", false,`) {
		t.Error("the certificate bypass is not an explicit flag defaulting to false")
	}
	// ★ THE SETENV, NOT A MENTION OF IT. The first version of this test searched for the flag STRING and
	// found the comment that explains why it is gated — a check satisfied by prose about the thing it is
	// checking. What matters is the line that actually sets the environment.
	i := strings.Index(src, `os.Setenv("WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS"`)
	if i < 0 {
		return // removed entirely is also fine
	}
	guard := strings.LastIndex(src[:i], "if *insecureSkipPortalVerify {")
	if guard < 0 {
		t.Fatal("--ignore-certificate-errors is set outside the opt-in — this window would accept any " +
			"certificate for the portal and the identity provider, on the screen where a password is typed")
	}
	// And it says so out loud. A bypass whose danger is being left on has to announce itself every run.
	between := src[guard:i]
	if !strings.Contains(between, "WARNING") {
		t.Error("the bypass does not announce itself; the danger of this flag is being left on")
	}
}
