package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// ★★★ TELLING THE CONTROL PLANE WHERE ITS CONSOLE IS BROKE STEP 3 OF THIS PRODUCT'S OWN INSTALL PROCEDURE
// (2026-08-31, found by building a deployment from nothing).
//
//	dsse-install: the sign-in carried no session
//
// The sign-in withholds the session from the body whenever the deployment names a Console — right for a
// browser, whose cookie is HttpOnly so that page script cannot read it and an XSS on the Console cannot lift
// it. But `dsse-install -bootstrap-admin` signs in here too, and reads the session out of the body. So a
// deployment that names a Console could not be installed at all, while the deployment that had been standing
// for hours went on working: only a build from nothing shows it.
func TestADeploymentThatNamesAConsoleStillGivesAProgramItsSession(t *testing.T) {
	const origin = "https://console.example.test"

	browser := httptest.NewRequest(http.MethodPost, "/admin/login/totp", nil)
	browser.Header.Set("Sec-Fetch-Mode", "cors")
	browser.Header.Set("Origin", origin)
	answer := signInAnswer("p", "the-session", origin, browser)
	if _, leaked := answer["session"]; leaked {
		t.Error("a browser was handed the session in the response body. The cookie is HttpOnly precisely so " +
			"page script cannot read it; putting it in the body gives an XSS on the Console the session.")
	}
	if answer["redirect"] != origin+"/#signed-in" {
		t.Errorf("a browser was not sent to the Console: %v", answer["redirect"])
	}

	installer := httptest.NewRequest(http.MethodPost, "/admin/login/totp", nil)
	answer = signInAnswer("p", "the-session", origin, installer)
	if answer["session"] != "the-session" {
		t.Error("a command-line client signing in got no session, so `dsse-install -bootstrap-admin` fails " +
			"and a deployment that names a Console cannot be installed")
	}
	if answer["redirect"] != origin+"/#signed-in" {
		t.Errorf("the redirect should still be stated: %v", answer["redirect"])
	}

	// A deployment with no Console named behaves as it always did.
	answer = signInAnswer("p", "the-session", "", installer)
	if answer["session"] != "the-session" {
		t.Error("a deployment that names no Console stopped returning the session")
	}
	if _, present := answer["redirect"]; present {
		t.Error("a redirect was invented for a deployment that named no Console")
	}
}
