package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ★★ THE CONSOLE ANSWERED AN ASSET REQUEST WITH A PAGE, AND THE SCREEN STOPPED (2026-08-18, seen as a
// signed-in customer administrator).
//
// Every refusal from the auth gate was a 302 to "/". For a navigation that is right. For app.js it returns the
// login HTML, so the browser reports "Refused to execute script ... MIME type ('text/html')", the application
// never boots, and the page sits on "Checking your session…" indefinitely with nothing on it that says why.
//
// The trigger was not a lost session. validateSession fails closed on ANY error including a five-second
// timeout, and this deployment's Edge shares a process between its admin listener and the data plane, so a
// brief saturation is enough. A hiccup presented itself as a permanent blank screen.
func TestAnAssetRefusalIsNeverAPage(t *testing.T) {
	// The authority is unreachable: every validation is unverifiable.
	gate := authGate("http://127.0.0.1:1/session", &http.Client{}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("SECRET ASSET"))
	}))

	asset := httptest.NewRequest(http.MethodGet, "/app.js", nil)
	asset.Header.Set("Cookie", "admin_session=whatever")
	asset.Header.Set("Sec-Fetch-Mode", "no-cors")
	rec := httptest.NewRecorder()
	gate.ServeHTTP(rec, asset)

	if rec.Code == http.StatusFound {
		t.Fatal("an asset was answered with a redirect; the browser fetches the login HTML and tries to run " +
			"it as JavaScript, which is how the screen ends up frozen on 'Checking your session…'")
	}
	if ct := rec.Header().Get("Content-Type"); strings.Contains(ct, "text/html") {
		t.Fatalf("an asset refusal carries Content-Type %q", ct)
	}
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("an unreachable authority answered %d; it must say the session could not be CHECKED, not that "+
			"it is invalid — those mean opposite things to the reader", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "not a sign-out") {
		t.Fatalf("the body does not distinguish a hiccup from a sign-out: %q", rec.Body.String())
	}
	// ★ AND IT IS STILL CLOSED. The whole point of the gate is that the bytes are never served.
	if strings.Contains(rec.Body.String(), "SECRET ASSET") {
		t.Fatal("the asset was served despite an unverifiable session")
	}

	// No cookie at all is a different answer: the reader is genuinely not signed in.
	nocookie := httptest.NewRequest(http.MethodGet, "/app.js", nil)
	nocookie.Header.Set("Sec-Fetch-Mode", "no-cors")
	rec2 := httptest.NewRecorder()
	gate.ServeHTTP(rec2, nocookie)
	if rec2.Code != http.StatusUnauthorized {
		t.Fatalf("an asset request with no session answered %d, want 401", rec2.Code)
	}

	// ★ A NAVIGATION STILL REDIRECTS. Somebody arriving at a gated page belongs on the login page, and a 401
	// body would be a blank white screen with a sentence on it.
	nav := httptest.NewRequest(http.MethodGet, "/console.html", nil)
	nav.Header.Set("Sec-Fetch-Mode", "navigate")
	rec3 := httptest.NewRecorder()
	gate.ServeHTTP(rec3, nav)
	if rec3.Code != http.StatusFound {
		t.Fatalf("a navigation answered %d, want a redirect to the login page", rec3.Code)
	}

	// And a client that sends no Sec-Fetch-Mode is judged by Accept, which is what curl and older browsers do.
	old := httptest.NewRequest(http.MethodGet, "/console.html", nil)
	old.Header.Set("Accept", "text/html,application/xhtml+xml")
	rec4 := httptest.NewRecorder()
	gate.ServeHTTP(rec4, old)
	if rec4.Code != http.StatusFound {
		t.Fatalf("a navigation without Sec-Fetch-Mode answered %d", rec4.Code)
	}
}

// ★ THE CONTROL: a VALID session still gets the bytes. Without it every assertion above is satisfied by a gate
// that refuses everything, which would be a far worse outage than the one being fixed.
func TestAValidSessionStillGetsTheAsset(t *testing.T) {
	authority := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"principal_id":"adm"}`)
	}))
	defer authority.Close()
	gate := authGate(authority.URL, authority.Client(), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("SECRET ASSET"))
	}))
	req := httptest.NewRequest(http.MethodGet, "/app.js", nil)
	req.Header.Set("Cookie", "admin_session=good")
	req.Header.Set("Sec-Fetch-Mode", "no-cors")
	rec := httptest.NewRecorder()
	gate.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "SECRET ASSET") {
		t.Fatalf("a valid session did not get the asset: %d %q", rec.Code, rec.Body.String())
	}
}

// The login logo is public; other branding paths and application assets remain gated.
func TestLoginBrandDoesNotExposeAuthenticatedAssets(t *testing.T) {
	gate := authGate("http://127.0.0.1:1/session", &http.Client{}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	for _, tc := range []struct {
		path string
		want int
	}{
		{"/brand/lantern-symbol.svg", http.StatusOK},
		{"/brand/private.svg", http.StatusUnauthorized},
		{"/app.js", http.StatusUnauthorized},
		{"/ui.css", http.StatusUnauthorized},
		{"/console.html", http.StatusUnauthorized},
	} {
		t.Run(tc.path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			req.Header.Set("Sec-Fetch-Mode", "no-cors")
			rec := httptest.NewRecorder()
			gate.ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d", rec.Code, tc.want)
			}
		})
	}
}
