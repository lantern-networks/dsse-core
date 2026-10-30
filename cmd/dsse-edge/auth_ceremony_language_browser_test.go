package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// Opt-in local UI fixture: no IdP, credential, agent, grant or AWS connection.
// Browser automation uses a separate test profile and loopback-only TLS.
func TestCeremonyLanguageBrowserFixture(t *testing.T) {
	dir := os.Getenv("DSSE_AUTH_LANGUAGE_BROWSER_DIR")
	if dir == "" {
		t.Skip("set DSSE_AUTH_LANGUAGE_BROWSER_DIR for the isolated browser fixture")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	counts := make(map[string]int)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		counts[r.URL.Path]++
		data, _ := json.Marshal(counts)
		err := os.WriteFile(filepath.Join(dir, "requests.json"), data, 0600)
		mu.Unlock()
		if err != nil {
			http.Error(w, "fixture recording failed", 500)
			return
		}
		switch r.URL.Path {
		case "/success":
			http.SetCookie(w, &http.Cookie{Name: authSessionCookie, Value: "local-fixture-binding", Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
			writeCeremonySuccessHTML(w, "fixture@example.invalid", "phishing_resistant", "10.200.0.10:18081", r)
		case "/success-peer":
			// A stateless peer's renderer receives the same host-only preference.
			binding, err := r.Cookie(authSessionCookie)
			if err != nil || binding.Value != "local-fixture-binding" {
				http.Error(w, "fixture browser binding changed", 403)
				return
			}
			writeCeremonySuccessHTML(w, "fixture@example.invalid", "phishing_resistant", "10.200.0.10:18081", r)
		case "/error":
			respondCeremonyError(w, r, 401, "Sign-in link expired", "Return to your app and request a fresh sign-in link.")
		case "/confirm":
			writeDestinationConfirmation(w, r, "local-fixture-confirmation")
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	data, _ := json.Marshal(map[string]string{"origin": srv.URL})
	if err := os.WriteFile(filepath.Join(dir, "fixture.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	deadline := time.NewTimer(5 * time.Minute)
	defer deadline.Stop()
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-deadline.C:
			t.Fatal("language browser fixture timed out")
		case <-tick.C:
			if _, err := os.Stat(filepath.Join(dir, "finish")); err == nil {
				return
			}
		}
	}
}
