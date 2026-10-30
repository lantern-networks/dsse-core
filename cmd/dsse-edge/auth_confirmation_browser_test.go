package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/grantstore"
	"github.com/lantern-networks/dsse-core/idpregistry"
)

// Opt-in loopback-only UI fixture. No external IdP, credentials, OS agent or AWS.
// The fixture's self-signed TLS is solely for secure-cookie browser semantics.
func TestDestinationConfirmationBrowserFixture(t *testing.T) {
	dir := os.Getenv("DSSE_AUTH_CONFIRM_BROWSER_DIR")
	if dir == "" {
		t.Skip("set DSSE_AUTH_CONFIRM_BROWSER_DIR for the isolated browser fixture")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()
	// A same-origin IdP cannot catch Chromium blocking a POST's cross-origin
	// redirect under form-action 'self'. Use a genuinely different TLS origin.
	idp := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = os.WriteFile(filepath.Join(dir, "confirmed.json"), []byte(`{"explicit_confirmation_reached_idp":true}`), 0600)
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<h1>Local identity provider reached after confirmation</h1>"))
	}))
	defer idp.Close()
	registry := idpregistry.NewStore()
	if _, err := registry.Upsert(idpregistry.Connection{TenantID: "fixture", IdPID: "local", Type: "oidc", Issuer: idp.URL, AuthorizationEndpoint: idp.URL + "/fixture-idp", ClientID: "fixture-client"}); err != nil {
		t.Fatal(err)
	}
	b := newClientlessBroker(registry, grantstore.NewStore(), srv.Client(), srv.URL, "fixture", time.Minute, nil)
	b.register(mux)
	data, _ := json.Marshal(map[string]string{"start": srv.URL + "/clientless/auth/start?idp=local&return_to=app.internal%3A22"})
	if err := os.WriteFile(filepath.Join(dir, "fixture.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	timer := time.NewTimer(5 * time.Minute)
	defer timer.Stop()
	tick := time.NewTicker(200 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-timer.C:
			t.Fatal("local browser fixture timed out")
		case <-tick.C:
			if _, err := os.Stat(filepath.Join(dir, "finish")); err == nil {
				return
			}
		}
	}
}
