package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestInstallReadCredentialIsMintedFromNamedSessionWithOnlyStateRead(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/admin/api-tokens" || r.Header.Get("Authorization") != "" {
			t.Error("credential minting did not use the admin session")
		}
		cookie, err := r.Cookie("admin_session")
		if err != nil || cookie.Value != "named-session" || r.Header.Get("X-CSRF-Token") != "named-csrf" {
			t.Error("administrator session or CSRF missing")
		}
		var input struct {
			Name          string
			Roles, Scopes []string
		}
		if json.NewDecoder(r.Body).Decode(&input) != nil {
			t.Error("invalid credential request")
		}
		if input.Name != "installation-state-read" || !slices.Equal(input.Roles, []string{"admin"}) || !slices.Equal(input.Scopes, []string{"admin.state.read"}) {
			t.Error("installation credential exceeded state-read scope")
		}
		w.WriteHeader(201)
		json.NewEncoder(w).Encode(map[string]string{"raw_token": "disposable-reader"})
	}))
	defer server.Close()
	got, err := mintInstallationReadToken(server.Client(), server.URL, adminSession{ID: "named-session", CSRF: "named-csrf"})
	if err != nil || got != "disposable-reader" {
		t.Fatalf("read credential mint failed: %v", err)
	}
}

func TestBootstrapWillNotOverwriteExistingInstallationReadCredential(t *testing.T) {
	dir := installerFixture(t, threeNodesOneRegionPlan())
	path := privateInstallReadTokenDestination(dir)
	if err := os.WriteFile(path, []byte("existing-reader"), 0600); err != nil {
		t.Fatal(err)
	}
	calls := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; w.WriteHeader(500) }))
	defer server.Close()
	err := runBootstrapAdminWithTokenFile(dir, server.URL, "test@example.invalid", "", filepath.Join(t.TempDir(), "operator-token"))
	if err == nil || calls != 0 {
		t.Fatal("bootstrap contacted authority before reserving the read-credential destination")
	}
	if raw, _ := os.ReadFile(path); string(raw) != "existing-reader" {
		t.Fatal("bootstrap overwrote read credential")
	}
}
