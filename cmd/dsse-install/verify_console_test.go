package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestVerifyConsoleRequiresServingLoginAndDenyingGatedAsset(t *testing.T) {
	for _, test := range []struct {
		name        string
		loginStatus int
		assetStatus int
		wantRoot    bool
		wantGate    bool
	}{
		{name: "healthy", loginStatus: http.StatusOK, assetStatus: http.StatusUnauthorized, wantRoot: true, wantGate: true},
		{name: "broken login", loginStatus: http.StatusInternalServerError, assetStatus: http.StatusUnauthorized, wantRoot: false, wantGate: true},
		{name: "missing asset", loginStatus: http.StatusOK, assetStatus: http.StatusNotFound, wantRoot: true, wantGate: false},
		{name: "asset service unavailable", loginStatus: http.StatusOK, assetStatus: http.StatusServiceUnavailable, wantRoot: true, wantGate: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/":
					w.WriteHeader(test.loginStatus)
				case "/app.js":
					w.WriteHeader(test.assetStatus)
				case "/admin/login/password":
					w.WriteHeader(http.StatusUnauthorized)
				default:
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			defer server.Close()
			results := verifyConsole(server.Client(), server.URL)
			var foundRoot, foundGate bool
			for _, result := range results {
				switch result.name {
				case "the Console answers":
					foundRoot = true
					if result.ok != test.wantRoot {
						t.Errorf("Console login status %d: result %+v", test.loginStatus, result)
					}
				case "the Console refuses an unauthenticated request":
					foundGate = true
					if result.ok != test.wantGate {
						t.Errorf("gated asset status %d: result %+v", test.assetStatus, result)
					}
				}
			}
			if !foundRoot || !foundGate {
				t.Fatalf("missing Console verdicts: %+v", results)
			}
		})
	}
}
