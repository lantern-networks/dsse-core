package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lantern-networks/dsse-core/grantstore"
)

func TestEndpointOnlyConfigurationRemainsAReceiver(t *testing.T) {
	base, err := resolveConfigSourceURL("", "region-a=https://cp-a.example:9443;region-b=https://cp-b.example:9443")
	if err != nil {
		t.Fatal(err)
	}
	if newRemoteEnrolmentTokenAuthority(base, "machine-token", http.DefaultClient) == nil {
		t.Error("endpoint-only receiver retained local enrollment authority")
	}
	mux := http.NewServeMux()
	registerGrantReportRoute(mux, grantstore.NewStore(), nil, base, true)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/grant-report", strings.NewReader(`{"grants":[]}`)))
	if w.Code != http.StatusNotFound {
		t.Errorf("config receiver exposed authority grant-report route: %d", w.Code)
	}
}

func TestConfigSourceURLResolutionPreservesExplicitFallback(t *testing.T) {
	for _, tc := range []struct{ fixed, endpoints, want string }{
		{"", "", ""},
		{" https://fixed.example ", "", "https://fixed.example"},
		{"https://fixed.example", "a=https://a.example", "https://fixed.example"},
		{"", " a=https://a.example/; b=https://b.example ", "https://a.example/"},
	} {
		got, err := resolveConfigSourceURL(tc.fixed, tc.endpoints)
		if err != nil || got != tc.want {
			t.Errorf("resolve fixed=%q endpoints=%q got=%q error=%v", tc.fixed, tc.endpoints, got, err)
		}
	}
	if _, err := resolveConfigSourceURL("https://fixed.example", "a=https://a.example;bad"); err == nil {
		t.Error("malformed endpoint list silently fell back to fixed URL")
	}
}
