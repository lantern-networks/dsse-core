package main

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestConsoleRefusesCoalescedPortalRequest(t *testing.T) {
	for _, tc := range []struct {
		name, sni, host string
		wantStatus      int
	}{
		{"coalesced Portal", "console.example.test", "portal-a.example.test", http.StatusMisdirectedRequest},
		{"other Console alias", "console.example.test", "console.region-a.example.test", http.StatusMisdirectedRequest},
		{"matching Console", "console.example.test", "console.example.test", http.StatusNoContent},
		{"matching Console with port", "console.example.test", "console.example.test:443", http.StatusNoContent},
		{"HAProxy readiness without Host", "console.example.test", "", http.StatusNoContent},
		{"IP connection without SNI", "", "127.0.0.1:8443", http.StatusNoContent},
	} {
		t.Run(tc.name, func(t *testing.T) {
			called := false
			h := rejectMisdirectedConsoleRequest(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				called = true
				w.WriteHeader(http.StatusNoContent)
			}))
			r := httptest.NewRequest(http.MethodGet, "https://console.example.test/ready", nil)
			r.Host = tc.host
			r.TLS = &tls.ConnectionState{ServerName: tc.sni, NegotiatedProtocol: "h2"}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != tc.wantStatus || called != (tc.wantStatus == http.StatusNoContent) {
				t.Fatalf("status=%d called=%t, want status=%d", w.Code, called, tc.wantStatus)
			}
			if tc.wantStatus == http.StatusMisdirectedRequest && w.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("misdirected response can be cached")
			}
		})
	}
}
