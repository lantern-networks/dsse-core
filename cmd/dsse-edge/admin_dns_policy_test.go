package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/logs"
)

// the admin DNS-policy HTTP endpoints read + hot-apply the live ruleset (API-first / ).
func TestAdminDNSPolicyEndpoint(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	handler := newServerWithConfig(serverConfig{
		Evaluator: testEvaluator(),
		Writer:    writer,
		Registry:  connector.NewRegistry(),
		AdminAuth: newAdminAuthStore(),
	})
	do := func(method, path, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("content-type", "application/json")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}

	// PUT a ruleset -> 200 and the response echoes it back.
	put := do(http.MethodPut, "/admin/dns-policy", `{"deny":["evil.example"],"sinkhole":{"ads.example":"100.64.0.250"},"ech_strip":true}`)
	if put.Code != http.StatusOK {
		t.Fatalf("PUT status=%d body=%s", put.Code, put.Body.String())
	}
	if !strings.Contains(put.Body.String(), "evil.example") || !strings.Contains(put.Body.String(), "100.64.0.250") {
		t.Fatalf("PUT response should echo the ruleset; body=%s", put.Body.String())
	}

	// GET reflects the hot-applied ruleset (proves it landed on the live resolver, not just env).
	get := do(http.MethodGet, "/admin/dns-policy", "")
	if get.Code != http.StatusOK || !strings.Contains(get.Body.String(), "evil.example") {
		t.Fatalf("GET must reflect applied ruleset; code=%d body=%s", get.Code, get.Body.String())
	}

	// Invalid ruleset (bad IP) -> 400.
	if bad := do(http.MethodPut, "/admin/dns-policy", `{"sinkhole":{"x.example":"nope"}}`); bad.Code != http.StatusBadRequest {
		t.Fatalf("bad IP must be 400; got %d body=%s", bad.Code, bad.Body.String())
	}
}
