package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClientIPForRateLimit(t *testing.T) {
	req := func(remote, xff string) *http.Request {
		r := httptest.NewRequest("GET", "/admin/x", nil)
		r.RemoteAddr = remote
		if xff != "" {
			r.Header.Set("X-Forwarded-For", xff)
		}
		return r
	}

	// No trusted proxies: XFF is ignored (spoof-safe), always RemoteAddr host.
	rateLimitTrustedProxies = nil
	if got := clientIPForRateLimit(req("203.0.113.9:5555", "1.2.3.4")); got != "203.0.113.9" {
		t.Fatalf("no trusted proxies: want RemoteAddr 203.0.113.9, got %q", got)
	}

	// With a trusted LB: a connection FROM the LB uses the rightmost non-proxy XFF entry (the real client).
	rateLimitTrustedProxies = parseTrustedProxies("10.0.0.1, 10.0.0.0/24")
	defer func() { rateLimitTrustedProxies = nil }()
	if got := clientIPForRateLimit(req("10.0.0.1:443", "9.9.9.9, 10.0.0.5")); got != "9.9.9.9" {
		t.Fatalf("trusted LB: want client 9.9.9.9 (rightmost non-proxy), got %q", got)
	}
	// A connection NOT from a trusted proxy: XFF ignored even if present (spoofed).
	if got := clientIPForRateLimit(req("203.0.113.9:5555", "9.9.9.9")); got != "203.0.113.9" {
		t.Fatalf("untrusted source: XFF must be ignored, got %q", got)
	}
	// XFF with only trusted-proxy entries falls back to the connecting proxy.
	if got := clientIPForRateLimit(req("10.0.0.1:443", "10.0.0.7")); got != "10.0.0.1" {
		t.Fatalf("all-proxy XFF: want fallback 10.0.0.1, got %q", got)
	}
}
