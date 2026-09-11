package main

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/model"
)

// the token bucket allows up to `burst` immediately, denies beyond it, and refills over time.
func TestTokenBucketLimiter(t *testing.T) {
	base := time.Unix(1700000000, 0)
	now := base
	l := newTokenBucketLimiter(10, 3) // 10 rps, burst 3
	l.now = func() time.Time { return now }

	// First 3 (burst) allowed, 4th denied.
	for i := 0; i < 3; i++ {
		if !l.allow("1.2.3.4") {
			t.Fatalf("request %d within burst should be allowed", i+1)
		}
	}
	if l.allow("1.2.3.4") {
		t.Fatal("4th request (over burst) must be denied")
	}
	// A different client has its own bucket.
	if !l.allow("5.6.7.8") {
		t.Fatal("a different client must not be limited by another's bucket")
	}
	// After 0.2s at 10rps, ~2 tokens refill -> allowed again.
	now = base.Add(200 * time.Millisecond)
	if !l.allow("1.2.3.4") {
		t.Fatal("after refill the client should be allowed again")
	}

	// rps<=0 (disabled) always allows.
	off := newTokenBucketLimiter(0, 0)
	for i := 0; i < 100; i++ {
		if !off.allow("x") {
			t.Fatal("disabled limiter must always allow")
		}
	}
}

func TestIsRateLimitedEdgePath(t *testing.T) {
	for _, p := range []string{"/admin/applications", "/auth/oidc/login", "/clientless/auth/start", "/clientless/auth/callback"} {
		if !isRateLimitedEdgePath(p) {
			t.Fatalf("%s should be rate-limited", p)
		}
	}
	for _, p := range []string{"/steer", "/healthz", "/connectors/register", "/clientless/apps/wiki"} {
		if isRateLimitedEdgePath(p) {
			t.Fatalf("%s (data plane) must NOT be rate-limited", p)
		}
	}
}

// the middleware returns 429 on admin/auth paths past the burst, but never limits the data
// plane, and a disabled limiter is a pass-through.
func TestRateLimitMiddleware(t *testing.T) {
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	limiter := newTokenBucketLimiter(1, 2) // burst 2
	h := rateLimitMiddleware(ok, limiter, isRateLimitedEdgePath)
	call := func(path string) int {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.RemoteAddr = "9.9.9.9:5555"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	if call("/admin/x") != http.StatusOK || call("/admin/x") != http.StatusOK {
		t.Fatal("first two admin requests (burst) should pass")
	}
	if got := call("/admin/x"); got != http.StatusTooManyRequests {
		t.Fatalf("third admin request should be 429, got %d", got)
	}
	// Data-plane path is never limited even after the admin bucket is drained.
	for i := 0; i < 10; i++ {
		if got := call("/steer"); got != http.StatusOK {
			t.Fatalf("/steer must never be rate-limited, got %d", got)
		}
	}
	// nil/disabled limiter is a pass-through.
	pass := rateLimitMiddleware(ok, newTokenBucketLimiter(0, 0), isRateLimitedEdgePath)
	req := httptest.NewRequest(http.MethodGet, "/admin/x", nil)
	rec := httptest.NewRecorder()
	pass.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("disabled limiter must pass through, got %d", rec.Code)
	}
}

// the legacy -admin-token is fail-closed in production — empty is OK (disabled), but a weak
// or short value when lab-mode is off refuses to start. Lab imposes no constraint.
func TestValidateAdminTokenConfig(t *testing.T) {
	strong := "Zk3pQ9rV7sW2xY5tB8nC1mD4fG6hJ0kL" // 32 chars
	cases := []struct {
		name    string
		lab     bool
		token   string
		wantErr bool
	}{
		{"lab allows anything", true, "admin", false},
		{"empty disabled is ok", false, "", false},
		{"empty trimmed is ok", false, "   ", false},
		{"weak rejected", false, "admin", true},
		{"weak default rejected", false, "local-connector-secret", true},
		{"short rejected", false, "abc123", true},
		{"strong accepted", false, strong, false},
	}
	for _, c := range cases {
		err := validateAdminTokenConfig(c.lab, c.token)
		if (err != nil) != c.wantErr {
			t.Fatalf("%s: validateAdminTokenConfig(lab=%v, %q) err=%v wantErr=%v", c.name, c.lab, c.token, err, c.wantErr)
		}
	}
}

// CORS for the separate-host Admin Console — exact-origin only, admin surface only, preflight
// answered, never "*".
func TestAdminConsoleCORSMiddleware(t *testing.T) {
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	h := adminConsoleCORSMiddleware(ok, "https://console.internal")
	do := func(method, path, origin string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, nil)
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	// Matching origin on the admin surface -> CORS header echoes the exact origin.
	r := do(http.MethodGet, "/admin/state", "https://console.internal")
	if r.Header().Get("Access-Control-Allow-Origin") != "https://console.internal" {
		t.Fatalf("expected exact-origin CORS header, got %q", r.Header().Get("Access-Control-Allow-Origin"))
	}
	// Preflight OPTIONS -> 204, short-circuited.
	if pre := do(http.MethodOptions, "/admin/dns-policy", "https://console.internal"); pre.Code != http.StatusNoContent {
		t.Fatalf("preflight should be 204, got %d", pre.Code)
	}
	// Wrong origin -> no CORS header.
	if r := do(http.MethodGet, "/admin/state", "https://evil.example"); r.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("non-matching origin must not get a CORS header")
	}
	// Data-plane path -> no CORS even from the allowed origin.
	if r := do(http.MethodGet, "/steer", "https://console.internal"); r.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("data-plane path must not get CORS")
	}
	// Disabled (empty origin) -> pass-through, no CORS.
	off := adminConsoleCORSMiddleware(ok, "")
	rec := httptest.NewRecorder()
	off.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/admin/state", nil))
	if rec.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("disabled CORS must not set headers")
	}
}

// the dedicated admin listener must NOT be loopback (the Admin Console is a separate host).
func TestValidateAdminListenAddr(t *testing.T) {
	ok := []string{"", ":9443", "0.0.0.0:9443", "10.0.0.5:9443", "edge.internal:9443"}
	for _, a := range ok {
		if err := validateAdminListenAddr(a); err != nil {
			t.Fatalf("%q should be allowed: %v", a, err)
		}
	}
	bad := []string{"127.0.0.1:9443", "localhost:9443", "[::1]:9443"}
	for _, a := range bad {
		if err := validateAdminListenAddr(a); err == nil {
			t.Fatalf("loopback %q must be rejected: the admin listener is not on loopback", a)
		}
	}
}

// the listener separation — admin listener serves only the admin surface; data-plane listener
// excludes it.
func TestAdminSurfaceSeparationMiddleware(t *testing.T) {
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	adminOnly := adminSurfaceOnlyMiddleware(ok)
	dataOnly := dataPlaneOnlyMiddleware(ok)
	get := func(h http.Handler, path string) int {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		return rec.Code
	}
	// admin listener: admin/auth + healthz allowed, data plane 404.
	if get(adminOnly, "/admin/state") != http.StatusOK || get(adminOnly, "/auth/oidc/login") != http.StatusOK || get(adminOnly, "/healthz") != http.StatusOK {
		t.Fatal("admin listener must serve admin/auth/healthz")
	}
	if get(adminOnly, "/steer") != http.StatusNotFound || get(adminOnly, "/connectors/register") != http.StatusNotFound {
		t.Fatal("admin listener must 404 the data plane")
	}
	// data-plane listener: data plane allowed, admin/auth 404.
	if get(dataOnly, "/steer") != http.StatusOK || get(dataOnly, "/clientless/apps/x") != http.StatusOK {
		t.Fatal("data-plane listener must serve the data plane")
	}
	if get(dataOnly, "/admin/state") != http.StatusNotFound || get(dataOnly, "/auth/oidc/login") != http.StatusNotFound {
		t.Fatal("data-plane listener must 404 the admin surface")
	}
}

// the Edge is TLS-only; plaintext is fail-closed. Resolve the listener mode by precedence.
func TestMainEdgeListenerMode(t *testing.T) {
	if m := mainEdgeListenerMode("c.pem", "k.pem", false, false); m != "tls_cert" {
		t.Fatalf("cert/key -> tls_cert, got %q", m)
	}
	if m := mainEdgeListenerMode("", "", true, false); m != "tls_lab" {
		t.Fatalf("lab -> tls_lab, got %q", m)
	}
	if m := mainEdgeListenerMode("", "", false, true); m != "insecure_plaintext" {
		t.Fatalf("explicit insecure -> insecure_plaintext, got %q", m)
	}
	// No cert, not lab, not explicitly insecure -> REFUSE (fail-closed, no plaintext).
	if m := mainEdgeListenerMode("", "", false, false); m != "" {
		t.Fatalf("default must refuse (empty), got %q", m)
	}
	// cert/key wins over lab (explicit production cert).
	if m := mainEdgeListenerMode("c.pem", "k.pem", true, true); m != "tls_cert" {
		t.Fatalf("cert/key must take precedence, got %q", m)
	}
}

// session/admin/OIDC cookies are Secure (never traverse plaintext) + HttpOnly.
func TestCookiesAreSecure(t *testing.T) {
	cookies := []*http.Cookie{
		sessionCookie(model.Session{ID: "s"}),
		adminSessionCookie(adminSession{ID: "a"}),
		oidcCookie("n", "v"),
		oidcReturnToCookie("/x"),
		eastWestChallengeCookie("c"),
		expiredCookie("z"),
	}
	for _, c := range cookies {
		if !c.Secure {
			t.Fatalf("cookie %q must be Secure", c.Name)
		}
		if !c.HttpOnly {
			t.Fatalf("cookie %q must be HttpOnly", c.Name)
		}
	}
}

// security headers on every response; HSTS only over TLS.
func TestSecurityHeadersMiddleware(t *testing.T) {
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	h := securityHeadersMiddleware(ok)

	// Plaintext request: base headers present, NO HSTS.
	req := httptest.NewRequest(http.MethodGet, "/admin/x", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	res := rec.Result().Header
	if res.Get("X-Content-Type-Options") != "nosniff" || res.Get("X-Frame-Options") != "DENY" {
		t.Fatalf("missing nosniff/XFO: %v", res)
	}
	if res.Get("Referrer-Policy") == "" || res.Get("Content-Security-Policy") == "" {
		t.Fatalf("missing referrer/CSP: %v", res)
	}
	// The Edge is API-only (the Console is a separate strict-CSP host), so the CSP is always strict:
	// no 'unsafe-inline' under any configuration.
	if strings.Contains(res.Get("Content-Security-Policy"), "unsafe-inline") {
		t.Fatalf("CSP must not contain unsafe-inline: %q", res.Get("Content-Security-Policy"))
	}
	if res.Get("Strict-Transport-Security") != "" {
		t.Fatal("HSTS must NOT be sent over plaintext")
	}

	// TLS request: HSTS present.
	reqTLS := httptest.NewRequest(http.MethodGet, "/admin/x", nil)
	reqTLS.TLS = &tls.ConnectionState{}
	recTLS := httptest.NewRecorder()
	h.ServeHTTP(recTLS, reqTLS)
	if recTLS.Result().Header.Get("Strict-Transport-Security") == "" {
		t.Fatal("HSTS must be sent over TLS")
	}
}

// the hardened server sets Slowloris-safe timeouts and leaves streaming bodies unbounded.
func TestHardenedHTTPServerTimeouts(t *testing.T) {
	srv := hardenedHTTPServer(":0", "test", http.NewServeMux())
	if srv.ReadHeaderTimeout != edgeReadHeaderTimeout {
		t.Fatalf("ReadHeaderTimeout = %v, want %v", srv.ReadHeaderTimeout, edgeReadHeaderTimeout)
	}
	if srv.IdleTimeout != edgeIdleTimeout {
		t.Fatalf("IdleTimeout = %v, want %v", srv.IdleTimeout, edgeIdleTimeout)
	}
	if srv.ReadTimeout != 0 || srv.WriteTimeout != 0 {
		t.Fatalf("Read/Write timeouts must be 0 for streaming; got read=%v write=%v", srv.ReadTimeout, srv.WriteTimeout)
	}
}
