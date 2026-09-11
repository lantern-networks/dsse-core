// Hardened static file server for the reference deployment's Admin Console container (a separate "host").
// The Admin Console is an administrative surface, so access to it is locked down the same way the rest of the
// product is: TLS-only (no plaintext), strict security headers, a refusal to bind a loopback address, and a
// SERVER-SIDE AUTH GATE so the admin SPA bundle is never handed to an unauthenticated client. Static linux
// binary -> runs on scratch with no base-image pull.
//
// Auth gate (the attack-surface control): the only assets served without a session are the minimal login
// surface (index.html/login.js + shared chrome). Every other asset — console.html, app.js (the admin
// endpoint catalog), and anything added later — is DENIED unless the request carries a valid admin session,
// which the gate validates server-side by forwarding the request's cookies to the Edge's GET /admin/session.
// Deny-by-default + fail-closed (Edge unreachable -> denied): an anonymous client can fetch nothing but the
// login page, so there is no admin surface to attack pre-authentication.
//
// Env:
//
//	CONSOLE_DIR                   directory of static assets (default /console)
//	LISTEN                        non-loopback listen addr (default :8443)
//	TLS_CERT, TLS_KEY             server certificate + key (REQUIRED — no plaintext fallback)
//	CLIENT_CA                     PEM bundle of admin CA(s); client certs are verified against it (mTLS)
//	CONSOLE_ALLOW_NO_CLIENT_CERT  "1" -> serve TLS without requiring a client cert (explicit opt-out)
//	ADMIN_SESSION_VALIDATE_URL    Edge session endpoint, e.g. https://edge:9443/admin/session. Set => the
//	                              server-side auth gate is ENABLED. Empty => derived from ADMIN_API_UPSTREAM,
//	                              else gate off (back-compat; logged).
//	ADMIN_SESSION_VALIDATE_CA     PEM CA used to verify upstream TLS on the validation + proxy calls (lab:
//	                              the reference edge.crt, whose SANs cover edge + controlplane). Empty => roots.
//
// Same-origin admin front door (production topology — see docs/admin_console_production_topology_design.md):
// to make the server-side gate hold across SEPARATE hosts, the console-server is the single public origin and
// reverse-proxies the admin API to the Edge so the session cookie is always in scope (no cross-origin, no
// shared-IP dependency, no CORS). Set:
//
//	ADMIN_API_UPSTREAM            Edge admin base, e.g. https://edge:9443. Set => /admin/* and /auth/* are
//	                              proxied here; the gate validates at <upstream>/admin/session.
//	CONTROL_API_UPSTREAM          Control-plane admin base, e.g. https://controlplane:9443. Set => /control/*
//	                              is proxied here (prefix stripped) for audit/reporting endpoints.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"
)

// publicAssets is the allowlist served WITHOUT a session — the minimal pre-auth login surface only. It
// deliberately excludes console.html and app.js (the admin endpoint catalog). i18n.js/styles.css are shared
// UI chrome (no admin endpoint map — that lives only in app.js) so they are safe to serve pre-auth.
var publicAssets = map[string]bool{
	"/":                         true,
	"/index.html":               true,
	"/login.js":                 true,
	"/i18n.js":                  true,
	"/styles.css":               true,
	"/brand/lantern-symbol.svg": true,
	"/vendor/qrcode.min.js":     true,
	"/favicon.ico":              true,
}

// authGate enforces deny-by-default access to non-public assets. A request for any gated asset must carry a
// cookie that the Edge accepts at GET /admin/session; otherwise the bytes are never served (redirect to the
// login page). validateURL empty => gate disabled.
func authGate(validateURL string, client *http.Client, next http.Handler) http.Handler {
	if validateURL == "" {
		log.Printf("WARNING: auth gate DISABLED (ADMIN_SESSION_VALIDATE_URL unset) — the admin SPA is served without a server-side session check")
		return next
	}
	log.Printf("server-side auth gate ENABLED — non-login assets require a valid admin session (validated at %s)", validateURL)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clean := path.Clean(r.URL.Path)
		if clean == "." || clean == "" {
			clean = "/"
		}
		if publicAssets[clean] {
			next.ServeHTTP(w, r)
			return
		}
		verdict := validateSession(r, validateURL, client)
		if verdict == sessionValid {
			next.ServeHTTP(w, r)
			return
		}
		// ★★ AN ASSET REQUEST MUST NOT BE ANSWERED WITH A PAGE (2026-08-18, seen in the Console as a signed-in
		// customer administrator). Every refusal used to be a 302 to "/", which for app.js or console.html
		// returns the login HTML — so the browser reports "Refused to execute script ... MIME type
		// ('text/html')", the app never boots, and the screen sits on "Checking your session…" for as long as
		// the reader is willing to wait. There is nothing on it that says what happened.
		//
		// A navigation still redirects: that is the right answer for somebody arriving at a gated page. An
		// asset gets a status its loader can act on, and a body that says which of the two things went wrong.
		if !isNavigation(r) {
			if verdict == sessionUnverifiable {
				w.Header().Set("Content-Type", "text/plain; charset=utf-8")
				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = w.Write([]byte("the console could not reach the session authority to check your sign-in; " +
					"this is not a sign-out — reload in a moment\n"))
				return
			}
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte("no valid admin session for this asset; sign in at /\n"))
			return
		}
		http.Redirect(w, r, "/", http.StatusFound)
	})
}

// sessionVerdict distinguishes the two reasons an asset is refused. They fail the same way — closed — and
// they mean opposite things to the person in front of the screen: one is "you are not signed in", the other
// is "we could not ask".
type sessionVerdict int

const (
	sessionInvalid sessionVerdict = iota
	sessionValid
	// sessionUnverifiable: the authority did not answer. On this deployment that happens when the Edge is
	// briefly saturated — its admin listener shares a process with the data plane — and it lasts seconds.
	// Reporting it as "not signed in" turns a hiccup into an apparent sign-out.
	sessionUnverifiable
)

// validateSession forwards the incoming request's cookies to the Edge's GET /admin/session. A 200 means the
// cookie authenticated as an admin session (no cookie / bad cookie => 401). Anything else fails CLOSED; what
// changes is that a transport failure is reported as unverifiable rather than as invalid.
func validateSession(r *http.Request, validateURL string, client *http.Client) sessionVerdict {
	cookie := r.Header.Get("Cookie")
	if cookie == "" {
		return sessionInvalid
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, validateURL, nil)
	if err != nil {
		return sessionUnverifiable
	}
	req.Header.Set("Cookie", cookie)
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return sessionUnverifiable
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	switch {
	case resp.StatusCode == http.StatusOK:
		return sessionValid
	case resp.StatusCode >= 500:
		// The authority is there and unwell. Same reasoning as a transport failure.
		return sessionUnverifiable
	default:
		return sessionInvalid
	}
}

// isNavigation reports whether this request is the browser going somewhere, as opposed to fetching a
// subresource. Sec-Fetch-Mode is authoritative where the browser sends it; the Accept header is the fallback
// for clients that do not.
func isNavigation(r *http.Request) bool {
	if mode := r.Header.Get("Sec-Fetch-Mode"); mode != "" {
		return mode == "navigate"
	}
	return strings.Contains(r.Header.Get("Accept"), "text/html")
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// rejectLoopback refuses to bind a loopback address — every service in this deployment is non-loopback so an
// admin surface is never reachable in a way that hides it from the network policy.
func rejectLoopback(addr string) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	h := strings.ToLower(strings.Trim(host, "[]"))
	if h == "localhost" {
		log.Fatalf("refusing to bind a loopback admin-console address: %q", addr)
	}
	if ip := net.ParseIP(h); ip != nil && ip.IsLoopback() {
		log.Fatalf("refusing to bind a loopback admin-console address: %q", addr)
	}
}

// securityHeaders hardens the served console page. The SPA has no inline <script> (external app.js/i18n.js),
// so script-src can be strict 'self'; it fetches arbitrary admin APIs the operator types, so connect-src
// allows https:. HSTS is sent because the listener is TLS-only.
func securityHeaders(next http.Handler) http.Handler {
	const csp = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; " +
		"connect-src 'self' https:; img-src 'self' data:; font-src 'self'; " +
		"base-uri 'none'; frame-ancestors 'none'; form-action 'self'; object-src 'none'"
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		h.Set("Content-Security-Policy", csp)
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

func main() {
	dir := env("CONSOLE_DIR", "/console")
	addr := env("LISTEN", ":8443")
	certFile := os.Getenv("TLS_CERT")
	keyFile := os.Getenv("TLS_KEY")
	clientCA := os.Getenv("CLIENT_CA")
	allowNoClientCert := os.Getenv("CONSOLE_ALLOW_NO_CLIENT_CERT") == "1"

	rejectLoopback(addr)
	if certFile == "" || keyFile == "" {
		log.Fatal("TLS_CERT and TLS_KEY are required — the admin console is TLS-only (no plaintext)")
	}

	_ = allowNoClientCert // retained for back-compat; mTLS is opt-in (set CLIENT_CA), not required
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12, CipherSuites: []uint16{
		// Forward-secret AEAD only on the TLS 1.2 fallback (no CBC / RSA-kx / 3DES); TLS 1.3 suites are fixed.
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
	}}
	// Access control is performed by the admin API via per-tenant IdP login (OIDC) — the Console serves a
	// static SPA over TLS. mTLS is optional defense-in-depth: enable it only when CLIENT_CA is configured.
	if clientCA != "" {
		pem, err := os.ReadFile(clientCA)
		if err != nil {
			log.Fatalf("reading CLIENT_CA %q: %v", clientCA, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			log.Fatalf("CLIENT_CA %q contained no usable certificates", clientCA)
		}
		tlsCfg.ClientCAs = pool
		tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert
		log.Printf("optional mTLS ENABLED — clients must also present a cert issued by %s", clientCA)
	} else {
		log.Printf("TLS-only — admin access control is enforced by the admin API via per-tenant IdP login")
	}

	// Upstream TLS trust (Edge / control-plane admin APIs) — one CA pool reused by the validation client and
	// the reverse proxies.
	upstreamTLS := upstreamTLSConfig(os.Getenv("ADMIN_SESSION_VALIDATE_CA"))
	validateClient := &http.Client{Timeout: 8 * time.Second, Transport: &http.Transport{TLSClientConfig: upstreamTLS}}

	// Same-origin front door: proxy the admin API so the session cookie is always in scope. Routing splits the
	// management surface across the two backends (docs/admin_auth_centralization_design.md):
	//   - the AUTH/identity surface (login/activate/admins/session/logout/oidc) -> control plane (the admin
	//     auth AUTHORITY that mints + owns sessions),
	//   - enforcement config/state (/admin/*) -> the Edge,
	//   - durable data (/control/*) -> the control plane.
	// The gate validates against the auth authority; only the static SPA is subject to deny-by-default.
	adminUpstream := os.Getenv("ADMIN_API_UPSTREAM")     // enforcement Edge
	controlUpstream := os.Getenv("CONTROL_API_UPSTREAM") // control-plane durable data
	authUpstream := os.Getenv("AUTH_API_UPSTREAM")       // admin auth authority (control plane); empty => Edge
	validateURL := os.Getenv("ADMIN_SESSION_VALIDATE_URL")
	if validateURL == "" {
		if authUpstream != "" {
			validateURL = strings.TrimRight(authUpstream, "/") + "/admin/session"
		} else if adminUpstream != "" {
			validateURL = strings.TrimRight(adminUpstream, "/") + "/admin/session"
		}
	}

	mux := http.NewServeMux()
	var edgeProxy http.Handler
	if adminUpstream != "" {
		edgeProxy = newReverseProxy(adminUpstream, upstreamTLS)
		mux.Handle("/admin/", edgeProxy) // enforcement config/state (auth subpaths overridden below)
		log.Printf("front door: /admin/* -> %s (enforcement Edge)", adminUpstream)
	}
	// The auth/identity surface goes to the auth authority (control plane); when AUTH_API_UPSTREAM is unset it
	// falls back to the Edge (legacy single-authority behavior). Registered as more-specific patterns so they
	// win over /admin/ in the ServeMux.
	authProxy := edgeProxy
	if authUpstream != "" {
		authProxy = newReverseProxy(authUpstream, upstreamTLS)
		log.Printf("front door: auth surface (login/activate/admins/session/logout/oidc + /auth/) -> %s (auth authority)", authUpstream)
	}
	if authProxy != nil {
		for _, p := range []string{"/admin/login/", "/admin/activate", "/admin/activate/", "/admin/admins", "/admin/admins/", "/admin/session", "/admin/logout", "/admin/oidc/", "/auth/"} {
			mux.Handle(p, authProxy)
		}
	}
	if controlUpstream != "" {
		cpProxy := newReverseProxy(controlUpstream, upstreamTLS)
		mux.Handle("/control/", http.StripPrefix("/control", cpProxy))
		log.Printf("front door: /control/* -> %s (durable data)", controlUpstream)
	}
	mux.Handle("/", authGate(validateURL, validateClient, http.FileServer(http.Dir(dir))))

	srv := &http.Server{
		Addr:      addr,
		Handler:   securityHeaders(mux),
		TLSConfig: tlsCfg,
		// Public front-door hardening: bound the time to read request headers (Slowloris) + reap idle keep-alives
		// + cap header size. ReadTimeout/WriteTimeout are deliberately unset: this reverse-proxies long admin
		// calls (e.g. the AI-Ops LLM answer with its keepalive heartbeat) and must not time-bound the body.
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20, // 1 MiB
	}
	// Cap concurrent connections so a fan-out / connection-exhaustion flood cannot run the public front door out
	// of file descriptors (the timeouts above bound per-connection cost; this bounds the count). 0 = unlimited.
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("listen %s: %v", addr, err)
	}
	if maxConns := envInt("CONSOLE_MAX_CONNECTIONS", 4096); maxConns > 0 {
		ln = newLimitListener(ln, maxConns)
		log.Printf("admin console: concurrent connection cap = %d (CONSOLE_MAX_CONNECTIONS)", maxConns)
	}
	log.Printf("admin console (TLS) on %s serving %s", addr, dir)
	log.Fatal(srv.ServeTLS(ln, certFile, keyFile))
}

// envInt reads an int env var, or returns def when unset/invalid.
func envInt(k string, def int) int {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

// limitListener caps the number of concurrent accepted connections (the standard golang.org/x/net/netutil
// pattern, inlined so this zero-dependency module stays dependency-free). Accept blocks once the cap is hit
// until a live connection closes.
type limitListener struct {
	net.Listener
	sem chan struct{}
}

func newLimitListener(l net.Listener, n int) net.Listener {
	return &limitListener{Listener: l, sem: make(chan struct{}, n)}
}

func (l *limitListener) Accept() (net.Conn, error) {
	l.sem <- struct{}{}
	c, err := l.Listener.Accept()
	if err != nil {
		<-l.sem
		return nil, err
	}
	return &limitConn{Conn: c, release: func() { <-l.sem }}, nil
}

type limitConn struct {
	net.Conn
	release func()
	once    sync.Once
}

func (c *limitConn) Close() error {
	c.once.Do(c.release)
	return c.Conn.Close()
}

// upstreamTLSConfig builds the TLS config used to reach the Edge / control-plane admin APIs. When caFile is
// set its cert(s) are the ONLY trust anchors (the reference edge.crt, SANs cover edge + controlplane);
// otherwise system roots are used.
func upstreamTLSConfig(caFile string) *tls.Config {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			log.Fatalf("reading ADMIN_SESSION_VALIDATE_CA %q: %v", caFile, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			log.Fatalf("ADMIN_SESSION_VALIDATE_CA %q contained no usable certificates", caFile)
		}
		cfg.RootCAs = pool
	}
	return cfg
}

// newReverseProxy proxies to a single upstream admin API over TLS, forwarding cookies both ways (the default
// ReverseProxy behavior) so the browser's same-origin session cookie reaches the Edge and Set-Cookie comes
// back scoped to the front-door origin. The upstream Host is set for correct SNI/vhost.
func newReverseProxy(target string, tlsCfg *tls.Config) http.Handler {
	u, err := url.Parse(target)
	if err != nil {
		log.Fatalf("invalid upstream URL %q: %v", target, err)
	}
	p := httputil.NewSingleHostReverseProxy(u)
	// DisableKeepAlives: use a fresh upstream connection per request. Without it, a POST that lands on a pooled
	// keep-alive connection the upstream had already closed FAILS — Go's transport silently retries idempotent
	// GETs on a stale connection but never a POST, so GETs worked while "Add connector" (a POST) intermittently
	// stalled/"Failed to fetch", worst on the first POST after page load. An admin console's request volume makes
	// per-request connections a non-issue, and it matches curl (fresh connection), which never reproduced the bug.
	p.Transport = &http.Transport{TLSClientConfig: tlsCfg, DisableKeepAlives: true}
	orig := p.Director
	p.Director = func(r *http.Request) { orig(r); r.Host = u.Host }
	return p
}
