package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	certreload "github.com/lantern-networks/dsse-core/certreload"
)

// Edge/Admin server hardening: bounded request-read timeouts (Slowloris defense) and an
// optional per-client rate limiter on the auth + admin surfaces.
//
// Timeout choice: the Edge carries long-lived STREAMING connections (the connector tunnel relay, the (T)
// transport carrying steered flows, DNS-over-tunnel, websocket tunnels). A global ReadTimeout/WriteTimeout
// would kill those, so we set ONLY ReadHeaderTimeout (bounds the time to read request headers — the actual
// Slowloris vector) and IdleTimeout (keep-alive reaping). Read/Write bodies stay unbounded for streaming.

const (
	edgeReadHeaderTimeout = 10 * time.Second
	edgeIdleTimeout       = 120 * time.Second
)

// hardenedHTTPServer wraps a handler in an http.Server with Slowloris-safe timeouts. addr may be "" when the
// caller serves a pre-built net.Listener (the (T) TLS listener).
// ★ AND IT MUST SAY WHICH DOOR (2026-08-22, measured). An Edge serves several listeners from one process —
// the agent/data plane, the admin surface, the (T) transport plane — and net/http's handshake errors name only
// the CLIENT's address. A device refusing this node's certificate once a minute was therefore unanswerable:
// the line said a peer sent unknown_certificate, and nothing said which of the three certificates it had been
// offered. Diagnosing it meant guessing. The door goes in the prefix.
func hardenedHTTPServer(addr, door string, handler http.Handler) *http.Server {
	if strings.TrimSpace(door) == "" {
		door = "unnamed"
	}
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: edgeReadHeaderTimeout,
		IdleTimeout:       edgeIdleTimeout,
		// ReadTimeout / WriteTimeout deliberately unset (0): streaming tunnels must not be time-bounded.
		// Filter net/http's own ErrorLog: its per-connection "TLS handshake error … EOF/reset" lines are
		// benign client aborts (health probes, port scans, keep-alive closes) — pure Plane-A noise that
		// otherwise defeats the quiet-at-INFO contract. Genuine server errors still surface.
		ErrorLog: log.New(&benignConnErrorFilter{}, "door="+door+" ", 0),
	}
}

// benignConnErrorFilter is an io.Writer for http.Server.ErrorLog that drops the stdlib's benign per-connection
// TLS/handshake noise (client aborts, port scans) unless DEBUG is on, and passes anything else straight
// through. This keeps a busy edge silent at INFO without hiding real server errors. See
//
// The benign set is an explicit list of NOISE SHAPES, never the whole "TLS handshake error" class. The first
// version swallowed every handshake-error line, and on 2026-08-02 that included "failed to verify client
// certificate: x509: certificate signed by unknown authority" — the Edge refusing its own fleet's renewed
// certificates for hours, with nothing in the log on the side doing the refusing. A handshake the EDGE decides
// to reject is a security event; only a handshake the CLIENT or the network abandoned is noise.
type benignConnErrorFilter struct{}

// benignHandshakeNoise are the abandonment/scanner shapes inside a "TLS handshake error" line that carry no
// information about this Edge's own decisions: the peer went away, or was never speaking TLS at all.
var benignHandshakeNoise = []string{
	"EOF",
	"connection reset",
	"broken pipe",
	"i/o timeout",
	"use of closed network connection",
	"first record does not look like a TLS handshake",
	"client offered only unsupported versions",
	"no cipher suite supported by both client and server",
}

func (benignConnErrorFilter) Write(p []byte) (int, error) {
	msg := string(p)
	benign := strings.Contains(msg, "http: connection reset") ||
		strings.HasSuffix(strings.TrimSpace(msg), "EOF")
	if strings.Contains(msg, "TLS handshake error") {
		for _, noise := range benignHandshakeNoise {
			if strings.Contains(msg, noise) {
				benign = true
				break
			}
		}
	}
	if benign && !logDebugEnabled() {
		return len(p), nil // swallow the benign line (report success so net/http is unaffected)
	}
	log.Print(strings.TrimRight(msg, "\n"))
	return len(p), nil
}

// minProductionAdminTokenLength is the floor for the legacy -admin-token in production (non-lab). It is a
// single static `owner` bearer with no rotation/expiry, so a short/guessable value is a full-control risk.
const minProductionAdminTokenLength = 32

// minProductionSecretLength is the floor for shared runtime secrets (e.g. -connector-secret) in production —
// short/guessable values defeat the constant-time auth they gate. Matches the admin-token floor.
const minProductionSecretLength = 32

// edgeTLS12CipherSuites pins the TLS 1.2 cipher allowlist for the public listeners to forward-secret AEAD
// suites only (ECDHE + AES-GCM / ChaCha20-Poly1305) — no CBC, no RSA key-exchange, no 3DES. Go ignores this
// for TLS 1.3 (its suites are fixed and already safe), so this only constrains the 1.2 fallback. Modern
// clients (Go agents, current browsers) negotiate 1.3; this hardens older-1.2 peers.
var edgeTLS12CipherSuites = []uint16{
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
	tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
}

// weakAdminTokens are obviously-guessable values rejected outright in production.
var weakAdminTokens = map[string]bool{
	"admin": true, "password": true, "changeme": true, "secret": true, "token": true,
	"admin-token": true, "admintoken": true, "owner": true, "local-connector-secret": true,
}

// validateAdminTokenConfig enforces the production rules on the legacy -admin-token. Empty is allowed (the legacy
// path is simply disabled). When set in production (non-lab), it must be long enough and not a known-weak
// value — otherwise the Edge refuses to start (fail-closed). Lab imposes no constraint. Pure / unit-testable.
func validateAdminTokenConfig(devMode bool, adminToken string) error {
	adminToken = strings.TrimSpace(adminToken)
	if devMode || adminToken == "" {
		return nil
	}
	if weakAdminTokens[strings.ToLower(adminToken)] {
		return fmt.Errorf("admin-token is a known-weak value; use a long random secret (or unset it and use admin API tokens)")
	}
	if len(adminToken) < minProductionAdminTokenLength {
		return fmt.Errorf("admin-token must be at least %d chars when lab-mode is disabled (it is a static owner bearer); use a long random secret or unset it and use admin API tokens", minProductionAdminTokenLength)
	}
	return nil
}

// mainEdgeListenerMode resolves how the main -listen should be served (the Edge is TLS-only;
// plaintext is fail-closed). Pure, so the policy is unit-testable: returns one of "tls_cert", "tls_lab",
// "insecure_plaintext", or "" (refuse). Precedence: explicit cert/key > lab auto-cert > explicit insecure.
func mainEdgeListenerMode(certFile, keyFile string, devMode, allowInsecurePlaintext bool) string {
	if strings.TrimSpace(certFile) != "" && strings.TrimSpace(keyFile) != "" {
		return "tls_cert"
	}
	if devMode {
		return "tls_lab"
	}
	if allowInsecurePlaintext {
		return "insecure_plaintext"
	}
	return ""
}

// mainEdgeListenerTLSConfig is what the door devices actually arrive at presents.
//
// ★★★ AN ORGANIZATION'S OWN CERTIFICATE WHEN ITS NAME IS ASKED FOR, AND IT WAS NOT (2026-08-28, measured on
// the two-region lab: an organization was given its own transport authority, every Edge fetched and installed
// the material, and an SNI probe for its name was still answered with the deployment-wide certificate).
//
// The seam existed and was installed on the SECURE TRANSPORT listener — the separate (T) port. The agent plane
// was then folded onto this one, which the comment beside startSecureTransportListener already names as "the
// one a generated deployment opens", and the seam stayed on the door that no longer has devices behind it. So
// on every deployment this installer builds, a per-organization transport certificate could be issued,
// fetched, installed, counted — and never once served.
//
// ★ NAMED AND SEPARATE SO THE CALL SITE CAN BE TESTED. The seam's own tests all passed while this was broken,
// because they call the seam. What was wrong was which listener had it.
//
// Wrapping rather than replacing: a deployment with no per-organization certificates behaves exactly as
// before, and a name this node does not serve still falls through to the shared certificate.
func mainEdgeListenerTLSConfig(shared func(*tls.ClientHelloInfo) (*tls.Certificate, error)) *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS12, CipherSuites: edgeTLS12CipherSuites,
		GetCertificate: transportCertificateForClientHello(shared)}
}

// serveMainEdgeListener serves the hardened handler on addr. The Edge is TLS-only: HTTPS via -tls-cert/-key,
// else a lab auto-generated self-signed cert, else (only with -allow-insecure-plaintext) plaintext with a
// loud warning, else fail-closed (refuse to start). Blocks until the server stops.
func serveMainEdgeListener(addr, door string, handler http.Handler, certFile, keyFile string, devMode, allowInsecurePlaintext bool, drainState *atomic.Bool, drainPeriod time.Duration) error {
	srv := hardenedHTTPServer(addr, door, mainEdgeListenerHandlerForDoor(door, handler))
	// Phase 4 (LB + graceful drain): on SIGTERM/SIGINT, mark this Edge UNHEALTHY (/healthz -> 503) so the LB
	// drains it, keep serving in-flight + slow clients for drainPeriod, then Shutdown cleanly. This is what
	// makes a rolling upgrade zero-outage — the orchestrator SIGTERMs one Edge at a time. (A raw SIGKILL still
	// dies immediately = a crash, handled by failover.) Only the data-plane listener installs the drain.
	if drainState != nil {
		installGracefulDrain(srv, addr, drainState, drainPeriod)
	}
	switch mainEdgeListenerMode(certFile, keyFile, devMode, allowInsecurePlaintext) {
	case "tls_cert":
		// Hot-reloadable server cert: serve via GetCertificate so the material can be rotated with no restart
		// (SIGHUP / the cert-rotation admin endpoint). See docs/admin_certificate_rotation_design.md.
		provider, err := certreload.NewReloadableCert(certFile, keyFile)
		if err != nil {
			return fmt.Errorf("load TLS cert for %s: %w", addr, err)
		}
		certreload.RegisterReloadable(provider)
		srv.TLSConfig = mainEdgeListenerTLSConfig(provider.GetCertificate)
		// ★ ASK FOR A CLIENT CERTIFICATE, OR THE BINDING THAT DEPENDS ON IT CANNOT EXIST (2026-08-12, eleventh
		// review). The audit-ingest receiver derives the shipping Edge's tenant from its verified certificate
		// and refuses a record naming another — and this listener never REQUESTED one, so VerifiedChains was
		// always empty, the check always took its "cannot verify" branch, and after that branch was made to
		// fail closed it would have refused every shipment instead.
		//
		// VerifyClientCertIfGiven rather than RequireAndVerify: this listener also serves the Console and the
		// admin API, whose clients are browsers and operators holding bearer tokens, and demanding a
		// certificate from them would take the whole admin surface down. A client that PRESENTS one has it
		// verified against the registered CAs and gets a VerifiedChains; one that does not is unchanged, and
		// the routes that need an identity say so themselves.
		// ★★★ AND THE POOL IS READ PER HANDSHAKE, NOT ONCE (2026-08-22, measured on the lab).
		//
		// This used to assign edgeClientCAPool() here, at start-up. addEdgeClientCAs does not MUTATE the pool
		// — it builds a new one and swaps the pointer — so a listener that captured the value kept verifying
		// against the set that existed when it started, for the life of the process. Every CA registered at
		// runtime was invisible to it.
		//
		// What that cost, measured end to end: a device-identity authority created while the fleet was running
		// registered cleanly, appeared on every screen, and issued a certificate through POST /enroll — and
		// that device was refused at the handshake. The Edge's own log named the OTHER authority as the
		// candidate it had tried, because both carry the same subject, which reads as a signing failure rather
		// than as a stale trust set. Only a restart of every Edge fixed it, and a restart looks like a fix for
		// the wrong reason: it rebuilds the pool at boot.
		//
		// GetConfigForClient is the same shape the transport listener already uses, and it costs a pointer load
		// per handshake. The per-connection config must not carry the hook itself, or every handshake recurses.
		// ★★★ AND THE HOOK IS INSTALLED WHETHER OR NOT THERE IS A POOL YET (2026-08-24, found by walking a
		// generated deployment as a device). This whole block used to be inside `if pool != nil`, and on a new
		// deployment there IS no pool at start-up: an Edge boots, and its organization's device CA arrives
		// afterwards in the control plane's config bundle. So the listener never asked for a client
		// certificate, VerifiedChains was empty for ever, and every enrolled device was answered 401 by the
		// steer tunnel. The deployment issued certificates its own Edges would not look at, every screen said
		// the device was enrolled, and only restarting every Edge — after the CA happened to be there — made
		// it work. Which is the same defect this file already records one paragraph up, one level out: it was
		// fixed for the CONTENTS of the pool and not for whether the pool is consulted at all.
		//
		// ★ AN EMPTY POOL STILL ASKS FOR NOTHING, DELIBERATELY. tls.VerifyClientCertIfGiven with no ClientCAs
		// verifies against the SYSTEM roots, so a certificate from any public CA would produce a verified
		// chain and a device identity. Requesting nothing until there is something to verify against is the
		// honest state for a deployment that has registered no organization.
		srv.TLSConfig = mainEdgeListenerClientTLSConfig(srv.TLSConfig, door)
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return fmt.Errorf("listen %s: %w", addr, err)
		}
		log.Printf("local edge listening (HTTPS, hot-reloadable cert) on %s", addr)
		return ignoreServerClosed(srv.ServeTLS(wrapAgentPlaneListener(ln, door), "", ""))
	case "tls_lab":
		cert, _, err := generateSelfSignedTransportCert(secureTransportCertHosts(addr))
		if err != nil {
			return fmt.Errorf("auto-generate lab TLS cert for main listener: %w", err)
		}
		srv.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12, CipherSuites: edgeTLS12CipherSuites, Certificates: []tls.Certificate{cert}}
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return fmt.Errorf("listen %s: %w", addr, err)
		}
		log.Printf("local edge listening (HTTPS, lab self-signed) on %s", addr)
		return ignoreServerClosed(srv.ServeTLS(wrapAgentPlaneListener(ln, door), "", ""))
	case "insecure_plaintext":
		log.Printf("WARNING: -allow-insecure-plaintext set — main edge listener is PLAINTEXT HTTP on %s (local debug only, NOT for production)", addr)
		return ignoreServerClosed(srv.ListenAndServe())
	default:
		return fmt.Errorf("refusing to serve plaintext: set -tls-cert/-tls-key for HTTPS, or -lab-mode for an auto self-signed cert, or -allow-insecure-plaintext to force insecure HTTP")
	}
}

// ignoreServerClosed treats the expected post-Shutdown error as success (a graceful drain, not a failure).
func ignoreServerClosed(err error) error {
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// installGracefulDrain wires SIGTERM/SIGINT to the drain sequence: flip the drain flag (so /healthz reports
// unhealthy and the LB stops sending new connections), bleed in-flight for drainPeriod, then Shutdown.
func installGracefulDrain(srv *http.Server, addr string, drainState *atomic.Bool, drainPeriod time.Duration) {
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
		<-sigCh
		log.Printf("graceful drain: shutdown signal received — marking %s UNHEALTHY, bleeding in-flight for %s", addr, drainPeriod)
		drainState.Store(true)
		metricDraining.Store(true) // surface drain to /metrics so an alert can fire if a node is stuck draining
		time.Sleep(drainPeriod)
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			log.Printf("graceful drain: shutdown error on %s: %v", addr, err)
		} else {
			log.Printf("graceful drain: %s shut down cleanly after drain", addr)
		}
	}()
}

// tokenBucketLimiter is a tiny self-contained per-client token-bucket rate limiter (no external dependency,
// keeping the OSS dependency surface minimal). Keyed by client IP.
type tokenBucketLimiter struct {
	mu      sync.Mutex
	buckets map[string]*tokenBucketState
	rps     float64
	burst   float64
	now     func() time.Time
}

type tokenBucketState struct {
	tokens   float64
	lastSeen time.Time
}

func newTokenBucketLimiter(rps, burst float64) *tokenBucketLimiter {
	if burst <= 0 {
		burst = rps
	}
	return &tokenBucketLimiter{
		buckets: map[string]*tokenBucketState{},
		rps:     rps,
		burst:   burst,
		now:     time.Now,
	}
}

// allow reports whether a request from key may proceed, consuming one token. Refills by elapsed*rps capped
// at burst. A non-positive rps means "unlimited" (disabled).
func (l *tokenBucketLimiter) allow(key string) bool {
	if l == nil || l.rps <= 0 {
		return true
	}
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.buckets[key]
	if !ok {
		l.buckets[key] = &tokenBucketState{tokens: l.burst - 1, lastSeen: now}
		return true
	}
	elapsed := now.Sub(b.lastSeen).Seconds()
	if elapsed > 0 {
		b.tokens += elapsed * l.rps
		if b.tokens > l.burst {
			b.tokens = l.burst
		}
		b.lastSeen = now
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// isAdminSurfacePath reports whether a path is on the admin/management surface (admin API + auth/login). The
// steering data plane (/steer, /connectors, /devices, /clientless, /decisions, /ingest, ...) and /healthz
// are NOT on it. Used for rate limiting and for the dedicated-admin-listener separation.
func isAdminSurfacePath(path string) bool {
	return strings.HasPrefix(path, "/admin") || strings.HasPrefix(path, "/auth")
}

// isRateLimitedEdgePath: the rate-limited surface is the admin surface PLUS the clientless AUTH broker
// (/clientless/auth/* — a public pre-auth login/callback surface, a brute-force / enumeration target when
// enabled). The clientless APP relay (/clientless/apps/*) is the data path to a published app and is NOT
// rate-limited (throttling it would harm legitimate app access). NOTE: wider than isAdminSurfacePath, which
// gates the admin-only listener; clientless must NOT be reachable there.
func isRateLimitedEdgePath(path string) bool {
	return isAdminSurfacePath(path) || strings.HasPrefix(path, "/clientless/auth")
}

// adminSurfaceOnlyMiddleware serves ONLY the admin surface (+ /healthz); everything else 404s. Used on the
// dedicated admin listener so the steering data plane is not reachable there.
func adminSurfaceOnlyMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// /leader and /audit-ingest are served here too: the Edge→CP control channel (config pull + revocation +
		// audit ship + the follows-leader /leader probe) all target the admin/management listener, so they resolve
		// to ONE base per region and one regionfailover.Selector routes them together (cp_endpoint_failover.go).
		// ★ /tenant-transport-material rides the SAME channel for the same reason (2026-08-20): an Edge fetches
		// each organization's short-lived server material from its control plane, over the connection it
		// already authenticates on. Adding it here rather than to the admin surface keeps it out of the admin
		// API — it is a machine route, not something an administrator calls.
		if isAdminSurfacePath(r.URL.Path) || r.URL.Path == "/healthz" || r.URL.Path == "/metrics" || r.URL.Path == "/leader" || r.URL.Path == "/audit-ingest" || r.URL.Path == "/tenant-edge-material" {
			next.ServeHTTP(w, r)
			return
		}
		http.NotFound(w, r)
	})
}

// dataPlaneOnlyMiddleware 404s the admin surface (it is served on the dedicated admin listener) so the main
// data-plane listener carries only steering traffic — admin is not reachable on the data-plane port.
func dataPlaneOnlyMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// /metrics is management-only: 404 it on the data plane so decision counts are not exposed on the public
		// data-plane port (it is served on the dedicated admin listener).
		if isAdminSurfacePath(r.URL.Path) || r.URL.Path == "/metrics" {
			http.NotFound(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// validateAdminListenAddr enforces that the ADMIN LISTENER IS NOT ON LOOPBACK: it must bind a
// non-loopback address, because the Admin Console runs on a SEPARATE host and reaches the admin API as a
// real remote TLS client — not same-host loopback. Empty = the dedicated listener is disabled. A bind-all
// host (":port" / "0.0.0.0") is allowed; explicit loopback (127.0.0.1 / ::1 / localhost) is rejected.
func validateAdminListenAddr(addr string) error {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return nil
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("admin-listen %q: %w", addr, err)
	}
	host = strings.TrimSpace(host)
	if host == "" {
		return nil // bind-all (e.g. ":9443") is reachable remotely — allowed
	}
	if strings.EqualFold(host, "localhost") {
		return fmt.Errorf("admin-listen must not be loopback (%q): the Admin Console runs on a separate host", addr)
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return fmt.Errorf("admin-listen must not be loopback (%q): the Admin Console runs on a separate host", addr)
	}
	return nil
}

// rateLimitTrustedProxies is the set of front proxies / load balancers (set at startup from
// -rate-limit-trusted-proxies) whose X-Forwarded-For may be trusted. Empty = XFF ignored (RemoteAddr only).
var rateLimitTrustedProxies []*net.IPNet

// parseTrustedProxies parses a comma-separated list of IPs (treated as /32 or /128) and CIDRs into nets.
func parseTrustedProxies(raw string) []*net.IPNet {
	var nets []*net.IPNet
	for _, s := range strings.Split(raw, ",") {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if !strings.Contains(s, "/") {
			if ip := net.ParseIP(s); ip != nil {
				bits := 32
				if ip.To4() == nil {
					bits = 128
				}
				s = fmt.Sprintf("%s/%d", s, bits)
			}
		}
		if _, n, err := net.ParseCIDR(s); err == nil {
			nets = append(nets, n)
		}
	}
	return nets
}

func isTrustedRateLimitProxy(host string) bool {
	ip := net.ParseIP(strings.TrimSpace(host))
	if ip == nil {
		return false
	}
	for _, n := range rateLimitTrustedProxies {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// clientIPForRateLimit derives the rate-limit key from the connection's remote address. X-Forwarded-For is
// NOT trusted by default (client-spoofable). When -rate-limit-trusted-proxies is set AND the connection comes
// FROM a trusted proxy (the LB), the real client is the rightmost XFF entry that is not itself a trusted proxy
// — otherwise every client behind the LB collapses to the LB's IP and shares one bucket.
func clientIPForRateLimit(r *http.Request) string {
	host := strings.TrimSpace(r.RemoteAddr)
	if h, _, err := net.SplitHostPort(host); err == nil && h != "" {
		host = h
	}
	if len(rateLimitTrustedProxies) > 0 && isTrustedRateLimitProxy(host) {
		parts := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
		for i := len(parts) - 1; i >= 0; i-- {
			if cand := strings.TrimSpace(parts[i]); cand != "" && !isTrustedRateLimitProxy(cand) {
				return cand
			}
		}
	}
	return host
}

// edgeContentSecurityPolicyStrict is the default: self-origin only, no framing, no
// object/base-uri hijack, and NO 'unsafe-inline'. Production / OSS is API-only (the Console is a separate
// strict-CSP host), so the Edge no longer needs to relax CSP. API clients (curl/agents) ignore CSP.
const edgeContentSecurityPolicyStrict = "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'; script-src 'self'; style-src 'self'"

// adminConsoleCORSMiddleware enables the separate-host Admin Console to call the admin API
// cross-origin. CORS headers are sent ONLY for the admin surface and ONLY when the request Origin exactly
// matches the single configured Console origin (never "*"); preflight OPTIONS is answered 204. Empty
// allowedOrigin = no CORS (same-origin only). No Allow-Credentials: the Console authenticates with a bearer
// token, not cookies.
func adminConsoleCORSMiddleware(next http.Handler, allowedOrigin string) http.Handler {
	allowedOrigin = strings.TrimSpace(allowedOrigin)
	if allowedOrigin == "" {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isAdminSurfacePath(r.URL.Path) && r.Header.Get("Origin") == allowedOrigin {
			h := w.Header()
			h.Set("Access-Control-Allow-Origin", allowedOrigin)
			h.Add("Vary", "Origin")
			h.Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			h.Set("Access-Control-Allow-Headers", "authorization, content-type, x-admin-token, x-csrf-token")
			// Cookie-based admin sessions (per-tenant IdP login) need credentialed CORS; the origin is already
			// pinned to the exact console origin (never "*"), so allowing credentials is safe.
			h.Set("Access-Control-Allow-Credentials", "true")
			h.Set("Access-Control-Max-Age", "600")
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// securityHeadersMiddleware sets browser security headers on every response: clickjacking
// (X-Frame-Options), MIME-sniffing (X-Content-Type-Options), referrer leakage, a CSP baseline, and HSTS
// (only over TLS — never advertise HSTS on the plaintext listener). API clients (curl/agents) ignore these,
// so it is safe to apply unconditionally.
func securityHeadersMiddleware(next http.Handler) http.Handler {
	csp := edgeContentSecurityPolicyStrict
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", csp)
		if r.TLS != nil {
			h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		next.ServeHTTP(w, r)
	})
}

// rateLimitMiddleware applies the limiter to matching paths, returning 429 when exceeded. nil limiter or a
// disabled (rps<=0) limiter is a pass-through.
func rateLimitMiddleware(next http.Handler, limiter *tokenBucketLimiter, shouldLimit func(string) bool) http.Handler {
	if limiter == nil || limiter.rps <= 0 {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if shouldLimit(r.URL.Path) && !limiter.allow(clientIPForRateLimit(r)) {
			w.Header().Set("Retry-After", "1")
			writeError(w, http.StatusTooManyRequests, fmt.Errorf("rate limit exceeded"))
			return
		}
		next.ServeHTTP(w, r)
	})
}
