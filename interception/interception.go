// Package interception is the OSS TLS interception (decrypt-all) data plane: it terminates a steered
// TLS flow with a per-SNI leaf certificate signed by an interception CA, hands the decrypted HTTP to a
// flow handler (which applies policy + header rewrite + forwards to the real origin), and writes the
// response back to the client. The endpoint trusts the interception CA, so the edge can see and enforce
// inside otherwise-opaque HTTPS — the core of an SSE secure web gateway.
//
// Hosts can be intercepted (decrypted) or bypassed (raw-forwarded, e.g. cert-pinned apps). Bypass is the
// caller's responsibility (the engine only reports Matches); raw forwarding stays in the tunnel.
package interception

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http2"
)

// Route is the destination of a steered flow.
type Route struct {
	Host string
	Port int
	SNI  string // set from the TLS ClientHello when known (robust for connect-by-IP)
}

// FlowHandler receives a decrypted request for an intercepted flow and is responsible for policy
// enforcement, header rewrite, and forwarding to the real origin (route). The engine serves it over the
// terminated TLS connection.
type FlowHandler interface {
	ServeFlow(w http.ResponseWriter, r *http.Request, route Route)
}

// Engine terminates intercepted TLS flows and serves them through a FlowHandler.
type Engine struct {
	mu          sync.Mutex
	rootCert    *x509.Certificate
	rootKey     *ecdsa.PrivateKey
	rootCertPEM []byte
	leafKey     *ecdsa.PrivateKey
	// leafCache/handshakeFailures/everSucceeded are keyed by the client-controlled SNI under decrypt-all, so
	// they are LRU-BOUNDED (review #22): a plain map grew one entry per distinct SNI forever, a
	// memory-exhaustion lever. An evicted leaf is simply re-minted on next use; evicted detection state at
	// worst re-learns a host's pinning behavior.
	leafCache *lru[*tls.Certificate]

	hosts       []string // intercept patterns: exact, "*.suffix", or "*"
	bypassHosts []string // never intercept (raw-forward), even under "*"
	sniBased    bool
	handler     FlowHandler

	// Cert-pinning detection (default on, safe): a host that repeatedly rejects the interception leaf
	// (handshake failure) is PROPOSED as a bypass candidate via certPinObserver — never auto-bypassed.
	// everSucceeded guards against pinning a host that has previously completed a handshake.
	certPinObserver   func(Route, int)
	pinThreshold      int
	handshakeFailures *lru[int]
	everSucceeded     *lru[bool]
}

// maxInterceptionCacheEntries bounds each per-SNI map. Sized generously (a busy edge sees far fewer distinct
// live hosts than this) so eviction only bites under a hostile distinct-SNI flood, not normal traffic.
const maxInterceptionCacheEntries = 16384

// CAOptions configures the interception CA subject when generating an ephemeral root.
type CAOptions struct {
	CommonName   string
	Organization string
}

func serial() *big.Int {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return big.NewInt(time.Now().UnixNano())
	}
	return n
}

// NewEngine builds an interception engine with a freshly-generated ephemeral CA. Provision RootCertPEM()
// into the endpoints' trust store so they accept the leaf certificates.
func NewEngine(hostPatterns []string, handler FlowHandler, ca CAOptions) (*Engine, error) {
	cn := strings.TrimSpace(ca.CommonName)
	if cn == "" {
		cn = "DSSE Interception Root"
	}
	org := strings.TrimSpace(ca.Organization)
	if org == "" {
		org = "DSSE"
	}
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{CommonName: cn, Organization: []string{org}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		return nil, err
	}
	rootCert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return newEngine(rootCert, rootKey, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), hostPatterns, handler)
}

// NewEngineWithCA builds an interception engine from a provided CA cert + key (PEM). Use this so a fleet
// of edges share one CA (the endpoints trust a single root).
func NewEngineWithCA(caCertPEM, caKeyPEM []byte, hostPatterns []string, handler FlowHandler) (*Engine, error) {
	certBlock, _ := pem.Decode(caCertPEM)
	if certBlock == nil {
		return nil, fmt.Errorf("interception CA cert PEM is invalid")
	}
	rootCert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse interception CA cert: %w", err)
	}
	keyBlock, _ := pem.Decode(caKeyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("interception CA key PEM is invalid")
	}
	rootKey, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse interception CA key (expected EC private key): %w", err)
	}
	return newEngine(rootCert, rootKey, caCertPEM, hostPatterns, handler)
}

func newEngine(rootCert *x509.Certificate, rootKey *ecdsa.PrivateKey, rootCertPEM []byte, hostPatterns []string, handler FlowHandler) (*Engine, error) {
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Engine{
		rootCert:          rootCert,
		rootKey:           rootKey,
		rootCertPEM:       rootCertPEM,
		leafKey:           leafKey,
		leafCache:         newLRU[*tls.Certificate](maxInterceptionCacheEntries),
		hosts:             normalizePatterns(hostPatterns),
		handler:           handler,
		pinThreshold:      2,
		handshakeFailures: newLRU[int](maxInterceptionCacheEntries),
		everSucceeded:     newLRU[bool](maxInterceptionCacheEntries),
	}, nil
}

// SetCertPinObserver enables cert-pinning detection: when a host rejects the interception leaf
// threshold times in a row (and has never completed a handshake), observer is called with the route and
// failure count. The observer should PROPOSE a bypass candidate for admin review — it must not bypass.
// threshold <= 0 keeps the default (2).
func (e *Engine) SetCertPinObserver(observer func(Route, int), threshold int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.certPinObserver = observer
	if threshold > 0 {
		e.pinThreshold = threshold
	}
}

// recordHandshakeOutcome tracks per-host interception-handshake results. On success it clears the host's
// failures and marks it as ever-succeeded. On failure (the client rejected the leaf — a cert-pinning
// signal) it increments the count and, at the threshold, returns the route+count to report (only for
// hosts that never succeeded, to avoid false positives from transient errors).
func (e *Engine) recordHandshakeOutcome(route Route, success bool) (func(Route, int), int) {
	host := route.Host
	if e.sniBased && strings.TrimSpace(route.SNI) != "" {
		host = route.SNI
	}
	host = normalizeHost(host)
	if host == "" {
		return nil, 0
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if success {
		e.everSucceeded.put(host, true)
		e.handshakeFailures.delete(host)
		return nil, 0
	}
	if succeeded, _ := e.everSucceeded.peek(host); e.certPinObserver == nil || succeeded {
		return nil, 0
	}
	count, _ := e.handshakeFailures.peek(host)
	count++
	e.handshakeFailures.put(host, count)
	if count >= e.pinThreshold {
		return e.certPinObserver, count
	}
	return nil, 0
}

// SetBypassHosts sets hosts that are never intercepted (raw-forwarded), even under a "*" intercept rule.
func (e *Engine) SetBypassHosts(patterns []string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.bypassHosts = normalizePatterns(patterns)
}

// BypassHosts returns a copy of the current raw-forward (never-intercept) host patterns. Used by the admin
// API to reflect the live bypass set (e.g. authored egress bypass rules + materialized cert-pin candidates).
func (e *Engine) BypassHosts() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]string(nil), e.bypassHosts...)
}

// SetSNIBasedDecision routes intercept/bypass on the ClientHello SNI rather than the route Host (robust
// when the client connected by IP).
func (e *Engine) SetSNIBasedDecision(enabled bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.sniBased = enabled
}

// RootCertPEM returns the interception CA root certificate (PEM) to trust on the endpoints.
func (e *Engine) RootCertPEM() []byte { return e.rootCertPEM }

func normalizeHost(h string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(h)), ".")
}

func normalizePatterns(patterns []string) []string {
	out := make([]string, 0, len(patterns))
	for _, p := range patterns {
		if p = normalizeHost(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// HostMatchesPatterns reports whether host matches any of the bypass-style patterns using the SAME semantics
// the interception engine applies to its bypass set: "*" matches everything, "*.suffix" matches the suffix
// apex AND any sub-domain, otherwise an exact (normalized) host match. Exported so callers that explain the
// effective inspect/bypass basis (the Effective-Policy view) classify a host exactly as the engine would,
// rather than re-deriving the semantics.
func HostMatchesPatterns(host string, patterns []string) bool {
	return hostMatchesPatterns(host, patterns)
}

func hostMatchesPatterns(host string, patterns []string) bool {
	host = normalizeHost(host)
	for _, p := range patterns {
		switch {
		case p == "*":
			return true
		case strings.HasPrefix(p, "*."):
			if host == p[2:] || strings.HasSuffix(host, p[1:]) {
				return true
			}
		case host == p:
			return true
		}
	}
	return false
}

// Matches reports whether a flow should be intercepted (decrypted) rather than raw-forwarded. Only
// port 443 is intercepted; bypass hosts always win.
func (e *Engine) Matches(r Route) bool {
	if e == nil || r.Port != 443 {
		return false
	}
	e.mu.Lock()
	sniBased := e.sniBased
	hosts := e.hosts
	bypass := e.bypassHosts
	e.mu.Unlock()
	host := r.Host
	if sniBased && strings.TrimSpace(r.SNI) != "" {
		host = r.SNI
	}
	if hostMatchesPatterns(host, bypass) {
		return false
	}
	return hostMatchesPatterns(host, hosts)
}

// leafRenewBefore re-mints a cached leaf once it is within this window of NotAfter. Without it, a long-lived
// Engine (e.g. a process frozen across host sleep, alive past the 24h leaf validity) keeps serving an expired
// cached leaf and the client rejects it. The serve path had no expiry check.
const leafRenewBefore = time.Hour

// leafFresh reports whether a cached leaf is still safely usable. cert.Leaf is set at mint time.
func leafFresh(cert *tls.Certificate) bool {
	return cert.Leaf != nil && time.Now().Add(leafRenewBefore).Before(cert.Leaf.NotAfter)
}

// leafFor returns (and caches) a leaf certificate for the host, signed by the interception CA.
func (e *Engine) leafFor(host string) (*tls.Certificate, error) {
	host = normalizeHost(host)
	if host == "" {
		return nil, fmt.Errorf("leaf host is required")
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if c, ok := e.leafCache.get(host); ok && leafFresh(c) {
		return c, nil
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial(),
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, e.rootCert, &e.leafKey.PublicKey, e.rootKey)
	if err != nil {
		return nil, err
	}
	cert := &tls.Certificate{Certificate: [][]byte{der, e.rootCert.Raw}, PrivateKey: e.leafKey, Leaf: tmpl}
	e.leafCache.put(host, cert)
	return cert, nil
}

// oneShotListener serves a single already-accepted connection through http.Server.Serve.
type oneShotListener struct {
	conn net.Conn
	once sync.Once
	done chan struct{}
}

func (l *oneShotListener) Accept() (net.Conn, error) {
	c := net.Conn(nil)
	first := false
	l.once.Do(func() { c = l.conn; first = true })
	if first {
		return c, nil
	}
	<-l.done
	return nil, net.ErrClosed
}
func (l *oneShotListener) Close() error {
	select {
	case <-l.done:
	default:
		close(l.done)
	}
	return nil
}
func (l *oneShotListener) Addr() net.Addr { return l.conn.LocalAddr() }

// Intercept terminates the client's TLS on clientConn with a leaf for the route, then serves the
// decrypted HTTP through the FlowHandler (policy + rewrite + forward). It blocks until the flow ends.
func (e *Engine) Intercept(clientConn net.Conn, route Route) {
	leafHost := route.Host
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		// Offer HTTP/2 first: real browsers negotiate h2, and matching it preserves multiplexing rather
		// than forcing the client down to HTTP/1.1.
		NextProtos: []string{"h2", "http/1.1"},
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			h := leafHost
			if strings.TrimSpace(hello.ServerName) != "" {
				h = hello.ServerName
			}
			return e.leafFor(h)
		},
	}
	tlsConn := tls.Server(clientConn, cfg)
	handshakeErr := tlsConn.Handshake()
	// Cert-pinning detection: report a repeatedly-failing host so it can be PROPOSED as a bypass
	// candidate (never auto-bypassed here).
	if observer, count := e.recordHandshakeOutcome(route, handshakeErr == nil); observer != nil {
		observer(route, count)
	}
	if handshakeErr != nil {
		_ = clientConn.Close()
		return
	}
	flowHandler := e.handler
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if flowHandler == nil {
			http.Error(w, "no flow handler", http.StatusBadGateway)
			return
		}
		flowHandler.ServeFlow(w, r, route)
	})
	if tlsConn.ConnectionState().NegotiatedProtocol == "h2" {
		// Serve the already-terminated TLS connection as HTTP/2 (multiplexed streams -> the handler).
		// Bound idle/read time and concurrent streams (review #22): the bare http2.Server had NO timeouts,
		// unlike the h1 path below, so a stalled or slow-loris browser leaked the serving goroutine and its
		// streams indefinitely, and an unbounded stream count let one connection fan out arbitrarily.
		(&http2.Server{
			IdleTimeout:          120 * time.Second, // drop a connection idle this long (goroutine reclaim)
			ReadIdleTimeout:      30 * time.Second,  // PING-probe a silent peer; tear down if unanswered
			MaxConcurrentStreams: 250,               // cap simultaneous streams per connection
		}).ServeConn(tlsConn, &http2.ServeConnOpts{Handler: handler})
		return
	}
	srv := &http.Server{Handler: handler, ReadHeaderTimeout: 30 * time.Second, IdleTimeout: 120 * time.Second}
	ln := &oneShotListener{conn: tlsConn, done: make(chan struct{})}
	_ = srv.Serve(ln)
}
