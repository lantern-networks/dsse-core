package outboundtls

// Complete an origin's incomplete TLS chain using its CA Issuers AIA link.
// A fetched certificate is an intermediate only: the leaf must still verify
// against the operating system's existing roots and the requested hostname.

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	maxIssuerHops  = 3
	maxIssuerBytes = 64 << 10
	issuerCacheTTL = 12 * time.Hour
)

type issuerEntry struct {
	cert *x509.Certificate
	at   time.Time
}

type verifier struct {
	roots *x509.CertPool
	fetch func(context.Context, string) (*x509.Certificate, error)
	mu    sync.Mutex
	cache map[string]issuerEntry
}

type roundTripper struct {
	base http.RoundTripper
	aia  *http.Transport
}

var wrapped sync.Map // *http.Transport -> http.RoundTripper

// CloseIdleConnectionsForTransport closes the existing AIA and original idle
// pools without creating a wrapper or interrupting active responses. The caller
// can reuse the same immutable TLS profile later; the cache identity is stable.
func CloseIdleConnectionsForTransport(base *http.Transport) {
	if base == nil {
		return
	}
	if cached, ok := wrapped.Load(base); ok {
		cached.(*roundTripper).CloseIdleConnections()
		return
	}
	base.CloseIdleConnections()
}

// WrapRoundTripper completes missing public intermediates for DNS origins.
// Numeric-IP origins keep the original transport because TLS does not send
// their IP in SNI, and the verifier must never lose the requested IP name.
// Fetched certificates are intermediates only, never new trust anchors.
func WrapRoundTripper(base http.RoundTripper) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	transport, ok := base.(*http.Transport)
	if !ok {
		return base
	}
	if transport.DialTLSContext != nil || transport.DialTLS != nil {
		return base // A custom TLS dialer owns certificate verification.
	}
	if existing, ok := wrapped.Load(transport); ok {
		return existing.(http.RoundTripper)
	}
	var config *tls.Config
	if transport.TLSClientConfig != nil {
		config = transport.TLSClientConfig.Clone()
		if config.InsecureSkipVerify || config.VerifyConnection != nil || config.VerifyPeerCertificate != nil || config.ServerName != "" {
			return base // Preserve explicit verification semantics.
		}
	} else {
		config = &tls.Config{}
	}
	roots := config.RootCAs
	if roots == nil {
		var err error
		roots, err = x509.SystemCertPool()
		if err != nil || roots == nil {
			return base // The original transport still fails closed on missing roots.
		}
	}
	v := &verifier{roots: roots, fetch: fetchPublicIssuer, cache: make(map[string]issuerEntry)}
	aia := transport.Clone()
	config.InsecureSkipVerify = true
	config.VerifyConnection = v.verifyConnection
	aia.TLSClientConfig = config
	result := &roundTripper{base: base, aia: aia}
	actual, _ := wrapped.LoadOrStore(transport, result)
	if actual != result {
		aia.CloseIdleConnections()
	}
	return actual.(http.RoundTripper)
}

func (t *roundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	if net.ParseIP(request.URL.Hostname()) != nil {
		return t.base.RoundTrip(request)
	}
	return t.aia.RoundTrip(request)
}

func (t *roundTripper) CloseIdleConnections() {
	t.aia.CloseIdleConnections()
	if closer, ok := t.base.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
}

func (v *verifier) verifyConnection(cs tls.ConnectionState) error {
	if cs.ServerName == "" || len(cs.PeerCertificates) == 0 {
		return errors.New("outbound TLS hostname or peer chain missing")
	}
	chain := append([]*x509.Certificate(nil), cs.PeerCertificates...)
	pending := make(map[string]*x509.Certificate)
	for hop := 0; hop <= maxIssuerHops; hop++ {
		intermediates := x509.NewCertPool()
		for _, cert := range chain[1:] {
			intermediates.AddCert(cert)
		}
		_, err := chain[0].Verify(x509.VerifyOptions{
			Roots:         v.roots,
			Intermediates: intermediates,
			DNSName:       cs.ServerName,
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		})
		if err == nil {
			v.remember(pending)
			return nil
		}
		var unknown x509.UnknownAuthorityError
		if !errors.As(err, &unknown) || hop == maxIssuerHops {
			return err
		}
		top := chain[len(chain)-1]
		var next *x509.Certificate
		var source string
		for _, rawURL := range top.IssuingCertificateURL {
			candidate := v.cached(rawURL)
			if candidate == nil || top.CheckSignatureFrom(candidate) != nil {
				ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
				candidate, _ = v.fetch(ctx, rawURL)
				cancel()
			}
			if candidate == nil || bytes.Equal(candidate.Raw, top.Raw) || top.CheckSignatureFrom(candidate) != nil {
				continue
			}
			next, source = candidate, rawURL
			break
		}
		if next == nil {
			return err
		}
		chain = append(chain, next)
		pending[source] = next
	}
	return errors.New("outbound TLS issuer chain exceeded hop limit")
}

func (v *verifier) cached(rawURL string) *x509.Certificate {
	v.mu.Lock()
	defer v.mu.Unlock()
	entry, ok := v.cache[rawURL]
	if !ok || time.Since(entry.at) > issuerCacheTTL || time.Now().After(entry.cert.NotAfter) {
		delete(v.cache, rawURL)
		return nil
	}
	return entry.cert
}

func (v *verifier) remember(certs map[string]*x509.Certificate) {
	if len(certs) == 0 {
		return
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if len(v.cache) > 256 {
		v.cache = make(map[string]issuerEntry)
	}
	for source, cert := range certs {
		v.cache[source] = issuerEntry{cert: cert, at: time.Now()}
	}
}

func fetchPublicIssuer(ctx context.Context, rawURL string) (*x509.Certificate, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.User != nil || u.Fragment != "" || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return nil, errors.New("invalid CA Issuers URL")
	}
	port := u.Port()
	if port == "" {
		port = "80"
		if u.Scheme == "https" {
			port = "443"
		}
	}
	if port != "80" && port != "443" {
		return nil, errors.New("CA Issuers port is not allowed")
	}
	host := u.Hostname()
	addresses, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil || len(addresses) == 0 {
		return nil, errors.New("CA Issuers name does not resolve")
	}
	var public []net.IP
	for _, candidate := range addresses {
		if publicIP(candidate.IP) {
			public = append(public, candidate.IP)
		}
	}
	if len(public) != len(addresses) {
		return nil, errors.New("CA Issuers name includes a nonpublic address")
	}
	transport := &http.Transport{
		Proxy: nil, DisableKeepAlives: true, TLSHandshakeTimeout: 3 * time.Second,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var last error
			for _, ip := range public {
				conn, err := (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
				if err == nil {
					return conn, nil
				}
				last = err
			}
			return nil, last
		},
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport, Timeout: 5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	response, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("CA Issuers returned HTTP %d", response.StatusCode)
	}
	encoded, err := io.ReadAll(io.LimitReader(response.Body, maxIssuerBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read CA Issuers response: %w", err)
	}
	if len(encoded) > maxIssuerBytes {
		return nil, errors.New("CA Issuers response exceeds size limit")
	}
	if block, _ := pem.Decode(encoded); block != nil && strings.EqualFold(block.Type, "CERTIFICATE") {
		encoded = block.Bytes
	}
	cert, err := x509.ParseCertificate(encoded)
	if err != nil || !cert.IsCA {
		return nil, errors.New("CA Issuers response is not a CA certificate")
	}
	return cert, nil
}

func publicIP(ip net.IP) bool {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	addr = addr.Unmap()
	if !addr.IsGlobalUnicast() || addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast() {
		return false
	}
	for _, blocked := range []string{
		"100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "198.18.0.0/15",
		"198.51.100.0/24", "203.0.113.0/24", "64:ff9b::/96", "64:ff9b:1::/48",
		"2001::/32", "2001:db8::/32", "2002::/16",
	} {
		if netip.MustParsePrefix(blocked).Contains(addr) {
			return false
		}
	}
	return true
}
