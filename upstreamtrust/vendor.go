// Package upstreamtrust supplies explicitly scoped trust for operating-system services
// whose vendor authorities are absent from a Linux public Web PKI bundle.
package upstreamtrust

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"embed"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net/http"
	"strings"
	"sync"
)

//go:embed roots/*.pem
var rootFiles embed.FS

var rootPins = map[string]string{
	"apple-root":          "b0b1730ecbc7ff4505142c49f1295e6eda6bcaed7e2c68c5be91b5a11001f024",
	"apple-root-g3":       "63343abfb89a6a03ebb57e9b3f5fa7be7c4f5c756f3017b3a8c488c3653e9179",
	"microsoft-root-2011": "847df6a78497943f27fc72eb93f9a637320a02b561d0a91b09e87a7807ed7c61",
}

// Exact destination names, not suffix matches or names supplied by a certificate.
var serviceRoots = map[string]string{
	"init.ess.apple.com":                       "apple-root-g3",
	"pds-init.ess.apple.com":                   "apple-root",
	"msedge.api.cdp.microsoft.com":             "microsoft-root-2011",
	"watson.events.data.microsoft.com":         "microsoft-root-2011",
	"tsfe.trafficshaping.dsp.mp.microsoft.com": "microsoft-root-2011",
}

var roots = loadRoots()

func loadRoots() map[string]*x509.Certificate {
	result := make(map[string]*x509.Certificate, len(rootPins))
	for name, pin := range rootPins {
		data, err := rootFiles.ReadFile("roots/" + name + ".pem")
		if err != nil {
			panic(err)
		}
		block, rest := pem.Decode(data)
		if block == nil || block.Type != "CERTIFICATE" || len(strings.TrimSpace(string(rest))) != 0 {
			panic("invalid embedded vendor root: " + name)
		}
		sum := sha256.Sum256(block.Bytes)
		if hex.EncodeToString(sum[:]) != pin {
			panic("vendor root fingerprint mismatch: " + name)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		// The authenticated, pinned DER defines the trust anchor. Its self-signature
		// is not a link in a verified path (the original Apple root uses SHA-1).
		if err != nil || !cert.IsCA || !cert.BasicConstraintsValid || cert.KeyUsage&x509.KeyUsageCertSign == 0 || !bytes.Equal(cert.RawSubject, cert.RawIssuer) {
			panic("invalid vendor root certificate: " + name)
		}
		result[name] = cert
	}
	return result
}

type cacheKey struct {
	base *http.Transport
	host string
}

var transports sync.Map

// ForHost augments only the listed service's HTTPS transport. It keeps the normal
// Go TLS verifier, existing anchors, dialer, callbacks and HTTP/2 configuration.
// It never writes the system trust store or learns an authority from a peer/AIA URL.
// Other engines and custom TLS dialers retain their own verification policy.
func ForHost(base http.RoundTripper, hostname string) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	host := strings.ToLower(hostname)
	rootName, ok := serviceRoots[host]
	if !ok {
		return base
	}
	transport, ok := base.(*http.Transport)
	if !ok || transport.DialTLSContext != nil || transport.DialTLS != nil {
		return base
	}
	if cfg := transport.TLSClientConfig; cfg != nil {
		if cfg.InsecureSkipVerify || (cfg.ServerName != "" && !strings.EqualFold(cfg.ServerName, host)) {
			return base
		}
	}
	key := cacheKey{transport, host}
	if cached, ok := transports.Load(key); ok {
		return cached.(http.RoundTripper)
	}
	result, err := scopedTransport(transport, host, roots[rootName])
	if err != nil {
		return base
	} // A broken system store is never replaced with vendor-only trust.
	actual, _ := transports.LoadOrStore(key, result)
	return actual.(http.RoundTripper)
}

type hostTransport struct {
	host      string
	transport *http.Transport
}

func (t *hostTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme != "https" || !strings.EqualFold(req.URL.Hostname(), t.host) {
		return nil, fmt.Errorf("vendor upstream trust is scoped to https://%s", t.host)
	}
	return t.transport.RoundTrip(req)
}

func scopedTransport(base *http.Transport, host string, root *x509.Certificate) (*hostTransport, error) {
	t := base.Clone()
	if t.TLSClientConfig == nil {
		t.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	var pool *x509.CertPool
	if t.TLSClientConfig.RootCAs != nil {
		pool = t.TLSClientConfig.RootCAs.Clone()
	} else {
		var err error
		pool, err = x509.SystemCertPool()
		if err != nil || pool == nil {
			return nil, fmt.Errorf("read upstream system roots: %v", err)
		}
	}
	pool.AddCert(root)
	t.TLSClientConfig.RootCAs = pool
	return &hostTransport{host: host, transport: t}, nil
}
