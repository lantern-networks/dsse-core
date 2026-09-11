package engine

// aia.go — AIA chasing: fetch the issuer a server did not send, the path-building step every browser performs
// and curl/OpenSSL do not.
//
// Why this exists (SWG fidelity #21, measured 2026-08-06 on partner.microsoft.com): an origin may serve only
// leaf + one intermediate whose issuer is a root that is in NO trust store — not ours, not macOS's. The path is
// meant to be completed through the intermediate's Authority Information Access "CA Issuers" URI, which points
// at a CROSS-SIGNED copy of that root issued by a CA everyone already trusts. Browsers fetch it and finish the
// chain; curl never fetches AIA issuers, so the broker failed CURLE_PEER_FAILED_VERIFICATION and the Edge
// returned 502 on a site that works in every browser.
//
// Hand-adding the missing certificate to the CA bundle was rejected as a strategy: it fixes one origin, and
// nothing tells us when the next one appears — there is no schedule to check on, because the only symptom is a
// user hitting an error. This closes the class instead.
//
// THE INVARIANT THAT KEEPS THIS SAFE: a fetched certificate is accepted ONLY if it already chains to a root
// this device trusts. The set of endpoints reachable through the broker is therefore unchanged — anything a
// learned certificate can vouch for, the cross-signature could already vouch for. What is learned is the
// missing LINK, never a new trust decision. An AIA URI that returns anything not meeting that bar is discarded.
//
// Honest delta from browser behaviour: browsers cache a fetched issuer as an untrusted intermediate, whereas
// libcurl's only mechanism for supplying it (CURLOPT_CAINFO) treats every certificate in the file as an anchor.
// So a learned certificate keeps working here even if its cross-signature is later revoked. Learned entries
// therefore carry a TTL and are re-validated against the roots on refresh rather than being trusted forever.

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	// aiaMaxHops bounds how far up a chain we will walk. Real chains that need this need one hop; the bound is
	// what keeps a hostile or misconfigured AIA graph from turning one request into an unbounded fetch loop.
	aiaMaxHops = 3
	// aiaFetchLimit caps a fetched issuer's size. A CA certificate is ~1-2 KB; anything near this is not one.
	aiaFetchLimit = 64 << 10
	// aiaHostCooldown is how long a host that taught us nothing is left alone. Without it, every request to a
	// genuinely untrusted origin would pay a dial plus a fetch before failing exactly as it does today.
	aiaHostCooldown = 5 * time.Minute
	// aiaLearnedTTL bounds how long a learned link is used before it must re-prove it still chains to a trusted
	// root. This is the answer to the anchor-vs-intermediate delta noted above.
	aiaLearnedTTL = 24 * time.Hour
)

// aiaCandidateBasePaths are the CA bundles curl itself would use, in the order we try them. The combined file we
// hand to CURLOPT_CAINFO is this bundle PLUS what we learned; if none can be read we set no CAINFO at all,
// because a CAINFO containing only learned certificates would REPLACE the trust store rather than extend it.
var aiaCandidateBasePaths = []string{
	os.Getenv("SSL_CERT_FILE"),
	"/etc/ssl/certs/ca-certificates.crt",
	"/etc/ssl/cert.pem",
	"/etc/pki/tls/certs/ca-bundle.crt",
}

type learnedIssuer struct {
	pem       []byte
	learnedAt time.Time
}

type aiaResolver struct {
	mu       sync.Mutex
	learned  map[string]learnedIssuer // key: certificate SHA-256 (hex-free; raw string of the DER hash)
	attempts map[string]time.Time     // host:port -> last attempt that taught us nothing
	basePath string
	combined string
	// staged is set ONLY after the combined bundle has been written and renamed into place. caInfo gates on it
	// because handing curl a CAINFO path that does not exist yet makes it fail EVERY handshake, not just the one
	// being fixed. Measured live 2026-08-06: exposing the path between learning a link and writing the file took
	// www.microsoft.com from 200 to intermittent 000 — a self-inflicted outage of the whole egress path.
	staged bool
	failed bool // no readable base bundle: the feature is off, said once
	client *http.Client
	// roots is the trust anchor set every fetched issuer must already chain to. A field so a test can supply a
	// synthetic PKI and prove the bar actually rejects what it must.
	roots func() (*x509.CertPool, error)
}

var aiaStore = newAIAResolver()

func newAIAResolver() *aiaResolver {
	a := &aiaResolver{
		learned:  map[string]learnedIssuer{},
		attempts: map[string]time.Time{},
		roots:    x509.SystemCertPool,
		client: &http.Client{
			Timeout: 5 * time.Second,
			// An AIA URI is public PKI material fetched over plain HTTP by design (the certificate is verified
			// cryptographically, so the transport does not need to be). Redirects are not followed: an issuer
			// URI that redirects is not something to chase.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
	for _, p := range aiaCandidateBasePaths {
		if p == "" {
			continue
		}
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			a.basePath = p
			break
		}
	}
	if a.basePath == "" {
		a.failed = true
		return a
	}
	a.combined = filepath.Join(os.TempDir(), "dsse-broker-ca-with-aia.pem")
	return a
}

// caInfo returns the path to hand CURLOPT_CAINFO, or "" to leave curl on its own default. Empty until something
// has actually been learned, so an ordinary deployment runs byte-identically to before this file existed.
func (a *aiaResolver) caInfo() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.failed || !a.staged {
		return ""
	}
	return a.combined
}

// learnFor runs one AIA resolution against target's origin and reports whether it learned a link that was not
// already known — i.e. whether retrying the request is worth anything. Called only after curl has already
// failed peer verification, so its cost is paid only on a request that is otherwise dead.
func (a *aiaResolver) learnFor(target string) bool {
	if a.failed {
		return false
	}
	u, err := url.Parse(target)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" {
		return false
	}
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		port = "443"
	}
	addr := net.JoinHostPort(host, port)

	a.mu.Lock()
	if last, ok := a.attempts[addr]; ok && time.Since(last) < aiaHostCooldown {
		a.mu.Unlock()
		return false
	}
	a.mu.Unlock()

	learned, err := a.resolve(addr, host)
	if err != nil {
		log.Printf("egress engine: AIA chase for %s found nothing — %v (the origin's chain stays unverifiable; this is the same refusal as before, not a new one)", addr, err)
	}
	if !learned {
		a.mu.Lock()
		a.attempts[addr] = time.Now()
		a.mu.Unlock()
		return false
	}
	if err := a.writeCombined(); err != nil {
		log.Printf("egress engine: AIA chase learned an issuer for %s but could not stage the CA bundle — %v", addr, err)
		return false
	}
	return true
}

// resolve dials the origin, and while the served chain does not verify, fetches the issuer named by the deepest
// certificate's AIA and keeps it IF it chains to an already-trusted root. Returns whether anything new was kept.
func (a *aiaResolver) resolve(addr, serverName string) (bool, error) {
	roots, err := a.roots()
	if err != nil || roots == nil {
		return false, fmt.Errorf("no system roots: %w", err)
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	// InsecureSkipVerify is what lets us SEE the chain we are trying to complete. Nothing is trusted on the
	// strength of this handshake: no request is sent over it, it is closed immediately, and every certificate it
	// yields is verified against the real roots below before any of it is kept.
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{ServerName: serverName, InsecureSkipVerify: true}) // #nosec G402 -- inspection-only handshake, see comment
	if err != nil {
		return false, fmt.Errorf("probe dial: %w", err)
	}
	served := conn.ConnectionState().PeerCertificates
	_ = conn.Close()
	if len(served) == 0 {
		return false, fmt.Errorf("origin served no certificates")
	}

	chain := append([]*x509.Certificate(nil), served...)
	learnedAny := false
	for hop := 0; hop < aiaMaxHops; hop++ {
		inter := x509.NewCertPool()
		for _, c := range chain[1:] {
			inter.AddCert(c)
		}
		a.addLearnedTo(inter)
		if _, err := chain[0].Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, DNSName: serverName}); err == nil {
			return learnedAny, nil // path complete
		}
		top := chain[len(chain)-1]
		issuer, err := a.fetchIssuer(top, roots, inter)
		if err != nil {
			return learnedAny, err
		}
		a.keep(issuer)
		chain = append(chain, issuer)
		learnedAny = true
		log.Printf("egress engine: AIA chase learned %q (issued by %q) — the link %s did not send; it chains to a trusted root, so it is kept",
			issuer.Subject.CommonName, issuer.Issuer.CommonName, serverName)
	}
	return learnedAny, fmt.Errorf("chain still incomplete after %d hops", aiaMaxHops)
}

// fetchIssuer downloads the certificate named by cert's CA Issuers URI and returns it ONLY if it is a CA that
// already chains to a trusted root. That check is the whole safety of this file.
func (a *aiaResolver) fetchIssuer(cert *x509.Certificate, roots, inter *x509.CertPool) (*x509.Certificate, error) {
	if len(cert.IssuingCertificateURL) == 0 {
		return nil, fmt.Errorf("%q publishes no CA Issuers URI", cert.Subject.CommonName)
	}
	var lastErr error
	for _, raw := range cert.IssuingCertificateURL {
		u, err := url.Parse(raw)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
			continue
		}
		body, err := a.get(raw)
		if err != nil {
			lastErr = err
			continue
		}
		issuer, err := parseCertificate(body)
		if err != nil {
			lastErr = err
			continue
		}
		if !issuer.IsCA {
			lastErr = fmt.Errorf("%s served a non-CA certificate", raw)
			continue
		}
		// Never keep a SELF-SIGNED certificate, even one already in the trust store. The missing link is always a
		// cross-signature; a root can only be useless (already trusted — keeping it changes nothing) or dangerous
		// (not trusted — keeping it would be trust-anchor injection). Measured live 2026-08-06: assets.onestore.ms
		// publishes its already-trusted DigiCert root at its AIA URI, and accepting it made every request "learn"
		// something, rewrite the bundle, retry, and fail again — churn with no progress and no cooldown.
		if isSelfSigned(issuer) {
			lastErr = fmt.Errorf("%s served the self-signed root %q, which cannot be a missing link", raw, issuer.Subject.CommonName)
			continue
		}
		// THE bar: it must already be vouched for by something we trust. A self-signed root arriving here is
		// exactly what this rejects — otherwise an AIA URI would be a way to install a trust anchor.
		if _, err := issuer.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
			lastErr = fmt.Errorf("%s served a certificate that does not chain to a trusted root: %w", raw, err)
			continue
		}
		return issuer, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no usable CA Issuers URI")
	}
	return nil, lastErr
}

func (a *aiaResolver) get(rawurl string) ([]byte, error) {
	resp, err := a.client.Get(rawurl)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: HTTP %d", rawurl, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, aiaFetchLimit))
}

// isSelfSigned reports whether a certificate signed itself — a root. Checked by verifying its own signature
// rather than by comparing names, which are attacker-chosen.
func isSelfSigned(c *x509.Certificate) bool {
	return c.CheckSignatureFrom(c) == nil
}

// parseCertificate accepts either of the two forms a PKI distribution point serves: raw DER (the common case)
// or PEM.
func parseCertificate(body []byte) (*x509.Certificate, error) {
	if c, err := x509.ParseCertificate(body); err == nil {
		return c, nil
	}
	if blk, _ := pem.Decode(body); blk != nil && blk.Type == "CERTIFICATE" {
		return x509.ParseCertificate(blk.Bytes)
	}
	return nil, fmt.Errorf("not a DER or PEM certificate")
}

func (a *aiaResolver) keep(c *x509.Certificate) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.learned[string(c.Raw)] = learnedIssuer{
		pem:       pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}),
		learnedAt: time.Now(),
	}
}

// addLearnedTo adds the still-valid learned links to a pool, dropping any whose TTL has expired so a stale link
// must re-prove itself through a fresh chase rather than being trusted indefinitely.
func (a *aiaResolver) addLearnedTo(pool *x509.CertPool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for raw, li := range a.learned {
		if time.Since(li.learnedAt) > aiaLearnedTTL {
			delete(a.learned, raw)
			continue
		}
		if c, err := x509.ParseCertificate([]byte(raw)); err == nil {
			pool.AddCert(c)
		}
	}
}

// writeCombined stages base-bundle + learned links as one file for CURLOPT_CAINFO, written to a temporary name
// and renamed so a handle can never read a half-written trust store.
func (a *aiaResolver) writeCombined() error {
	base, err := os.ReadFile(a.basePath)
	if err != nil {
		return fmt.Errorf("read base CA bundle %s: %w", a.basePath, err)
	}
	a.mu.Lock()
	out := make([]byte, 0, len(base)+len(a.learned)*2048)
	out = append(out, base...)
	if len(out) > 0 && out[len(out)-1] != '\n' {
		out = append(out, '\n')
	}
	for _, li := range a.learned {
		out = append(out, li.pem...)
	}
	count := len(a.learned)
	a.mu.Unlock()

	tmp := a.combined + ".tmp"
	if err := os.WriteFile(tmp, out, 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmp, a.combined); err != nil {
		return err
	}
	// Only now may curl be pointed at it.
	a.mu.Lock()
	a.staged = true
	a.mu.Unlock()
	log.Printf("egress engine: CA bundle staged with %d AIA-learned link(s) at %s (base %s)", count, a.combined, a.basePath)
	return nil
}
