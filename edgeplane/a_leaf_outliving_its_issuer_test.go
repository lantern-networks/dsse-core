package edgeplane

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

// anIssuingCA mints a CA certificate with the given name and life. The name is a parameter because the
// defect this file is about is a REPLACEMENT that keeps every name it had.
func anIssuingCA(t *testing.T, commonName string, notBefore, notAfter time.Time) *InterceptionIssuer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &InterceptionIssuer{signingCert: parsed, signer: key, chain: [][]byte{der}}
}

// aLeafSignedBy mints a leaf under the issuer and packs it the way the interception path caches it:
// [leafDER, issuer chain...].
func aLeafSignedBy(t *testing.T, issuer *InterceptionIssuer, host string, notBefore, notAfter time.Time) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, issuer.signingCert, &key.PublicKey, issuer.signer)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{
		Certificate: append([][]byte{der}, issuer.chain...),
		PrivateKey:  key,
		Leaf:        tmpl,
	}
}

// ★★★ A LEAF LIVES THIRTY DAYS AND THE CA UNDER IT LIVES TWELVE HOURS (2026-09-08).
//
// The cache's freshness check asked the leaf about its own NotAfter. From twelve hours after minting — the
// moment the per-organization issuing CA is replaced by the ordinary material refresh — the cached leaf was
// still "fresh" and the Edge went on serving a certificate whose chain no client could verify, for the
// remaining twenty-nine days.
//
// And the cache key cannot save it: it is organization + host, and the organization is precisely what does
// not change when that organization's issuing certificate is replaced.
func TestACachedLeafIsNotFreshOnceItsIssuerHasBeenReplaced(t *testing.T) {
	at := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	now := func() time.Time { return at }

	// The ordinary lifetimes of this deployment: a twelve-hour issuing CA, a thirty-day leaf.
	issuer := anIssuingCA(t, "Renge Systems Interception Issuing CA", at.Add(-time.Hour), at.Add(11*time.Hour))
	leaf := aLeafSignedBy(t, issuer, "www.example.com", at.Add(-time.Minute), at.Add(30*24*time.Hour))

	if !networkExtensionLabTLSLeafFresh(leaf, now, issuer) {
		t.Fatal("a leaf just minted under the issuer in force was not usable")
	}

	// ★ THE DEFECT. The refresh installs a new issuing certificate — same organization, same subject, new
	// bytes — which is what happens every twelve hours on its own, with nobody involved.
	replacement := anIssuingCA(t, "Renge Systems Interception Issuing CA", at, at.Add(12*time.Hour))
	if networkExtensionLabTLSLeafFresh(leaf, now, replacement) {
		t.Fatal("a leaf minted under the SUPERSEDED issuing certificate was still served: its own dates are " +
			"fine for another twenty-nine days, and no client can verify the chain it carries")
	}

	// The issuer in force is itself past its end: re-mint and fail loudly rather than serve from cache.
	expired := anIssuingCA(t, "Renge Systems Interception Issuing CA", at.Add(-13*time.Hour), at.Add(-time.Minute))
	staleUnderExpired := aLeafSignedBy(t, expired, "www.example.com", at.Add(-12*time.Hour), at.Add(18*24*time.Hour))
	if networkExtensionLabTLSLeafFresh(staleUnderExpired, now, expired) {
		t.Fatal("a leaf whose issuing certificate has expired was still served from cache")
	}

	// ★ THE CONTROL. The leaf's own end still matters — this must not become "the issuer decides everything".
	ending := aLeafSignedBy(t, issuer, "www.example.com", at.Add(-30*24*time.Hour), at.Add(time.Minute))
	if networkExtensionLabTLSLeafFresh(ending, now, issuer) {
		t.Fatal("a leaf inside its own renew-before window was served")
	}

	// ★ AND WITH NO ISSUER TO COMPARE AGAINST, the leaf's own dates are all there is — the behaviour before
	// this change, kept so a caller that cannot resolve an issuer degrades instead of refusing everything.
	if !networkExtensionLabTLSLeafFresh(leaf, now, nil) {
		t.Fatal("with no issuer given, a leaf well inside its own dates was refused")
	}
}
