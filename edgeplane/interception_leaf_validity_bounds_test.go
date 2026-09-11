package edgeplane

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

func boundedInterceptionCA(t *testing.T, name string, parent *x509.Certificate, parentKey *ecdsa.PrivateKey, start, end time.Time) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: name}, NotBefore: start, NotAfter: end, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	if parent == nil {
		parent = tmpl
		parentKey = key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

func TestInterceptionLeafValidityFitsWholeChainAndRemainsCacheable(t *testing.T) {
	for _, tc := range []struct {
		name                     string
		root, parent, edge, want time.Duration
	}{
		{"short edge", 24 * time.Hour, 12 * time.Hour, 6 * time.Minute, 6 * time.Minute},
		{"short parent", 24 * time.Hour, 6 * time.Minute, 12 * time.Hour, 6 * time.Minute},
		{"short omitted root", 6 * time.Minute, 12 * time.Hour, 24 * time.Hour, 6 * time.Minute},
		{"normal TTL", 365 * 24 * time.Hour, 24 * time.Hour, 12 * time.Hour, 12 * time.Hour},
		{"leaf cap", 365 * 24 * time.Hour, 90 * 24 * time.Hour, 60 * 24 * time.Hour, networkExtensionLabTLSLeafValidity},
	} {
		t.Run(tc.name, func(t *testing.T) {
			start := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
			now := start
			engine, err := NewNetworkExtensionLabTLSInterception([]string{"*"}, func() time.Time { return now })
			if err != nil {
				t.Fatal(err)
			}
			root, rk := boundedInterceptionCA(t, "root", nil, nil, start.Add(-5*time.Minute), start.Add(tc.root))
			parent, pk := boundedInterceptionCA(t, "parent", root, rk, start.Add(-2*time.Minute), start.Add(tc.parent))
			edge, ek := boundedInterceptionCA(t, "edge", parent, pk, start.Add(-3*time.Minute), start.Add(tc.edge))
			chain := append(pemOf(edge), pemOf(parent)...)
			if _, err = engine.LoadOfflineTenantIntermediate("tenant_a", pemOf(root), chain, ecKeyPEM(t, ek)); err != nil {
				t.Fatal(err)
			}
			first, err := engine.leafCertificate("tenant_a", "www.example.com")
			if err != nil {
				t.Fatal(err)
			}
			leaf, err := x509.ParseCertificate(first.Certificate[0])
			if err != nil {
				t.Fatal(err)
			}
			if !leaf.NotAfter.Equal(start.Add(tc.want)) || !leaf.NotBefore.Equal(parent.NotBefore) {
				t.Fatalf("leaf dates escape effective path: %s .. %s", leaf.NotBefore, leaf.NotAfter)
			}
			roots := x509.NewCertPool()
			roots.AddCert(root)
			intermediates := x509.NewCertPool()
			intermediates.AddCert(parent)
			intermediates.AddCert(edge)
			verify := func(at time.Time) error {
				_, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, DNSName: "www.example.com", CurrentTime: at})
				return err
			}
			if err = verify(start.Add(tc.want - time.Second)); err != nil {
				t.Fatalf("leaf does not verify inside advertised interval: %v", err)
			}
			if err = verify(start.Add(tc.want + time.Second)); err == nil {
				t.Fatal("expired chain verified")
			}
			now = start.Add(time.Second)
			cached, err := engine.leafCertificate("tenant_a", "www.example.com")
			if err != nil || !bytes.Equal(first.Certificate[0], cached.Certificate[0]) {
				t.Fatalf("short TTL disabled the leaf cache: %v", err)
			}
			if tc.want < networkExtensionLabTLSLeafValidity {
				now = start.Add(tc.want + time.Second)
				if _, err = engine.leafCertificate("tenant_a", "new.example.com"); err == nil {
					t.Fatal("minted under an expired path")
				}
			}
		})
	}
}
