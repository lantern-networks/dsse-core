package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	certreload "github.com/lantern-networks/dsse-core/certreload"
)

// selfSignedPEM returns a fresh self-signed cert + key as PEM strings (unique serial), valid around `now`.
func selfSignedPEM(t *testing.T, cn string, notBefore, notAfter time.Time) (string, string, *big.Int) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: cn}, NotBefore: notBefore, NotAfter: notAfter, DNSNames: []string{cn}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	return certPEM, keyPEM, serial
}

func TestRotateNamedCertHotSwapAndFailSafe(t *testing.T) {
	// isolate the global registry
	saved := certreload.Registered()
	certreload.SetRegistryForTest(nil)
	t.Cleanup(func() { certreload.SetRegistryForTest(saved) })

	dir := t.TempDir()
	certPath := filepath.Join(dir, "svc.crt")
	keyPath := filepath.Join(dir, "svc.key")
	now := time.Now().UTC()

	c0, k0, serial0 := selfSignedPEM(t, "svc", now.Add(-time.Hour), now.Add(time.Hour))
	os.WriteFile(certPath, []byte(c0), 0o600)
	os.WriteFile(keyPath, []byte(k0), 0o600)
	r, err := certreload.NewReloadableCert(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	certreload.RegisterReloadable(r)

	// inventory lists it under the derived name "svc"
	inv := certInventory()
	if len(inv) != 1 || inv[0].Name != "svc" || inv[0].FingerprintSHA256 == "" {
		t.Fatalf("inventory = %+v, want one entry named svc with a fingerprint", inv)
	}

	// rotate to a new cert -> hot-swapped (served serial changes), no restart
	c1, k1, serial1 := selfSignedPEM(t, "svc", now.Add(-time.Hour), now.Add(2*time.Hour))
	if serial0.Cmp(serial1) == 0 {
		t.Fatal("serials should differ")
	}
	if _, err := rotateNamedCert("svc", c1, k1, now); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if got := servedSerial(t, r); got.Cmp(serial1) != 0 {
		t.Fatalf("after rotation served serial = %s, want %s", got, serial1)
	}

	// mismatched cert/key -> rejected, previous cert kept (fail-safe, link not bricked)
	_, kOther, _ := selfSignedPEM(t, "svc", now.Add(-time.Hour), now.Add(time.Hour))
	if _, err := rotateNamedCert("svc", c1, kOther, now); err == nil {
		t.Fatal("a cert/key mismatch must be rejected")
	}
	if got := servedSerial(t, r); got.Cmp(serial1) != 0 {
		t.Fatalf("after a rejected rotation the previous cert must still serve, got serial %s", got)
	}

	// expired cert -> rejected (validate-before-accept)
	cExp, kExp, _ := selfSignedPEM(t, "svc", now.Add(-2*time.Hour), now.Add(-time.Hour))
	if _, err := rotateNamedCert("svc", cExp, kExp, now); err == nil {
		t.Fatal("an expired cert must be rejected")
	}

	// unknown name -> rejected
	if _, err := rotateNamedCert("nope", c1, k1, now); err == nil {
		t.Fatal("an unknown cert name must be rejected")
	}
}

// servedSerial extracts the serial of the leaf cert the provider currently serves.
func servedSerial(t *testing.T, r *certreload.ReloadableCert) *big.Int {
	t.Helper()
	c, err := r.GetCertificate(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(c.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	return leaf.SerialNumber
}
