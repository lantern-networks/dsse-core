package certreload

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
)

// writeSelfSigned writes a fresh self-signed cert/key pair (unique serial) to certPath/keyPath and returns the
// serial so the test can assert which cert is being served.
func writeSelfSigned(t *testing.T, certPath, keyPath, cn string) *big.Int {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{cn},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return serial
}

// servedSerial extracts the serial of the leaf cert the provider currently serves.
func servedSerial(t *testing.T, r *ReloadableCert) *big.Int {
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

func TestReloadableCertHotSwap(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "edge.crt")
	keyPath := filepath.Join(dir, "edge.key")

	serial1 := writeSelfSigned(t, certPath, keyPath, "edge")
	r, err := NewReloadableCert(certPath, keyPath)
	if err != nil {
		t.Fatalf("initial load: %v", err)
	}
	if got := servedSerial(t, r); got.Cmp(serial1) != 0 {
		t.Fatalf("served serial = %s, want initial %s", got, serial1)
	}

	// Rotate the files in place, then Reload — the provider must now serve the NEW cert with no new object.
	serial2 := writeSelfSigned(t, certPath, keyPath, "edge")
	if serial1.Cmp(serial2) == 0 {
		t.Fatal("test setup: serials should differ")
	}
	if err := r.Reload(); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if got := servedSerial(t, r); got.Cmp(serial2) != 0 {
		t.Fatalf("after reload served serial = %s, want rotated %s", got, serial2)
	}
}

func TestReloadableCertBadRotationKeepsPrevious(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "edge.crt")
	keyPath := filepath.Join(dir, "edge.key")

	good := writeSelfSigned(t, certPath, keyPath, "edge")
	r, err := NewReloadableCert(certPath, keyPath)
	if err != nil {
		t.Fatalf("initial load: %v", err)
	}

	// Corrupt the cert file, then Reload must FAIL and keep serving the previous good cert (fail-safe).
	if err := os.WriteFile(certPath, []byte("-----BEGIN CERTIFICATE-----\nnope\n-----END CERTIFICATE-----\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := r.Reload(); err == nil {
		t.Fatal("expected reload error on corrupt cert")
	}
	if got := servedSerial(t, r); got.Cmp(good) != 0 {
		t.Fatalf("after failed reload served serial = %s, want previous good %s", got, good)
	}
}

func TestReloadAllCertsRegistry(t *testing.T) {
	reloadablesMu.Lock()
	saved := reloadables
	reloadables = nil
	reloadablesMu.Unlock()
	t.Cleanup(func() { reloadablesMu.Lock(); reloadables = saved; reloadablesMu.Unlock() })

	dir := t.TempDir()
	certPath := filepath.Join(dir, "c.crt")
	keyPath := filepath.Join(dir, "c.key")
	writeSelfSigned(t, certPath, keyPath, "edge")
	r, err := NewReloadableCert(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	RegisterReloadable(r)

	rotated := writeSelfSigned(t, certPath, keyPath, "edge")
	n, err := ReloadAll()
	if err != nil || n != 1 {
		t.Fatalf("ReloadAll = (%d, %v), want (1, nil)", n, err)
	}
	if got := servedSerial(t, r); got.Cmp(rotated) != 0 {
		t.Fatalf("registry reload served serial = %s, want %s", got, rotated)
	}
}
