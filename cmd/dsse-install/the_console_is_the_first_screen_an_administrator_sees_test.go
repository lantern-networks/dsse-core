package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ★★★ THE FIRST SCREEN AN ADMINISTRATOR SEES MUST NOT BE A CERTIFICATE WARNING (2026-09-03, the operator:
// "the certificate error every time you enter the Admin Console — shouldn't that be solved first, and be in
// the published install procedure?").
//
// Dropping the pair in IS the intent, so the installer does the bookkeeping. Both directions are held,
// because a mechanism that only adopts and never releases leaves a deployment pointing at a certificate that
// is no longer there — which is a Console that will not start, for a reason nothing says.
func TestTheOperatorsConsoleCertificateIsAdoptedAndReleased(t *testing.T) {
	dir := t.TempDir()
	if err := writeEnvironment(dir, []string{"console.example.test"}, nil); err != nil {
		t.Fatalf("render the environment: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(dir, consoleCertDirName), 0o755); err != nil {
		t.Fatal(err)
	}
	crt := filepath.Join(dir, consoleCertDirName, "tls.crt")
	key := filepath.Join(dir, consoleCertDirName, "tls.key")
	writeSelfSignedPair(t, "console.example.test", crt, key)

	if said := adoptConsoleCertificate(dir); said == "" {
		t.Fatal("a certificate pair was put in place and the installer said nothing and changed nothing")
	}
	env := readDeploymentEnv(dir)
	if env[consoleCertEnvKey] != "/deployment/"+consoleCertDirName+"/tls.crt" {
		t.Errorf("the Console was not pointed at the operator's certificate: %q", env[consoleCertEnvKey])
	}

	// ★ AND TAKING IT AWAY PUTS IT BACK. Otherwise the Console keeps a path to a file that is gone.
	if err := os.Remove(crt); err != nil {
		t.Fatal(err)
	}
	if said := adoptConsoleCertificate(dir); said == "" {
		t.Fatal("the pair was removed and the deployment still points at it")
	}
	if v := strings.TrimSpace(readDeploymentEnv(dir)[consoleCertEnvKey]); v != "" {
		t.Errorf("the Console still points at %q, which is not there — it will not start and nothing says why", v)
	}

	// The compose default is what an empty value falls back to.
	body, err := composeBodyFor(dir, foundingShape)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(body, "${DSSE_CONSOLE_TLS_CERT:-/deployment/management.crt}") {
		t.Error("the Console has no fallback to this deployment's own certificate, so a deployment without " +
			"an operator certificate has none at all")
	}
	// And the directory is mounted, or the pair is invisible inside the container.
	if !strings.Contains(body, "./console:/deployment/console") {
		t.Error("the console/ directory is not given to the Console, so a pair dropped there cannot be read")
	}
}

// ★ THE FINGERPRINT PRINTED IS THE ONE THE BROWSER SHOWS. The installer has printed the deployment ANCHOR's
// fingerprint since 2026-08-22 — right for a device's anchor file, and not what a browser warning displays.
// An administrator told to compare the anchor's finds it does not match and learns the printed value is not
// for them.
func TestTheFingerprintOfferedForTheBrowserIsTheLeafItPresents(t *testing.T) {
	dir := t.TempDir()
	crt := filepath.Join(dir, "management.crt")
	writeSelfSignedPair(t, "console.example.test", crt, filepath.Join(dir, "management.key"))
	got := certificateFingerprintFile(crt)
	if got == "" {
		t.Fatal("no fingerprint was read from the certificate the Console presents")
	}
	if strings.Count(got, ":") < 10 {
		t.Errorf("the fingerprint is not in a form anybody can compare against a browser: %q", got)
	}
}

func writeSelfSignedPair(t *testing.T, host, certPath, keyPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	kb, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600); err != nil {
		t.Fatal(err)
	}
}
