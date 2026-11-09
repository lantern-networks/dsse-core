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
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// consoleStandIn answers the three questions verifyConsole asks, the way a healthy Console does.
func consoleStandIn(t *testing.T, pair tls.Certificate) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.WriteHeader(http.StatusOK)
		case "/app.js", "/admin/login/password":
			w.WriteHeader(http.StatusUnauthorized)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{pair}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func writeConsolePair(t *testing.T, dir string, pair tls.Certificate) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(dir, consoleCertDirName), 0o700); err != nil {
		t.Fatal(err)
	}
	crt := []byte{}
	for _, der := range pair.Certificate {
		crt = append(crt, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	key, err := x509.MarshalPKCS8PrivateKey(pair.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, consoleCertDirName, "tls.crt"), crt, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, consoleCertDirName, "tls.key"),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), 0o600); err != nil {
		t.Fatal(err)
	}
}

func askConsole(t *testing.T, client *http.Client, srv *httptest.Server, host string) []verifyResult {
	t.Helper()
	client.Transport.(*http.Transport).TLSClientConfig.ServerName = host
	return verifyConsole(client, srv.URL)
}

func allPass(rows []verifyResult) bool {
	if len(rows) == 0 {
		return false
	}
	for _, r := range rows {
		if !r.ok {
			return false
		}
	}
	return true
}

// The operator's own certificate for the Console, adopted the way the installer says to, from a
// CA this machine does not otherwise trust.
func TestTheConsoleCheckAcceptsTheOperatorsAdoptedCertificate(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "deployment")
	installFromPlan(t, "../../docs/plans/single-region.json", dir)
	const host = "console.region-a.example.test"
	pair, _ := clientProbeCertificate(t, host)
	writeConsolePair(t, dir, pair)
	if said := adoptConsoleCertificate(dir); said == "" {
		t.Fatal("the operator's certificate was not adopted")
	}
	srv := consoleStandIn(t, pair)

	// The control: the deployment client is what the walk used, and it refuses a healthy Console.
	deployment, err := deploymentClient(dir)
	if err != nil {
		t.Fatal(err)
	}
	if rows := askConsole(t, deployment, srv, host); allPass(rows) {
		t.Fatalf("the control passed, so this test cannot show the defect: %+v", rows)
	}

	console, err := consoleClient(dir)
	if err != nil {
		t.Fatal(err)
	}
	if rows := askConsole(t, console, srv, host); !allPass(rows) {
		t.Fatalf("a Console presenting the adopted certificate fails the check: %+v", rows)
	}
}

// And it trusts that certificate only: another one from the same CA, or the adopted one under another name, fails.
func TestTheConsoleCheckTrustsOnlyTheAdoptedCertificate(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "deployment")
	installFromPlan(t, "../../docs/plans/single-region.json", dir)
	const host = "console.region-a.example.test"
	adopted, _ := clientProbeCertificate(t, host)
	writeConsolePair(t, dir, adopted)
	adoptConsoleCertificate(dir)
	other, _ := clientProbeCertificate(t, host)

	console, err := consoleClient(dir)
	if err != nil {
		t.Fatal(err)
	}
	if rows := askConsole(t, console, consoleStandIn(t, other), host); allPass(rows) {
		t.Fatalf("a certificate the operator did not adopt passed: %+v", rows)
	}
	console, _ = consoleClient(dir)
	rows := askConsole(t, console, consoleStandIn(t, adopted), "admin.region-a.example.test")
	if allPass(rows) {
		t.Fatalf("the adopted certificate passed under a name it does not carry: %+v", rows)
	}
}

// Day zero: no operator pair, and the Console presents the deployment's own certificate, as before.
func TestTheConsoleCheckStillAcceptsTheDeploymentsOwnCertificate(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "deployment")
	installFromPlan(t, "../../docs/plans/single-region.json", dir)
	pair, err := tls.LoadX509KeyPair(filepath.Join(dir, "console-server.crt"), filepath.Join(dir, "console-server.key"))
	if err != nil {
		t.Skipf("this plan's Console certificate is not at console-server.crt: %v", err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	host := ""
	for _, name := range leaf.DNSNames {
		if strings.HasPrefix(name, "console.") {
			host = name
		}
	}
	if host == "" {
		t.Fatalf("the deployment's Console certificate names no console host: %v", leaf.DNSNames)
	}
	console, err := consoleClient(dir)
	if err != nil {
		t.Fatal(err)
	}
	if rows := askConsole(t, console, consoleStandIn(t, pair), host); !allPass(rows) {
		t.Fatalf("the deployment's own Console certificate fails the check: %+v", rows)
	}
}

// The walk asks the Console with this client, not with the deployment client.
func TestTheWalkAsksTheConsoleWithItsOwnClient(t *testing.T) {
	src, err := os.ReadFile("verify.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(src)
	if strings.Contains(text, "verifyConsole(client, consoleURL)") {
		t.Fatal("verify.go still asks the Console with the deployment client")
	}
	if !strings.Contains(text, "console, err := consoleClient(dir)") || !strings.Contains(text, "verifyConsole(console, consoleURL)") {
		t.Fatal("verify.go does not ask the Console with consoleClient")
	}
}

// consoleCertificate is a server certificate for host. With issuer nil it signs itself; with mayIssue it also
// carries CA:TRUE and keyCertSign, as some certificate tools give a self-signed certificate by default.
func consoleCertificate(t *testing.T, host string, mayIssue bool, issuer *tls.Certificate) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: host}, DNSNames: []string{host},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		BasicConstraintsValid: true, IsCA: mayIssue,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if mayIssue {
		tmpl.KeyUsage |= x509.KeyUsageCertSign
	}
	parent, signer := tmpl, any(key)
	if issuer != nil {
		if parent, err = x509.ParseCertificate(issuer.Certificate[0]); err != nil {
			t.Fatal(err)
		}
		signer = issuer.PrivateKey
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, signer)
	if err != nil {
		t.Fatal(err)
	}
	pair := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	if issuer != nil {
		pair.Certificate = append(pair.Certificate, issuer.Certificate...)
	}
	return pair
}

// An adopted certificate that may also sign certificates was a root in the Console client's
// pool, so another certificate for the same name, signed by it, passed every Console check.
func TestAnAdoptedCertificateThatIsACATrustsOnlyItself(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "deployment")
	installFromPlan(t, "../../docs/plans/single-region.json", dir)
	const host = "console.region-a.example.test"
	adopted := consoleCertificate(t, host, true, nil)
	writeConsolePair(t, dir, adopted)
	if said := adoptConsoleCertificate(dir); said == "" {
		t.Fatal("the operator's certificate was not adopted")
	}

	console, err := consoleClient(dir)
	if err != nil {
		t.Fatal(err)
	}
	if rows := askConsole(t, console, consoleStandIn(t, adopted), host); !allPass(rows) {
		t.Fatalf("a Console presenting the adopted certificate fails the check: %+v", rows)
	}

	signedByIt := consoleCertificate(t, host, false, &adopted)
	console, _ = consoleClient(dir)
	if rows := askConsole(t, console, consoleStandIn(t, signedByIt), host); allPass(rows) {
		t.Fatalf("a certificate the adopted one signed passed: %+v", rows)
	}
}

// The adopted certificate was ALSO a root before it was adopted, and the narrowing refused a
// valid certificate that root issued, which passed before the adoption. Here the operator put this deployment's
// own anchor in console/, and the Console presents the certificate the deployment issued it on day zero.
func TestAnAdoptedRootThatWasAlreadyTrustedStillTrustsWhatItIssued(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "deployment")
	installFromPlan(t, "../../docs/plans/single-region.json", dir)
	day0, err := tls.LoadX509KeyPair(filepath.Join(dir, "console-server.crt"), filepath.Join(dir, "console-server.key"))
	if err != nil {
		t.Skipf("this plan's Console certificate is not at console-server.crt: %v", err)
	}
	leaf, err := x509.ParseCertificate(day0.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	host := ""
	for _, name := range leaf.DNSNames {
		if strings.HasPrefix(name, "console.") {
			host = name
		}
	}
	if host == "" {
		t.Fatalf("the deployment's Console certificate names no console host: %v", leaf.DNSNames)
	}

	before, err := consoleClient(dir)
	if err != nil {
		t.Fatal(err)
	}
	if rows := askConsole(t, before, consoleStandIn(t, day0), host); !allPass(rows) {
		t.Fatalf("the control failed, so this test cannot show the defect: %+v", rows)
	}

	anchor, err := os.ReadFile(filepath.Join(dir, "deployment-anchor.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, consoleCertDirName), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, consoleCertDirName, "tls.crt"), anchor, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, consoleCertDirName, "tls.key"), []byte("present"), 0o600); err != nil {
		t.Fatal(err)
	}
	after, err := consoleClient(dir)
	if err != nil {
		t.Fatal(err)
	}
	if rows := askConsole(t, after, consoleStandIn(t, day0), host); !allPass(rows) {
		t.Fatalf("adopting a root this machine already trusted refused a certificate it issued: %+v", rows)
	}

	// And a CA the adoption alone brought in still trusts only itself (F4).
	other := consoleCertificate(t, host, true, nil)
	writeConsolePair(t, dir, other)
	narrowed, err := consoleClient(dir)
	if err != nil {
		t.Fatal(err)
	}
	if rows := askConsole(t, narrowed, consoleStandIn(t, consoleCertificate(t, host, false, &other)), host); allPass(rows) {
		t.Fatalf("a certificate signed by an adopted CA nothing else trusts passed: %+v", rows)
	}
}
