package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Opt-in because this crosses an actual certificate deadline. No clock is
// replaced. The child uses the production fetcher, TLS selector and fatal expiry
// watcher, including its real process exit. Restart is performed by this test's
// supervisor; this is not acceptance evidence for Docker, macOS or Windows.
func TestPKIWallClockControlPlaneLoss(t *testing.T) {
	if os.Getenv("DSSE_PKI_WALL_CLOCK_CHILD") != "" {
		runPKIWallClockChild(t)
		return
	}
	if os.Getenv("DSSE_PKI_WALL_CLOCK") != "1" {
		t.Skip("set DSSE_PKI_WALL_CLOCK=1 for the isolated 90-second expiry acceptance")
	}
	const tenant = "tenant_wall_clock"
	const name = "wall-clock.dsse.invalid"
	const bearer = "isolated-wall-clock-fixture"
	root := t.TempDir()
	ca, caKey := interceptionTestCA(t, "Isolated Edge Client CA", nil, nil, time.Now())
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{CommonName: "isolated-edge"}, NotBefore: time.Now().Add(-time.Minute),
		NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	write := func(name string, data []byte) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(root, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write("client.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	write("client-key.pem", []byte(ecKeyPEMForTest(t, key)))
	authority := newTenantTransportAuthority(nil, func([]byte) error { return nil }, time.Now)
	if _, err := authority.EnsureCA(tenant, name); err != nil {
		t.Fatal(err)
	}
	material, err := authority.IssueFor(tenant, "probe", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	deviceRoots := x509.NewCertPool()
	if !deviceRoots.AppendCertsFromPEM([]byte(material.AnchorPEM)) {
		t.Fatal("tenant root")
	}
	mux := http.NewServeMux()
	registerTenantTransportMaterialRoute(mux, authority, nil, nil, bearer, 90*time.Second, nil, false)
	var unavailable atomic.Bool
	var refused atomic.Int64
	cp := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if unavailable.Load() {
			refused.Add(1)
			http.Error(w, "injected control-plane outage", http.StatusServiceUnavailable)
			return
		}
		mux.ServeHTTP(w, r)
	}))
	clientRoots := x509.NewCertPool()
	clientRoots.AddCert(ca)
	cp.TLS = &tls.Config{MinVersion: tls.VersionTLS12, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: clientRoots}
	cp.StartTLS()
	defer cp.Close()
	write("cp.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cp.Certificate().Raw}))

	type child struct {
		cmd     *exec.Cmd
		done    chan error
		address string
		logPath string
	}
	start := func(label string) child {
		t.Helper()
		addressPath := filepath.Join(root, label+".addr")
		logPath := filepath.Join(root, label+".log")
		logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(os.Args[0], "-test.run=^TestPKIWallClockControlPlaneLoss$", "-test.timeout=3m")
		cmd.Env = append(os.Environ(), "DSSE_PKI_WALL_CLOCK_CHILD="+root,
			"DSSE_PKI_WALL_CLOCK_CP="+cp.URL, "DSSE_PKI_WALL_CLOCK_ADDRESS="+addressPath)
		cmd.Stdout, cmd.Stderr = logFile, logFile
		if err := cmd.Start(); err != nil {
			logFile.Close()
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { err := cmd.Wait(); logFile.Close(); done <- err }()
		t.Cleanup(func() { _ = cmd.Process.Kill() })
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			if b, err := os.ReadFile(addressPath); err == nil {
				return child{cmd, done, string(b), logPath}
			}
			select {
			case err := <-done:
				b, _ := os.ReadFile(logPath)
				t.Fatalf("child startup: %v: %s", err, b)
			default:
			}
			time.Sleep(50 * time.Millisecond)
		}
		t.Fatal("child did not publish listener")
		return child{}
	}
	probe := func(address string) (*x509.Certificate, error) {
		c, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", address,
			&tls.Config{MinVersion: tls.VersionTLS12, RootCAs: deviceRoots, ServerName: name})
		if err != nil {
			return nil, err
		}
		defer c.Close()
		return c.ConnectionState().PeerCertificates[0], nil
	}
	first := start("before-outage")
	cert, err := probe(first.address)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("initial TLS verified: at=%s serial=%s not_after=%s", time.Now().UTC().Format(time.RFC3339Nano), cert.SerialNumber, cert.NotAfter.Format(time.RFC3339))
	unavailable.Store(true)
	deadline := cert.NotAfter.Add(5 * time.Second)
	for time.Now().Before(cert.NotAfter.Add(-time.Second)) {
		if _, err := probe(first.address); err != nil {
			t.Fatalf("valid tenant door failed before expiry: %v", err)
		}
		time.Sleep(time.Second)
	}
	select {
	case err := <-first.done:
		if e, ok := err.(*exec.ExitError); !ok || e.ExitCode() != 1 {
			t.Fatalf("expected production fatal exit 1: %v", err)
		}
	case <-time.After(time.Until(deadline)):
		t.Fatal("node remained alive past its last material deadline")
	}
	logBytes, err := os.ReadFile(first.logPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(logBytes), "EXPIRED for every door") || refused.Load() == 0 {
		t.Fatalf("missing expiry/outage evidence: refusals=%d log=%s", refused.Load(), logBytes)
	}
	if _, err := probe(first.address); err == nil {
		t.Fatal("expired node still accepts TLS")
	}
	t.Logf("expiry process exit observed: at=%s CP_refusals=%d", time.Now().UTC().Format(time.RFC3339Nano), refused.Load())
	unavailable.Store(false)
	second := start("after-restoration")
	renewed, err := probe(second.address)
	if err != nil {
		t.Fatalf("supervised restart failed to reacquire material: %v", err)
	}
	if renewed.SerialNumber.Cmp(cert.SerialNumber) == 0 || !renewed.NotAfter.After(cert.NotAfter) {
		t.Fatal("restored node reused expired material")
	}
	t.Logf("new process TLS verified with same tenant root: at=%s serial=%s not_after=%s", time.Now().UTC().Format(time.RFC3339Nano), renewed.SerialNumber, renewed.NotAfter.Format(time.RFC3339))
	_ = second.cmd.Process.Kill()
	<-second.done
}

func runPKIWallClockChild(t *testing.T) {
	root := os.Getenv("DSSE_PKI_WALL_CLOCK_CHILD")
	cert, err := tls.LoadX509KeyPair(filepath.Join(root, "client.pem"), filepath.Join(root, "client-key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	ca, err := os.ReadFile(filepath.Join(root, "cp.pem"))
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		t.Fatal("control-plane root")
	}
	f := newTenantTransportMaterialFetcher(os.Getenv("DSSE_PKI_WALL_CLOCK_CP"), "isolated-wall-clock-fixture",
		&tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool, Certificates: []tls.Certificate{cert}}, func() []string { return nil })
	f.dataURL = func() string { return "" }
	if _, err := f.FetchOnce(); err != nil || f.installedTenants.Load() != 1 {
		t.Fatalf("startup fetch: %v", err)
	}
	f.Start()
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{MinVersion: tls.VersionTLS12,
		GetCertificate: transportCertificateForClientHello(func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			return nil, fmt.Errorf("no shared certificate in this fixture")
		})})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := os.WriteFile(os.Getenv("DSSE_PKI_WALL_CLOCK_ADDRESS"), []byte(listener.Addr().String()), 0600); err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ready") }), ReadHeaderTimeout: time.Second}
	if err := server.Serve(listener); err != nil {
		t.Fatal(err)
	}
}
