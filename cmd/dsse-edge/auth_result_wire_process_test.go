package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/migrations"
	"github.com/lantern-networks/dsse-core/tenantca"
)

// This helper runs the production CP result route and Edge machine client in
// separate processes. It does not simulate an endpoint mux or an OS agent.
func TestAuthResultWireProcessHelper(t *testing.T) {
	mode := os.Getenv("DSSE_AUTH_RESULT_WIRE_HELPER")
	if mode == "" {
		t.Skip("subprocess helper")
	}
	caPEM, err := os.ReadFile(os.Getenv("DSSE_AUTH_RESULT_WIRE_CA"))
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		t.Fatal("invalid process test CA")
	}
	cert, err := tls.LoadX509KeyPair(os.Getenv("DSSE_AUTH_RESULT_WIRE_CERT"), os.Getenv("DSSE_AUTH_RESULT_WIRE_KEY"))
	if err != nil {
		t.Fatal(err)
	}
	switch mode {
	case "cp":
		db, err := sql.Open("postgres", os.Getenv("DSSE_TEST_POSTGRES_DSN"))
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		reg, err := tenantca.LoadTenantCARegistry(os.Getenv("DSSE_AUTH_RESULT_WIRE_REGISTRY"))
		if err != nil {
			t.Fatal(err)
		}
		auditIngestAuthorityMap = &auditIngestAuthority{byEdge: map[string][]string{"edge-a": {os.Getenv("DSSE_AUTH_RESULT_WIRE_TENANT")}, "edge-b": {os.Getenv("DSSE_AUTH_RESULT_WIRE_TENANT")}}}
		mux := http.NewServeMux()
		registerAuthResultAuthorityRoutes(mux, newPostgresAuthResultStore(db), "", func(r *http.Request, tenant string) bool {
			return authResultEdgeAuthorized(r, reg, tenant)
		})
		listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
			MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert},
			ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool,
		})
		if err != nil {
			t.Fatal(err)
		}
		server := &http.Server{Handler: adminSurfaceOnlyMiddleware(mux)}
		served := make(chan error, 1)
		go func() { served <- server.Serve(listener) }()
		fmt.Println(listener.Addr().String())
		_, _ = io.Copy(io.Discard, os.Stdin)
		_ = server.Close()
		if err := <-served; err != http.ErrServerClosed {
			t.Fatal(err)
		}
	case "edge-write", "edge-query":
		client := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12, RootCAs: pool, Certificates: []tls.Certificate{cert},
		}}}
		store := remoteAuthResultStore{url: "https://" + os.Getenv("DSSE_AUTH_RESULT_WIRE_ADDRESS") + "/auth-flow-results", client: client}
		r := authResultFixture(time.Now().UTC().Truncate(time.Second))
		r.TenantID = os.Getenv("DSSE_AUTH_RESULT_WIRE_TENANT")
		r.RequestID = authResultProcessID(r.TenantID, "wire")
		if mode == "edge-write" {
			if err := store.Record(r); err != nil {
				t.Fatal(err)
			}
			return
		}
		want := os.Getenv("DSSE_AUTH_RESULT_WIRE_WANT")
		if got, err := store.Lookup(r.RequestID, r.TenantID, r.DeviceID, r.Principal, r.Session); err != nil || got != want {
			t.Fatalf("Edge result lookup = %q, %v; want %q", got, err, want)
		}
		if got, err := store.Lookup(r.RequestID, r.TenantID, "different-device", r.Principal, r.Session); err != nil || got != "" {
			t.Fatalf("different device learned result = %q, %v", got, err)
		}
	default:
		t.Fatal("unknown wire process mode")
	}
}

func authResultWireCert(t *testing.T, dir string, ca testCA, name string, usages []x509.ExtKeyUsage) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: usages,
	}
	if name == "cp" {
		tmpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPath, keyPath := filepath.Join(dir, name+".pem"), filepath.Join(dir, name+".key")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

// A CP restart must not lose a confirmed result. Each CP and Edge role runs in
// its own process over real mTLS and the CPs share only PostgreSQL.
func TestAuthResultWireAcrossProcessesAndCPRestart(t *testing.T) {
	dsn := os.Getenv("DSSE_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("set DSSE_TEST_POSTGRES_DSN for the real PostgreSQL process check")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Ping(); err != nil {
		t.Fatal(err)
	}
	ddl, err := os.ReadFile("../../migrations/053_auth_flow_results.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, statement := range migrations.SplitSQLStatements(string(ddl)) {
		if _, err := db.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	tenant := fmt.Sprintf("test_auth_wire_%d", time.Now().UnixNano())
	defer func() { _, _ = db.Exec("DELETE FROM auth_flow_results WHERE tenant_id=$1", tenant) }()
	dir := t.TempDir()
	ca := makeTestCA(t, dir, "auth-wire-ca", 91)
	registry := writeRegistry(t, dir, map[string]string{tenant: ca.pemPath})
	cpCert, cpKey := authResultWireCert(t, dir, ca, "cp", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	aCert, aKey := authResultWireCert(t, dir, ca, "edge-a", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	bCert, bKey := authResultWireCert(t, dir, ca, "edge-b", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	endpointCert, endpointKey := authResultWireCert(t, dir, ca, "endpoint", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	baseEnv := append(os.Environ(), "DSSE_AUTH_RESULT_WIRE_CA="+ca.pemPath,
		"DSSE_AUTH_RESULT_WIRE_REGISTRY="+registry, "DSSE_AUTH_RESULT_WIRE_TENANT="+tenant)
	child := func(mode, cert, key, address, want string) *exec.Cmd {
		cmd := exec.Command(os.Args[0], "-test.run=^TestAuthResultWireProcessHelper$", "-test.timeout=20s")
		cmd.Env = append(append([]string(nil), baseEnv...), "DSSE_AUTH_RESULT_WIRE_HELPER="+mode,
			"DSSE_AUTH_RESULT_WIRE_CERT="+cert, "DSSE_AUTH_RESULT_WIRE_KEY="+key,
			"DSSE_AUTH_RESULT_WIRE_ADDRESS="+address, "DSSE_AUTH_RESULT_WIRE_WANT="+want)
		return cmd
	}
	startCP := func() (string, func()) {
		cmd := child("cp", cpCert, cpKey, "", "")
		input, err := cmd.StdinPipe()
		if err != nil {
			t.Fatal(err)
		}
		output, err := cmd.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		logPath := filepath.Join(dir, fmt.Sprintf("cp-%d.log", time.Now().UnixNano()))
		logFile, err := os.Create(logPath)
		if err != nil {
			t.Fatal(err)
		}
		cmd.Stderr = logFile
		if err := cmd.Start(); err != nil {
			logFile.Close()
			t.Fatal(err)
		}
		stopped := false
		t.Cleanup(func() {
			if !stopped {
				_ = cmd.Process.Kill()
				_ = cmd.Wait()
			}
			_ = logFile.Close()
		})
		ready := make(chan string, 1)
		go func() {
			line, _ := bufio.NewReader(output).ReadString('\n')
			ready <- strings.TrimSpace(line)
		}()
		var address string
		select {
		case address = <-ready:
		case <-time.After(10 * time.Second):
			t.Fatal("CP process readiness timed out")
		}
		if _, _, err := net.SplitHostPort(address); err != nil {
			t.Fatalf("CP process did not start: %q", address)
		}
		return address, func() {
			_ = input.Close()
			done := make(chan error, 1)
			go func() { done <- cmd.Wait() }()
			select {
			case err := <-done:
				stopped = true
				if err != nil {
					data, _ := os.ReadFile(logPath)
					t.Fatalf("CP process stopped with %v: %s", err, data)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("CP process did not stop")
			}
		}
	}
	runEdge := func(mode, cert, key, address, want string) {
		t.Helper()
		if output, err := child(mode, cert, key, address, want).CombinedOutput(); err != nil {
			t.Fatalf("%s process failed: %v; %s", mode, err, output)
		}
	}
	first, stopFirst := startCP()
	runEdge("edge-write", aCert, aKey, first, "")
	runEdge("edge-query", bCert, bKey, first, "resumed")
	runEdge("edge-query", endpointCert, endpointKey, first, "")
	stopFirst()
	second, stopSecond := startCP()
	runEdge("edge-query", bCert, bKey, second, "resumed")
	stopSecond()
}
