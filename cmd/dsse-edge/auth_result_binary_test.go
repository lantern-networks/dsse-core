package main

// This opt-in test exercises the current dsse-edge executable, rather than a
// Go test subprocess. It uses an empty disposable PostgreSQL database and
// loopback TLS only; no endpoint agent or external IdP is involved.

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAuthResultCurrentExecutables(t *testing.T) {
	bin, dsn := os.Getenv("DSSE_AUTH_CURRENT_BINARY"), os.Getenv("DSSE_AUTH_BINARY_DSN")
	if bin == "" || dsn == "" {
		t.Skip("requires DSSE_AUTH_CURRENT_BINARY and an empty disposable DSSE_AUTH_BINARY_DSN")
	}
	if !filepath.IsAbs(bin) {
		t.Fatal("absolute executable path required")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var tables int
	if err := db.QueryRow(`SELECT count(*) FROM information_schema.tables WHERE table_schema='public'`).Scan(&tables); err != nil || tables != 0 {
		t.Fatal("requires empty disposable database", tables, err)
	}
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	ca := makeTestCA(t, dir, "auth-binary-ca", 97)
	serverCert, serverKey := authResultWireCert(t, dir, ca, "cp", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	aCert, aKey := authResultWireCert(t, dir, ca, "edge-a", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	bCert, bKey := authResultWireCert(t, dir, ca, "edge-b", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	deviceCert, deviceKey := authResultWireCert(t, dir, ca, "device", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	devicePair, err := tls.LoadX509KeyPair(deviceCert, deviceKey)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(mustReadFile(t, ca.pemPath)) {
		t.Fatal("invalid test CA")
	}
	registry := writeRegistry(t, dir, map[string]string{"tenant": ca.pemPath})
	inventory := filepath.Join(dir, "enrolled.json")
	binaryJSON(t, inventory, map[string][]string{"enrolled_identities": {"device"}})
	authority := filepath.Join(dir, "authority.json")
	binaryJSON(t, authority, map[string][]string{"edge-a": {"tenant"}, "edge-b": {"tenant"}})
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}
	signingKey := filepath.Join(dir, "signing.seed")
	binaryWrite(t, signingKey, []byte(hex.EncodeToString(seed)))
	policyPath, bundlePath := filepath.Join(dir, "policy.json"), filepath.Join(dir, "bundle.json")
	for src, dst := range map[string]string{
		"samples/phase1/policy_lab_https_allow.json": policyPath,
		"samples/phase1/policy_bundle_standard.json": bundlePath,
	} {
		var fixture map[string]any
		if err := json.Unmarshal(mustReadFile(t, filepath.Join(root, src)), &fixture); err != nil {
			t.Fatal(err)
		}
		fixture["tenant_id"] = "tenant"
		binaryJSON(t, dst, fixture)
	}
	cp := &binaryRolloutNode{id: "cp", role: "cp", addr: binaryAddress(t), transport: binaryAddress(t), dir: filepath.Join(dir, "cp")}
	a := &binaryRolloutNode{id: "edge-a", role: "edge", addr: binaryAddress(t), transport: binaryAddress(t), dir: filepath.Join(dir, "edge-a"), cert: aCert, key: aKey}
	b := &binaryRolloutNode{id: "edge-b", role: "edge", addr: binaryAddress(t), transport: binaryAddress(t), dir: filepath.Join(dir, "edge-b"), cert: bCert, key: bKey}
	nodes := []*binaryRolloutNode{cp, a, b}
	for _, n := range nodes {
		if err := os.MkdirAll(n.dir, 0700); err != nil {
			t.Fatal(err)
		}
		n := n
		t.Cleanup(func() { n.stop(t) })
	}
	healthClient := &http.Client{Timeout: time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}}
	defer healthClient.CloseIdleConnections()
	start := func(n *binaryRolloutNode) {
		args := []string{"-lab-mode", "-operator-tenant-id", "tenant", "-transport-tenant-ca-registry", registry,
			"-transport-enrolled-inventory", inventory,
			"-listen", n.addr, "-tls-cert", serverCert, "-tls-key", serverKey,
			"-transport-tls-listen", n.transport, "-transport-tls-cert", serverCert, "-transport-tls-key", serverKey,
			"-transport-tls-client-ca", ca.pemPath, "-transport-tls-require-client-cert",
			"-policy", policyPath, "-bundle", bundlePath, "-schema-dir", filepath.Join(root, "schemas"),
			"-migration-dir", filepath.Join(root, "migrations"), "-log-dir", filepath.Join(n.dir, "logs"),
			"-admin-token", "local-binary-test", "-admin-token-break-glass-armed",
			"-agent-policy-signing-key", signingKey, "-clientless-base-url", "https://127.0.0.1:1",
			"-step-up-binding-secret", "local-binary-test-binding", "-drain-period", "100ms"}
		if n.role == "cp" {
			args = append(args, "-control-plane", "-site-store", filepath.Join(n.dir, "sites.json"),
				"-postgres-dsn", dsn, "-audit-ingest-client-ca", ca.pemPath, "-audit-ingest-authority", authority)
		} else {
			args = append(args, "-state-dir", n.dir, "-grant-store", filepath.Join(n.dir, "grants.json"),
				"-config-source-url", "https://"+cp.addr, "-config-source-ca", ca.pemPath,
				"-config-source-poll", "200ms", "-audit-ingest-url", "https://"+cp.addr+"/audit-ingest",
				"-audit-ingest-ca", ca.pemPath, "-audit-ingest-client-cert", n.cert,
				"-audit-ingest-client-key", n.key)
		}
		logFile, err := os.Create(filepath.Join(n.dir, "process.log"))
		if err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(bin, args...)
		cmd.Dir = root
		cmd.Stdout, cmd.Stderr = logFile, logFile
		cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + n.dir, "TMPDIR=" + os.TempDir()}
		if err := cmd.Start(); err != nil {
			logFile.Close()
			t.Fatal(err)
		}
		n.cmd = cmd
		n.done = make(chan error, 1)
		go func() { err := cmd.Wait(); logFile.Close(); n.done <- err }()
		ready := func() bool {
			resp, err := healthClient.Get("https://" + n.addr + "/healthz")
			if err != nil {
				return false
			}
			resp.Body.Close()
			// Edge health can be degraded while an unrelated lab catalog is
			// still converging. The result path only needs the listener ready.
			return resp.StatusCode > 0
		}
		until := time.Now().Add(40 * time.Second)
		for time.Now().Before(until) {
			if ready() {
				return
			}
			time.Sleep(200 * time.Millisecond)
		}
		data, _ := os.ReadFile(filepath.Join(n.dir, "process.log"))
		if len(data) > 4096 {
			data = data[len(data)-4096:]
		}
		t.Fatalf("%s listener timed out; log tail: %s", n.id, data)
	}
	start(cp)
	start(a)
	start(b)
	clientPair, err := tls.LoadX509KeyPair(aCert, aKey)
	if err != nil {
		t.Fatal(err)
	}
	machine := remoteAuthResultStore{url: "https://" + cp.addr + "/auth-flow-results", client: &http.Client{
		Timeout: 3 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{
			RootCAs: pool, Certificates: []tls.Certificate{clientPair}, MinVersion: tls.VersionTLS12,
		}},
	}}
	r := authResultFixture(time.Now().UTC().Truncate(time.Second))
	if err := machine.Record(r); err != nil {
		t.Fatal("actual CP result write:", err)
	}
	lastQueryStage := "not started"
	query := func(edge *binaryRolloutNode, pair tls.Certificate, session string) bool {
		lastQueryStage = "TLS dial"
		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", edge.transport,
			&tls.Config{RootCAs: pool, Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12})
		if err != nil {
			return false
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(2 * time.Second))
		lastQueryStage = "CONNECT write"
		if _, err := fmt.Fprintf(conn, "CONNECT /steer-mux HTTP/1.1\r\nHost: localhost\r\n\r\n"); err != nil {
			return false
		}
		reader := bufio.NewReader(conn)
		lastQueryStage = "CONNECT response"
		resp, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
		if err != nil {
			lastQueryStage = "CONNECT response: " + err.Error()
			return false
		}
		if resp.StatusCode != http.StatusOK {
			lastQueryStage = fmt.Sprintf("CONNECT status %d", resp.StatusCode)
			return false
		}
		payload, _ := json.Marshal(map[string]string{"request_id": r.RequestID, "os_principal": r.Principal, "os_session": session})
		frame := make([]byte, 9+len(payload))
		frame[4] = 6 // AUTH_QUERY on control flow 0
		binary.BigEndian.PutUint32(frame[5:9], uint32(len(payload)))
		copy(frame[9:], payload)
		lastQueryStage = "AUTH_QUERY write"
		if _, err := conn.Write(frame); err != nil {
			return false
		}
		var header [9]byte
		lastQueryStage = "AUTH_RESULT read"
		if _, err := io.ReadFull(reader, header[:]); err != nil {
			lastQueryStage = "AUTH_RESULT read: " + err.Error()
			return false
		}
		if binary.BigEndian.Uint32(header[:4]) != 0 || header[4] != 5 || binary.BigEndian.Uint32(header[5:]) > 256 {
			lastQueryStage = fmt.Sprintf("AUTH_RESULT header flow=%d type=%d len=%d", binary.BigEndian.Uint32(header[:4]), header[4], binary.BigEndian.Uint32(header[5:]))
			return false
		}
		answer := make([]byte, binary.BigEndian.Uint32(header[5:]))
		if _, err := io.ReadFull(reader, answer); err != nil {
			lastQueryStage = "AUTH_RESULT payload: " + err.Error()
			return false
		}
		if bytes.Contains(answer, []byte(`"result":"resumed"`)) {
			lastQueryStage = "success"
			return true
		}
		lastQueryStage = "AUTH_RESULT payload did not match"
		return false
	}
	until := time.Now().Add(8 * time.Second)
	passed := false
	for time.Now().Before(until) {
		if query(b, devicePair, r.Session) {
			passed = true
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if !passed {
		data, _ := os.ReadFile(filepath.Join(b.dir, "process.log"))
		if len(data) > 2048 {
			data = data[len(data)-2048:]
		}
		t.Fatalf("actual Edge B result requery failed at %s; Edge log tail: %s", lastQueryStage, data)
	}
	if query(a, devicePair, r.Session) == false {
		t.Fatal("actual Edge A could not read the same confirmed result")
	}
	if query(b, devicePair, strings.Repeat("b", 64)) {
		t.Fatal("different OS login session learned a confirmed result")
	}
	cp.stop(t)
	start(cp)
	binaryEventually(t, "result after CP restart", func() bool { return query(b, devicePair, r.Session) })
	// A tenant endpoint certificate must not be able to call the Edge-only CP route.
	endpointClient := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs: pool, Certificates: []tls.Certificate{devicePair}, MinVersion: tls.VersionTLS12,
	}}}
	defer endpointClient.CloseIdleConnections()
	body, _ := json.Marshal(r)
	resp, err := endpointClient.Post(machine.url, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("endpoint wrote CP result: status %d", resp.StatusCode)
	}
	t.Log("actual CP and two Edge executables preserved result across mTLS, mux requery and CP restart")
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
