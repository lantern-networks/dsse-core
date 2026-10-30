package main

// This opt-in integration test launches the real dsse-edge executables. The
// released executable must be built from the separately retained release source.
// It requires an EMPTY disposable PostgreSQL database; it never drops a user's DB.
// Local lab bootstrap is used, but TLS verification, individual member mTLS,
// signed configuration distribution, PostgreSQL election and mux enforcement are real.
import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
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
	"syscall"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/authrollout"
	"github.com/lantern-networks/dsse-core/grantstore"
	"github.com/lantern-networks/dsse-core/idpregistry"
)

type binaryRolloutNode struct {
	id, role, addr, transport, dir, cert, key string
	cmd                                       *exec.Cmd
	done                                      chan error
	starts                                    int
}

func binaryWrite(t *testing.T, path string, b []byte) {
	t.Helper()
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
}
func binaryJSON(t *testing.T, path string, v any) {
	t.Helper()
	b, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	binaryWrite(t, path, b)
}
func binaryAddress(t *testing.T) string {
	t.Helper()
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	a := l.Addr().String()
	l.Close()
	return a
}
func binaryEventually(t *testing.T, label string, check func() bool) {
	t.Helper()
	until := time.Now().Add(40 * time.Second)
	for time.Now().Before(until) {
		if check() {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatal("timed out:", label)
}
func (n *binaryRolloutNode) stop(t *testing.T) {
	t.Helper()
	if n.cmd == nil {
		return
	}
	_ = n.cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-n.done:
	case <-time.After(8 * time.Second):
		_ = n.cmd.Process.Kill()
		<-n.done
		t.Errorf("%s failed to stop gracefully", n.id)
	}
	n.cmd = nil
}

func TestAuthReleasedAndCurrentExecutables(t *testing.T) {
	released, current, dsn := os.Getenv("DSSE_AUTH_RELEASED_BINARY"), os.Getenv("DSSE_AUTH_CURRENT_BINARY"), os.Getenv("DSSE_AUTH_BINARY_DSN")
	if released == "" || current == "" || dsn == "" {
		t.Skip("requires two executables and empty disposable DSSE_AUTH_BINARY_DSN")
	}
	for _, p := range []string{released, current} {
		if !filepath.IsAbs(p) {
			t.Fatal("absolute executable paths required")
		}
	}
	db, e := sql.Open("postgres", dsn)
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	var tables int
	if e = db.QueryRow(`SELECT count(*) FROM information_schema.tables WHERE table_schema='public'`).Scan(&tables); e != nil || tables != 0 {
		t.Fatal("requires empty disposable database", tables, e)
	}
	root, e := filepath.Abs("../..")
	if e != nil {
		t.Fatal(e)
	}
	dir := t.TempDir()
	if out := os.Getenv("DSSE_AUTH_BINARY_OUTPUT"); out != "" {
		dir, e = os.MkdirTemp(out, "run-")
		if e != nil {
			t.Fatal(e)
		}
	}
	t.Log("private fixture directory:", dir)
	ca, caKey, caPEM := testAdmissionCA(t)
	caPath := filepath.Join(dir, "ca.pem")
	binaryWrite(t, caPath, []byte(caPEM))
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	serial := int64(10)
	issue := func(name string) (string, string, tls.Certificate, string) {
		serial++
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		leaf := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}}
		der, err := x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		pk, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		certPath, keyPath := filepath.Join(dir, name+".pem"), filepath.Join(dir, name+".key")
		binaryWrite(t, certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
		binaryWrite(t, keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: pk}))
		pair, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(der)
		return certPath, keyPath, pair, hex.EncodeToString(sum[:])
	}
	serverCert, serverKey, _, _ := issue("server")
	_, _, device, _ := issue("device")
	_, _, ungranted, _ := issue("ungranted")
	_, _, legacyDevice, _ := issue("legacy-device")
	client := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}}
	defer client.CloseIdleConnections()
	request := func(n *binaryRolloutNode, method, path string, body any) (int, []byte) {
		var b []byte
		if body != nil {
			b, _ = json.Marshal(body)
		}
		r, _ := http.NewRequest(method, "https://"+n.addr+path, bytes.NewReader(b))
		r.Header.Set("X-Admin-Token", "local-binary-test")
		r.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(r)
		if err != nil {
			return 0, nil
		}
		defer resp.Body.Close()
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		return resp.StatusCode, data
	}
	// Test-only echo destination: no public upstream or external identity provider.
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); c.SetDeadline(time.Now().Add(3 * time.Minute)); io.Copy(c, c) }()
		}
	}()
	policyPath, bundlePath := filepath.Join(dir, "policy.json"), filepath.Join(dir, "bundle.json")
	sample, err := os.ReadFile(filepath.Join(root, "samples/phase1/policy_lab_https_allow.json"))
	if err != nil {
		t.Fatal(err)
	}
	var policy map[string]any
	json.Unmarshal(sample, &policy)
	policy["tenant_id"] = "tenant"
	policy["conditions"] = map[string]any{"actor_type": "human"}
	policy["action"] = map[string]any{"decision": "require_reauthentication"}
	policy["metadata"] = map[string]any{"required_idp_id": "corp", "min_acr": "2"}
	binaryJSON(t, policyPath, policy)
	sample, err = os.ReadFile(filepath.Join(root, "samples/phase1/policy_bundle_standard.json"))
	if err != nil {
		t.Fatal(err)
	}
	var bundle map[string]any
	json.Unmarshal(sample, &bundle)
	bundle["tenant_id"] = "tenant"
	bundle["policy_ids"] = []string{policy["id"].(string)}
	binaryJSON(t, bundlePath, bundle)
	registryPath := filepath.Join(dir, "tenant-ca.json")
	binaryJSON(t, registryPath, map[string]any{"tenants": []map[string]string{{"tenant_id": "tenant", "ca_file": caPath}}})
	seed := make([]byte, 32)
	rand.Read(seed)
	signKey := filepath.Join(dir, "signing.seed")
	binaryWrite(t, signKey, []byte(hex.EncodeToString(seed)))
	census := authrollout.Manifest{Deployment: "binary-test", Generation: 1}
	nodes := make([]*binaryRolloutNode, 9)
	for i := range nodes {
		role := "edge"
		if i < 3 {
			role = "cp"
		}
		id := fmt.Sprintf("%s-%d", role, i)
		cert, key, _, pin := issue(id)
		n := &binaryRolloutNode{id: id, role: role, addr: binaryAddress(t), transport: binaryAddress(t), dir: filepath.Join(dir, id), cert: cert, key: key}
		os.MkdirAll(n.dir, 0700)
		nodes[i] = n
		census.Members = append(census.Members, authrollout.Member{ID: id, Role: role, CertificateSHA256: pin, Version: "0.3.1"})
	}
	// A loopback L4 authority entrance routes new TLS connections to the actual
	// PostgreSQL-elected leader. TLS is passed through; it is never terminated here.
	entrance, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer entrance.Close()
	go func() {
		for {
			downstream, err := entrance.Accept()
			if err != nil {
				return
			}
			go func() {
				defer downstream.Close()
				for _, cp := range nodes[:3] {
					code, b := request(cp, "GET", "/leader", nil)
					if code != 200 || !bytes.Contains(b, []byte(`"leader":true`)) {
						continue
					}
					upstream, e := net.DialTimeout("tcp", cp.addr, time.Second)
					if e != nil {
						return
					}
					defer upstream.Close()
					done := make(chan struct{})
					go func() {
						io.Copy(upstream, downstream)
						if c, ok := upstream.(*net.TCPConn); ok {
							c.CloseWrite()
						}
						close(done)
					}()
					io.Copy(downstream, upstream)
					downstream.Close()
					<-done
					return
				}
			}()
		}
	}()
	censusPath := filepath.Join(dir, "census.json")
	binaryJSON(t, censusPath, census)
	cpEndpoints := []string{}
	for _, n := range nodes[:3] {
		cpEndpoints = append(cpEndpoints, n.id+"=https://"+n.addr)
	}
	for _, n := range nodes {
		n := n
		t.Cleanup(func() { n.stop(t) })
	}
	start := func(n *binaryRolloutNode, modern bool) {
		bin := released
		if modern {
			bin = current
		}
		args := []string{"-lab-mode", "-operator-tenant-id", "tenant", "-transport-tenant-ca-registry", registryPath, "-audit-ingest-client-ca", caPath, "-listen", n.addr, "-tls-cert", serverCert, "-tls-key", serverKey, "-transport-tls-listen", n.transport, "-transport-tls-cert", serverCert, "-transport-tls-key", serverKey, "-transport-tls-client-ca", caPath, "-transport-tls-require-client-cert", "-policy", policyPath, "-bundle", bundlePath, "-schema-dir", filepath.Join(root, "schemas"), "-migration-dir", filepath.Join(root, "migrations"), "-log-dir", filepath.Join(n.dir, "logs"), "-admin-token", "local-binary-test", "-admin-token-break-glass-armed", "-agent-policy-signing-key", signKey, "-clientless-base-url", "https://127.0.0.1:1", "-step-up-binding-secret", "local-binary-test-binding", "-drain-period", "100ms"}
		if n.role == "cp" {
			args = append(args, "-control-plane", "-site-store", filepath.Join(n.dir, "sites.json"), "-postgres-dsn", dsn)
		} else {
			args = append(args, "-state-dir", n.dir, "-grant-store", filepath.Join(n.dir, "grants.json"), "-config-source-url", "https://"+nodes[0].addr, "-config-source-endpoints", strings.Join(cpEndpoints, ";"), "-config-source-home", nodes[0].id, "-config-source-strikes", "1", "-config-source-poll", "200ms", "-steer-exclusion-source-ca", caPath)
		}
		if modern {
			args = append(args, "-auth-rollout-census", censusPath, "-auth-rollout-ca", caPath, "-auth-rollout-client-cert", n.cert, "-auth-rollout-client-key", n.key, "-auth-rollout-report-url", "https://"+entrance.Addr().String()+"/fleet-capabilities/report")
		}
		label := "released"
		if modern {
			label = "current"
		}
		n.starts++
		log, err := os.Create(filepath.Join(n.dir, fmt.Sprintf("%02d-%s.log", n.starts, label)))
		if err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(bin, args...)
		cmd.Dir = root
		cmd.Stdout = log
		cmd.Stderr = log
		// Do not inherit a deployed topology or credentials from the developer shell.
		cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + n.dir, "TMPDIR=" + os.TempDir()}
		if err = cmd.Start(); err != nil {
			log.Close()
			t.Fatal(err)
		}
		n.cmd = cmd
		n.done = make(chan error, 1)
		go func() { e := cmd.Wait(); log.Close(); n.done <- e }()
		binaryEventually(t, n.id+" health ("+label+")", func() bool { status, _ := request(n, "GET", "/healthz", nil); return status == 200 })
		t.Log("started", n.id, label)
	}
	leader := func() *binaryRolloutNode {
		for _, n := range nodes[:3] {
			if n.cmd == nil {
				continue
			}
			s, b := request(n, "GET", "/leader", nil)
			if s == 200 && bytes.Contains(b, []byte(`"leader":true`)) {
				return n
			}
		}
		return nil
	}
	for _, n := range nodes[:3] {
		start(n, false)
	}
	binaryEventually(t, "released CP leader", func() bool { return leader() != nil })
	registry := idpregistry.NewStore()
	if err = registry.SetPersister(postgresBlobPersister{db, "idp_connections"}); err != nil {
		t.Fatal(err)
	}
	_, provider := rollingProcessProvider(t)
	provider, err = registry.Upsert(provider)
	if err != nil {
		t.Fatal(err)
	}
	if err = registry.SetDefault("tenant", "corp"); err != nil {
		t.Fatal(err)
	}
	grants := grantstore.NewStore()
	if err = grants.SetPersister(grantstore.RollingPersister{Backend: postgresGrantPair{db}}); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	grant, err := grants.Mint(grantstore.Grant{GrantID: "issued", TenantID: "tenant", DeviceID: "device", UserID: "user", IdPID: "corp", ACR: "2", Scope: echo.Addr().String(), AuthTime: now.Format(time.RFC3339), Issuer: provider.Issuer, ProviderConfigSHA256: authEvidenceProviderDigest(provider)}, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	legacy := grantstore.Grant{GrantID: "legacy", TenantID: "tenant", DeviceID: "legacy-device", UserID: "user", IdPID: "corp", ACR: "2", Scope: echo.Addr().String(), IssuedAt: now.Format(time.RFC3339), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339)}
	if code, _ := request(leader(), "POST", "/grant-report", map[string]any{"grants": []grantstore.Grant{legacy}}); code != 200 {
		t.Fatalf("released grant writer returned %d", code)
	}
	// The released process rewrites the map containing the modern-issued grant.
	binaryEventually(t, "released writer preserved modern authority evidence", func() bool {
		g, ok := grants.Get(grant.GrantID)
		return ok && !g.Revoked && g.AuthTime == grant.AuthTime
	})
	for _, n := range nodes[3:] {
		start(n, false)
	}
	exchange := func(n *binaryRolloutNode, cert tls.Certificate) int {
		c, err := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", n.transport, &tls.Config{RootCAs: pool, Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
		if err != nil {
			return 0
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(2 * time.Second))
		fmt.Fprintf(c, "CONNECT /steer-mux HTTP/1.1\r\nHost: localhost\r\n\r\n")
		r := bufio.NewReader(c)
		resp, err := http.ReadResponse(r, &http.Request{Method: "CONNECT"})
		if err != nil || resp.StatusCode != 200 {
			return 0
		}
		frame := func(kind byte, data []byte) {
			h := make([]byte, 9)
			binary.BigEndian.PutUint32(h, 1)
			h[4] = kind
			binary.BigEndian.PutUint32(h[5:], uint32(len(data)))
			c.Write(append(h, data...))
		}
		frame(0, []byte(echo.Addr().String()+"\x00u=user a=test"))
		frame(1, []byte("proof"))
		for {
			h := make([]byte, 9)
			if _, err = io.ReadFull(r, h); err != nil {
				return 0
			}
			size := binary.BigEndian.Uint32(h[5:])
			if size > 1<<20 {
				return 0
			}
			b := make([]byte, size)
			if _, err = io.ReadFull(r, b); err != nil {
				return 0
			}
			if h[4] == 1 {
				if string(b) == "proof" {
					return 1
				}
				return 0
			}
			if h[4] == 3 {
				return 2
			} // authentication required, not a transport error
			if h[4] == 2 {
				return 0
			}
		}
	}
	probe := func(n *binaryRolloutNode, cert tls.Certificate) bool { return exchange(n, cert) == 1 }

	for _, n := range nodes[3:] {
		binaryEventually(t, n.id+" released authenticated mux", func() bool { return probe(n, device) })
		if exchange(n, ungranted) != 2 {
			t.Fatal("ungranted device did not receive authentication challenge")
		}
	}
	for _, n := range nodes[3:] {
		if !probe(n, legacyDevice) {
			t.Fatal("released legacy grant rejected", n.id)
		}
	}
	t.Log("released fleet authenticated mux and negative control passed")
	heldOwner := nodes[len(nodes)-1]
	held, err := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", heldOwner.transport, &tls.Config{RootCAs: pool, Certificates: []tls.Certificate{device}, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	held.SetDeadline(time.Now().Add(3 * time.Second))
	fmt.Fprintf(held, "CONNECT /steer-mux HTTP/1.1\r\nHost: localhost\r\n\r\n")
	heldReader := bufio.NewReader(held)
	heldResponse, err := http.ReadResponse(heldReader, &http.Request{Method: "CONNECT"})
	if err != nil || heldResponse.StatusCode != 200 {
		t.Fatal("held mux handshake failed")
	}
	binaryMuxWrite(t, held, 0, []byte(echo.Addr().String()+"\x00u=user a=test"))
	heldPing := func() {
		t.Helper()
		held.SetDeadline(time.Now().Add(3 * time.Second))
		binaryMuxWrite(t, held, 1, []byte("held-proof"))
		header := make([]byte, 9)
		if _, e := io.ReadFull(heldReader, header); e != nil {
			t.Fatal("held stream lost", e)
		}
		if header[4] != 1 || binary.BigEndian.Uint32(header[5:]) != 10 {
			t.Fatal("held stream did not forward data")
		}
		body := make([]byte, 10)
		if _, e := io.ReadFull(heldReader, body); e != nil || string(body) != "held-proof" {
			t.Fatal("held stream echo mismatch")
		}
	}
	heldPing()
	// Upgrade the leader first, forcing a real advisory-lock transfer to a released CP.
	for i := 0; i < 3; i++ {
		n := leader()
		if n == nil {
			t.Fatal("no CP leader")
		}
		n.stop(t)
		binaryEventually(t, "CP election", func() bool { return leader() != nil })
		start(n, true)
		t.Log("CP upgraded; current leader", leader().id)
		heldPing()
		for _, edge := range nodes[3:] {
			if !probe(edge, device) {
				t.Fatalf("CP promotion interrupted authenticated access on %s", edge.id)
			}
		}
	}
	// Ensure each node was replaced once, even if election order chose an upgraded node.
	for _, n := range nodes[:3] {
		if n.cmd.Path == released {
			n.stop(t)
			start(n, true)
		}
	}
	binaryEventually(t, "census creation", func() bool {
		var s authrollout.State
		b, _ := (postgresBlobPersister{db, "auth_rollout_v1"}).Load()
		return json.Unmarshal(b, &s) == nil && s.Schema != 0
	})
	for index, n := range nodes[3:] {
		if n == heldOwner {
			heldPing()
			held.Close()
		}
		n.stop(t)
		start(n, true)
		binaryEventually(t, n.id+" upgraded authenticated mux", func() bool { return probe(n, device) })
		if index < len(nodes[3:])-1 {
			heldPing()
			binaryEventually(t, n.id+" mixed legacy grant", func() bool { return probe(n, legacyDevice) })
		}
		for _, other := range nodes[3:] {
			if other != n && !probe(other, device) {
				t.Fatalf("surviving Edge %s lost authentication", other.id)
			}
		}
	}
	binaryEventually(t, "all nine real processes reported completion", func() bool {
		var s authrollout.State
		b, _ := (postgresBlobPersister{db, "auth_rollout_v1"}).Load()
		return json.Unmarshal(b, &s) == nil && s.Complete
	})
	for _, n := range nodes[3:] {
		if !probe(n, device) {
			t.Fatal("completed fleet lost grant", n.id)
		}
		if exchange(n, ungranted) != 2 {
			t.Fatal("completed fleet did not issue authentication challenge")
		}
	}
	for _, n := range nodes[3:] {
		binaryEventually(t, n.id+" rejects legacy after completion", func() bool { return exchange(n, legacyDevice) == 2 })
	}
	promotedFrom := leader()
	promotedFrom.stop(t)
	binaryEventually(t, "completed CP leader transfer", func() bool { return leader() != nil })
	for _, n := range nodes[3:] {
		if !probe(n, device) {
			t.Fatal("completed CP transfer lost evidence", n.id)
		}
	}
	start(promotedFrom, true)
	restarted := nodes[3]
	restarted.stop(t)
	start(restarted, true)
	if !probe(restarted, device) || exchange(restarted, legacyDevice) != 2 {
		t.Fatal("restart lost completion or evidence")
	}
	if _, _, err = grants.RevokeForTenant("tenant", "issued"); err != nil {
		t.Fatal(err)
	}
	for _, n := range nodes[3:] {
		binaryEventually(t, n.id+" revocation", func() bool { return exchange(n, device) == 2 })
	}
	t.Log("real executable rollout, CP promotion, authenticated mux and revocation passed")
}

func binaryMuxWrite(t *testing.T, conn net.Conn, kind byte, payload []byte) {
	t.Helper()
	header := make([]byte, 9)
	binary.BigEndian.PutUint32(header, 1)
	header[4] = kind
	binary.BigEndian.PutUint32(header[5:], uint32(len(payload)))
	if _, err := io.Copy(conn, bytes.NewReader(append(header, payload...))); err != nil {
		t.Fatal("mux frame write failed", err)
	}
}
