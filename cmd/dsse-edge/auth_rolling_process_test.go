package main

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/authrollout"
	"github.com/lantern-networks/dsse-core/edgeplane"
	"github.com/lantern-networks/dsse-core/grantstore"
	old "github.com/lantern-networks/dsse-core/grantstore/testdata/releasedv031"
	"github.com/lantern-networks/dsse-core/idpregistry"
)

// This subprocess harness exercises the production grant predicates, shared SQL
// persistence and native mux transport. It is NOT a packaged-binary, installer,
// TLS admission, OS-agent or full CP-election acceptance test. The old predicate
// and store are frozen released code; the transport harness is current code.
func TestAuthRollingProcessHelper(t *testing.T) {
	mode := os.Getenv("DSSE_AUTH_PROCESS_HELPER")
	if mode == "" {
		t.Skip("subprocess helper")
	}
	db, err := sql.Open("postgres", os.Getenv("DSSE_ROLLING_TEST_DSN"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	registry, provider := rollingProcessProvider(t)
	legacy := old.NewStore()
	modern := grantstore.NewStore()
	if err = legacy.SetPersister(postgresBlobPersister{db, "grants"}); err != nil {
		t.Fatal(err)
	}
	if err = modern.SetPersister(grantstore.RollingPersister{Backend: postgresGrantPair{db}}); err != nil {
		t.Fatal(err)
	}
	authority := authrollout.NewStore(postgresBlobPersister{db, "auth_rollout_v1"})
	state, err := authority.Read()
	if err != nil {
		t.Fatal(err)
	}
	id := os.Getenv("DSSE_AUTH_PROCESS_ID")
	var member *authrollout.Member
	for i := range state.Manifest.Members {
		if state.Manifest.Members[i].ID == id {
			member = &state.Manifest.Members[i]
		}
	}
	if member == nil {
		t.Fatal("missing process census")
	}
	gate := &federatedAuthGate{registry: registry, grants: modern, tenantID: provider.TenantID,
		rollout: &authRolloutRuntime{authority: authority, expected: member, deployment: state.Manifest.Deployment}}
	var draining atomic.Bool
	gate.draining = &draining
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	var streams sync.WaitGroup
	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			streams.Add(1)
			go func() {
				defer streams.Done()
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(45 * time.Second))
				edgeplane.NewSteerMux(c).Run(func(_ uint32, device string, flow *edgeplane.MuxVirtualConn) {
					defer flow.Close()
					accepted := old.GateAccepts(legacy, "tenant", device, "2")
					if mode == "new" {
						accepted = gate.hasLiveGrantWithRequirements("tenant", device, federatedRequirements{IdP: "corp", ACR: "2", Scope: "app:22"})
					}
					if !accepted {
						return
					}
					_, _ = io.Copy(flow, flow)
				})
			}()
		}
	}()
	fmt.Println(ln.Addr().String())
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		if scanner.Text() == "drain" {
			draining.Store(true)
			_ = ln.Close()
			<-acceptDone
			fmt.Println("drained")
		}
	}
	_ = ln.Close()
	<-acceptDone
	streams.Wait()
}

func rollingProcessProvider(t *testing.T) (*idpregistry.Store, idpregistry.Connection) {
	t.Helper()
	r := idpregistry.NewStore()
	p, err := r.Upsert(idpregistry.Connection{IdPID: "corp", TenantID: "tenant", Type: "oidc", Issuer: "https://idp.example", AuthorizationEndpoint: "https://idp.example/auth", TokenEndpoint: "https://idp.example/token", JWKSURI: "https://idp.example/keys", ClientID: "client"})
	if err != nil {
		t.Fatal(err)
	}
	return r, p
}

type rollingChild struct {
	cmd     *exec.Cmd
	input   io.WriteCloser
	lines   *bufio.Scanner
	address string
	stopped bool
}

func startRollingChild(t *testing.T, mode, id string) *rollingChild {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestAuthRollingProcessHelper$", "-test.timeout=60s")
	cmd.Env = append(os.Environ(), "DSSE_AUTH_PROCESS_HELPER="+mode, "DSSE_AUTH_PROCESS_ID="+id)
	input, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	output, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	log, err := os.Create(filepath.Join(t.TempDir(), "child.log"))
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = log
	if err = cmd.Start(); err != nil {
		log.Close()
		t.Fatal(err)
	}
	child := &rollingChild{cmd: cmd, input: input, lines: bufio.NewScanner(output)}
	t.Cleanup(func() {
		if !child.stopped {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
		_ = log.Close()
	})
	ready := make(chan bool, 1)
	go func() { ready <- child.lines.Scan() }()
	select {
	case ok := <-ready:
		if !ok {
			t.Fatal("child did not start")
		}
	case <-time.After(15 * time.Second):
		t.Fatal("child start timeout")
	}
	child.address = child.lines.Text()
	if _, _, err = net.SplitHostPort(child.address); err != nil {
		t.Fatal("child startup failed")
	}
	return child
}
func (c *rollingChild) stop(t *testing.T) {
	t.Helper()
	_ = c.input.Close()
	done := make(chan error, 1)
	go func() { done <- c.cmd.Wait() }()
	select {
	case err := <-done:
		c.stopped = true
		if err != nil {
			t.Fatal("child stop:", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("child did not finish drain")
	}
}
func rollingNative(t *testing.T, c *rollingChild, device string) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", c.address, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	if err = authTestFrame(conn, 1, 0, []byte(device)); err != nil {
		conn.Close()
		t.Fatal(err)
	}
	return conn
}
func rollingEcho(t *testing.T, c net.Conn, allow bool) {
	t.Helper()
	if err := authTestFrame(c, 1, 1, []byte("native")); err != nil {
		t.Fatal(err)
	}
	h := make([]byte, 9)
	if _, err := io.ReadFull(c, h); err != nil {
		t.Fatal(err)
	}
	n := binary.BigEndian.Uint32(h[5:])
	if n > 1024 {
		t.Fatal("invalid frame")
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(c, b); err != nil {
		t.Fatal(err)
	}
	if allow && (h[4] != 1 || string(b) != "native") {
		t.Fatal("issued authorization did not carry native data")
	}
	if !allow && h[4] != 2 {
		t.Fatal("revoked/unsupported grant carried native data")
	}
}

func TestPostgresAuthRollingNativeProcesses(t *testing.T) {
	dsn := os.Getenv("DSSE_ROLLING_TEST_DSN")
	if dsn == "" {
		t.Skip("dedicated disposable database not set")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err = db.Exec(`CREATE TABLE cp_state_blobs (store_key TEXT PRIMARY KEY,payload BYTEA NOT NULL,updated_at TIMESTAMPTZ NOT NULL DEFAULT now())`); err != nil {
		t.Fatal("requires fresh disposable database:", err)
	}
	defer db.Exec(`DROP TABLE cp_state_blobs`)
	_, provider := rollingProcessProvider(t)
	_, m := rolloutFixture(t)
	m.Members = m.Members[:1]
	for i := 0; i < 3; i++ {
		m.Members = append(m.Members, authrollout.Member{ID: fmt.Sprint("edge", i), Role: "edge", Version: "0.3.1", CertificateSHA256: fmt.Sprintf("%064x", i+2)})
	}
	m.Providers = map[string]string{authrollout.ProviderKey("tenant", "corp"): authEvidenceProviderDigest(provider)}
	authority := authrollout.NewStore(postgresBlobPersister{db, "auth_rollout_v1"})
	if err = authority.Configure(context.Background(), 0, m); err != nil {
		t.Fatal(err)
	}
	modern := grantstore.NewStore()
	if err = modern.SetPersister(grantstore.RollingPersister{Backend: postgresGrantPair{db}}); err != nil {
		t.Fatal(err)
	}
	released := old.NewStore()
	if err = released.SetPersister(postgresBlobPersister{db, "grants"}); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	if _, err = released.Mint(old.Grant{GrantID: "legacy", TenantID: "tenant", DeviceID: "legacy-device", UserID: "user", IdPID: "corp", ACR: "2", Scope: "app:22"}, time.Hour, now); err != nil {
		t.Fatal(err)
	}
	base := grantstore.Grant{AuthTime: now.Format(time.RFC3339), GrantID: "evidence", TenantID: "tenant", DeviceID: "evidence-device", UserID: "user", IdPID: "corp", ACR: "2", Scope: "app:22", Issuer: provider.Issuer, ProviderConfigSHA256: authEvidenceProviderDigest(provider)}
	if _, err = modern.Mint(base, time.Hour, now); err != nil {
		t.Fatal(err)
	}
	// A released writer rewrites the whole map AFTER modern auth_time issuance.
	if _, err = released.Mint(old.Grant{GrantID: "unrelated", TenantID: "other"}, time.Hour, now); err != nil {
		t.Fatal(err)
	}
	children := make([]*rollingChild, 3)
	for i := range children {
		children[i] = startRollingChild(t, "old", m.Members[i+1].ID)
	}
	probe := func(c *rollingChild, device string, allow bool) {
		t.Helper()
		conn := rollingNative(t, c, device)
		defer conn.Close()
		rollingEcho(t, conn, allow)
	}
	for i := range children {
		current := children[i]
		held := rollingNative(t, current, "evidence-device")
		rollingEcho(t, held, true)
		fmt.Fprintln(current.input, "drain")
		if !current.lines.Scan() || current.lines.Text() != "drained" {
			t.Fatal("drain not acknowledged")
		}
		// The existing authenticated native socket survives draining. New flows use
		// the other two processes, including legacy grants throughout the mixed phase.
		rollingEcho(t, held, true)
		for j, c := range children {
			if j != i {
				probe(c, "evidence-device", true)
				probe(c, "legacy-device", true)
			}
		}
		held.Close()
		current.stop(t)
		children[i] = startRollingChild(t, "new", m.Members[i+1].ID)
		probe(children[i], "evidence-device", true)
		probe(children[i], "legacy-device", true)
	}
	runtime := &authRolloutRuntime{authority: authority}
	completeRollout(t, runtime, m)
	for _, c := range children {
		probe(c, "evidence-device", true)
		probe(c, "legacy-device", false)
	}
	if _, _, err = released.RevokeForTenant("tenant", "evidence"); err != nil {
		t.Fatal(err)
	}
	// Authorization reads use the existing five-second shared-store cache.
	// Verify within that documented propagation bound, not instantaneous revocation.
	time.Sleep(5100 * time.Millisecond)
	for _, c := range children {
		probe(c, "evidence-device", false)
		c.stop(t)
	}
	// No authorization state was reconstructed from child memory on restart.
	raw, err := postgresBlobPersister{db, "grants"}.Load()
	if err != nil {
		t.Fatal(err)
	}
	var rows map[string]old.Grant
	if json.Unmarshal(raw, &rows) != nil || !rows["evidence"].Revoked {
		t.Fatal("release-compatible revocation missing")
	}
}
