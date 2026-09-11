package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/edgeplane"
)

// fakeAgent speaks the dsse-hsm-agent protocol over a unix socket, backed by a local key. It exercises the
// EDGE side of the seam; the agent's own PKCS#11 behaviour is covered against a real token in
// deploy/reference/hsm-agent.
func fakeAgent(t *testing.T, key crypto.Signer, token string, signFails bool) string {
	t.Helper()
	// Short path: sockaddr_un caps the path at ~104 bytes, and t.TempDir under a long TMPDIR overflows it.
	dir, err := os.MkdirTemp("/tmp", "dsse-agent-")
	if err != nil {
		t.Fatalf("tempdir: %v", err)
	}
	sock := filepath.Join(dir, "a.sock")
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	der, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		t.Fatalf("marshal pub: %v", err)
	}
	keyID := "testkey"

	mux := http.NewServeMux()
	mux.HandleFunc("GET /keys", func(w http.ResponseWriter, r *http.Request) {
		if token != "" && r.Header.Get("authorization") != "Bearer "+token {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": map[string]string{keyID: base64.StdEncoding.EncodeToString(der)},
		})
	})
	mux.HandleFunc("POST /sign", func(w http.ResponseWriter, r *http.Request) {
		if signFails {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		var req struct{ KeyID, Digest, Hash string }
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		digest, _ := base64.StdEncoding.DecodeString(req.Digest)
		sig, err := key.Sign(rand.Reader, digest, crypto.SHA256)
		if err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"signature": base64.StdEncoding.EncodeToString(sig)})
	})

	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return sock
}

// The payoff: the Edge mints its CA certificate with a key it does not hold, over the socket, and the result
// is a valid self-signed certificate. x509.CreateCertificate takes a crypto.Signer, so nothing in the
// interception path had to change to make this work.
func TestHSMAgentProviderMintsCACertWithRemoteKey(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	sock := fakeAgent(t, key, "tok", false)
	certPath := filepath.Join(t.TempDir(), "ca.pem")

	p, err := newHSMAgentProvider(sock, "tok", "", certPath, "Test HSM Root", time.Now)
	if err != nil {
		t.Fatalf("newHSMAgentProvider: %v", err)
	}

	if p.Certificate() == nil || !p.Certificate().IsCA {
		t.Fatal("expected a CA certificate")
	}
	// It must actually verify — a certificate that does not check out against its own key would produce leaves
	// every client rejects.
	if err := p.Certificate().CheckSignatureFrom(p.Certificate()); err != nil {
		t.Fatalf("minted CA cert does not verify against itself: %v", err)
	}
	if p.KeyCustody() != "pkcs11" {
		t.Fatalf("custody = %q, want pkcs11 — the admin surface must report hardware, not file", p.KeyCustody())
	}
	// Persisted, so a restart reuses the same CA rather than minting a second root and breaking every client
	// that trusts the first.
	if _, err := os.Stat(certPath); err != nil {
		t.Fatalf("CA cert was not persisted: %v", err)
	}
}

// A restart must adopt the certificate already on disk. Minting a fresh root every boot would silently rotate
// the trust anchor and break every endpoint that trusts the previous one.
func TestHSMAgentProviderReusesPersistedCert(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	sock := fakeAgent(t, key, "", false)
	certPath := filepath.Join(t.TempDir(), "ca.pem")

	first, err := newHSMAgentProvider(sock, "", "", certPath, "Reuse Root", time.Now)
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	second, err := newHSMAgentProvider(sock, "", "", certPath, "Reuse Root", time.Now)
	if err != nil {
		t.Fatalf("second: %v", err)
	}
	if !first.Certificate().Equal(second.Certificate()) {
		t.Fatal("a restart minted a NEW root instead of reusing the persisted one — " +
			"that would rotate the trust anchor silently and break every endpoint trusting the old CA")
	}
}

// A persisted certificate that belongs to a DIFFERENT key (a stale file, a rebuilt token) must be refused
// SYNCHRONOUSLY at load, not paired with the token key and left for the async health monitor to catch after
// readiness is already true.
func TestHSMAgentProviderRefusesACertForADifferentKey(t *testing.T) {
	tokenKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sock := fakeAgent(t, tokenKey, "", false)
	certPath := filepath.Join(t.TempDir(), "ca.pem")

	// A self-signed certificate for a stranger key, written where the provider will load it.
	strangerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, strangerPEM, err := mintSelfSignedWithSigner(strangerKey, "Stale Root", time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certPath, strangerPEM, 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := newHSMAgentProvider(sock, "", "", certPath, "Stale Root", time.Now); err == nil {
		t.Fatal("a persisted cert for a different key must be refused at load, never paired")
	} else if !strings.Contains(err.Error(), "does not match the token key") {
		t.Fatalf("the refusal must name the mismatch, got: %v", err)
	}
}

// The custody health check (interception_key_custody.go) must work through the remote signer too — that is the
// whole reason it was written against the provider interface rather than against a local key.
func TestHSMAgentProviderHealthCheckWorksRemotely(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	sock := fakeAgent(t, key, "", false)
	p, err := newHSMAgentProvider(sock, "", "", filepath.Join(t.TempDir(), "ca.pem"), "Health Root", time.Now)
	if err != nil {
		t.Fatalf("provider: %v", err)
	}

	h := edgeplane.CheckKeyCustodyHealth(p, time.Now)
	if !h.Healthy {
		t.Fatalf("expected healthy through the socket, got %q", h.Error)
	}
	if h.Custody != "pkcs11" {
		t.Fatalf("custody = %q, want pkcs11", h.Custody)
	}

	st := edgeplane.KeyCustodyStatus(edgeplane.NewKeyCustodyChecker(), p, time.Now)
	if st["non_exportable"] != true {
		t.Fatal("a token-backed key must report non_exportable=true")
	}
}

// When the agent cannot sign, the provider must FAIL rather than fall back to anything. Leaf minting then
// fails for that host, which is the fail-closed behaviour specifies — cached leaves keep working, so the
// degradation is gradual rather than a cliff.
func TestHSMAgentSignFailurePropagates(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	sock := fakeAgent(t, key, "", true) // agent returns 503 on /sign

	_, err = newHSMAgentProvider(sock, "", "", filepath.Join(t.TempDir(), "ca.pem"), "Fail Root", time.Now)
	if err == nil {
		t.Fatal("minting the CA cert must fail when the agent cannot sign — silently continuing without a " +
			"usable signing key is the failure mode this design exists to prevent")
	}
}

// An unreachable agent is reported clearly at startup rather than surfacing later as a mysterious handshake
// failure on the first uncached host.
func TestHSMAgentUnreachableIsReportedAtStartup(t *testing.T) {
	_, err := newHSMAgentProvider("/tmp/dsse-agent-does-not-exist.sock", "", "", "", "X", time.Now)
	if err == nil {
		t.Fatal("expected an error when the agent socket does not exist")
	}
}

// ★ The real end-to-end: the Edge provider against the ACTUAL dsse-hsm-agent backed by a real PKCS#11 token.
// The fake above proves the Edge side in isolation; this proves the whole chain — Edge -> unix socket -> agent
// -> SoftHSM2 -> a CA certificate signed by a key that never left the token.
//
//	(start the agent, then)
//	DSSE_HSM_AGENT_SOCKET=/tmp/dsse-hsm.sock DSSE_HSM_AGENT_TOKEN=e2e-token go test ./cmd/edge/ -run RealAgent
func TestHSMAgentRealEndToEnd(t *testing.T) {
	sock := os.Getenv("DSSE_HSM_AGENT_SOCKET")
	if sock == "" {
		t.Skip("DSSE_HSM_AGENT_SOCKET not set — start dsse-hsm-agent to run the real end-to-end")
	}
	certPath := filepath.Join(t.TempDir(), "ca.pem")
	p, err := newHSMAgentProvider(sock, os.Getenv("DSSE_HSM_AGENT_TOKEN"), "", certPath, "DSSE Interception Root (SoftHSM2)", time.Now)
	if err != nil {
		t.Fatalf("connect to the real agent: %v", err)
	}
	if err := p.Certificate().CheckSignatureFrom(p.Certificate()); err != nil {
		t.Fatalf("CA cert minted by the token does not verify: %v", err)
	}
	h := edgeplane.CheckKeyCustodyHealth(p, time.Now)
	if !h.Healthy {
		t.Fatalf("health through the real agent failed: %s", h.Error)
	}
	t.Logf("minted CA %q via a token-held key; custody=%s healthy=%v latency=%.2fms",
		p.Certificate().Subject.CommonName, h.Custody, h.Healthy, h.LatencyMS)
}
