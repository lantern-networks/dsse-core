package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
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

// ★★★ THE READER IS THE PART THAT GOT THIS WRONG. Measured 2026-08-26: this check reported "this deployment
// tells devices to expect NOTHING" against a deployment that was announcing its root correctly, because the
// signed envelope carries its document in payload_b64 and the reader looked for payload. A verification that
// misreads the answer manufactures the very finding it exists to catch — and this one's finding is "every
// site on the machine fails at once", which is not a thing to report by accident.
//
// So the two envelope shapes are pinned here, against a server that answers the way the Edge answers.
func TestTheAnnouncedRootsAreReadFromTheShapeTheEdgeSends(t *testing.T) {
	roots := []string{"8adf67419bc36408aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	document, _ := json.Marshal(map[string]any{"interception_root_sha256": roots, "version": 1})

	cases := []struct {
		name string
		body map[string]any
	}{
		{"signed, payload_b64", map[string]any{
			"type": "agent_policy", "version": 1, "signing_key_id": "k1",
			"payload_b64": base64.StdEncoding.EncodeToString(document),
			"signature":   "…", "payload_sha256": "…",
		}},
		{"unsigned, the document itself", map[string]any{
			"interception_root_sha256": roots, "version": 1,
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir, cert, key, door, stop := aDeploymentServing(t, tc.body)
			defer stop()
			got, err := announcedInterceptionRoots(dir, door, cert, key)
			if err != nil {
				t.Fatalf("%v", err)
			}
			if len(got) != 1 || !strings.EqualFold(got[0], roots[0]) {
				t.Fatalf("got %v", got)
			}
		})
	}
}

// ★ AND AN UNREADABLE ANSWER IS NOT AN EMPTY ONE. Reporting "announces nothing" for a document this walk
// could not parse is the same confusion between silence and absence that the check is about.
func TestAPolicyWithNoSuchFieldIsSaidToBeUnreadableRatherThanEmpty(t *testing.T) {
	dir, cert, key, door, stop := aDeploymentServing(t, map[string]any{"version": 1, "steer_exclusions": []string{}})
	defer stop()
	_, err := announcedInterceptionRoots(dir, door, cert, key)
	if err == nil {
		t.Fatal("a policy with no interception_root_sha256 was reported as an empty announcement")
	}
	// It names what WAS there, so the next person does not have to guess whether the field moved.
	if !strings.Contains(err.Error(), "steer_exclusions") {
		t.Fatalf("the failure does not say what the policy did carry: %v", err)
	}
}

// aDeploymentServing stands up a directory holding a deployment anchor and an interception root, plus a TLS
// server that answers /steer/agent-policy with body. Returns the client material and the door.
func aDeploymentServing(t *testing.T, body map[string]any) (dir string, certPEM, keyPEM []byte, door string, stop func()) {
	t.Helper()
	dir = t.TempDir()
	now := time.Now()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test deployment root"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		IsCA: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, _ := x509.ParseCertificate(caDER)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	if err := os.WriteFile(filepath.Join(dir, "deployment-anchor.pem"), caPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	// The interception root the fingerprint is taken from — the same file dsse-install writes.
	if err := os.WriteFile(filepath.Join(dir, interceptionRootCertFile), caPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	issue := func(cn string, dns ...string) ([]byte, []byte) {
		k, kerr := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if kerr != nil {
			t.Fatal(kerr)
		}
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(now.UnixNano()), Subject: pkix.Name{CommonName: cn},
			NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
			KeyUsage:    x509.KeyUsageDigitalSignature,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
			DNSNames:    dns,
		}
		der, cerr := x509.CreateCertificate(rand.Reader, tmpl, caCert, &k.PublicKey, caKey)
		if cerr != nil {
			t.Fatal(cerr)
		}
		kder, _ := x509.MarshalECPrivateKey(k)
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
			pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder})
	}
	certPEM, keyPEM = issue("a-device")
	srvCert, srvKey := issue("edge.localhost", "edge.localhost")
	pair, err := tls.X509KeyPair(srvCert, srvKey)
	if err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/steer/agent-policy", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(body)
	})
	srv := httptest.NewUnstartedServer(mux)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{pair}}
	srv.StartTLS()
	return dir, certPEM, keyPEM, strings.Replace(srv.URL, "127.0.0.1", "edge.localhost", 1), srv.Close
}

// The fingerprint compared against is the one an agent computes: sha256 over the DER.
func TestTheFingerprintIsTheOneAnAgentComputes(t *testing.T) {
	dir, _, _, _, stop := aDeploymentServing(t, map[string]any{})
	defer stop()
	got, err := interceptionAuthorityFingerprint(dir)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, interceptionRootCertFile))
	block, _ := pem.Decode(raw)
	sum := sha256.Sum256(block.Bytes)
	if got != hex.EncodeToString(sum[:]) {
		t.Fatalf("got %q", got)
	}
}
