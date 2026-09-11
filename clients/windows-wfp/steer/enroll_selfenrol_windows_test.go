//go:build windows

package main

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"crypto/rand"

	"github.com/lantern-networks/dsse-core/enroll"
)

// Day-0 self-enrolment, end to end against a fake Edge: an enrol endpoint that signs the CSR, and a (T)
// transport listener the issued identity is proven against BEFORE anything is committed. Windows-only because
// the store path DPAPI-wraps the key in the current security context (so this runs on the box, not Linux CI).
// The testCA / leafUnder / startTransportListener helpers are shared with trust_anchor_recovery_test.go.

// startEnrolServer signs incoming CSRs under the given CA — the shape POST /enroll answers with.
func startEnrolServer(t *testing.T, ca testCA) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req enroll.Request
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		block, _ := pem.Decode([]byte(req.CSRPEM))
		csr, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(time.Now().UnixNano()),
			Subject:      pkix.Name{CommonName: req.DeviceID},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(24 * time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, csr.PublicKey, ca.key)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		_ = json.NewEncoder(w).Encode(enroll.Response{
			CertPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
			CAPEM:   string(ca.pem),
			Tenant:  "tenant-test", Group: "grp",
		})
	}))
	t.Cleanup(srv.Close)
	return srv
}

// startMTLSTransport is a minimal (T) listener: presents serverLeaf, requires a client certificate chaining to
// clientCA, and answers one request — what probeIdentity needs to call the identity proven on the wire.
func startMTLSTransport(t *testing.T, serverLeaf tls.Certificate, clientCA *x509.Certificate) net.Listener {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AddCert(clientCA)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{serverLeaf},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				buf := make([]byte, 256)
				if _, err := c.Read(buf); err != nil {
					return
				}
				_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))
			}(conn)
		}
	}()
	return ln
}

func writeEnrolmentConfig(t *testing.T, dir string, cfg enrolmentConfig) string {
	t.Helper()
	raw, _ := json.Marshal(cfg)
	path := filepath.Join(dir, "enrolment.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// The reference lab has THREE distinct CAs and the fake models them faithfully: the enrol endpoint issues
// under the DEVICE CA, the transport SERVER cert chains to a SEPARATE transport CA, and the transport accepts
// client certs under the device CA. The probe must verify the server with the transport CA — verifying it with
// the enroll-returned device CA (the bug this fixture would catch) fails on any Edge where the two differ.
func TestSelfEnrolmentProvesThenCommitsAndSpendsToken(t *testing.T) {
	deviceCA := newTestCA(t, "Device CA")       // enrol endpoint issues under this; transport accepts clients under it
	transportCA := newTestCA(t, "Transport CA") // signs the transport SERVER leaf
	transport := startMTLSTransport(t, leafUnder(t, transportCA), deviceCA.cert)
	enrolSrv := startEnrolServer(t, deviceCA)

	sum := sha256.Sum256(deviceCA.cert.Raw)
	dir := t.TempDir()
	cfgPath := writeEnrolmentConfig(t, dir, enrolmentConfig{
		EnrolURL:          enrolSrv.URL,
		DeviceID:          "win-e2e-1",
		Token:             "one-time-secret",
		DeviceCAPinSHA256: hex.EncodeToString(sum[:]),
		EnrolCAPEM:        string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: enrolSrv.Certificate().Raw})),
	})

	cfg, _, _ := loadEnrolmentConfig(cfgPath)
	// Probe verifies the SERVER with the transport CA, not the enroll-returned device CA.
	if err := performSelfEnrolment(cfg, cfgPath, "https://"+transport.Addr().String(), "", transportCA.pem, dir); err != nil {
		t.Fatalf("self-enrolment failed: %v", err)
	}
	// Committed: the completion marker exists and the material loads back (DPAPI round-trip included).
	m, ok, err := loadEnrollment(dir)
	if err != nil || !ok {
		t.Fatalf("enrolled material after success: ok=%v err=%v", ok, err)
	}
	if m.Meta.DeviceID != "win-e2e-1" || m.Meta.Tenant != "tenant-test" {
		t.Fatalf("meta = %+v", m.Meta)
	}
	// The token was erased and the spending recorded.
	c, _, _ := loadEnrolmentConfig(cfgPath)
	if c.hasUnspentToken() || !c.TokenSpent {
		t.Fatalf("token not spent after success: %+v", c)
	}
}

// The identity is proven BEFORE commit: an Edge that ISSUES a certificate but REFUSES it at the transport must
// leave the machine exactly as it was — never-enrolled, no completion marker. Committing here would make the
// machine count as previously enrolled on the next start and take over the network path holding a credential
// that does not work.
func TestSelfEnrolmentRefusedIdentityCommitsNothing(t *testing.T) {
	deviceCA := newTestCA(t, "Device CA")       // what the enrol endpoint issues under
	transportCA := newTestCA(t, "Transport CA") // signs the transport server leaf (probe verifies the server here)
	otherCA := newTestCA(t, "Other CA")         // what the transport actually requires of clients
	// The server verifies fine (transportCA), but the transport requires a client cert under otherCA — so the
	// freshly issued identity (under deviceCA) is rejected at the mTLS handshake, and the probe fails.
	transport := startMTLSTransport(t, leafUnder(t, transportCA), otherCA.cert)
	enrolSrv := startEnrolServer(t, deviceCA)

	sum := sha256.Sum256(deviceCA.cert.Raw)
	dir := t.TempDir()
	cfgPath := writeEnrolmentConfig(t, dir, enrolmentConfig{
		EnrolURL:          enrolSrv.URL,
		DeviceID:          "win-e2e-2",
		Token:             "one-time-secret",
		DeviceCAPinSHA256: hex.EncodeToString(sum[:]),
		EnrolCAPEM:        string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: enrolSrv.Certificate().Raw})),
	})

	cfg, _, _ := loadEnrolmentConfig(cfgPath)
	if err := performSelfEnrolment(cfg, cfgPath, "https://"+transport.Addr().String(), "", transportCA.pem, dir); err == nil {
		t.Fatal("self-enrolment reported success though the identity was refused at the transport")
	}
	// Nothing committed: no completion marker, so the machine is still never-enrolled.
	if _, ok, _ := loadEnrollment(dir); ok {
		t.Fatal("a refused identity left a completion marker — the machine would count as previously enrolled")
	}
	// The token is NOT spent: a failed enrolment must be retryable on the next start.
	c, _, _ := loadEnrolmentConfig(cfgPath)
	if !c.hasUnspentToken() {
		t.Fatal("a failed enrolment spent the token; the next start could not retry")
	}
}

// A wrong device-CA pin is caught by the cryptographic validation inside enroll.Run, BEFORE the probe — the
// same case macOS verified live. Nothing is committed and the token stays unspent.
func TestSelfEnrolmentWrongDeviceCAPinCommitsNothing(t *testing.T) {
	deviceCA := newTestCA(t, "Device CA")
	transportCA := newTestCA(t, "Transport CA")
	transport := startMTLSTransport(t, leafUnder(t, transportCA), deviceCA.cert)
	enrolSrv := startEnrolServer(t, deviceCA)

	wrong := sha256.Sum256(transportCA.cert.Raw) // NOT the device CA the endpoint returns
	dir := t.TempDir()
	cfgPath := writeEnrolmentConfig(t, dir, enrolmentConfig{
		EnrolURL:          enrolSrv.URL,
		DeviceID:          "win-e2e-3",
		Token:             "one-time-secret",
		DeviceCAPinSHA256: hex.EncodeToString(wrong[:]),
		EnrolCAPEM:        string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: enrolSrv.Certificate().Raw})),
	})

	cfg, _, _ := loadEnrolmentConfig(cfgPath)
	if err := performSelfEnrolment(cfg, cfgPath, "https://"+transport.Addr().String(), "", transportCA.pem, dir); err == nil {
		t.Fatal("a wrong device-CA pin was accepted")
	}
	if _, ok, _ := loadEnrollment(dir); ok {
		t.Fatal("a pin-mismatched identity left a completion marker")
	}
	c, _, _ := loadEnrolmentConfig(cfgPath)
	if !c.hasUnspentToken() {
		t.Fatal("a pin failure spent the token")
	}
}

// With no transport CA to prove against, the probe is skipped and the machine commits on the cryptographic
// validation alone — mirroring macOS when there is no transport contract. A deployment without a (T) transport
// must still be able to enrol.
func TestSelfEnrolmentNoTransportCACommitsOnValidation(t *testing.T) {
	deviceCA := newTestCA(t, "Device CA")
	enrolSrv := startEnrolServer(t, deviceCA)

	sum := sha256.Sum256(deviceCA.cert.Raw)
	dir := t.TempDir()
	cfgPath := writeEnrolmentConfig(t, dir, enrolmentConfig{
		EnrolURL:          enrolSrv.URL,
		DeviceID:          "win-e2e-4",
		Token:             "one-time-secret",
		DeviceCAPinSHA256: hex.EncodeToString(sum[:]),
		EnrolCAPEM:        string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: enrolSrv.Certificate().Raw})),
	})

	cfg, _, _ := loadEnrolmentConfig(cfgPath)
	// No transport CA and no URL -> probe skipped.
	if err := performSelfEnrolment(cfg, cfgPath, "", "", nil, dir); err != nil {
		t.Fatalf("self-enrolment failed with no transport to probe: %v", err)
	}
	if _, ok, _ := loadEnrollment(dir); !ok {
		t.Fatal("nothing committed though the identity validated cryptographically")
	}
}

// An unpinned bootstrap is refused before any network call — enrolment is the trust bootstrap and must not run
// over a channel it cannot pin.
func TestSelfEnrolmentRefusesUnpinnedBootstrap(t *testing.T) {
	dir := t.TempDir()
	cfgPath := writeEnrolmentConfig(t, dir, enrolmentConfig{
		EnrolURL: "https://edge:8443/enroll", DeviceID: "d", Token: "s",
	})
	cfg, _, _ := loadEnrolmentConfig(cfgPath)
	if err := performSelfEnrolment(cfg, cfgPath, "https://edge:18543", "", nil, dir); err == nil {
		t.Fatal("enrolled over an unpinned bootstrap")
	}
}
