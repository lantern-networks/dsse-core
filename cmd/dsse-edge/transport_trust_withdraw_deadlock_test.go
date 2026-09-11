package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	enrolledinventory "github.com/lantern-networks/dsse-core/enrolledinventory"
)

// mintTestServerLeaf issues a SERVER leaf (the transport listener's kind) — verifiesCurrentChain checks the
// default (serverAuth) usage, which the clientAuth leaves the other tests mint do not satisfy.
func mintTestServerLeaf(t *testing.T, cn string, ca *x509.Certificate, caKey *ecdsa.PrivateKey) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// Reproduces the 2026-08-02 freeze: the FIRST withdrawal ever to pass the pre-check deadlocked the Edge's
// whole trust surface, because WithdrawIf holds the store mutex while re-judging the gate, and the gate read
// the distribution serial back through the same store (goroutine dump: WithdrawIf → anchorWithdrawGate →
// anchorCoverage → Current → the held mutex). Every earlier DELETE had been refused before reaching
// WithdrawIf, so the in-lock path had never actually run.
//
// The test drives the REAL handler against the REAL store with a gate arranged to PASS, and fails on a
// watchdog rather than hanging the suite if the deadlock ever returns.
func TestTransportAnchorWithdrawDoesNotDeadlockWhenTheGatePasses(t *testing.T) {
	legacyCA, legacyPEM, _ := mintTestCA(t, "Legacy Transport CA")
	newCA, newPEM, newKey := mintTestCA(t, "Current Transport CA")
	leafPEM := mintTestServerLeaf(t, "edge-transport", newCA, newKey)

	dir := t.TempDir()
	store, err := openTransportTrustStore(filepath.Join(dir, "transport_trust.json"),
		legacyPEM+newPEM, 3, func(string, int64) (func(), error) { return func() {}, nil })
	if err != nil {
		t.Fatal(err)
	}
	prevTrust := transportTrust
	transportTrust = store
	defer func() { transportTrust = prevTrust }()
	// The served chain must verify from the REMAINING certificate for the gate to pass — read from the
	// config file, so the hot-reload registry (which another test may have populated) is held empty.
	prevServed := transportServedCert
	transportServedCert = nil
	defer func() { transportServedCert = prevServed }()
	served := filepath.Join(dir, "transport.pem")
	if err := os.WriteFile(served, []byte(leafPEM+newPEM), 0o600); err != nil {
		t.Fatal(err)
	}

	const tenant = "tenant-withdraw-deadlock"
	ledger := enrolledinventory.NewLedger()
	ledger.SeedFromStatic(map[string]struct{}{"d1": {}}, "t0")
	observed := newObservedExclusionStore(4)
	_, serial := store.Current()
	observed.Record(observedExclusionEntry{
		TenantID: tenant, DeviceIdentity: "d1", ReportedAt: time.Now(),
		PinnedTransportCASHA256: []string{certFingerprint(newCA)},
		AdoptedTrustSerial:      serial,
	})
	config := serverConfig{
		EnrolledLedger:     ledger,
		ObservedExclusions: observed,
		TransportCertFile:  served,
		TenantIDForTrust:   tenant,
	}

	mux := http.NewServeMux()
	registerTransportTrustAnchorsEndpoint(mux, config, tenant,
		func(_ string, h http.HandlerFunc) http.HandlerFunc { return h }, nil)

	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodDelete,
			"/admin/transport-trust-anchors/"+certFingerprint(legacyCA), nil)
		mux.ServeHTTP(rec, req)
		done <- rec
	}()

	select {
	case rec := <-done:
		if rec.Code != http.StatusOK {
			t.Fatalf("withdrawal should succeed, got %d: %s", rec.Code, rec.Body.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the withdrawal hung — the in-lock gate is reading the trust store it is locked under (2026-08-02 deadlock)")
	}

	remaining := store.Anchors()
	if len(remaining) != 1 || certFingerprint(remaining[0]) != certFingerprint(newCA) {
		t.Fatalf("exactly the legacy CA must be gone, got %d anchors", len(remaining))
	}
	if _, after := store.Current(); after != serial+1 {
		t.Fatalf("a withdrawal must advance the serial, got %d -> %d", serial, after)
	}
}
