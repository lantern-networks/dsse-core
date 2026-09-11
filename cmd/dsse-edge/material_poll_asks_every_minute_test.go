package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// ★★ THE NODE SLEPT AN HOUR ON A PATH WHOSE OWN COMMENT SAYS ONE MINUTE (2026-08-21, measured on the lab: a
// new organization's transport material was ready on the control plane and the Edge did not pick it up for
// the better part of an hour).
//
// FetchOnce returns the soonest expiry so the caller knows when to come back. Start() recorded it — and the
// START-UP fetch, which runs in its own retry loop BEFORE Start(), threw it away. So the loop's first answer
// was "unchanged", which returns f.expiry, which was still zero, which selects the hourly branch. Every node
// whose start-up fetch succeeded then asked once an hour.
func TestTheFirstFetchRecordsTheExpirySoTheLoopKeepsAsking(t *testing.T) {
	certPEM, keyPEM, expiresAt := testTransportMaterialPair(t, "probe.example.invalid")
	notAfter := expiresAt.UTC().Format(time.RFC3339)
	generation := uint64(7)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			KnownGeneration uint64 `json:"known_generation"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body.KnownGeneration == generation {
			_ = json.NewEncoder(w).Encode(map[string]any{"unchanged": true, "generation": generation, "ttl": "12h0m0s"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"generation": generation, "ttl": "12h0m0s",
			"materials": []map[string]any{{"tenant_id": "tenant_probe", "server_name": "probe.example.invalid",
				"not_after": notAfter, "cert_pem": certPEM, "key_pem": keyPEM, "anchor_pem": certPEM}},
		})
	}))
	defer server.Close()

	f := newTenantTransportMaterialFetcher(server.URL, "t",
		&tls.Config{InsecureSkipVerify: true}, func() []string { return nil })

	// The start-up fetch, exactly as main.go runs it: FetchOnce on its own, result not stored by the caller.
	if _, err := f.FetchOnce(); err != nil {
		t.Fatalf("first fetch: %v", err)
	}

	// Now the loop's first question. The control plane says "unchanged" — the ordinary answer — and what comes
	// back must still carry an expiry, or the caller waits an hour.
	expiry, err := f.FetchOnce()
	if err != nil {
		t.Fatalf("second fetch: %v", err)
	}
	if expiry.IsZero() {
		t.Fatal("★ the second fetch returned no expiry, so the poll loop takes its hourly branch — a rotation " +
			"performed on the control plane waits up to an hour to reach this node, on the code path whose " +
			"comment says it asks every minute")
	}
}

// testTransportMaterialPair is a self-signed leaf the fetcher can actually install — the point of this test is
// what happens AFTER a successful install, so an uninstallable stub would prove nothing.
func testTransportMaterialPair(t *testing.T, name string) (string, string, time.Time) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	notAfter := time.Now().Add(12 * time.Hour)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: notAfter,
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, IsCA: true, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("certificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})), notAfter
}
