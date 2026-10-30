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
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/enroll"
)

func connectorRenewalFixture(t *testing.T) (string, connectorState, *tls.Config) {
	t.Helper()
	dir := t.TempDir()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(900), Subject: pkix.Name{CommonName: "identity test CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	sign := func(csrPEM []byte, serial int64) ([]byte, error) {
		block, _ := pem.Decode(csrPEM)
		if block == nil {
			return nil, fmt.Errorf("missing CSR")
		}
		csr, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil {
			return nil, err
		}
		if err := csr.CheckSignature(); err != nil {
			return nil, err
		}
		leaf := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: csr.Subject, DNSNames: csr.DNSNames, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(12 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
		der, err := x509.CreateCertificate(rand.Reader, leaf, ca, csr.PublicKey, key)
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), err
	}
	keyPEM, csr, err := enroll.GenerateKeyAndCSR("conn-renew", "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	certPEM, err := sign(csr, 1)
	if err != nil {
		t.Fatal(err)
	}
	cp, kp := filepath.Join(dir, connectorIdentityCertFile), filepath.Join(dir, connectorIdentityKeyFile)
	for p, b := range map[string][]byte{cp: certPEM, kp: keyPEM} {
		if err := os.WriteFile(p, b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/enroll/renew" {
			fmt.Fprint(w, r.TLS.PeerCertificates[0].SerialNumber)
			return
		}
		var req struct {
			CSR string `json:"csr_pem"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid CSR", 400)
			return
		}
		issued, err := sign([]byte(req.CSR), 2)
		if err != nil {
			http.Error(w, "invalid CSR", 400)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"cert_pem": string(issued), "ca_pem": string(caPEM)})
	}))
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	srv.TLS = &tls.Config{ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool, MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	anchor := filepath.Join(dir, "edge-ca.pem")
	if err := os.WriteFile(anchor, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := buildConnectorTLSConfig(connectorTransportConfig{EdgeCAFile: anchor, ClientCertFile: cp, ClientKeyFile: kp})
	if err != nil {
		t.Fatal(err)
	}
	return dir, connectorState{ConnectorID: "conn-renew", TenantID: "tenant-a", EdgeURL: srv.URL}, cfg
}

func connectorPresentedSerial(t *testing.T, cfg *tls.Config, endpoint string) string {
	t.Helper()
	client := newConnectorEdgeHTTPClient(cfg.Clone())
	defer client.CloseIdleConnections()
	resp, err := client.Get(endpoint + "/identity")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func TestConnectorRenewalActivatesOnNextTLSConnection(t *testing.T) {
	dir, st, cfg := connectorRenewalFixture(t)
	if got := connectorPresentedSerial(t, cfg, st.EdgeURL); got != "1" {
		t.Fatalf("initial serial=%s", got)
	}
	if err := renewConnectorIdentityIfDue(t.Context(), dir, st, cfg, true, nil); err != nil {
		t.Fatal(err)
	}
	if got := connectorPresentedSerial(t, cfg, st.EdgeURL); got != "2" {
		t.Fatalf("renewal saved but next live TLS connection presented serial=%s, want 2", got)
	}
}

func TestConnectorRenewalRefusesUnjournaledReplacement(t *testing.T) {
	dir, st, cfg := connectorRenewalFixture(t)
	cp, kp := filepath.Join(dir, connectorIdentityCertFile), filepath.Join(dir, connectorIdentityKeyFile)
	oldCert, _ := os.ReadFile(cp)
	oldKey, _ := os.ReadFile(kp)
	if err := os.Mkdir(cp+".dsse-pair-recovery.json", 0700); err != nil {
		t.Fatal(err)
	}
	if err := renewConnectorIdentityIfDue(t.Context(), dir, st, cfg, true, nil); err == nil {
		t.Fatal("renewal ignored unusable recovery journal")
	}
	newCert, _ := os.ReadFile(cp)
	newKey, _ := os.ReadFile(kp)
	if string(oldCert) != string(newCert) || string(oldKey) != string(newKey) {
		t.Fatal("failed renewal changed the existing identity pair")
	}
}

func TestConnectorManagedIdentityDoesNotIncludeOperatorFiles(t *testing.T) {
	dir := t.TempDir()
	cp, kp := filepath.Join(dir, connectorIdentityCertFile), filepath.Join(dir, connectorIdentityKeyFile)
	if !connectorUsesManagedIdentity(dir, cp, kp) {
		t.Fatal("enrolled identity is not recognized")
	}
	for _, pair := range [][2]string{{"", kp}, {cp, ""}, {filepath.Join(dir, "operator.crt"), kp}, {cp, filepath.Join(dir, "operator.key")}} {
		if connectorUsesManagedIdentity(dir, pair[0], pair[1]) {
			t.Fatalf("operator/partial identity selected for automatic renewal: %v", pair)
		}
	}
}

func TestConnectorManualRenewalUsesVerifiedDoorAndHonorsWithdrawal(t *testing.T) {
	dir, st, cfg := connectorRenewalFixture(t)
	currentURL := st.EdgeURL
	doors := parseConnectorEndpoints(currentURL)
	st.EdgeURL = "https://retired.invalid"
	if err := renewConnectorIdentityAtSelectedDoor(t.Context(), dir, st, cfg, doors, true, nil); err != nil {
		t.Fatal(err)
	}
	if got := connectorPresentedSerial(t, cfg, currentURL); got != "2" {
		t.Fatalf("serial=%s", got)
	}
	doors.withdraw(currentURL)
	if err := renewConnectorIdentityAtSelectedDoor(t.Context(), dir, st, cfg, doors, true, nil); err == nil {
		t.Fatal("manual renewal used a withdrawn door")
	}
}
