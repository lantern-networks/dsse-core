package enroll

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"testing"
	"time"
)

// mockCA is an in-test device CA that signs CSRs — stands in for the CP's issuance.
type mockCA struct {
	key   *ecdsa.PrivateKey
	cert  *x509.Certificate
	caPEM []byte
}

func newMockCA(t *testing.T) *mockCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Device CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(365 * 24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return &mockCA{key: key, cert: cert, caPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

func (c *mockCA) sign(t *testing.T, csrPEM string) string {
	t.Helper()
	blk, _ := pem.Decode([]byte(csrPEM))
	csr, err := x509.ParseCertificateRequest(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Fatalf("csr self-signature invalid: %v", err)
	}
	now := time.Now()
	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      csr.Subject,
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(60 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, leaf, c.cert, csr.PublicKey, c.key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// mockDoer implements Doer: it issues a cert for the CSR and returns the CP's authoritative tenant/group.
type mockDoer struct {
	t        *testing.T
	ca       *mockCA
	tenant   string
	group    string
	forceErr string
}

func (d mockDoer) Do(req *http.Request) (*http.Response, error) {
	body, _ := io.ReadAll(req.Body)
	var r Request
	_ = json.Unmarshal(body, &r)
	var resp Response
	status := http.StatusOK
	if d.forceErr != "" {
		resp = Response{Error: d.forceErr}
		status = http.StatusForbidden
	} else {
		resp = Response{CertPEM: d.ca.sign(d.t, r.CSRPEM), CAPEM: string(d.ca.caPEM), Tenant: d.tenant, Group: d.group, PolicyVersion: 1}
	}
	b, _ := json.Marshal(resp)
	return &http.Response{StatusCode: status, Body: io.NopCloser(bytes.NewReader(b)), Header: make(http.Header)}, nil
}

func TestRun_HappyPath_CPAssignsTenantGroup(t *testing.T) {
	ca := newMockCA(t)
	// The device REQUESTS tenant "requested" but the CP is authoritative and assigns "acme"/"developers".
	doer := mockDoer{t: t, ca: ca, tenant: "acme", group: "developers"}
	res, err := Run(context.Background(), "https://cp/enroll", "win-dev-1", "requested", "", Eligibility{Mode: "token", Token: "abc"}, doer)
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	if res.Tenant != "acme" || res.Group != "developers" {
		t.Fatalf("CP assignment not honored: tenant=%q group=%q", res.Tenant, res.Group)
	}
	if len(res.KeyPEM) == 0 || len(res.CertPEM) == 0 || len(res.CAPEM) == 0 {
		t.Fatalf("missing material in result")
	}
	// The returned cert must validate against our own key (Run already checked, re-assert explicitly).
	if err := ValidateIssuedCert(res.CertPEM, res.CAPEM, res.KeyPEM, ""); err != nil {
		t.Fatalf("issued cert should validate: %v", err)
	}
}

func TestValidateIssuedCert_KeyMismatch(t *testing.T) {
	ca := newMockCA(t)
	keyA, _, err := GenerateKeyAndCSR("dev-a", "acme")
	if err != nil {
		t.Fatal(err)
	}
	_, csrB, err := GenerateKeyAndCSR("dev-b", "acme") // a DIFFERENT key's CSR
	if err != nil {
		t.Fatal(err)
	}
	certForB := ca.sign(t, string(csrB))
	// A cert minted for key B must NOT validate against key A — else the CP could hand us someone else's cert.
	if err := ValidateIssuedCert([]byte(certForB), ca.caPEM, keyA, ""); err == nil {
		t.Fatalf("cert for another key must be rejected")
	}
}

func TestValidateIssuedCert_WrongCA(t *testing.T) {
	caX := newMockCA(t)
	caY := newMockCA(t)
	keyA, csrA, err := GenerateKeyAndCSR("dev-a", "acme")
	if err != nil {
		t.Fatal(err)
	}
	certByX := caX.sign(t, string(csrA))
	// cert signed by caX must not chain to caY.
	if err := ValidateIssuedCert([]byte(certByX), caY.caPEM, keyA, ""); err == nil {
		t.Fatalf("cert must not chain to the wrong CA")
	}
}

func TestRun_Refused(t *testing.T) {
	ca := newMockCA(t)
	doer := mockDoer{t: t, ca: ca, forceErr: "device not eligible"}
	if _, err := Run(context.Background(), "https://cp/enroll", "win-dev-1", "acme", "", Eligibility{Mode: "token"}, doer); err == nil {
		t.Fatalf("refused enrollment must return an error (stays Unenrolled)")
	}
}
