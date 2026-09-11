package enroll

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/deviceca"
)

// newDeviceCASigner returns a signer plus the SHA-256 pin of its CA (the anchor the agent would carry).
func newDeviceCASigner(t *testing.T) (*deviceca.Signer, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "DSSE Device CA (test)"},
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
	caCert, _ := x509.ParseCertificate(der)
	sum := sha256.Sum256(caCert.Raw)
	return deviceca.NewSigner(caCert, key), hex.EncodeToString(sum[:])
}

// TestEnrollment_E2E wires the client (Run) to the server (Issuer.Handler) over httptest for a full
// keygen → CSR → eligibility → CA-issuance → assignment → client-validation round trip.
func TestEnrollment_E2E(t *testing.T) {
	signer, caPin := newDeviceCASigner(t)
	var recorded string
	iss := Issuer{
		Signer:  signer,
		CertTTL: 60 * 24 * time.Hour,
		Assign: func(req Request) (tenant, group, reason string, ok bool) {
			// Weak eligibility gate: only a good token enrolls; the CP assigns tenant/group (device requested "x").
			if req.Eligibility.Mode == "token" && req.Eligibility.Token == "good" {
				return "acme", "developers", "", true
			}
			return "", "", "device not eligible", false
		},
		Record: func(deviceID, tenant, group string) error {
			recorded = deviceID + "/" + tenant + "/" + group
			return nil
		},
		NowPolicyVersion: 7,
	}
	srv := httptest.NewServer(iss.Handler())
	defer srv.Close()

	// Eligible device enrolls end to end (with the correct CA pin).
	res, err := Run(context.Background(), srv.URL, "win-dev-1", "requested-tenant", caPin, Eligibility{Mode: "token", Token: "good"}, http.DefaultClient)
	if err != nil {
		t.Fatalf("enroll E2E: %v", err)
	}
	if res.Tenant != "acme" || res.Group != "developers" || res.PolicyVersion != 7 {
		t.Fatalf("CP assignment not honored: %+v", res)
	}
	if err := ValidateIssuedCert(res.CertPEM, res.CAPEM, res.KeyPEM, caPin); err != nil {
		t.Fatalf("issued cert must validate against our key + pin: %v", err)
	}
	// The ISSUED CERT must carry the CP-authoritative identity, NOT the device-requested tenant. The device
	// requested tenant "requested-tenant"; the cert O must be the CP-assigned "acme" and CN the CP device id.
	blk, _ := pem.Decode(res.CertPEM)
	leaf, _ := x509.ParseCertificate(blk.Bytes)
	if leaf.Subject.CommonName != "win-dev-1" {
		t.Fatalf("cert CN = %q, want CP device id win-dev-1", leaf.Subject.CommonName)
	}
	if len(leaf.Subject.Organization) == 0 || leaf.Subject.Organization[0] != "acme" {
		t.Fatalf("cert O = %v, want CP-assigned tenant acme (NOT the device-requested tenant)", leaf.Subject.Organization)
	}
	if recorded != "win-dev-1/acme/developers" {
		t.Fatalf("inventory record hook not called correctly: %q", recorded)
	}

	// A WRONG CA pin must be rejected (enrollment-bootstrap MITM defense).
	wrongPin := "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	if _, err := Run(context.Background(), srv.URL, "win-dev-1", "acme", wrongPin, Eligibility{Mode: "token", Token: "good"}, http.DefaultClient); err == nil {
		t.Fatalf("wrong CA pin must be rejected")
	}

	// Ineligible device is refused (stays Unenrolled).
	if _, err := Run(context.Background(), srv.URL, "win-dev-2", "acme", "", Eligibility{Mode: "token", Token: "bad"}, http.DefaultClient); err == nil {
		t.Fatalf("ineligible device must be refused")
	}
}
