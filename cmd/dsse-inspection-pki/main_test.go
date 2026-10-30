package main

import (
	"crypto/x509"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/inspectioncrl"
)

func TestOfflineRootCustodyAndPermanentIssuingRevocation(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "custody")
	now := time.Now().UTC().Truncate(time.Second)
	if err := initialize(dir, "tenant_customer", "Customer", "http://enrol.customer.dsse.test:443", now); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "import.private.json"))
	if err != nil {
		t.Fatal(err)
	}
	rootKey, err := os.ReadFile(filepath.Join(dir, "root-key.offline.private.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), string(rootKey)) {
		t.Fatal("CP import contains the root private key")
	}
	var b importBundle
	if err = json.Unmarshal(raw, &b); err != nil {
		t.Fatal(err)
	}
	root, err := parseCert([]byte(b.RootPEM))
	if err != nil {
		t.Fatal(err)
	}
	issuing, err := parseCert([]byte(b.IssuingCertPEM))
	if err != nil {
		t.Fatal(err)
	}
	expected, _ := inspectioncrl.URL("http://enrol.customer.dsse.test:443", "tenant_customer", root)
	if len(issuing.CRLDistributionPoints) != 1 || issuing.CRLDistributionPoints[0] != expected {
		t.Fatal("Issuing CA cannot fetch its root-signed status")
	}
	if _, err = inspectioncrl.ParseAndValidate(b.RootCRL, root, now); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"root-key.offline.private.pem", "import.private.json"} {
		stat, e := os.Stat(filepath.Join(dir, name))
		if e != nil || stat.Mode().Perm() != 0600 {
			t.Fatal("Custody file readable beyond owner:", name)
		}
	}
	if err = initialize(dir, "tenant_customer", "Customer", "http://enrol.customer.dsse.test:443", now); err == nil {
		t.Fatal("Existing trust anchor overwritten")
	}
	if err = refresh(dir, inspectioncrl.Fingerprint(issuing), now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err = refresh(dir, "", now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	raw, err = os.ReadFile(filepath.Join(dir, "import.private.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(raw, &b); err != nil {
		t.Fatal(err)
	}
	status, err := inspectioncrl.ParseAndValidate(b.RootCRL, root, now.Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if status.Number.Cmp(big.NewInt(3)) != 0 || len(status.RevokedCertificateEntries) != 1 || status.RevokedCertificateEntries[0].SerialNumber.Cmp(issuing.SerialNumber) != 0 {
		t.Fatal("Status refresh forgot a permanent issuing CA revocation")
	}
	update, err := os.ReadFile(filepath.Join(dir, "root-crl-update.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(update), "PRIVATE KEY") {
		t.Fatal("Status update contains private signer material")
	}
	if _, err = x509.ParseRevocationList(b.RootCRL); err != nil {
		t.Fatal(err)
	}
}

func TestOfflineIssuerAdvertisesIndependentCRLOrigins(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "custody")
	now := time.Now().UTC().Truncate(time.Second)
	bases := []string{"http://192.0.2.1:80", "http://192.0.2.2:80", "http://192.0.2.3:80"}
	if err := initialize(dir, "tenant_customer", "Customer", strings.Join(bases, ","), now); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "import.private.json"))
	if err != nil {
		t.Fatal(err)
	}
	var bundle importBundle
	if err := json.Unmarshal(raw, &bundle); err != nil {
		t.Fatal(err)
	}
	root, err := parseCert([]byte(bundle.RootPEM))
	if err != nil {
		t.Fatal(err)
	}
	issuing, err := parseCert([]byte(bundle.IssuingCertPEM))
	if err != nil {
		t.Fatal(err)
	}
	expected, err := inspectioncrl.URLs(bases, bundle.TenantID, root)
	if err != nil {
		t.Fatal(err)
	}
	if len(issuing.CRLDistributionPoints) != len(expected) {
		t.Fatalf("issuer has %d CRL origins, want %d", len(issuing.CRLDistributionPoints), len(expected))
	}
	for i, point := range expected {
		if issuing.CRLDistributionPoints[i] != point {
			t.Fatalf("issuer CRL origin %d: %q", i, issuing.CRLDistributionPoints[i])
		}
	}
	if err := refresh(dir, "", now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
}

func TestOfflineStatusCannotRevokeAnUnrecordedAuthority(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "custody")
	now := time.Now().UTC().Truncate(time.Second)
	if err := initialize(dir, "tenant_customer", "Customer", "http://enrol.customer.dsse.test:443", now); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(filepath.Join(dir, "import.private.json"))
	if err := refresh(dir, strings.Repeat("0", 64), now.Add(time.Second)); err == nil {
		t.Fatal("Unrecorded authority revoked")
	}
	after, _ := os.ReadFile(filepath.Join(dir, "import.private.json"))
	if string(before) != string(after) {
		t.Fatal("Rejected update changed the committed authority")
	}
}

func TestOfflineRefreshDoesNotLeaveStaleUploadAfterPartialWrite(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "custody")
	now := time.Now().UTC().Truncate(time.Second)
	if err := initialize(dir, "tenant_customer", "Customer", "http://crl.example.test:80", now); err != nil {
		t.Fatal(err)
	}
	if err := refresh(dir, "", now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	updatePath := filepath.Join(dir, "root-crl-update.json")
	if _, err := os.Stat(updatePath); err != nil {
		t.Fatal(err)
	}
	// Force the convenience root.crl copy to fail after the authoritative
	// bundle has committed. A previous API upload must not remain available.
	crlPath := filepath.Join(dir, "root.crl")
	if err := os.Remove(crlPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(crlPath, 0700); err != nil {
		t.Fatal(err)
	}
	if err := refresh(dir, "", now.Add(2*time.Second)); err == nil {
		t.Fatal("forced root CRL copy failure was accepted")
	}
	if _, err := os.Stat(updatePath); !os.IsNotExist(err) {
		t.Fatalf("stale API upload survived an interrupted refresh: %v", err)
	}
	if err := os.Remove(crlPath); err != nil {
		t.Fatal(err)
	}
	if err := refresh(dir, "", now.Add(3*time.Second)); err != nil {
		t.Fatal(err)
	}
	upload, err := os.ReadFile(updatePath)
	if err != nil {
		t.Fatal("successful retry did not restore the upload payload:", err)
	}
	var update struct {
		TenantID string `json:"tenant_id"`
		DER      []byte `json:"der"`
	}
	if err := json.Unmarshal(upload, &update); err != nil {
		t.Fatal(err)
	}
	bundle, err := os.ReadFile(filepath.Join(dir, "import.private.json"))
	if err != nil {
		t.Fatal(err)
	}
	var stored importBundle
	if err := json.Unmarshal(bundle, &stored); err != nil {
		t.Fatal(err)
	}
	if update.TenantID != stored.TenantID || string(update.DER) != string(stored.RootCRL) {
		t.Fatal("upload payload does not match the committed root CRL")
	}
}
