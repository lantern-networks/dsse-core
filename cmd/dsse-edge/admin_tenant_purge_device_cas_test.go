package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/tenantca"
)

type recordingTrustStore struct {
	withdrawn []string
	reapplied int
	missing   bool
}

func (r *recordingTrustStore) Add(string) (*x509.Certificate, int64, error) { return nil, 0, nil }
func (r *recordingTrustStore) Withdraw(sha string) (*x509.Certificate, int64, error) {
	r.withdrawn = append(r.withdrawn, sha)
	if r.missing {
		return nil, 0, errors.New("no distributed certificate has that fingerprint")
	}
	return nil, 0, nil
}
func (r *recordingTrustStore) Reapply() error { r.reapplied++; return nil }

func purgeTestCA(t *testing.T, cn string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		IsCA:         true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("cert: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// ★★ AN ORGANIZATION'S DEVICE CA OUTLIVED THE ORGANIZATION (2026-08-17, measured: deleted through the Console,
// and the CA that admits its machines was still in the registry). Any device holding a certificate from that CA
// went on being admitted AS that organization — an admission path with no organization behind it.
//
// BOTH HALVES, in the order the per-CA withdrawal route established and paid for: the attribution first, then
// the trust set, then the rebuild. The pool a handshake reads is the registry's clone plus the trust store's
// own certificates, and only a change to the store rebuilds it — so removing trust first rebuilds the pool
// from a registry that still holds the CA, and the withdrawal defeats itself.
func TestPurgingAnOrganizationStopsItsDeviceCAsAdmittingDevices(t *testing.T) {
	registry := &tenantca.TenantCARegistry{Pool: x509.NewCertPool()}
	var err error
	if _, err = registry.Register("tenant_going", purgeTestCA(t, "Going CA")); err != nil {
		t.Fatalf("register: %v", err)
	}
	if _, err = registry.Register("tenant_staying", purgeTestCA(t, "Staying CA")); err != nil {
		t.Fatalf("register: %v", err)
	}
	trust := &recordingTrustStore{missing: true} // not distributed here: the Reapply path must still run

	removed, err2 := purgeTenantDeviceCAs(registry, "", trust, "tenant_going")
	if err2 != nil {
		t.Fatalf("purge device CAs: %v", err2)
	}
	if removed != 1 {
		t.Fatalf("the organization's CA must be withdrawn, got %d", removed)
	}
	if len(trust.withdrawn) != 1 {
		t.Fatalf("the trust set must be told too, or the CA keeps admitting devices: %+v", trust.withdrawn)
	}
	if trust.reapplied == 0 {
		t.Fatal("the pool a handshake reads folds in the registry — nothing else rebuilds it")
	}
	if registry.Registrations()["tenant_going"] != 0 {
		t.Fatalf("the attribution survived: %+v", registry.Registrations())
	}
	// The control: nobody else's CA was withdrawn.
	if registry.Registrations()["tenant_staying"] != 1 {
		t.Fatalf("another organization's CA was withdrawn with it: %+v", registry.Registrations())
	}
}
