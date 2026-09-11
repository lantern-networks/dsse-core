package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/tenantca"
)

// authorityExpiringIn registers one organization's CA with a chosen lifetime.
func authorityExpiringIn(t *testing.T, registry *tenantca.TenantCARegistry, tenant string, life time.Duration) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{Organization: []string{tenant}, CommonName: tenant + " Device CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(life),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("cert: %v", err)
	}
	if _, err := registry.Register(tenant, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})); err != nil {
		t.Fatalf("register %s: %v", tenant, err)
	}
}

// ★ A COUNT IS NOT AN INVENTORY (2026-08-16). The tenant-CA surface answered `ca_count: 1`, so an organization
// could not see which certificate identifies its devices or WHEN IT EXPIRES. That certificate's lapse stops
// every device of that organization at the handshake, at the same moment — the one expiry with fleet-wide
// blast radius was the one nothing reported.
func TestEachTenantAuthorityReportsItsOwnExpiry(t *testing.T) {
	registry := &tenantca.TenantCARegistry{Pool: x509.NewCertPool()}
	authorityExpiringIn(t, registry, "tenant_northwind", 29*24*time.Hour)
	authorityExpiringIn(t, registry, "tenant_lab", 3650*24*time.Hour)

	facts := registry.Facts(time.Now())

	if len(facts) != 2 {
		t.Fatalf("described %d authorities, registered 2", len(facts))
	}
	// Soonest first: the one about to lapse is the one read first, not the one sorted alphabetically.
	if facts[0].TenantID != "tenant_northwind" {
		t.Fatalf("first described authority is %q; the soonest expiry must lead", facts[0].TenantID)
	}
	if facts[0].DaysLeft > 29 || facts[0].DaysLeft < 27 {
		t.Fatalf("days_left = %d for a 29-day authority", facts[0].DaysLeft)
	}
	if facts[0].Expired {
		t.Fatal("an authority with days left was reported as expired")
	}
	if facts[0].CommonName == "" || facts[0].SHA256 == "" || facts[0].NotAfter == "" {
		t.Fatalf("the description carries no identity: %+v", facts[0])
	}
}

// An authority that has already lapsed is EXPIRED, not "0 days left" — the two lead to opposite actions, and
// the count that hid this in the first place made them the same answer.
func TestALapsedAuthorityIsReportedAsExpired(t *testing.T) {
	registry := &tenantca.TenantCARegistry{Pool: x509.NewCertPool()}
	authorityExpiringIn(t, registry, "tenant_gone", -time.Hour)

	facts := registry.Facts(time.Now())

	if len(facts) != 1 || !facts[0].Expired {
		t.Fatalf("a lapsed authority was not reported as expired: %+v", facts)
	}
	if facts[0].DaysLeft > 0 {
		t.Fatalf("days_left = %d for an authority that has already lapsed", facts[0].DaysLeft)
	}
}

// The watch must not depend on a registry existing, and must not block startup — an Edge whose expiry
// reporting is misconfigured still has to serve traffic. Nil in, no panic, a stop that is safe to call.
func TestTheExpiryWatchIsSafeWithoutARegistry(t *testing.T) {
	stop := watchTenantAuthorityExpiry(nil, nil)
	stop()

	registry := &tenantca.TenantCARegistry{Pool: x509.NewCertPool()}
	authorityExpiringIn(t, registry, "tenant_soon", 5*24*time.Hour)
	stop = watchTenantAuthorityExpiry(registry, time.Now)
	stop()
}
