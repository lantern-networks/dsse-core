package main

import (
	"crypto/tls"
	"crypto/x509"
	"github.com/lantern-networks/dsse-core/enrolledinventory"
	"testing"
	"time"
)

func TestRecoveryVerificationUsesServedOrganizationAndLedger(t *testing.T) {
	caA, keyA, _ := graceTestCA(t)
	caB, keyB, _ := graceTestCA(t)
	reg := graceTenantRegistry(t, caA, caB)
	oldPool := transportClientCAPool.Load()
	transportClientCAPool.Store(reg.Pool)
	t.Cleanup(func() { transportClientCAPool.Store(oldPool) })
	name := "recovery.organization-binding.test"
	transportTenantCertificates.put("tenant-a", []string{name}, &tls.Certificate{}, "")
	t.Cleanup(func() {
		transportTenantCertificates.mu.Lock()
		defer transportTenantCertificates.mu.Unlock()
		delete(transportTenantCertificates.bySNI, name)
		delete(transportTenantCertificates.tenantOf, name)
		delete(transportTenantCertificates.anchorOf, "tenant-a")
	})
	ledger := enrolledinventory.NewLedger()
	if _, err := ledger.Enroll("holiday-laptop", "tenant-a", "default", time.Now().UTC().Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	cfg := enrollRenewGraceConfig{Tenant: "tenant_default", TenantRegistry: reg, Ledger: ledger, Window: time.Hour}
	now := time.Now()
	own := graceTestDeviceCert(t, caA, keyA, "holiday-laptop", now.Add(-2*time.Hour), now.Add(-time.Minute))
	other := graceTestDeviceCert(t, caB, keyB, "holiday-laptop", now.Add(-2*time.Hour), now.Add(-time.Minute))
	verify := enrollRenewGraceVerify(cfg, reg.Pool)
	state := func(name string, cert *x509.Certificate) tls.ConnectionState {
		return tls.ConnectionState{ServerName: name, PeerCertificates: []*x509.Certificate{cert}}
	}
	if err := verify(state(name, own)); err != nil {
		t.Fatalf("own served organization recovery refused: %v", err)
	}
	if err := verify(state(name, other)); err == nil {
		t.Fatal("another tenant recovered through this organization's name")
	}
	if err := verify(state("recovery.unknown.test", own)); err == nil {
		t.Fatal("unknown name selected a tenant")
	}
	wrongLedger := enrolledinventory.NewLedger()
	if _, err := wrongLedger.Enroll("holiday-laptop", "tenant-b", "default", now.Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	cfg.Ledger = wrongLedger
	if err := enrollRenewGraceVerify(cfg, reg.Pool)(state(name, own)); err == nil {
		t.Fatal("certificate and ledger organization mismatch accepted")
	}
	cfg.Ledger = ledger
	cfg.TenantRegistry = nil
	if err := enrollRenewGraceVerify(cfg, reg.Pool)(state(name, own)); err == nil {
		t.Fatal("named organization without issuer registry accepted")
	}
}
