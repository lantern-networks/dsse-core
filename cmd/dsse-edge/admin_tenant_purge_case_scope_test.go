package main

import (
	"context"
	"crypto/x509"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/enrolledinventory"
	"github.com/lantern-networks/dsse-core/revocation"
	"github.com/lantern-networks/dsse-core/tenantca"
)

func TestTenantPurgePreservesCaseDistinctTenantDevicesAndCA(t *testing.T) {
	now := time.Now().UTC()
	ledger := enrolledinventory.NewLedger()
	for _, entry := range []struct{ device, tenant string }{
		{"device-upper", "Acme"},
		{"device-lower", "acme"},
	} {
		if _, err := ledger.Enroll(entry.device, entry.tenant, "", now.Format(time.RFC3339)); err != nil {
			t.Fatalf("enroll %s: %v", entry.device, err)
		}
	}
	admissions := revocation.NewAdmissionRevocations()
	risk := revocation.NewHighRiskOverlay()
	for _, device := range []string{"device-upper", "device-lower"} {
		admissions.Revoke(device, "review")
		risk.Mark(device, "high")
	}
	registry := &tenantca.TenantCARegistry{Pool: x509.NewCertPool()}
	for _, entry := range []struct{ tenant, name string }{
		{"Acme", "Upper CA"},
		{"acme", "Lower CA"},
	} {
		if _, err := registry.Register(entry.tenant, purgeTestCA(t, entry.name)); err != nil {
			t.Fatalf("register %s CA: %v", entry.tenant, err)
		}
	}
	var lowerFingerprint, upperFingerprint string
	for _, fact := range registry.Facts(now) {
		if fact.TenantID == "acme" {
			lowerFingerprint = fact.SHA256
		} else if fact.TenantID == "Acme" {
			upperFingerprint = fact.SHA256
		}
	}
	if lowerFingerprint == "" || upperFingerprint == "" {
		t.Fatal("both case-distinct tenant CAs must be registered")
	}
	trust := &recordingTrustStore{missing: true}
	result := purgeAdminTenantData(context.Background(), "node", "Acme", nil, nil,
		nil, ledger, nil, registry, "", trust, nil,
		adminTenantExtraStores{Admissions: admissions, HighRisk: risk}, nil, now)
	if len(result.Failures) != 0 {
		t.Fatalf("tenant purge failed: %v", result.Failures)
	}
	if !ledger.IsAdmitted("device-lower") {
		t.Fatal("case-distinct tenant's enrolled device was removed")
	}
	if ledger.IsAdmitted("device-upper") {
		t.Fatal("selected tenant's enrolled device was not removed")
	}
	if _, ok := admissions.IsRevoked("device-lower"); !ok {
		t.Fatal("case-distinct tenant's admission block was erased")
	}
	if _, ok := admissions.IsRevoked("device-upper"); ok {
		t.Fatal("selected tenant's admission block was not erased")
	}
	if _, ok := risk.IsHighRisk("device-lower"); !ok {
		t.Fatal("case-distinct tenant's high-risk mark was erased")
	}
	if _, ok := risk.IsHighRisk("device-upper"); ok {
		t.Fatal("selected tenant's high-risk mark was not erased")
	}
	if registry.Registrations()["acme"] != 1 {
		t.Fatal("case-distinct tenant's CA attribution was removed")
	}
	if registry.Registrations()["Acme"] != 0 {
		t.Fatal("selected tenant's CA attribution was not removed")
	}
	upperWithdrawn := false
	for _, fingerprint := range trust.withdrawn {
		if fingerprint == lowerFingerprint {
			t.Fatal("case-distinct tenant's CA was withdrawn from the live trust store")
		}
		upperWithdrawn = upperWithdrawn || fingerprint == upperFingerprint
	}
	if !upperWithdrawn {
		t.Fatal("selected tenant's CA was not withdrawn from the live trust store")
	}
}
