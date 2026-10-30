package edgeplane

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestOfflineTenantIssuerDoesNotClaimDurabilityWhenBundleWriteFails(t *testing.T) {
	now := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	engine, err := NewNetworkExtensionLabTLSInterception([]string{"*"}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	engine.SetOfflineTenantIntermediateDir(dir)
	tenant := "tenant_northwind"
	// The announcement record can be written, but the intermediate key cannot.
	blockedKey := filepath.Join(dir, interceptionTenantFileKey(tenant)+".key.pem")
	if err := os.Mkdir(blockedKey, 0o700); err != nil {
		t.Fatal(err)
	}
	root, intermediate, key, _ := tenantOfflineBundle(t, "Northwind", now)
	if _, err := engine.LoadOfflineTenantIntermediate(tenant, root, intermediate, key); err != nil {
		t.Fatalf("issuer must remain live after a persistence failure: %v", err)
	}
	rows := engine.ListOfflineTenantIntermediates()
	if len(rows) != 1 || rows[0].Tenant != tenant {
		t.Fatalf("live issuer missing from inventory: %+v", rows)
	}
	if rows[0].Durable {
		t.Fatal("a configured directory was reported durable despite failure to save the signing key")
	}
}

func TestOfflineTenantIssuerClaimsDurabilityAfterSuccessfulBundleWrite(t *testing.T) {
	now := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	engine, err := NewNetworkExtensionLabTLSInterception([]string{"*"}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	engine.SetOfflineTenantIntermediateDir(t.TempDir())
	root, intermediate, key, _ := tenantOfflineBundle(t, "Northwind", now)
	if _, err := engine.LoadOfflineTenantIntermediate("tenant_northwind", root, intermediate, key); err != nil {
		t.Fatal(err)
	}
	rows := engine.ListOfflineTenantIntermediates()
	if len(rows) != 1 || !rows[0].Durable {
		t.Fatalf("successfully stored issuer should be reported durable: %+v", rows)
	}
}
