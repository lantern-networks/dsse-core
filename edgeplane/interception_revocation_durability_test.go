package edgeplane

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestInterceptionRevocationRefusesUndurableCommitAndCanRetry(t *testing.T) {
	now := time.Date(2026, 10, 23, 0, 0, 0, 0, time.UTC)
	dir := t.TempDir()
	issuer, err := NewNetworkExtensionLabTLSInterception([]string{"*"}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	issuer.SetOfflineTenantIntermediateDir(dir)
	root, intermediate, key, _ := tenantOfflineBundle(t, "Northwind", now)
	if _, err := issuer.LoadOfflineTenantIntermediate("tenant_northwind", root, intermediate, key); err != nil {
		t.Fatal(err)
	}
	blocker := filepath.Join(dir, revocationFileName("tenant_northwind"))
	if err := os.Mkdir(blocker, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := issuer.RevokeTenantInterceptionAuthority("tenant_northwind", "key exposed"); err == nil {
		t.Fatal("revocation reported success without a durable record")
	}
	if _, err := leafIssuerCN(t, issuer, "tenant_northwind", "example.com"); err != nil {
		t.Fatalf("uncommitted revocation changed live issuer: %v", err)
	}
	if err := os.Remove(blocker); err != nil {
		t.Fatal(err)
	}
	if _, err := issuer.RevokeTenantInterceptionAuthority("tenant_northwind", "key exposed"); err != nil {
		t.Fatalf("durable revocation could not be retried: %v", err)
	}
	restarted, err := NewNetworkExtensionLabTLSInterception([]string{"*"}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.LoadOfflineTenantIntermediatesFromDir(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.LoadOfflineTenantIntermediate("tenant_northwind", root, intermediate, key); err == nil {
		t.Fatal("durable revocation lost after restart")
	}
}

func TestInterceptionRevocationRequiresDurableDirectory(t *testing.T) {
	now := time.Date(2026, 10, 23, 0, 0, 0, 0, time.UTC)
	issuer, err := NewNetworkExtensionLabTLSInterception([]string{"*"}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	root, intermediate, key, _ := tenantOfflineBundle(t, "Northwind", now)
	if _, err := issuer.LoadOfflineTenantIntermediate("tenant_northwind", root, intermediate, key); err != nil {
		t.Fatal(err)
	}
	if _, err := issuer.RevokeTenantInterceptionAuthority("tenant_northwind", "key exposed"); err == nil {
		t.Fatal("revocation succeeded with no durable record location")
	}
	if _, err := leafIssuerCN(t, issuer, "tenant_northwind", "example.com"); err != nil {
		t.Fatalf("refused revocation changed live issuer: %v", err)
	}
}

func TestUnreadableInterceptionRevocationQuarantinesItsTenant(t *testing.T) {
	now := time.Date(2026, 10, 23, 0, 0, 0, 0, time.UTC)
	dir := t.TempDir()
	first, err := NewNetworkExtensionLabTLSInterception([]string{"*"}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	first.SetOfflineTenantIntermediateDir(dir)
	root, intermediate, key, _ := tenantOfflineBundle(t, "Northwind", now)
	if _, err := first.LoadOfflineTenantIntermediate("tenant_northwind", root, intermediate, key); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, revocationFileName("tenant_northwind")), []byte("{broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	restarted, err := NewNetworkExtensionLabTLSInterception([]string{"*"}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := restarted.LoadOfflineTenantIntermediatesFromDir(dir)
	if loaded != 0 {
		t.Fatalf("unreadable revocation restored %d issuer(s)", loaded)
	}
	if err != nil {
		t.Fatal(err)
	}
	if _, revoked := restarted.TenantInterceptionRevoked("tenant_northwind"); !revoked {
		t.Fatal("unreadable revocation was not surfaced")
	}
	if _, err := leafIssuerCN(t, restarted, "tenant_northwind", "example.com"); err == nil {
		t.Fatal("unreadable revocation allowed leaf issuance")
	}
	if _, err := restarted.LoadOfflineTenantIntermediate("tenant_northwind", root, intermediate, key); err == nil {
		t.Fatal("unreadable revocation allowed direct reload of possibly compromised authority")
	}
}

func TestInterceptionRevocationSurvivesFailedBundleCleanup(t *testing.T) {
	now := time.Date(2026, 10, 23, 0, 0, 0, 0, time.UTC)
	dir := t.TempDir()
	issuer, err := NewNetworkExtensionLabTLSInterception([]string{"*"}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	issuer.SetOfflineTenantIntermediateDir(dir)
	root, intermediate, key, _ := tenantOfflineBundle(t, "Northwind", now)
	if _, err := issuer.LoadOfflineTenantIntermediate("tenant_northwind", root, intermediate, key); err != nil {
		t.Fatal(err)
	}
	safe := interceptionTenantFileKey("tenant_northwind")
	rootPath := filepath.Join(dir, safe+".root.pem")
	if err := os.Remove(rootPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(rootPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rootPath, "blocker"), []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := issuer.RevokeTenantInterceptionAuthority("tenant_northwind", "key exposed"); err != nil {
		t.Fatalf("revocation with failed cleanup should remain committed: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, revocationFileName("tenant_northwind")))
	if err != nil {
		t.Fatal(err)
	}
	var record persistedRevocation
	if err := json.Unmarshal(raw, &record); err != nil {
		t.Fatal(err)
	}
	if err := validatePersistedRevocation(record, "tenant_northwind"); err != nil {
		t.Fatal(err)
	}
	// Emulate a stale bundle surviving the failed unlink or being copied back.
	if err := os.Remove(filepath.Join(rootPath, "blocker")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(rootPath); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string][]byte{
		safe + ".root.pem":         root,
		safe + ".intermediate.pem": intermediate,
		safe + ".key.pem":          key,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), content, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	restarted, err := NewNetworkExtensionLabTLSInterception([]string{"*"}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := restarted.LoadOfflineTenantIntermediatesFromDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if loaded != 0 {
		t.Fatalf("restored %d issuer(s) despite committed revocation", loaded)
	}
	if _, err := restarted.LoadOfflineTenantIntermediate("tenant_northwind", root, intermediate, key); err == nil {
		t.Fatal("stale bundle reloaded after committed revocation")
	}
}

func TestMalformedInterceptionRevocationQuarantinesTenant(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  string
	}{
		{name: "wrong tenant", raw: `{"tenant":"tenant_other","reason":"key exposed","revoked_sha256_reason":{"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef":"key exposed"}}`},
		{name: "empty revoked roots", raw: `{"tenant":"tenant_northwind","reason":"key exposed","revoked_sha256_reason":{}}`},
		{name: "invalid fingerprint", raw: `{"tenant":"tenant_northwind","reason":"key exposed","revoked_sha256_reason":{"bad":"key exposed"}}`},
		{name: "noncanonical fingerprint", raw: `{"tenant":"tenant_northwind","reason":"key exposed","revoked_sha256_reason":{"ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef0123456789":"key exposed"}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			now := time.Date(2026, 10, 23, 0, 0, 0, 0, time.UTC)
			dir := t.TempDir()
			issuer, err := NewNetworkExtensionLabTLSInterception([]string{"*"}, func() time.Time { return now })
			if err != nil {
				t.Fatal(err)
			}
			issuer.SetOfflineTenantIntermediateDir(dir)
			root, intermediate, key, _ := tenantOfflineBundle(t, "Northwind", now)
			if _, err := issuer.LoadOfflineTenantIntermediate("tenant_northwind", root, intermediate, key); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, revocationFileName("tenant_northwind")), []byte(tc.raw), 0o600); err != nil {
				t.Fatal(err)
			}
			restarted, err := NewNetworkExtensionLabTLSInterception([]string{"*"}, func() time.Time { return now })
			if err != nil {
				t.Fatal(err)
			}
			loaded, err := restarted.LoadOfflineTenantIntermediatesFromDir(dir)
			if err != nil {
				t.Fatal(err)
			}
			if loaded != 0 {
				t.Fatalf("restored %d issuer(s) despite invalid tombstone", loaded)
			}
			if _, err := restarted.LoadOfflineTenantIntermediate("tenant_northwind", root, intermediate, key); err == nil {
				t.Fatal("direct authority load bypassed invalid tombstone")
			}
		})
	}
}

func TestUnreadableRevocationDirectoryRefusesPreviouslyLoadedAndFetchedIssuers(t *testing.T) {
	now := time.Date(2026, 10, 23, 0, 0, 0, 0, time.UTC)
	issuer, err := NewNetworkExtensionLabTLSInterception([]string{"*"}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	root, intermediate, key, _ := tenantOfflineBundle(t, "Northwind", now)
	if _, err := issuer.LoadOfflineTenantIntermediate("tenant_northwind", root, intermediate, key); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "configured-revocation-store")
	if err := os.WriteFile(path, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := issuer.LoadOfflineTenantIntermediatesFromDir(path); err == nil {
		t.Fatal("unreadable revocation directory reported success")
	}
	if _, err := leafIssuerCN(t, issuer, "tenant_northwind", "example.com"); err == nil {
		t.Fatal("previously loaded issuer kept signing without readable revocations")
	}
	if _, err := issuer.LoadOfflineTenantIntermediate("tenant_northwind", root, intermediate, key); err == nil {
		t.Fatal("CP-fetched issuer could be loaded without readable revocations")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := issuer.LoadOfflineTenantIntermediatesFromDir(path); err != nil {
		t.Fatalf("could not clear guard after repairing store: %v", err)
	}
	if _, err := leafIssuerCN(t, issuer, "tenant_northwind", "example.com"); err != nil {
		t.Fatalf("repair did not restore the existing authority: %v", err)
	}
}
