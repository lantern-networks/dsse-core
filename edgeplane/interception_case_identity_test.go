package edgeplane

import (
	"bytes"
	"os"
	"testing"
	"time"
)

func TestInterceptionSigningKeepsCaseDistinctTenantIdentities(t *testing.T) {
	now := time.Date(2026, 10, 23, 0, 0, 0, 0, time.UTC)
	engine, err := NewNetworkExtensionLabTLSInterception([]string{"*"}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ tenant, name string }{{"Acme", "Upper"}, {"acme", "Lower"}} {
		root, issuer, key, _ := tenantOfflineBundle(t, tc.name, now)
		if _, err := engine.LoadOfflineTenantIntermediate(tc.tenant, root, issuer, key); err != nil {
			t.Fatal(err)
		}
	}
	upper, err := leafIssuerCN(t, engine, "Acme", "example.com")
	if err != nil {
		t.Fatal(err)
	}
	lower, err := leafIssuerCN(t, engine, "acme", "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if upper != "Upper Interception Issuing CA" || lower != "Lower Interception Issuing CA" {
		t.Fatalf("case-distinct tenants shared one issuer: upper=%q lower=%q", upper, lower)
	}
}

func TestPerTenantRootFilesDoNotAliasValidTenantIDs(t *testing.T) {
	now := func() time.Time { return time.Date(2026, 10, 23, 0, 0, 0, 0, time.UTC) }
	dir := t.TempDir()
	engine, err := NewNetworkExtensionLabTLSInterception([]string{"*"}, now)
	if err != nil {
		t.Fatal(err)
	}
	engine.SetPerTenantInterceptionRootDir(dir)
	engine.EnablePerTenantInterceptionRoots("primary")
	for _, tenant := range []string{"Acme:prod", "Acme_prod"} {
		if _, err := engine.ProvisionTenantInterceptionRoot(tenant); err != nil {
			t.Fatal(err)
		}
	}
	restarted, err := NewNetworkExtensionLabTLSInterception([]string{"*"}, now)
	if err != nil {
		t.Fatal(err)
	}
	restarted.SetPerTenantInterceptionRootDir(dir)
	restarted.EnablePerTenantInterceptionRoots("primary")
	seen := map[string]bool{}
	for _, row := range restarted.ListTenantInterceptionRoots() {
		seen[row.Tenant] = true
	}
	if !seen["Acme:prod"] || !seen["Acme_prod"] {
		t.Fatalf("durable inventory lost one tenant: %v", seen)
	}
	a := leafRootDER(t, restarted, "Acme:prod", "example.com")
	b := leafRootDER(t, restarted, "Acme_prod", "example.com")
	if bytes.Equal(a, b) {
		t.Fatal("two valid tenant IDs reused the same durable interception root")
	}
}

func TestInterceptionDurableFilesDoNotAliasValidTenantIDs(t *testing.T) {
	now := time.Date(2026, 10, 23, 0, 0, 0, 0, time.UTC)
	dir := t.TempDir()
	engine, err := NewNetworkExtensionLabTLSInterception([]string{"*"}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	engine.SetOfflineTenantIntermediateDir(dir)
	for _, tc := range []struct{ tenant, name string }{{"Acme:prod", "Colon"}, {"Acme_prod", "Underscore"}} {
		root, issuer, key, _ := tenantOfflineBundle(t, tc.name, now)
		if _, err := engine.LoadOfflineTenantIntermediate(tc.tenant, root, issuer, key); err != nil {
			t.Fatal(err)
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, entry := range entries {
		if len(entry.Name()) > len(".root.pem") && entry.Name()[len(entry.Name())-len(".root.pem"):] == ".root.pem" {
			count++
		}
	}
	if count != 2 {
		t.Fatalf("two valid tenant IDs shared one durable root file; found %d among %d entries", count, len(entries))
	}
	restarted, err := NewNetworkExtensionLabTLSInterception([]string{"*"}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	if loaded, err := restarted.LoadOfflineTenantIntermediatesFromDir(dir); err != nil || loaded != 2 {
		t.Fatalf("restore distinct authorities: loaded=%d err=%v", loaded, err)
	}
	for _, tc := range []struct{ tenant, issuer string }{{"Acme:prod", "Colon Interception Issuing CA"}, {"Acme_prod", "Underscore Interception Issuing CA"}} {
		got, err := leafIssuerCN(t, restarted, tc.tenant, "example.com")
		if err != nil || got != tc.issuer {
			t.Fatalf("tenant %q restored issuer=%q err=%v", tc.tenant, got, err)
		}
	}
}
