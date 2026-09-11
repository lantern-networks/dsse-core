package edgeplane

import (
	"bytes"
	"crypto/x509"
	"strings"
	"testing"
	"time"
)

// TestPerTenantInterceptionRootsPersistAcrossRestart proves a per-tenant root is DURABLE: with a root dir set, a
// tenant's root loaded by a fresh engine (a restart) is the SAME root — otherwise it would regenerate and every
// device that trusted the old one would break. Also covers Provision (pre-distribution) returning that cert.
func TestPerTenantInterceptionRootsPersistAcrossRestart(t *testing.T) {
	now := func() time.Time { return time.Date(2026, 6, 28, 0, 0, 0, 0, time.UTC) }
	dir := t.TempDir()

	eng1, err := NewNetworkExtensionLabTLSInterception([]string{"*"}, now)
	if err != nil {
		t.Fatal(err)
	}
	eng1.SetPerTenantInterceptionRootDir(dir)
	eng1.EnablePerTenantInterceptionRoots("primary")
	// Provision returns the tenant root cert (for distribution) and persists it.
	info, err := eng1.ProvisionTenantInterceptionRoot("tenant-b")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(info.CertPEM, "BEGIN CERTIFICATE") || info.Tenant != "tenant-b" {
		t.Fatalf("provision returned no cert: %+v", info)
	}
	rootB1 := leafRootDER(t, eng1, "tenant-b", "host.example.com")

	// Simulate a restart: a fresh engine with the same root dir must resolve tenant-b to the SAME persisted root.
	eng2, err := NewNetworkExtensionLabTLSInterception([]string{"*"}, now)
	if err != nil {
		t.Fatal(err)
	}
	eng2.SetPerTenantInterceptionRootDir(dir)
	eng2.EnablePerTenantInterceptionRoots("primary")
	rootB2 := leafRootDER(t, eng2, "tenant-b", "host.example.com")
	if !bytes.Equal(rootB1, rootB2) {
		t.Fatal("per-tenant root did not persist across restart (it regenerated — device trust would break)")
	}
	if list := eng2.ListTenantInterceptionRoots(); len(list) == 0 {
		t.Fatal("ListTenantInterceptionRoots should include the loaded tenant-b root")
	}
}

func leafRootDER(t *testing.T, interception *NetworkExtensionLabTLSInterception, tenant, host string) []byte {
	t.Helper()
	leaf, err := interception.leafCertificate(tenant, host)
	if err != nil {
		t.Fatalf("leafCertificate(%q,%q): %v", tenant, host, err)
	}
	if len(leaf.Certificate) < 2 {
		t.Fatalf("leaf for (%q,%q) carries no root in its chain", tenant, host)
	}
	return leaf.Certificate[1] // chain is [leafDER, rootDER]
}

// TestPerTenantInterceptionRootsOffByDefaultShareOneRoot proves the SAFE default: with per-tenant isolation off
// (the default), every tenant's leaf is signed by the single default root — today's behavior, so the lab /
// North-Star trust (devices trust the one existing root) is unchanged.
func TestPerTenantInterceptionRootsOffByDefaultShareOneRoot(t *testing.T) {
	now := func() time.Time { return time.Date(2026, 6, 24, 0, 0, 0, 0, time.UTC) }
	interception, err := NewNetworkExtensionLabTLSInterception([]string{"*"}, now)
	if err != nil {
		t.Fatalf("new interception: %v", err)
	}
	rootA := leafRootDER(t, interception, "tenant-a", "example.com")
	rootB := leafRootDER(t, interception, "tenant-b", "other.example.com")
	if !bytes.Equal(rootA, rootB) {
		t.Fatal("per-tenant OFF: tenants got different roots (must share the one default root)")
	}
	if !bytes.Equal(rootA, interception.rootCert.Raw) {
		t.Fatal("per-tenant OFF: the leaf root is not the engine's default root")
	}
}

// TestPerTenantInterceptionRootsIsolateNonPrimaryTenants proves Slice 2: with per-tenant ON, the primary tenant
// keeps the default root (already-trusting devices unaffected) while every OTHER tenant gets its own distinct
// root that its leaf actually chains to — and a non-primary leaf does NOT verify against the default root, so a
// leaked tenant root can MITM only that tenant (blast-radius containment).
func TestPerTenantInterceptionRootsIsolateNonPrimaryTenants(t *testing.T) {
	now := func() time.Time { return time.Date(2026, 6, 24, 0, 0, 0, 0, time.UTC) }
	interception, err := NewNetworkExtensionLabTLSInterception([]string{"*"}, now)
	if err != nil {
		t.Fatalf("new interception: %v", err)
	}
	interception.EnablePerTenantInterceptionRoots("tenant-primary")

	defaultRoot := interception.rootCert.Raw
	if !bytes.Equal(leafRootDER(t, interception, "tenant-primary", "a.example.com"), defaultRoot) {
		t.Fatal("primary tenant must keep the default root (devices already trust it)")
	}
	if !bytes.Equal(leafRootDER(t, interception, "", "b.example.com"), defaultRoot) {
		t.Fatal("empty tenant must use the default root")
	}
	tenantBRoot := leafRootDER(t, interception, "tenant-b", "c.example.com")
	tenantCRoot := leafRootDER(t, interception, "tenant-c", "d.example.com")
	if bytes.Equal(tenantBRoot, defaultRoot) {
		t.Fatal("non-primary tenant-b must NOT use the default root (no isolation)")
	}
	if bytes.Equal(tenantBRoot, tenantCRoot) {
		t.Fatal("two different non-primary tenants must get DISTINCT roots")
	}

	// tenant-b's leaf must chain to tenant-b's root (the per-tenant signer really signed it)...
	leafB, err := interception.leafCertificate("tenant-b", "host.example.com")
	if err != nil {
		t.Fatalf("leaf tenant-b: %v", err)
	}
	leafX, err := x509.ParseCertificate(leafB.Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	rootX, err := x509.ParseCertificate(leafB.Certificate[1])
	if err != nil {
		t.Fatalf("parse tenant-b root: %v", err)
	}
	tenantPool := x509.NewCertPool()
	tenantPool.AddCert(rootX)
	if _, err := leafX.Verify(x509.VerifyOptions{Roots: tenantPool, DNSName: "host.example.com", CurrentTime: now(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		t.Fatalf("tenant-b leaf does not chain to tenant-b root: %v", err)
	}
	// ...and must NOT verify against the DEFAULT root — that is the isolation guarantee.
	defRootX, err := x509.ParseCertificate(defaultRoot)
	if err != nil {
		t.Fatalf("parse default root: %v", err)
	}
	defPool := x509.NewCertPool()
	defPool.AddCert(defRootX)
	if _, err := leafX.Verify(x509.VerifyOptions{Roots: defPool, DNSName: "host.example.com", CurrentTime: now(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err == nil {
		t.Fatal("tenant-b leaf verified against the DEFAULT root — per-tenant isolation is broken")
	}
}
