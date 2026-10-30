package main

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/edgeplane"
)

// Tenant IDs are case-sensitive identities; only DNS/SNI names are case-insensitive.
func caseDistinctTransportFixture(t *testing.T) *transportTenantCerts {
	t.Helper()
	useEmptyTenantCertificateIndex(t)
	for tenant, sni := range map[string]string{"TenantCase": "upper.example.test", "tenantcase": "lower.example.test"} {
		// macOS development volumes may be case-insensitive, so use a separate directory per tenant.
		dir := t.TempDir()
		writeTenantCert(t, dir, tenant, sni)
		if n, err := loadTransportTenantCertificates(dir); err != nil || n != 1 {
			t.Fatalf("load tenant %q: n=%d err=%v", tenant, n, err)
		}
	}
	return transportTenantCertificates
}

func TestCaseDistinctTransportTenantsKeepSeparateActiveCertificates(t *testing.T) {
	store := caseDistinctTransportFixture(t)
	upper, upperTenant, upperOK := store.For("UPPER.EXAMPLE.TEST")
	lower, lowerTenant, lowerOK := store.For("LOWER.EXAMPLE.TEST")
	if !upperOK || !lowerOK || upperTenant != "TenantCase" || lowerTenant != "tenantcase" {
		t.Fatalf("SNI ownership crossed tenant boundary: upper=%q/%v lower=%q/%v", upperTenant, upperOK, lowerTenant, lowerOK)
	}
	upperAnchor, upperOK := store.AnchorFingerprintFor("TenantCase")
	lowerAnchor, lowerOK := store.AnchorFingerprintFor("tenantcase")
	if !upperOK || !lowerOK || upperAnchor != certFingerprint(upper.Leaf) || lowerAnchor != certFingerprint(lower.Leaf) || upperAnchor == lowerAnchor {
		t.Fatal("case-distinct tenants did not retain their own transport anchors")
	}
	served := store.ServedTenants()
	if len(served) != 2 || served[0] != "TenantCase" || served[1] != "tenantcase" {
		t.Fatalf("case-distinct tenants collapsed in served inventory: %q", served)
	}
}

func TestCaseDistinctTransportTenantRefusalAndRemovalStayOwned(t *testing.T) {
	store := caseDistinctTransportFixture(t)
	store.Refuse("TenantCase", "test refusal")
	if _, refused := store.refusalFor("upper.example.test"); !refused {
		t.Fatal("requested tenant was not refused")
	}
	if _, refused := store.refusalFor("lower.example.test"); refused {
		t.Fatal("case-distinct tenant was also refused")
	}
	if dropped := store.StopServing("TenantCase"); dropped != 1 {
		t.Fatalf("removed %d names; only one tenant was requested", dropped)
	}
	if _, _, ok := store.For("lower.example.test"); !ok {
		t.Fatal("case-distinct tenant certificate was removed")
	}
	if _, ok := store.AnchorFor("tenantcase"); !ok {
		t.Fatal("case-distinct tenant anchor was removed")
	}
}

func TestCaseDistinctPendingTransportPromotionKeepsOtherTenantPending(t *testing.T) {
	store := caseDistinctTransportFixture(t)
	for tenant, sni := range map[string]string{"TenantCase": "upper-next.example.test", "tenantcase": "lower-next.example.test"} {
		dir := t.TempDir()
		writeTenantCert(t, dir, tenant, sni)
		pair, err := tls.LoadX509KeyPair(filepath.Join(dir, tenant+".crt"), filepath.Join(dir, tenant+".key"))
		if err != nil {
			t.Fatal(err)
		}
		pair.Leaf, err = x509.ParseCertificate(pair.Certificate[0])
		if err != nil {
			t.Fatal(err)
		}
		anchor, err := os.ReadFile(filepath.Join(dir, tenant+".crt"))
		if err != nil {
			t.Fatal(err)
		}
		store.putPending(tenant, pair.Leaf.DNSNames, &pair, string(anchor))
	}
	upperPending := store.PendingFingerprintFor("TenantCase")
	lowerPending := store.PendingFingerprintFor("tenantcase")
	if upperPending == "" || lowerPending == "" || upperPending == lowerPending {
		t.Fatal("case-distinct pending authorities were collapsed")
	}
	if !store.PromotePending("TenantCase") {
		t.Fatal("upper tenant pending material was not promoted")
	}
	if store.PendingFingerprintFor("tenantcase") != lowerPending {
		t.Fatal("lower tenant pending authority changed during upper promotion")
	}
	if _, owner, ok := store.For("upper-next.example.test"); !ok || owner != "TenantCase" {
		t.Fatalf("promoted name owner=%q present=%v", owner, ok)
	}
}

func TestCaseDistinctFetcherAnswerAndHeldDeadlines(t *testing.T) {
	f := &tenantTransportMaterialFetcher{}
	known := map[string]bool{"TenantCase": true}
	f.lastAnswer.Store(&known)
	if f.OrganizationIsGone("TenantCase") || !f.OrganizationIsGone("tenantcase") {
		t.Fatal("case-distinct organization presence was collapsed")
	}
	upper := time.Now().Add(time.Hour)
	lower := time.Now().Add(2 * time.Hour)
	f.recordHeld("device", "TenantCase", upper)
	f.recordHeld("device", "tenantcase", lower)
	if len(f.held) != 2 {
		t.Fatal("case-distinct held deadlines were collapsed")
	}
	f.forgetHeld("TenantCase")
	if len(f.held) != 1 || !f.heldDeadline().Equal(lower) {
		t.Fatal("forgetting one tenant removed the other tenant's deadline")
	}
}

func TestCaseDistinctFleetAnnouncementDoesNotPromoteOtherTenant(t *testing.T) {
	store := caseDistinctTransportFixture(t)
	dir := t.TempDir()
	writeTenantCert(t, dir, "TenantCase", "upper-next.example.test")
	pair, err := tls.LoadX509KeyPair(filepath.Join(dir, "TenantCase.crt"), filepath.Join(dir, "TenantCase.key"))
	if err != nil {
		t.Fatal(err)
	}
	pair.Leaf, err = x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	anchor, err := os.ReadFile(filepath.Join(dir, "TenantCase.crt"))
	if err != nil {
		t.Fatal(err)
	}
	store.putPending("TenantCase", pair.Leaf.DNSNames, &pair, string(anchor))
	pending := store.PendingFingerprintFor("TenantCase")
	b := newPerTenantTrustBundles(serverConfig{}, "")
	b.CatchUpWithTheFleet("TenantCase", "tenantcase="+pending)
	if store.PendingFingerprintFor("TenantCase") != pending {
		t.Fatal("case-distinct fleet announcement promoted another tenant's authority")
	}
}

func TestCaseDistinctFetcherDoesNotWithdrawOtherTenantPendingAuthority(t *testing.T) {
	store := caseDistinctTransportFixture(t)
	dir := t.TempDir()
	writeTenantCert(t, dir, "TenantCase", "upper-next.example.test")
	pair, err := tls.LoadX509KeyPair(filepath.Join(dir, "TenantCase.crt"), filepath.Join(dir, "TenantCase.key"))
	if err != nil {
		t.Fatal(err)
	}
	pair.Leaf, err = x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	anchor, err := os.ReadFile(filepath.Join(dir, "TenantCase.crt"))
	if err != nil {
		t.Fatal(err)
	}
	store.putPending("TenantCase", pair.Leaf.DNSNames, &pair, string(anchor))
	pending := store.PendingFingerprintFor("TenantCase")
	f := &tenantTransportMaterialFetcher{log: func(string, ...any) {}}
	f.withdrawAuthoritiesTheControlPlaneNoLongerSends([]tenantTransportMaterial{
		{TenantID: "tenantcase", AnchorPEM: "lower tenant authority"},
	}, 0, "")
	if store.PendingFingerprintFor("TenantCase") != pending {
		t.Fatal("other tenant's complete answer withdrew this tenant's pending authority")
	}
}

func TestCaseDistinctTenantInterceptionIssuerNotShared(t *testing.T) {
	now := time.Date(2026, 10, 23, 0, 0, 0, 0, time.UTC)
	interception, err := edgeplane.NewNetworkExtensionLabTLSInterception([]string{"*"}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	root, intermediate, key := offlineTenantBundleForTest(t, "Case Root", now)
	if _, err := interception.LoadOfflineTenantIntermediate("TenantCase", root, intermediate, key); err != nil {
		t.Fatal(err)
	}
	config := serverConfig{NetworkExtensionLabTLS: interception}
	if !tenantHasItsOwnInterceptionIssuer(config, "TenantCase") {
		t.Fatal("own interception issuer is missing")
	}
	if tenantHasItsOwnInterceptionIssuer(config, "tenantcase") || tenantHasCentralInterceptionAuthority(config, "tenantcase") {
		t.Fatal("case-distinct tenant inherited another tenant's interception issuer")
	}
	upperFingerprint := fingerprintOfPEMForTest(t, root)
	upper := interceptionRootFingerprintsForTenant(config, "TenantCase", "tenantcase")
	lower := interceptionRootFingerprintsForTenant(config, "tenantcase", "tenantcase")
	if len(upper) != 1 || upper[0] != upperFingerprint {
		t.Fatal("own interception root was not announced")
	}
	for _, fingerprint := range lower {
		if fingerprint == upperFingerprint {
			t.Fatal("case-distinct tenant was announced another tenant's interception root")
		}
	}
}
