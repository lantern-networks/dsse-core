package edgeplane

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

// tenantOfflineBundle mints a self-signed ROOT for one organization and an intermediate under it — the
// out-of-band ceremony a customer's own PKI performs, reduced to what this test needs. The root key is
// discarded: the Edge must never hold it, and a test that kept it would be testing a different product.
func tenantOfflineBundle(t *testing.T, org string, now time.Time) (rootPEM, interPEM, keyPEM []byte, rootCert *x509.Certificate) {
	t.Helper()
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("root key: %v", err)
	}
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(now.UnixNano()),
		Subject:               pkix.Name{Organization: []string{org}, CommonName: org + " Interception Root"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("root cert: %v", err)
	}
	rootCert, err = x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatalf("parse root: %v", err)
	}

	interKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("intermediate key: %v", err)
	}
	interTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(now.UnixNano() + 1),
		Subject:               pkix.Name{Organization: []string{org}, CommonName: org + " Interception Issuing CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(12 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	interDER, err := x509.CreateCertificate(rand.Reader, interTemplate, rootCert, &interKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("intermediate cert: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(interKey)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: interDER}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
		rootCert
}

func leafIssuerCN(t *testing.T, interception *NetworkExtensionLabTLSInterception, tenant, host string) (string, error) {
	t.Helper()
	cert, err := interception.leafCertificate(tenant, host)
	if err != nil {
		return "", err
	}
	parsed, perr := x509.ParseCertificate(cert.Certificate[0])
	if perr != nil {
		t.Fatalf("parse leaf: %v", perr)
	}
	return parsed.Issuer.CommonName, nil
}

// ★ PER-TENANT INTERCEPTION BECOMES REAL HERE (2026-08-16). Before this, an Edge could hold a per-tenant root
// for every organization it served and still sign every leaf with ONE shared intermediate: issuerFor returned
// the offline issuer before the per-tenant root was consulted, and startup refused the combination outright.
// Measured on the reference lab with two organizations, each holding a durable root that signed nothing.
//
// The claim being tested is the product claim: a device belonging to organization A is shown a certificate
// issued under A's own CA, and organization B's CA never appears in front of A's device.
func TestEachTenantsLeafIsSignedByItsOwnOfflineIntermediate(t *testing.T) {
	now := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	interception, err := NewNetworkExtensionLabTLSInterception([]string{"*"}, func() time.Time { return now })
	if err != nil {
		t.Fatalf("interception: %v", err)
	}
	for _, org := range []string{"Acme", "Northwind"} {
		rootPEM, interPEM, keyPEM, _ := tenantOfflineBundle(t, org, now)
		if _, err := interception.LoadOfflineTenantIntermediate("tenant_"+strings.ToLower(org), rootPEM, interPEM, keyPEM); err != nil {
			t.Fatalf("load %s: %v", org, err)
		}
	}

	acme, err := leafIssuerCN(t, interception, "tenant_acme", "example.com")
	if err != nil {
		t.Fatalf("acme leaf: %v", err)
	}
	northwind, err := leafIssuerCN(t, interception, "tenant_northwind", "example.com")
	if err != nil {
		t.Fatalf("northwind leaf: %v", err)
	}

	if acme != "Acme Interception Issuing CA" {
		t.Fatalf("acme's device was shown a certificate from %q", acme)
	}
	if northwind != "Northwind Interception Issuing CA" {
		t.Fatalf("northwind's device was shown a certificate from %q", northwind)
	}
	// ★ THE SAME HOST, WHICH IS THE TRAP. The leaf cache is keyed by the ROOT REGISTRY's tenant, and that is ""
	// for everybody while the registry is in shared scope — so without a cache scope of its own, the second
	// request would be served Acme's cached certificate for example.com. The separation would exist at the
	// signing step and be undone one line later by a map lookup, and it would look perfect in any test that
	// used two different hostnames.
	if acme == northwind {
		t.Fatal("both organizations were served the same issuer for the same host — the leaf cache crossed the boundary")
	}
}

// ★ AND AN ORGANIZATION WITHOUT ONE IS NEVER SIGNED UNDER ANOTHER CUSTOMER'S CA. That is the sharp edge of the
// feature: falling back to a NAMED customer's authority would mint, in customer A's name, the certificate
// customer B's browser is shown — and it would SUCCEED, so nothing looks wrong until somebody reads a
// certificate.
//
// ★★★ IT IS SIGNED UNDER THIS DEPLOYMENT'S OWN ROOT, WHICH IS NOT THE SAME THING (corrected 2026-08-28, after
// the original rule was measured on a two-region lab). This used to refuse outright, and the refusal took
// inspection away from every organization on the node the moment ONE of them was given its own root — the
// deployment's own organization included. Nothing said so: the refusal was handed to the TLS stack, which turned
// it into an `internal error` alert, and every site on those devices failed at once.
//
// An organization that has not been given its own authority is inspected under the deployment's — that is the
// sentence /admin/tenant-interception-authority returns to the customer, and the anchor every device of this
// deployment already trusts. The boundary this test protects is "never another CUSTOMER's CA", not "never any
// CA but its own".
func TestATenantWithNoIntermediateIsNeverSignedUnderAnotherCustomersCA(t *testing.T) {
	now := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	interception, err := NewNetworkExtensionLabTLSInterception([]string{"*"}, func() time.Time { return now })
	if err != nil {
		t.Fatalf("interception: %v", err)
	}
	rootPEM, interPEM, keyPEM, _ := tenantOfflineBundle(t, "Acme", now)
	if _, err := interception.LoadOfflineTenantIntermediate("tenant_acme", rootPEM, interPEM, keyPEM); err != nil {
		t.Fatalf("load: %v", err)
	}

	unprovisioned, err := leafIssuerCN(t, interception, "tenant_unprovisioned", "example.com")
	if err != nil {
		t.Fatalf("an organization with no authority of its own lost interception entirely because ANOTHER "+
			"organization was given one — every site on its devices fails at once, and the reason reaches the "+
			"wire as `internal error`: %v", err)
	}
	if strings.Contains(unprovisioned, "Acme") {
		t.Fatalf("it was signed under another customer's CA (%q) — that certificate is minted in Acme's name and "+
			"shown to somebody else's browser", unprovisioned)
	}
	// The provisioned one still gets its own, which is the separation this feature exists for.
	if cn, err := leafIssuerCN(t, interception, "tenant_acme", "example.com"); err != nil || cn != "Acme Interception Issuing CA" {
		t.Fatalf("the provisioned organization lost interception too: %q %v", cn, err)
	}
	if unprovisioned == "Acme Interception Issuing CA" {
		t.Fatal("both organizations were served the same issuer — the boundary is gone")
	}
}

// Turning per-tenant signing on must not break the organization that was already working: the node-wide
// intermediate keeps serving the tenant it belongs to, whose devices already trust that anchor.
func TestThePrimaryTenantKeepsTheAnchorItsDevicesAlreadyTrust(t *testing.T) {
	now := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	rootPEM, interPEM, keyPEM, _ := tenantOfflineBundle(t, "Operator", now)
	interception, err := NewNetworkExtensionLabTLSInterceptionOfflineIntermediate(
		[]string{"*"}, func() time.Time { return now }, rootPEM, interPEM, keyPEM, "")
	if err != nil {
		t.Fatalf("offline interception: %v", err)
	}
	interception.SetOfflinePrimaryTenant("tenant_lab")
	nwRoot, nwInter, nwKey, _ := tenantOfflineBundle(t, "Northwind", now)
	if _, err := interception.LoadOfflineTenantIntermediate("tenant_northwind", nwRoot, nwInter, nwKey); err != nil {
		t.Fatalf("load northwind: %v", err)
	}

	primary, err := leafIssuerCN(t, interception, "tenant_lab", "example.com")
	if err != nil {
		t.Fatalf("the organization that was already working lost interception: %v", err)
	}
	if primary != "Operator Interception Issuing CA" {
		t.Fatalf("the primary tenant's issuer changed to %q — its devices trust the old anchor", primary)
	}
	if nw, err := leafIssuerCN(t, interception, "tenant_northwind", "example.com"); err != nil || nw != "Northwind Interception Issuing CA" {
		t.Fatalf("northwind = %q %v", nw, err)
	}
	// ★ REVERSED ON 2026-08-18, AND THE REASONING IT REPLACES IS WORTH KEEPING. This asserted that a flow
	// whose tenant did not resolve keeps the node-wide intermediate, because "a device that is not the
	// primary's cannot be fooled by it anyway — it does not trust that anchor". True, and it leaves out the
	// case that matters: the PRIMARY's own devices do trust it, and they are precisely the devices whose
	// unattributed flows arrive here. The one situation where it has any effect is the one where it works.
	//
	// The other half of the old argument — that refusing turns an attribution gap into an outage — was a real
	// risk and was settled by measuring rather than by arguing. With the counter in place the reference lab
	// signed 33 leaves and never once took this path, so there was no outage to trade against.
	if unattributed, err := leafIssuerCN(t, interception, "", "example.com"); err == nil {
		t.Fatalf("an unattributed flow was signed under %q, a named organization's authority", unattributed)
	}

	scope := interception.InterceptionRootScope()
	if !scope.PerTenantSigning || scope.Effective != "per_tenant_offline_intermediate" {
		t.Fatalf("scope does not report per-tenant signing: %+v", scope)
	}
}

// A bundle must survive a restart. The per-tenant ROOTS shipped without this once and were found only by
// restarting: provisioned, listed, distributed, gone. Here the consequence would be worse than an empty list —
// the node would return to REFUSING an organization it was serving five seconds earlier.
func TestALoadedTenantIntermediateSurvivesARestart(t *testing.T) {
	now := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	dir := t.TempDir()
	first, err := NewNetworkExtensionLabTLSInterception([]string{"*"}, func() time.Time { return now })
	if err != nil {
		t.Fatalf("interception: %v", err)
	}
	first.SetOfflineTenantIntermediateDir(dir)
	rootPEM, interPEM, keyPEM, _ := tenantOfflineBundle(t, "Northwind", now)
	if _, err := first.LoadOfflineTenantIntermediate("tenant_northwind", rootPEM, interPEM, keyPEM); err != nil {
		t.Fatalf("load: %v", err)
	}

	second, err := NewNetworkExtensionLabTLSInterception([]string{"*"}, func() time.Time { return now })
	if err != nil {
		t.Fatalf("restart: %v", err)
	}
	loaded, err := second.LoadOfflineTenantIntermediatesFromDir(dir)
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if loaded != 1 {
		t.Fatalf("restored %d bundles from %s", loaded, dir)
	}
	if cn, err := leafIssuerCN(t, second, "tenant_northwind", "example.com"); err != nil || cn != "Northwind Interception Issuing CA" {
		t.Fatalf("after restart the organization is served by %q (%v)", cn, err)
	}
}

// ★ THE KEY FILE AN OPERATOR ACTUALLY HAS (2026-08-16). `openssl ecparam -genkey` — the canonical way to make
// an EC key — writes an `EC PARAMETERS` block before the key. The parser read only the first PEM block, so the
// most ordinary key file in existence was rejected as "unrecognized private key format", which reads as "your
// key is broken". Found while onboarding a real tenant's issuing CA on the lab, at the last step.
func TestAnECKeyWithParametersAheadOfItIsAccepted(t *testing.T) {
	now := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	interception, err := NewNetworkExtensionLabTLSInterception([]string{"*"}, func() time.Time { return now })
	if err != nil {
		t.Fatalf("interception: %v", err)
	}
	rootPEM, interPEM, keyPEM, _ := tenantOfflineBundle(t, "Northwind", now)
	// Exactly what openssl writes: parameters first, key second.
	withParams := append([]byte("-----BEGIN EC PARAMETERS-----\nBggqhkjOPQMBBw==\n-----END EC PARAMETERS-----\n"), keyPEM...)

	if _, err := interception.LoadOfflineTenantIntermediate("tenant_northwind", rootPEM, interPEM, withParams); err != nil {
		t.Fatalf("a key generated the standard way was rejected: %v", err)
	}
	if cn, err := leafIssuerCN(t, interception, "tenant_northwind", "example.com"); err != nil || cn != "Northwind Interception Issuing CA" {
		t.Fatalf("issuer = %q %v", cn, err)
	}
}

// ★ REPLACING AN ORGANIZATION'S AUTHORITY MUST NOT BE A FLAG DAY (2026-08-16, the day after the device-side
// pin shipped). A tenant announced exactly one root — whichever its current issuer chained to — so loading a
// replacement switched the announced set instantly, and every device of that organization still pinned to the
// previous root went from satisfied to mismatch at the same moment. With the pin armed, the whole fleet stands
// aside together. The agent's own rule that an OVERLAP is a match could never fire, because the Edge had no
// way to name two.
func TestReplacingATenantsAuthorityKeepsThePreviousOneAnnounced(t *testing.T) {
	now := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	interception, err := NewNetworkExtensionLabTLSInterception([]string{"*"}, func() time.Time { return now })
	if err != nil {
		t.Fatalf("interception: %v", err)
	}
	oldRoot, oldInter, oldKey, oldCert := tenantOfflineBundle(t, "Northwind", now)
	if _, err := interception.LoadOfflineTenantIntermediate("tenant_northwind", oldRoot, oldInter, oldKey); err != nil {
		t.Fatalf("load first: %v", err)
	}
	newRoot, newInter, newKey, newCert := tenantOfflineBundle(t, "Northwind Next", now)
	if _, err := interception.LoadOfflineTenantIntermediate("tenant_northwind", newRoot, newInter, newKey); err != nil {
		t.Fatalf("load replacement: %v", err)
	}

	announced := interception.OfflineTenantAnnouncedRoots("tenant_northwind")

	if len(announced) != 2 {
		t.Fatalf("announced %d root(s); a replacement must name the new one AND the one devices are moving off", len(announced))
	}
	// The signing one first: an operator reading the list has to know which is actually in use.
	if !announced[0].Equal(newCert) {
		t.Fatalf("the first announced root is %q, not the one now signing", announced[0].Subject.CommonName)
	}
	if !announced[1].Equal(oldCert) {
		t.Fatalf("the previous authority is not being announced — every device still pinned to it would stand aside")
	}
	// And the traffic really has moved to the new authority: announcing both must not mean signing with both.
	if cn, err := leafIssuerCN(t, interception, "tenant_northwind", "example.com"); err != nil ||
		cn != "Northwind Next Interception Issuing CA" {
		t.Fatalf("leaves are signed by %q (%v) — the replacement did not take effect", cn, err)
	}
}

// Withdrawing is how the overlap ENDS, and it must refuse the one thing that would turn it into an outage:
// withdrawing the root that is currently signing tells every device of that organization to stop looking for
// the only certificate its own traffic uses.
func TestWithdrawingEndsTheOverlapAndRefusesTheSigningRoot(t *testing.T) {
	now := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	dir := t.TempDir()
	interception, err := NewNetworkExtensionLabTLSInterception([]string{"*"}, func() time.Time { return now })
	if err != nil {
		t.Fatalf("interception: %v", err)
	}
	interception.SetOfflineTenantIntermediateDir(dir)
	oldRoot, oldInter, oldKey, oldCert := tenantOfflineBundle(t, "Northwind", now)
	_, _ = interception.LoadOfflineTenantIntermediate("tenant_northwind", oldRoot, oldInter, oldKey)
	newRoot, newInter, newKey, newCert := tenantOfflineBundle(t, "Northwind Next", now)
	_, _ = interception.LoadOfflineTenantIntermediate("tenant_northwind", newRoot, newInter, newKey)

	if _, err := interception.WithdrawRetiringTenantRoot("tenant_northwind", interceptionCertSHA256Hex(newCert)); err == nil {
		t.Fatal("withdrawing the root that is currently signing was allowed — that is an outage, not a withdrawal")
	}

	removed, err := interception.WithdrawRetiringTenantRoot("tenant_northwind", interceptionCertSHA256Hex(oldCert))
	if err != nil || !removed {
		t.Fatalf("withdrawing the retiring root: removed=%v err=%v", removed, err)
	}
	announced := interception.OfflineTenantAnnouncedRoots("tenant_northwind")
	if len(announced) != 1 || !announced[0].Equal(newCert) {
		t.Fatalf("after the withdrawal the organization is told to look for %d root(s)", len(announced))
	}
}

// ★ AND THE OVERLAP SURVIVES A RESTART. Without that, a redeploy in the middle of a replacement silently ends
// it — the node comes back announcing only the new root, and every device still on the previous one stands
// aside. The flag day arrives anyway, by way of an unrelated restart.
func TestTheOverlapSurvivesARestart(t *testing.T) {
	now := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	dir := t.TempDir()
	first, err := NewNetworkExtensionLabTLSInterception([]string{"*"}, func() time.Time { return now })
	if err != nil {
		t.Fatalf("interception: %v", err)
	}
	first.SetOfflineTenantIntermediateDir(dir)
	oldRoot, oldInter, oldKey, oldCert := tenantOfflineBundle(t, "Northwind", now)
	_, _ = first.LoadOfflineTenantIntermediate("tenant_northwind", oldRoot, oldInter, oldKey)
	newRoot, newInter, newKey, _ := tenantOfflineBundle(t, "Northwind Next", now)
	_, _ = first.LoadOfflineTenantIntermediate("tenant_northwind", newRoot, newInter, newKey)

	second, err := NewNetworkExtensionLabTLSInterception([]string{"*"}, func() time.Time { return now })
	if err != nil {
		t.Fatalf("restart: %v", err)
	}
	if _, err := second.LoadOfflineTenantIntermediatesFromDir(dir); err != nil {
		t.Fatalf("restore: %v", err)
	}

	announced := second.OfflineTenantAnnouncedRoots("tenant_northwind")
	found := false
	for _, cert := range announced {
		if cert.Equal(oldCert) {
			found = true
		}
	}
	if !found {
		t.Fatalf("after a restart the organization is told to look for %d root(s) and the one its devices are "+
			"still pinned to is not among them", len(announced))
	}
}

// ★ A REFUSAL MUST CHECK WHAT IT CLAIMS (2026-08-16, found by running it). Retiring a provisioned per-tenant
// root refused "the node's primary tenant, whose root is the deployment anchor" — by comparing the tenant NAME
// against primaryTenant, which is only ever set when per-tenant scope is enabled. On a deployment with that
// scope off, which is exactly where this route gets used, the comparison was against an empty string and the
// guard passed everything while its message said it had protected the anchor.
func TestRetiringTheAnchorCertificateIsRefusedEvenWithNoPrimaryTenantSet(t *testing.T) {
	now := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	interception, err := NewNetworkExtensionLabTLSInterception([]string{"*"}, func() time.Time { return now })
	if err != nil {
		t.Fatalf("interception: %v", err)
	}
	// No EnablePerTenant*, so primaryTenant is "" — the state the old guard could not see.
	registry := interception.rootRegistry
	registry.mu.Lock()
	registry.providers["tenant_anchor_holder"] = registry.defaultProvider
	registry.mu.Unlock()

	retired, err := interception.RetireTenantInterceptionRoot("tenant_anchor_holder")

	if retired || err == nil {
		t.Fatalf("the anchor certificate was retired through the per-tenant route (retired=%v err=%v)", retired, err)
	}
	if !strings.Contains(err.Error(), "anchor") {
		t.Fatalf("the refusal does not say what it protected: %v", err)
	}
}

// And an ordinary provisioned root, which signs nothing while the scope is shared, is retired — a guard that
// refuses everything would leave the same-name collisions it exists to clear.
func TestAProvisionedRootThatSignsNothingCanBeRetired(t *testing.T) {
	now := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	interception, err := NewNetworkExtensionLabTLSInterception([]string{"*"}, func() time.Time { return now })
	if err != nil {
		t.Fatalf("interception: %v", err)
	}
	interception.SetPerTenantInterceptionRootDir(t.TempDir())
	if _, err := interception.ProvisionTenantInterceptionRoot("tenant_spare"); err != nil {
		t.Fatalf("provision: %v", err)
	}

	retired, err := interception.RetireTenantInterceptionRoot("tenant_spare")

	if !retired || err != nil {
		t.Fatalf("a provisioned root that signs nothing could not be retired: %v %v", retired, err)
	}
	// Gone from the listing too, or an operator is told it still exists.
	for _, info := range interception.ListTenantInterceptionRoots() {
		if info.Tenant == "tenant_spare" {
			t.Fatal("the retired root is still listed")
		}
	}
}

// ★ REVOCATION IS THE OPPOSITE OF WITHDRAWAL, ON PURPOSE (2026-08-16). Withdrawal ends a planned replacement
// and refuses to touch the root currently signing, because telling an organization's devices to stop looking
// for the certificate their traffic uses is an outage. A leaked key inverts that: the outage is the correct
// outcome, and continuing to sign with a key somebody else may hold is not.
func TestRevokingAnAuthorityStopsSigningAndCannotBeUndoneByReloading(t *testing.T) {
	now := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	dir := t.TempDir()
	interception, err := NewNetworkExtensionLabTLSInterception([]string{"*"}, func() time.Time { return now })
	if err != nil {
		t.Fatalf("interception: %v", err)
	}
	interception.SetOfflineTenantIntermediateDir(dir)
	rootPEM, interPEM, keyPEM, rootCert := tenantOfflineBundle(t, "Northwind", now)
	if _, err := interception.LoadOfflineTenantIntermediate("tenant_northwind", rootPEM, interPEM, keyPEM); err != nil {
		t.Fatalf("load: %v", err)
	}
	if _, err := leafIssuerCN(t, interception, "tenant_northwind", "example.com"); err != nil {
		t.Fatalf("the organization was not being intercepted before the revocation: %v", err)
	}

	revoked, err := interception.RevokeTenantInterceptionAuthority("tenant_northwind", "key exposed in a build log")
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}

	if len(revoked) != 1 || revoked[0] != interceptionCertSHA256Hex(rootCert) {
		t.Fatalf("revoked %v; the authority in force must be among them", revoked)
	}
	// FAIL-CLOSED: not intercepted, rather than intercepted under a key somebody else may hold.
	if _, err := leafIssuerCN(t, interception, "tenant_northwind", "example.com"); err == nil {
		t.Fatal("the organization is still being intercepted after its authority was revoked")
	}
	// ★ And it does not come back. Without this the revocation removes the loaded issuer and nothing else: the
	// next restore, or an operator repeating the onboarding call, installs the compromised key again and the
	// log says "loaded" like any other day.
	if _, err := interception.LoadOfflineTenantIntermediate("tenant_northwind", rootPEM, interPEM, keyPEM); err == nil {
		t.Fatal("a revoked authority was loaded again")
	}
	if reason := interception.RevokedTenantInterceptionRoots()[interceptionCertSHA256Hex(rootCert)]; reason == "" {
		t.Fatal("the node cannot say why that authority is refused")
	}
}

// A revocation a restart forgets is the worst of both: the operator believes the key is dead and the node
// quietly starts using it again at the next boot.
func TestARevocationSurvivesARestart(t *testing.T) {
	now := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	dir := t.TempDir()
	first, err := NewNetworkExtensionLabTLSInterception([]string{"*"}, func() time.Time { return now })
	if err != nil {
		t.Fatalf("interception: %v", err)
	}
	first.SetOfflineTenantIntermediateDir(dir)
	rootPEM, interPEM, keyPEM, rootCert := tenantOfflineBundle(t, "Northwind", now)
	if _, err := first.LoadOfflineTenantIntermediate("tenant_northwind", rootPEM, interPEM, keyPEM); err != nil {
		t.Fatalf("load: %v", err)
	}
	if _, err := first.RevokeTenantInterceptionAuthority("tenant_northwind", "key exposed"); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	second, err := NewNetworkExtensionLabTLSInterception([]string{"*"}, func() time.Time { return now })
	if err != nil {
		t.Fatalf("restart: %v", err)
	}
	if _, err := second.LoadOfflineTenantIntermediatesFromDir(dir); err != nil {
		t.Fatalf("restore: %v", err)
	}

	if reason := second.RevokedTenantInterceptionRoots()[interceptionCertSHA256Hex(rootCert)]; reason == "" {
		t.Fatal("after a restart this node no longer knows the authority was revoked")
	}
	if _, err := second.LoadOfflineTenantIntermediate("tenant_northwind", rootPEM, interPEM, keyPEM); err == nil {
		t.Fatal("the revoked authority became loadable again across a restart")
	}
}

// A revocation carries a REASON, because it is read months later by somebody deciding whether the authority
// may come back, and "revoked" alone does not answer that.
func TestARevocationWithoutAReasonIsRefused(t *testing.T) {
	now := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	interception, err := NewNetworkExtensionLabTLSInterception([]string{"*"}, func() time.Time { return now })
	if err != nil {
		t.Fatalf("interception: %v", err)
	}
	rootPEM, interPEM, keyPEM, _ := tenantOfflineBundle(t, "Northwind", now)
	if _, err := interception.LoadOfflineTenantIntermediate("tenant_northwind", rootPEM, interPEM, keyPEM); err != nil {
		t.Fatalf("load: %v", err)
	}

	if _, err := interception.RevokeTenantInterceptionAuthority("tenant_northwind", "   "); err == nil {
		t.Fatal("an authority was revoked with no reason recorded")
	}
	// And the organization is untouched by the refusal — a rejected revocation must not half-revoke.
	if _, err := leafIssuerCN(t, interception, "tenant_northwind", "example.com"); err != nil {
		t.Fatalf("a refused revocation stopped the interception anyway: %v", err)
	}
}

// Revocation must not be a one-way door for the ORGANIZATION, only for the compromised key: a replacement
// authority is exactly what ends the fail-closed state, and a node that refused it would leave the customer
// permanently un-intercepted for having reported a leak.
func TestAReplacementAuthorityEndsTheRevokedState(t *testing.T) {
	now := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	interception, err := NewNetworkExtensionLabTLSInterception([]string{"*"}, func() time.Time { return now })
	if err != nil {
		t.Fatalf("interception: %v", err)
	}
	oldRoot, oldInter, oldKey, _ := tenantOfflineBundle(t, "Northwind", now)
	if _, err := interception.LoadOfflineTenantIntermediate("tenant_northwind", oldRoot, oldInter, oldKey); err != nil {
		t.Fatalf("load: %v", err)
	}
	if _, err := interception.RevokeTenantInterceptionAuthority("tenant_northwind", "key exposed"); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	newRoot, newInter, newKey, _ := tenantOfflineBundle(t, "Northwind Recovered", now)
	if _, err := interception.LoadOfflineTenantIntermediate("tenant_northwind", newRoot, newInter, newKey); err != nil {
		t.Fatalf("a replacement authority was refused after a revocation: %v", err)
	}

	cn, err := leafIssuerCN(t, interception, "tenant_northwind", "example.com")
	if err != nil || cn != "Northwind Recovered Interception Issuing CA" {
		t.Fatalf("the organization is not intercepted under its replacement: %q %v", cn, err)
	}
}

// ★ A REVOKED ROOT CAME BACK THROUGH THE RETIRING SET (2026-08-16, found on the reference lab). Revocation
// removes the issuer and its bundle files, and the refusal to load a revoked root is checked on the bundle
// path. A root being RETIRED is persisted separately, one file each, and restored by its own loop — which
// asked nothing. So after a restart the organization's devices were told to trust a root this node had
// declared compromised, listed beside its replacement, and every surface reported the rotation as clean.
func TestARevokedRootIsNotAnnouncedAgainThroughTheRetiringSet(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	interception, err := NewNetworkExtensionLabTLSInterception([]string{"*"}, func() time.Time { return now })
	if err != nil {
		t.Fatalf("interception: %v", err)
	}
	interception.SetOfflineTenantIntermediateDir(dir)

	outgoingRoot, outgoingInter, outgoingKey, _ := tenantOfflineBundle(t, "Northwind Outgoing", now)
	if _, err := interception.LoadOfflineTenantIntermediate("tenant_northwind", outgoingRoot, outgoingInter, outgoingKey); err != nil {
		t.Fatalf("load outgoing: %v", err)
	}
	replacementRoot, replacementInter, replacementKey, _ := tenantOfflineBundle(t, "Northwind Replacement", now)
	if _, err := interception.LoadOfflineTenantIntermediate("tenant_northwind", replacementRoot, replacementInter, replacementKey); err != nil {
		t.Fatalf("load replacement: %v", err)
	}
	// The control: an overlap is the NORMAL state of a replacement, so both roots are announced right now.
	// Without this, "one root after the revocation" is also what a broken announcement looks like.
	if got := len(interception.OfflineTenantAnnouncedRoots("tenant_northwind")); got != 2 {
		t.Fatalf("the control failed: a replacement in progress announced %d root(s), not the overlap of 2", got)
	}

	if _, err := interception.RevokeTenantInterceptionAuthority("tenant_northwind", "key custody lost"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	// A replacement after the revocation: the organization recovers, the revoked roots do not.
	freshRoot, freshInter, freshKey, _ := tenantOfflineBundle(t, "Northwind After Revocation", now)
	if _, err := interception.LoadOfflineTenantIntermediate("tenant_northwind", freshRoot, freshInter, freshKey); err != nil {
		t.Fatalf("load fresh: %v", err)
	}

	// Now the node restarts: a second instance reading the same directory.
	restarted, err := NewNetworkExtensionLabTLSInterception([]string{"*"}, func() time.Time { return now })
	if err != nil {
		t.Fatalf("restarted interception: %v", err)
	}
	restarted.SetOfflineTenantIntermediateDir(dir)
	if _, err := restarted.LoadOfflineTenantIntermediatesFromDir(dir); err != nil {
		t.Fatalf("restore: %v", err)
	}

	announced := restarted.OfflineTenantAnnouncedRoots("tenant_northwind")
	if len(announced) != 1 {
		t.Fatalf("after a restart the devices are told to trust %d roots; only the replacement should remain: %v",
			len(announced), announced)
	}
	dead := restarted.RevokedTenantInterceptionRoots()
	for _, root := range announced {
		if reason, gone := dead[interceptionCertSHA256Hex(root)]; gone {
			t.Fatalf("a REVOKED root (%s) is being announced to devices again after a restart: %q",
				reason, root.Subject.CommonName)
		}
	}
}
