package main

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

// ★★ WHOSE CERTIFICATE THIS IS COMES FROM THE SIGNATURE, NOT FROM A NAME IN IT (2026-08-19).
//
// The attribution fallback used to scan a subject for the text "tenant_" and take whatever followed. On the
// reference lab that put this deployment's own device CA — registered to tenant_reference_lab, by its exact
// certificate — into "tenant_track_a_uc03a_lab", the name it was minted with on a track that no longer
// exists. And a subject is typed by whoever mints the certificate, so it was an attribution anyone could
// claim, deciding who may SEE the material.
//
// The fixture is that shape on purpose: a CA whose subject names one organization, issued by the CA another
// organization registered. Whoever signed it owns it.
func TestAttributionFollowsTheSignatureNotTheNameInTheSubject(t *testing.T) {
	ownerRoot, ownerKey := selfSignedCA(t, "Owning Org Device Root 2028")
	// Its subject says one organization; its ISSUER is another organization's registered root.
	misnamed := caSignedBy(t, "Device Issuing CA (tenant_some_other_org)", ownerRoot, ownerKey)

	inv := buildPKICertificateInventory(pkiCertInventoryInput{
		Now:                time.Now(),
		DeviceIssuingCAPEM: pemOf(misnamed),
		AttributeOwner: func(c *x509.Certificate) string {
			// The registry, in the form this test needs it: the owning organization registered ownerRoot.
			if c.Equal(ownerRoot) || c.CheckSignatureFrom(ownerRoot) == nil {
				return "tenant_owning_org"
			}
			return ""
		},
		TenantName: func(id string) string {
			if id == "tenant_owning_org" {
				return "Owning Org"
			}
			return ""
		},
	})

	var seen bool
	for _, item := range inv.Items {
		if item.Role != "device_issuing_ca" {
			continue
		}
		seen = true
		if item.TenantID != "tenant_owning_org" {
			t.Fatalf("the CA is attributed to %q — its subject says %q and the organization that SIGNED it is "+
				"tenant_owning_org; a name in a certificate is not evidence of whose it is",
				item.TenantID, item.Subject)
		}
		if item.TenantDisplayName != "Owning Org" {
			t.Fatalf("attributed but unnamed for the reader: %+v", item)
		}
		if !strings.Contains(item.Subject, "tenant_some_other_org") {
			t.Fatalf("the fixture stopped testing what it was written for — its subject no longer names a "+
				"different organization: %q", item.Subject)
		}
	}
	if !seen {
		t.Fatal("no device_issuing_ca in the inventory — the fixture produced nothing to judge")
	}
}

// ★ THE CONTROL: a certificate no registered authority signed stays unattributed. Without this, "attribute by
// signature" could quietly degrade into "attribute to the first organization we have", which is the same
// defect wearing the opposite hat.
func TestACertificateNoRegisteredAuthoritySignedStaysUnattributed(t *testing.T) {
	strayRoot, strayKey := selfSignedCA(t, "Somebody Else's Root")
	stray := caSignedBy(t, "Device Issuing CA (tenant_reference_lab)", strayRoot, strayKey)

	inv := buildPKICertificateInventory(pkiCertInventoryInput{
		Now:                time.Now(),
		DeviceIssuingCAPEM: pemOf(stray),
		AttributeOwner:     func(*x509.Certificate) string { return "" },
	})
	for _, item := range inv.Items {
		if item.Role == "device_issuing_ca" && item.TenantID != "" {
			t.Fatalf("a certificate nothing registered signed was attributed to %q — read out of its subject, "+
				"which is exactly what this change removed", item.TenantID)
		}
	}
}

func selfSignedCA(t *testing.T, cn string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(21), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(240 * time.Hour),
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c, key
}

func caSignedBy(t *testing.T, cn string, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(22), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(120 * time.Hour),
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func pemOf(c *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
}

// ★★ AND A CUSTOMER IS NOT SHOWN MATERIAL THIS NODE CANNOT PLACE (2026-08-19).
//
// Found within minutes of making attribution stricter, by looking as Northwind's administrator: their
// certificates page listed "Lantern DSSE Interception Issuing CA (tenant_reference_lab)" — another
// organization's id on a customer's screen. The old subject scan had been hiding it as a side effect, and
// removing the scan removed the guard with it.
//
// Roles that exist ON BEHALF of one organization — the CA that issues its devices' certificates, the authority
// that signs the certificates for its intercepted traffic — fail closed when nobody can place them.
func TestACustomerIsNotShownSigningMaterialTheNodeCannotPlace(t *testing.T) {
	items := []pkiCertificateItem{
		{ID: "transport_anchor", Role: "transport_anchor", Subject: "CN=Deployment Transport CA"},
		{ID: "device_client_ca:1", Role: "device_client_ca", TenantID: "tenant_northwind",
			Subject: "CN=Northwind Device Issuing CA"},
		{ID: "interception_intermediate", Role: "interception_intermediate",
			Subject: "CN=Lantern DSSE Interception Issuing CA (tenant_reference_lab)"},
		{ID: "device_issuing_ca", Role: "device_issuing_ca",
			Subject: "CN=Some Device Issuing CA (tenant_reference_lab)"},
	}

	for _, item := range pkiCertificateItemsForTenant(items, "tenant_northwind", nil) {
		if strings.Contains(item.Subject, "tenant_reference_lab") {
			t.Fatalf("Northwind was shown %q — material this node cannot attribute, naming another organization",
				item.Subject)
		}
	}

	// The deployment's own shared material still reaches the customer: withholding that would take away the one
	// thing the screen exists to give them.
	var sawAnchor, sawOwn bool
	for _, item := range pkiCertificateItemsForTenant(items, "tenant_northwind", nil) {
		if item.Role == "transport_anchor" {
			sawAnchor = true
		}
		if item.TenantID == "tenant_northwind" {
			sawOwn = true
		}
	}
	if !sawAnchor || !sawOwn {
		t.Fatalf("the filter took the deployment's own anchor (%v) or the customer's own CA (%v) with it",
			sawAnchor, sawOwn)
	}

	// ★ THE CONTROL: one organization, nothing attributed — the node's own signer IS theirs to see. Without
	// this, "unattributed is withheld" would blank the certificates screen of every single-tenant deployment.
	single := []pkiCertificateItem{
		{ID: "interception_intermediate", Role: "interception_intermediate", Subject: "CN=The Only Signer"},
	}
	if got := pkiCertificateItemsForTenant(single, "tenant_only", nil); len(got) != 1 {
		t.Fatalf("a single-organization deployment withheld its only interception signer from its only customer")
	}
}
