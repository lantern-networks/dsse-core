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
)

// ★★ WHOSE CERTIFICATE THIS IS COMES FROM THE DEPLOYMENT'S RECORD, NOT FROM THE CERTIFICATE (2026-08-19).
//
// The Console labelled a row "Tenant" and filled it from the subject's O= field. Measured on the lab, that
// produced both errors at once on one screen:
//
//	Lab Tenant Interception Root 2028   attributed to tenant_reference_lab, subject carries no O=
//	                                    -> the screen showed NO organization for material the registry places
//	Lantern DSSE Device Issuing CA ...  attributed to nobody, subject says O=Lantern DSSE
//	                                    -> the screen named "Lantern DSSE" as its organization
//
// An organization boundary read out of a field inside the material it is supposed to bound is not a boundary;
// it is whatever the issuer typed. So the server names the organization from the registry, or names nothing —
// and the two halves of that are what this test holds apart.
func TestTheOrganizationOnACertificateComesFromTheRegistryNotTheSubject(t *testing.T) {
	// A root the registry attributes, whose SUBJECT says nothing about an organization.
	attributed := interceptionRootPEMWithOrg(t, "Lab Tenant Interception Root 2028", "")
	// A CA the registry attributes to nobody, whose SUBJECT names an organization.
	unattributed := interceptionRootPEMWithOrg(t, "Lantern DSSE Device Issuing CA (tenant_track_a_uc03a_lab)", "Lantern DSSE")

	inv := buildPKICertificateInventory(pkiCertInventoryInput{
		Now:                 time.Now(),
		InterceptionEnabled: true,
		DeviceIssuingCAPEM:  unattributed,
		PerTenantInterceptionRoots: []perTenantInterceptionRoot{
			{Tenant: "tenant_reference_lab", RootPEM: string(attributed)},
		},
		TenantName: func(id string) string {
			if id == "tenant_reference_lab" {
				return "Lab Tenant (console)"
			}
			return ""
		},
	})

	var sawAttributed, sawUnattributed bool
	for _, item := range inv.Items {
		switch {
		case item.TenantID == "tenant_reference_lab":
			sawAttributed = true
			if item.TenantDisplayName != "Lab Tenant (console)" {
				t.Fatalf("material the registry places carries no organization name for the screen to show: %+v", item)
			}
		case item.Role == "device_issuing_ca":
			sawUnattributed = true
			// The subject says "O=Lantern DSSE". The registry says nothing. Nothing is the answer.
			if item.TenantDisplayName != "" {
				t.Fatalf("a CA the registry does not attribute was given the organization %q — read out of its "+
					"own subject, which is a string whoever minted it typed", item.TenantDisplayName)
			}
		}
	}
	if !sawAttributed || !sawUnattributed {
		t.Fatalf("the fixture did not produce both cases (attributed=%v unattributed=%v) — a test that checks "+
			"neither passes for the wrong reason", sawAttributed, sawUnattributed)
	}
}

// interceptionRootPEMWithOrg mints a self-signed CA with an optional O= in its subject, which is the field the
// screen used to read an organization out of.
func interceptionRootPEMWithOrg(t *testing.T, cn, org string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	subject := pkix.Name{CommonName: cn}
	if org != "" {
		subject.Organization = []string{org}
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(11),
		Subject:               subject,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// ★★ THE BADGE SAID "place or withdraw" AND THE ITEM OFFERED ONLY WITHDRAWAL (2026-08-19).
//
// An unattributed device-trust CA is marked on the card with exactly that sentence — it is the operator's
// only notice that a CA admitting devices belongs to nobody, and that devices admitted through it resolve to
// no organization. The item carried `download` and `retire`. Nothing placed it.
//
// Withdrawal is the half that locks machines out: whatever holds a certificate from this CA stops being
// admitted. Placing it is the safe half, and it was the one the screen named and did not offer.
func TestAnUnattributedDeviceCAOffersTheActThatPlacesIt(t *testing.T) {
	unowned := interceptionRootPEMWithOrg(t, "Somebody's Device Issuing CA", "")
	owned := interceptionRootPEMWithOrg(t, "Northwind Device Issuing CA 2028", "Northwind Traders")
	ownedSHA := ""
	for _, item := range buildPKICertificateInventory(pkiCertInventoryInput{
		Now: time.Now(), TransportClientCAPEM: owned, DeviceClientCARetirable: true,
	}).Items {
		if item.Role == "device_client_ca" {
			ownedSHA = item.SHA256
		}
	}
	if ownedSHA == "" {
		t.Fatal("the fixture produced no device_client_ca")
	}

	inv := buildPKICertificateInventory(pkiCertInventoryInput{
		Now:                     time.Now(),
		TransportClientCAPEM:    append(append([]byte{}, unowned...), owned...),
		DeviceClientCARetirable: true,
		DeviceCAOwners:          map[string]string{ownedSHA: "tenant_northwind"},
	})

	var sawUnowned, sawOwned bool
	for _, item := range inv.Items {
		if item.Role != "device_client_ca" {
			continue
		}
		has := func(cap string) bool {
			for _, c := range item.Capabilities {
				if c == cap {
					return true
				}
			}
			return false
		}
		if item.OwnerUnknown {
			sawUnowned = true
			if !has("place") {
				t.Fatalf("a CA belonging to nobody is marked \"place or withdraw\" and offers %v — the half that "+
					"locks machines out is offered and the safe half is not", item.Capabilities)
			}
			if item.PEM == "" {
				t.Fatal("the act carries the certificate over; without it the operator is asked to re-supply a fact this screen holds")
			}
			continue
		}
		sawOwned = true
		// The control: an attributed CA has nothing to place, and offering it would invite an operator to
		// re-register a CA that already belongs to somebody — which the registry refuses, correctly, as a
		// cross-tenant move.
		if has("place") {
			t.Fatalf("a CA that already belongs to an organization offers to be placed: %v", item.Capabilities)
		}
	}
	if !sawUnowned || !sawOwned {
		t.Fatalf("the fixture did not produce both cases (unowned=%v owned=%v)", sawUnowned, sawOwned)
	}
}
