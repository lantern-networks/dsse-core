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

// ★★★ A SHARED, AUTOSCALED FLEET NEEDS ONE MORE TIER, AND THE DEVICE MUST NOT NOTICE (2026-08-20).
//
// Until now an organization's interception issuer was ONE certificate its offline root had signed by hand.
// That cannot work when Edges appear under load: what such a node is handed has to be short-lived, so the
// customer signs an issuing authority once and the control plane mints a per-Edge tier beneath it.
//
// The property that makes this safe is asserted here: the ROOT is unchanged, so every device that already
// trusts this organization keeps working, and the certificate a browser is shown carries every tier between
// the leaf and that root. A chain that is short by one is a chain the browser rejects, and it rejects it on
// somebody's laptop rather than here.
func TestAPerEdgeTierIsServedAndStillReachesTheOrganizationsRoot(t *testing.T) {
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	interception, err := NewNetworkExtensionLabTLSInterception([]string{"*"}, func() time.Time { return now })
	if err != nil {
		t.Fatalf("interception: %v", err)
	}

	root, rootKey := threeTierCA(t, "Northwind Interception Root 2028", nil, nil, now)
	issuing, issuingKey := threeTierCA(t, "Northwind Issuing CA (operator)", root, rootKey, now)
	perEdge, perEdgeKey := threeTierCA(t, "Northwind Issuing CA (operator) — edge-a2", issuing, issuingKey, now)

	chainPEM := append(pemOf(perEdge), pemOf(issuing)...)
	if _, err := interception.LoadOfflineTenantIntermediate("tenant_northwind", pemOf(root), chainPEM,
		ecKeyPEM(t, perEdgeKey)); err != nil {
		t.Fatalf("a three-tier chain was refused: %v", err)
	}

	// The device's view: everything below the root must be presented, and it must verify TO that root.
	leaf, err := interception.leafCertificate("tenant_northwind", "www.example.com")
	if err != nil {
		t.Fatalf("mint a leaf: %v", err)
	}
	// leaf + per-Edge tier + issuing authority. The ROOT is NOT among them (2026-08-21): it is a trust anchor,
	// the device holds it in its own store, and presenting it made a four-deep chain ending in a self-signed
	// certificate — which git on the reference Mac reports as "self signed certificate in certificate chain"
	// and refuses. What matters is that NOTHING BETWEEN the leaf and the root is missing.
	if len(leaf.Certificate) != 3 {
		t.Fatalf("the browser is shown %d certificate(s); with two tiers between leaf and root it needs three "+
			"— the leaf and both intermediates — and a chain short by one is rejected on somebody's laptop "+
			"rather than here", len(leaf.Certificate))
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	inter := x509.NewCertPool()
	for _, der := range leaf.Certificate[1:] {
		c, perr := x509.ParseCertificate(der)
		if perr != nil {
			t.Fatalf("parse presented chain: %v", perr)
		}
		inter.AddCert(c)
	}
	presented, err := x509.ParseCertificate(leaf.Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	if _, err := presented.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, DNSName: "www.example.com",
		CurrentTime: now.Add(time.Minute), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		t.Fatalf("a device trusting this organization's root could not verify what it is shown: %v", err)
	}

	// ★ AND A CHAIN THAT DOES NOT LINK IS REFUSED HERE, not at the browser.
	stranger, strangerKey := threeTierCA(t, "Somebody Else's Issuing CA", nil, nil, now)
	orphan, orphanKey := threeTierCA(t, "Orphan — edge-a3", stranger, strangerKey, now)
	broken := append(pemOf(orphan), pemOf(issuing)...)
	if _, err := interception.LoadOfflineTenantIntermediate("tenant_broken", pemOf(root), broken,
		ecKeyPEM(t, orphanKey)); err == nil {
		t.Fatal("a chain whose tiers do not link was accepted — every leaf it signs is refused at the browser")
	} else if !strings.Contains(err.Error(), "does not link") {
		t.Fatalf("the refusal does not say what is wrong: %v", err)
	}
}

func threeTierCA(t *testing.T, cn string, parent *x509.Certificate, parentKey *ecdsa.PrivateKey,
	now time.Time) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(now.UnixNano() + int64(len(cn))),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    now.Add(-time.Hour), NotAfter: now.AddDate(2, 0, 0),
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		IsCA:     true, BasicConstraintsValid: true,
	}
	signer, signerKey := tmpl, key
	if parent != nil {
		signer, signerKey = parent, parentKey
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signer, &key.PublicKey, signerKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

func pemOf(c *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
}

func ecKeyPEM(t *testing.T, k *ecdsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
}
