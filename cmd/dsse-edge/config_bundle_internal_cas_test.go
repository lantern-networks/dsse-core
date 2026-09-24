package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/internalca"
)

func anInternalAuthorityPEM(t *testing.T, cn string) string {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestTheAuthoritiesTravelInTheBundleTheFleetActuallyPulls(t *testing.T) {
	now := time.Now().UTC()
	controlPlane, _ := internalca.NewStore(nil)
	if _, err := controlPlane.Upsert(internalca.Authority{
		ID: "a", TenantID: "kaede", Name: "Kaede internal", CertificatePEM: anInternalAuthorityPEM(t, "Kaede Internal CA")}, now); err != nil {
		t.Fatal(err)
	}
	section := internalCABundleSection(controlPlane)
	if section == nil || !section.Complete || len(section.Authorities) != 1 {
		t.Fatalf("the control plane must publish what it holds: %+v", section)
	}

	edge, _ := internalca.NewStore(nil)
	count, applied, _ := applyInternalCABundleSection(edge, section, t.Logf)
	if !applied || count != 1 {
		t.Fatalf("the Edge must take it, got applied=%v count=%d", applied, count)
	}
	if got := edge.AnchorsPEM("kaede", now); len(got) != 1 {
		t.Fatalf("and then vouch for it, got %d", len(got))
	}

	// ★ A DELETION REACHES THE FLEET. Empty means none here — unlike the device-CA registry, where empty would
	// refuse every device — because it is the only way an administrator's removal ever arrives.
	controlPlane.Delete("a", "kaede", now)
	if _, applied, _ := applyInternalCABundleSection(edge, internalCABundleSection(controlPlane), t.Logf); !applied {
		t.Fatal("an empty complete section must be applied")
	}
	if got := edge.AnchorsPEM("kaede", now); len(got) != 0 {
		t.Fatalf("a removed authority must stop being trusted, got %d", len(got))
	}

	// ★★ AND A CONTROL PLANE THAT COULD NOT LOOK CHANGES NOTHING.
	controlPlane.Upsert(internalca.Authority{ID: "a", TenantID: "kaede", CertificatePEM: anInternalAuthorityPEM(t, "Kaede Internal CA")}, now)
	applyInternalCABundleSection(edge, internalCABundleSection(controlPlane), t.Logf)
	if _, applied, _ := applyInternalCABundleSection(edge, &internalCABundle{Complete: false}, t.Logf); applied {
		t.Fatal("an incomplete section must never be read as \"there are none\"")
	}
	if got := edge.AnchorsPEM("kaede", now); len(got) != 1 {
		t.Fatalf("the last good list must stand, got %d", len(got))
	}
}

// ★★★ THE CALL SITE, NOT THE HELPER. Three versions of this object were wired to channels that do not run on
// this deployment; each helper was correct and each was dead. Go compiles an unreferenced function without
// complaint, so the test that matters is that the publish and apply sites NAME these functions.
func TestTheBundleSectionIsActuallyPublishedAndApplied(t *testing.T) {
	for path, want := range map[string]string{
		"admin_policy_routes.go": "bundle.InternalCAs = internalCABundleSection(",
		"config_bundle_sync.go":  "applyInternalCABundleSection(t.internalCAs,",
	} {
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(body), want) {
			t.Fatalf("%s no longer carries %q — the object would be published or applied nowhere, and nothing else would fail", path, want)
		}
	}
}
