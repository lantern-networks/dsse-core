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

func anAuthority(t *testing.T, cn string, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true,
	}
	signer, signerKey := tmpl, key
	if parent != nil {
		signer, signerKey = parent, parentKey
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signer, &key.PublicKey, signerKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return cert, key, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// ★★★ THE ANNOUNCEMENT IS WHAT A DEVICE INSTALLS. Naming the signing certificate when it is an intermediate
// sends an operator to put an intermediate in a Root store, which does not close the chain — measured on a
// real Windows machine on 2026-08-26, where it cost the box every HTTPS request it made.
func TestAnIntermediateSignerAnnouncesTheAnchorAndNotItself(t *testing.T) {
	root, rootKey, rootPEM := anAuthority(t, "deployment root", nil, nil)
	signing, _, _ := anAuthority(t, "interception CA", root, rootKey)

	got := announcedInterceptionAnchor(signing, rootPEM)
	if len(got) != 1 || got[0] != certFingerprint(root) {
		t.Fatalf("a device is told to hold %v; the chain closes on the root %s", got, certFingerprint(root))
	}
	if got[0] == certFingerprint(signing) {
		t.Fatalf("the intermediate was announced as the thing to install")
	}

	// Control: an authority that IS self-signed announces itself, which is the case this must not change.
	selfSigned, _, selfPEM := anAuthority(t, "a self-signed interception root", nil, nil)
	if own := announcedInterceptionAnchor(selfSigned, selfPEM); len(own) != 1 || own[0] != certFingerprint(selfSigned) {
		t.Fatalf("a self-signed authority must announce itself: %v", own)
	}
}

// ★ AND WITH NO ANCHOR CONFIGURED IT STILL SAYS SOMETHING. An empty announcement reads, on the device, as
// "this deployment does not inspect" — which is the confusion this whole lane is about. It announces the
// signer and logs what that costs, so the failure is loud rather than silent.
func TestWithNoAnchorItAnnouncesTheSignerRatherThanNothing(t *testing.T) {
	root, rootKey, _ := anAuthority(t, "deployment root", nil, nil)
	signing, _, _ := anAuthority(t, "interception CA", root, rootKey)
	got := announcedInterceptionAnchor(signing, "")
	if len(got) != 1 || got[0] != certFingerprint(signing) {
		t.Fatalf("got %v — silence would read as a deployment that does not inspect", got)
	}
}

// An anchor that did not sign this authority is not the anchor. Announcing it would send devices to install
// a certificate that closes nothing.
func TestAnUnrelatedAnchorIsNotAnnounced(t *testing.T) {
	root, rootKey, _ := anAuthority(t, "deployment root", nil, nil)
	signing, _, _ := anAuthority(t, "interception CA", root, rootKey)
	_, _, strangerPEM := anAuthority(t, "somebody else's root", nil, nil)
	if got := announcedInterceptionAnchor(signing, strangerPEM); len(got) != 1 || got[0] != certFingerprint(signing) {
		t.Fatalf("an unrelated certificate was announced as the anchor: %v", got)
	}
}
