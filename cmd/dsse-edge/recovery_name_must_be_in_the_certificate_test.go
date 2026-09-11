package main

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"
)

// ★★★ THE FOLD ANSWERED THE RECOVERY NAME WITH A CERTIFICATE THAT DOES NOT CARRY IT (2026-08-19, reported
// from win-dev-1, reproduced against the running Edge).
//
// Measured on the node: a ClientHello for recovery.dsse.invalid on the transport port came back with
// "O=Lantern DSSE, CN=Lantern DSSE Transport", SANs localhost / shinmac-mini.tail04460b.ts.net and four IP
// addresses. Every agent verifies the name against the anchors it adopted, so every agent refuses it — and the
// only device that ever dials this path is one whose own certificate has already expired, which is to say a
// device with no other way back and nobody watching.
//
// Both directions are asserted. A gate that cannot be shown refusing is the same silence with a new name, and
// this one exists because the live probe that should have caught the defect was refused as an anonymous caller
// first and reported the server's answer instead of the certificate's.
func TestRecoveryOnTheMainPortIsOnlyOfferedWhenTheCertificateCarriesTheName(t *testing.T) {
	served := &x509.Certificate{DNSNames: []string{"localhost", "shinmac-mini.tail04460b.ts.net"}}
	if recoveryNameIsInTheCertificate("recovery.dsse.invalid", served) {
		t.Fatal("the certificate measured on the running Edge was accepted for a name it does not carry — " +
			"every expired device dialling recovery would be refused, silently")
	}

	// The state the fold is allowed to be enabled in.
	carries := &x509.Certificate{DNSNames: []string{"lab.dsse.invalid", "recovery.dsse.invalid"}}
	if !recoveryNameIsInTheCertificate("Recovery.DSSE.invalid", carries) {
		t.Fatal("a certificate that does carry the name was refused — the fold would never enable")
	}

	// A CommonName that matches is not a match: no verifier has honoured it for years, so honouring it here
	// would enable the fold for certificates the agents go on refusing.
	cnOnly := &x509.Certificate{Subject: pkix.Name{CommonName: "recovery.dsse.invalid"}}
	if recoveryNameIsInTheCertificate("recovery.dsse.invalid", cnOnly) {
		t.Fatal("a CommonName was accepted as the name — agents check SANs, and this would enable a fold they refuse")
	}

	// A wildcard covers one label and no more, which is what a verifier does with it.
	wild := &x509.Certificate{DNSNames: []string{"*.dsse.invalid"}}
	if !recoveryNameIsInTheCertificate("recovery.dsse.invalid", wild) {
		t.Fatal("a wildcard that does cover the name was refused")
	}
	if recoveryNameIsInTheCertificate("a.b.dsse.invalid", wild) {
		t.Fatal("a wildcard was stretched over two labels — broader than any verifier will read it")
	}
	if recoveryNameIsInTheCertificate("", carries) {
		t.Fatal("an empty name matched, which would enable the fold for handshakes that asked for nothing")
	}
}
