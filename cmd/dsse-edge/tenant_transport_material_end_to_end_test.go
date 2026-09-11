package main

import (
	"crypto/tls"
	"strings"
	"testing"
	"time"
)

// ★★★ THE WHOLE POINT, IN ONE TEST: a node that was given NOTHING ends up serving an organization's own name.
//
// This is the failure measured on 2026-08-20 — this repository's scale-out definition carried no
// per-organization certificates, so an Edge added under load answered every ClientHello with the shared
// certificate and was refused by devices that had adopted their organization's anchor.
//
// The chain asserted here is the one that replaces the files: the control plane holds the authority, mints
// material that expires, the Edge installs it into the SAME index the file loader fills, and the SNI selector
// then answers that organization's name with that organization's certificate — while every other name is
// still served by whatever this node served before.
func TestAnUnpreparedEdgeAssemblesItsOrganizationsFromTheControlPlane(t *testing.T) {
	useEmptyTenantCertificateIndex(t)
	now := time.Date(2026, 8, 20, 9, 0, 0, 0, time.UTC)
	useTransportInstallClock(t, func() time.Time { return now })
	useTransportSelectorClock(t, func() time.Time { return now })
	authority := newTenantTransportAuthority(nil, func([]byte) error { return nil }, func() time.Time { return now })
	if _, err := authority.EnsureCA("tenant_reference_lab", "lab.dsse.invalid"); err != nil {
		t.Fatalf("authority: %v", err)
	}

	// The node starts with nothing — this is the state of an autoscaled Edge.
	if _, _, ok := transportTenantCertificates.For("lab.dsse.invalid"); ok {
		t.Fatal("the index was not empty, so this test would not be measuring what it claims")
	}

	mat, err := authority.IssueFor("tenant_reference_lab", "edge-a2", 12*time.Hour)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if err := installTenantTransportMaterial(mat); err != nil {
		t.Fatalf("install: %v", err)
	}

	// Now the selector answers that organization's name with that organization's certificate.
	sharedCalled := 0
	get := transportCertificateForClientHello(func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		sharedCalled++
		return &tls.Certificate{}, nil
	})
	own, err := get(&tls.ClientHelloInfo{ServerName: "lab.dsse.invalid"})
	if err != nil {
		t.Fatalf("select: %v", err)
	}
	if own.Leaf == nil || own.Leaf.Subject.CommonName != "lab.dsse.invalid" {
		t.Fatalf("the organization's name was answered with %+v", own.Leaf)
	}
	if sharedCalled != 0 {
		t.Fatal("the shared certificate was consulted for a name this node can now answer itself")
	}

	// ★ THE CONTROL, unchanged: every other connection is served exactly as before.
	if _, err := get(&tls.ClientHelloInfo{ServerName: "example.com"}); err != nil || sharedCalled != 1 {
		t.Fatalf("an unrelated name stopped being served by the shared certificate (shared=%d, err=%v)", sharedCalled, err)
	}

	// And the fleet guard — the thing that refuses to let an unprepared node speak for the fleet — now passes
	// for the name this node was given, which is the whole reason the material is fetched before serving.
	announced := "tenant_reference_lab@lab.dsse.invalid,recovery-sni=withdrawn"
	if err := refuseToJoinFleetIfPromisesCannotBeKept(announced,
		func(name string) bool { _, _, ok := transportTenantCertificates.For(name); return ok },
		func(string) bool { return false }); err != nil {
		t.Fatalf("a node that has just assembled itself was still refused: %v", err)
	}

	// The anchor it publishes is the authority that signed what it serves — not something derived separately.
	got, ok := transportTenantCertificates.AnchorFor("tenant_reference_lab")
	if !ok {
		t.Fatal("this node would announce NO anchor for an organization it is now serving — its devices would " +
			"be told nothing to verify it with")
	}
	if strings.TrimSpace(got) != strings.TrimSpace(mat.AnchorPEM) {
		t.Fatalf("the anchor this node would announce is not the authority that signed the certificate it "+
			"serves:\n announce: %.60s\n signed by: %.60s", got, mat.AnchorPEM)
	}
}
