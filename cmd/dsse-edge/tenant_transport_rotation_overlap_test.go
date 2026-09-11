package main

import (
	"crypto/tls"
	"strings"
	"testing"
	"time"
)

// ★★★ MOVING AN ORGANIZATION ONTO A NEW AUTHORITY IS AN OVERLAP, AND SERVING IT EARLY IS AN OUTAGE
// (2026-08-20, found by running it on the lab).
//
// A node fetched its material from the control plane, which had just been given a NEW authority for that
// organization, while the fleet was still announcing the old one. The node carried the right NAME, so the
// guard passed it — and every device that reached it would have refused the certificate, because the anchor
// they hold did not sign it.
//
// The sequence asserted here is the one that makes it safe, and it is roadmap D's, applied to the authority
// rather than to the shared anchor: keep serving what devices can verify, announce both ends, and move only
// when the measurement says they have adopted.
func TestANewAuthorityIsAnnouncedBeforeItIsServed(t *testing.T) {
	useEmptyTenantCertificateIndex(t)
	now := time.Date(2026, 8, 20, 9, 0, 0, 0, time.UTC)

	// What this node serves today: the organization's existing certificate, as a file would have provided it.
	dir := t.TempDir()
	writeTenantCert(t, dir, "tenant_reference_lab", "lab.dsse.invalid")
	if n, err := loadTransportTenantCertificates(dir); err != nil || n != 1 {
		t.Fatalf("loaded %d (%v)", n, err)
	}
	before, ok := transportTenantCertificates.AnchorFor("tenant_reference_lab")
	if !ok {
		t.Fatal("fixture did not produce an anchor")
	}

	// The control plane's NEW authority for the same organization and the same name.
	useTransportInstallClock(t, func() time.Time { return now })
	// Promotion refuses material that is not usable NOW, so a fixture minting at a fixed date has to place
	// the serving clock there too — otherwise the overlap it is testing is correctly refused as expired.
	useTransportSelectorClock(t, func() time.Time { return now })
	authority := newTenantTransportAuthority(nil, func([]byte) error { return nil }, func() time.Time { return now })
	if _, err := authority.EnsureCA("tenant_reference_lab", "lab.dsse.invalid"); err != nil {
		t.Fatalf("authority: %v", err)
	}
	mat, err := authority.IssueFor("tenant_reference_lab", "edge-a2", 12*time.Hour)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if err := installTenantTransportMaterial(mat); err != nil {
		t.Fatalf("install: %v", err)
	}

	// ★ WHAT IT SERVES HAS NOT CHANGED. Every device holding the old anchor still verifies this node.
	if after, _ := transportTenantCertificates.AnchorFor("tenant_reference_lab"); after != before {
		t.Fatal("the new authority was served the moment it arrived — every device that has not adopted it " +
			"would be refused, which is the outage this overlap exists to avoid")
	}
	get := transportCertificateForClientHello(func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		return &tls.Certificate{}, nil
	})
	served, err := get(&tls.ClientHelloInfo{ServerName: "lab.dsse.invalid"})
	if err != nil || served.Leaf == nil {
		t.Fatalf("the organization's name stopped being served: %v", err)
	}

	// ★ AND BOTH ARE ANNOUNCED, so devices can adopt the new one before anything moves.
	anchors := transportTenantCertificates.AnchorsFor("tenant_reference_lab")
	if len(anchors) != 2 {
		t.Fatalf("the bundle would announce %d anchor(s) — an overlap that names one end is not an overlap", len(anchors))
	}
	if fps := transportTenantCertificates.AnchorFingerprintsFor("tenant_reference_lab"); len(fps) != 2 {
		t.Fatalf("the readiness measurement would be keyed by %d fingerprint(s)", len(fps))
	}

	// ★ THE MOVE IS A DECISION, taken when adoption has been measured — not another fetch, and not automatic.
	if !transportTenantCertificates.PromotePending("tenant_reference_lab") {
		t.Fatal("there was nothing to promote, so the overlap could never close")
	}
	after, _ := transportTenantCertificates.AnchorFor("tenant_reference_lab")
	if strings.TrimSpace(after) != strings.TrimSpace(mat.AnchorPEM) {
		t.Fatal("after promotion this node does not serve the authority it announced")
	}
	if len(transportTenantCertificates.AnchorsFor("tenant_reference_lab")) != 1 {
		t.Fatal("the old authority is still announced after the move — the overlap never closes and the " +
			"organization keeps two anchors for ever")
	}
	if transportTenantCertificates.PromotePending("tenant_reference_lab") {
		t.Fatal("promoting twice reported success with nothing to promote")
	}
}
