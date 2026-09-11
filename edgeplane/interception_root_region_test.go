package edgeplane

import (
	"bytes"
	"crypto/x509"
	"strings"
	"testing"
	"time"
)

// TestPerTenantPerRegionInterceptionRootsAreDistinctAndRegionLabeled proves Slice 4: the SAME tenant on edges in
// DIFFERENT regions gets distinct interception roots, each identifiable as its region's key (CN labeled) and
// actually signing that region's leaves — so a leaked regional key can MITM only that region's traffic and "the
// EU key reads EU traffic" (residency, docs/multi_region_edge_architecture_design.md).
func TestPerTenantPerRegionInterceptionRootsAreDistinctAndRegionLabeled(t *testing.T) {
	now := func() time.Time { return time.Date(2026, 6, 25, 0, 0, 0, 0, time.UTC) }

	fra, err := NewNetworkExtensionLabTLSInterception([]string{"*"}, now)
	if err != nil {
		t.Fatalf("new fra: %v", err)
	}
	fra.EnablePerTenantPerRegionInterceptionRoots("tenant-primary", "eu-fra")

	us, err := NewNetworkExtensionLabTLSInterception([]string{"*"}, now)
	if err != nil {
		t.Fatalf("new us: %v", err)
	}
	us.EnablePerTenantPerRegionInterceptionRoots("tenant-primary", "us-iad")

	rootFra := leafRootDER(t, fra, "tenant-b", "example.com")
	rootUs := leafRootDER(t, us, "tenant-b", "example.com")

	if bytes.Equal(rootFra, rootUs) {
		t.Fatal("same tenant in different regions must get DISTINCT interception roots")
	}

	fraCert, err := x509.ParseCertificate(rootFra)
	if err != nil {
		t.Fatalf("parse fra root: %v", err)
	}
	usCert, err := x509.ParseCertificate(rootUs)
	if err != nil {
		t.Fatalf("parse us root: %v", err)
	}
	if !strings.Contains(fraCert.Subject.CommonName, "eu-fra") {
		t.Fatalf("fra root is not labeled with its region: CN=%q", fraCert.Subject.CommonName)
	}
	if !strings.Contains(usCert.Subject.CommonName, "us-iad") {
		t.Fatalf("us root is not labeled with its region: CN=%q", usCert.Subject.CommonName)
	}

	// The fra leaf is actually signed BY the fra-region root (the regional key really minted it).
	leaf, err := fra.leafCertificate("tenant-b", "host.example.com")
	if err != nil {
		t.Fatalf("fra leaf: %v", err)
	}
	leafX, err := x509.ParseCertificate(leaf.Certificate[0])
	if err != nil {
		t.Fatalf("parse fra leaf: %v", err)
	}
	if err := leafX.CheckSignatureFrom(fraCert); err != nil {
		t.Fatalf("fra leaf is not signed by the fra-region root: %v", err)
	}

	// Same tenant within the SAME region resolves to ONE stable root (no per-flow churn).
	if !bytes.Equal(rootFra, leafRootDER(t, fra, "tenant-b", "other.example.com")) {
		t.Fatal("same tenant+region must reuse one root, not regenerate per host")
	}
}

// ★ A PER-TENANT ROOT NAMES ITS ORGANIZATION (2026-08-16). This test asserted the OPPOSITE — that a
// region-agnostic per-tenant root is UNLABELED — and that expectation was the defect. The generator took a
// scope and was given the REGION, which is empty in the ordinary per-tenant deployment, so every organization's
// root came out with one common name and differed only by key and serial.
//
// A trust store shows names. Two organizations' roots called the same thing leave an operator deciding which
// of two identical strings to remove from a machine, and this product has already had an outage from exactly
// that (two same-subject intermediates side by side, 2026-08-02). It was reported again from the Windows
// machine on the day this was fixed: two per_tenant roots, same name, different keys.
//
// Existing roots keep their names — a rename is a new certificate, which is a replacement, and replacements go
// through the announced overlap rather than happening silently underneath a fleet.
func TestAPerTenantRootIsNamedAfterItsOrganization(t *testing.T) {
	now := func() time.Time { return time.Date(2026, 6, 25, 0, 0, 0, 0, time.UTC) }
	e, err := NewNetworkExtensionLabTLSInterception([]string{"*"}, now)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	e.EnablePerTenantInterceptionRoots("tenant-primary") // region-agnostic

	rootB, err := x509.ParseCertificate(leafRootDER(t, e, "tenant-b", "example.com"))
	if err != nil {
		t.Fatalf("parse root: %v", err)
	}
	rootC, err := x509.ParseCertificate(leafRootDER(t, e, "tenant-c", "example.com"))
	if err != nil {
		t.Fatalf("parse root: %v", err)
	}

	if !strings.Contains(rootB.Subject.CommonName, "tenant-b") {
		t.Fatalf("a per-tenant root does not name its organization: CN=%q", rootB.Subject.CommonName)
	}
	// The point is not the label, it is that two organizations are TELLABLE APART by the only thing a trust
	// store shows.
	if rootB.Subject.CommonName == rootC.Subject.CommonName {
		t.Fatalf("two organizations' roots are both called %q — indistinguishable in any trust store",
			rootB.Subject.CommonName)
	}
}
