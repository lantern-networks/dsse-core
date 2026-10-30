package main

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/enrolledinventory"
)

func TestTransportAnchorsRefuseRotationWithoutCurrentAuthority(t *testing.T) {
	seed, err := json.Marshal([]storedTenantTransportCA{{
		TenantID: "tenant", ServerName: "tenant.example",
		Incoming: &storedTenantTransportCA{TenantID: "tenant", CACertPEM: "incoming-anchor"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	a := newTenantTransportAuthority(seed, nil, time.Now)
	if anchors := a.AnchorsFor("tenant"); len(anchors) != 0 {
		t.Fatal("an incomplete rotation supplied an incoming-only trust bundle")
	}
}

func TestTrustAdoptionRejectsCaseDistinctTenantTelemetry(t *testing.T) {
	d, _ := trustDistributorFixture(t)
	now := time.Now()
	population := []enrolledinventory.Entry{{Identity: "device", TenantID: "Acme", Enabled: true}}
	report := observedExclusionEntry{TenantID: "acme", DeviceIdentity: "device", ReportedAt: now,
		AdoptedTrustSerial: 50, TransportServerNameSent: "a.example", PinnedTransportCASHA256: []string{"root"}}
	if d.adopted(population, []observedExclusionEntry{report}, "Acme", "a.example", "root", 50, now.Add(-time.Minute), now) {
		t.Fatal("another tenant's telemetry activated this tenant's authority")
	}
	report.TenantID = "Acme"
	if !d.adopted(population, []observedExclusionEntry{report}, "Acme", "a.example", "root", 50, now.Add(-time.Minute), now) {
		t.Fatal("the owning tenant's complete adoption evidence was refused")
	}
}

func TestDeviceAuthorityKeepsCaseDistinctTenantsSeparate(t *testing.T) {
	var saved []byte
	a := newTenantDeviceAuthority(nil, func(raw []byte) error { saved = append([]byte(nil), raw...); return nil }, time.Now)
	upper, err := a.EnsureCA("Acme", "Upper")
	if err != nil {
		t.Fatal(err)
	}
	lower, err := a.EnsureCA("acme", "Lower")
	if err != nil {
		t.Fatal(err)
	}
	if upper.TenantID != "Acme" || lower.TenantID != "acme" || upper.CACertPEM == lower.CACertPEM {
		t.Fatal("case-distinct tenants share a device signing authority")
	}
	a = newTenantDeviceAuthority(saved, nil, time.Now)
	mat, err := a.IssueFor("Acme", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if mat.TenantID != "Acme" || mat.CACertPEM != upper.CACertPEM {
		t.Fatal("reloaded authority is not owned by the requested tenant")
	}
	if _, err := a.IssueFor("ACME", time.Hour); err == nil {
		t.Fatal("unknown case alias can obtain signing material")
	}
	if _, err := a.RotateCA("acme"); err != nil {
		t.Fatal(err)
	}
	row, ok := a.Row("Acme")
	if !ok || row.Incoming != nil {
		t.Fatal("rotating acme also rotated Acme")
	}
	if n := a.RemoveTenant("acme"); n != 1 {
		t.Fatal("tenant erasure did not remove its authority")
	}
	if _, ok := a.Row("Acme"); !ok {
		t.Fatal("tenant erasure removed another tenant's authority")
	}
}

func TestTransportAuthorityKeepsCaseDistinctTenantsSeparate(t *testing.T) {
	var saved []byte
	a := newTenantTransportAuthority(nil, func(raw []byte) error { saved = append([]byte(nil), raw...); return nil }, time.Now)
	upper, err := a.EnsureCA("Acme", "Upper.EXAMPLE")
	if err != nil {
		t.Fatal(err)
	}
	lower, err := a.EnsureCA("acme", "lower.example")
	if err != nil {
		t.Fatal(err)
	}
	if upper.TenantID != "Acme" || lower.TenantID != "acme" || upper.CACertPEM == lower.CACertPEM {
		t.Fatal("case-distinct tenants share a transport authority")
	}
	a = newTenantTransportAuthority(saved, nil, time.Now)
	mat, err := a.IssueFor("Acme", "edge", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if mat.TenantID != "Acme" || mat.ServerName != "upper.example" || mat.AnchorPEM != upper.CACertPEM {
		t.Fatal("tenant identity or DNS normalization changed during issuance")
	}
	if _, err := a.IssueFor("ACME", "edge", time.Hour); err == nil {
		t.Fatal("unknown case alias can obtain server material")
	}
	if _, err := a.RotateCA("acme"); err != nil {
		t.Fatal(err)
	}
	row, ok := a.Row("Acme")
	if !ok || row.Incoming != nil {
		t.Fatal("rotating acme also rotated Acme")
	}
	if n := a.RemoveTenant("acme"); n != 1 {
		t.Fatal("tenant erasure did not remove its authority")
	}
	if _, ok := a.Row("Acme"); !ok {
		t.Fatal("tenant erasure removed another tenant's authority")
	}
}

func TestDeviceCABundleDoesNotTreatCaseDistinctTenantAsManaged(t *testing.T) {
	ca := makeBundleTestCA(t, "registered lower tenant")
	cp := registryWith(t, map[string][][]byte{"acme": {ca}})
	edge := registryWith(t, nil)
	section := deviceCABundleSection(cp, nil)
	section.ManagedComplete = true
	section.ManagedTenants = []string{"Acme"}
	added, _, err := applyDeviceCABundleSection(edge, section, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if added != 1 || edge.Registrations()["acme"] != 1 {
		t.Fatal("another tenant's managed status suppressed this tenant's registered CA")
	}
}
