package connector

import (
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/model"
)

// ★★★ Where a connector IS, versus where it said it would be. The registered region is written once, at
// enrolment; after a region failover it names the region the connector LEFT, and every Edge routes there.
func TestRecordingWhereAConnectorIsAttachedDoesNotMoveTheCatalogVersion(t *testing.T) {
	r := NewRegistry()
	now := time.Date(2026, 8, 26, 0, 0, 0, 0, time.UTC)
	if _, err := r.Register(model.ConnectorRegistration{
		ID: "conn-1", TenantID: "t1", Status: "registered", EdgeRegionID: "region-b",
		PrivateBaseURL: "https://internal.invalid",
	}, now); err != nil {
		t.Fatalf("register: %v", err)
	}
	before := r.ConfigGeneration()

	moved, err := r.RecordAttachedRegion("conn-1", "region-a")
	if err != nil {
		t.Fatalf("record: %v", err)
	}
	if !moved {
		t.Fatal("the first report of a new region is a change")
	}
	conn, _ := r.Get("conn-1")
	if conn.AttachedRegionID != "region-a" {
		t.Fatalf("attached region: got %q", conn.AttachedRegionID)
	}
	if conn.EdgeRegionID != "region-b" {
		t.Fatalf("the registered region is a separate fact and must not be overwritten: got %q", conn.EdgeRegionID)
	}

	// ★ THE VERSION MUST NOT MOVE. A connector flapping between regions would otherwise drive the deployment's
	// aggregate config generation on every reconnect, and a generation that never settles closes every gate
	// that waits for one.
	if after := r.ConfigGeneration(); after != before {
		t.Fatalf("recording runtime state moved the catalog version: %d -> %d", before, after)
	}

	// Reporting the same region again is not a change, so a fleet of nodes all holding this connector does not
	// write on every heartbeat.
	if moved, _ := r.RecordAttachedRegion("conn-1", "region-a"); moved {
		t.Fatal("the same region reported again is not a change")
	}
	if moved, _ := r.RecordAttachedRegion("conn-1", "REGION-A"); moved {
		t.Fatal("region names must compare case-insensitively, as they do everywhere else")
	}

	// Nothing to say is not an erasure: an empty report must leave the last known answer alone.
	if moved, _ := r.RecordAttachedRegion("conn-1", "  "); moved {
		t.Fatal("an empty region is not a report")
	}
	if conn, _ := r.Get("conn-1"); conn.AttachedRegionID != "region-a" {
		t.Fatalf("an empty report erased what was known: %q", conn.AttachedRegionID)
	}

	if _, err := r.RecordAttachedRegion("conn-unknown", "region-a"); err == nil {
		t.Fatal("a connector this registry does not have must be an error, not a silent success")
	}
}

// ★ A connector restarting must not erase where the deployment last saw it. The connector does not know that
// fact and never sends it, so an empty field in an incoming registration is silence, not an instruction.
func TestReRegisteringDoesNotEraseWhereAConnectorWasLastSeen(t *testing.T) {
	r := NewRegistry()
	now := time.Date(2026, 8, 26, 0, 0, 0, 0, time.UTC)
	base := model.ConnectorRegistration{
		ID: "conn-1", TenantID: "t1", Status: "registered", EdgeRegionID: "region-b",
		PrivateBaseURL: "https://internal.invalid",
	}
	if _, err := r.Register(base, now); err != nil {
		t.Fatalf("register: %v", err)
	}
	if _, err := r.RecordAttachedRegion("conn-1", "region-a"); err != nil {
		t.Fatalf("record: %v", err)
	}

	// The connector restarts and registers again, carrying nothing about where it is attached.
	if _, err := r.Register(base, now.Add(time.Minute)); err != nil {
		t.Fatalf("re-register: %v", err)
	}
	if got, _ := r.Get("conn-1"); got.AttachedRegionID != "region-a" {
		t.Fatalf("a re-registration erased where it was last seen: %q", got.AttachedRegionID)
	}

	// A registration that DOES carry one is a report and replaces it.
	moved := base
	moved.AttachedRegionID = "region-c"
	if _, err := r.Register(moved, now.Add(2*time.Minute)); err != nil {
		t.Fatalf("register with a region: %v", err)
	}
	if got, _ := r.Get("conn-1"); got.AttachedRegionID != "region-c" {
		t.Fatalf("a report must replace: %q", got.AttachedRegionID)
	}
}
