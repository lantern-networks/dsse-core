package connector

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/model"
)

// The registry was in-memory only. On 2026-07-17 an Edge restart therefore deleted the fleet: the connector
// registers exactly once at startup, so after the restart every heartbeat returned 404 (unknown connector)
// forever and the Console showed no connectors and no Networks for ~13 hours. Only restarting each connector
// recovered it. These tests pin the durability that removes that failure mode.

func testRegistration(id string) model.ConnectorRegistration {
	return model.ConnectorRegistration{
		ID:               id,
		TenantID:         "tenant_a",
		PrivateBaseURL:   "http://127.0.0.1:18090",
		ConnectorGroupID: "lab-dc",
	}
}

func newPersistedRegistry(t *testing.T, path string) *Registry {
	t.Helper()
	r := NewRegistry()
	if err := r.SetPersister(blobstore.FilePersister{Path: path}); err != nil {
		t.Fatalf("SetPersister: %v", err)
	}
	return r
}

// THE REGRESSION: a registration must outlive the process that recorded it.
func TestRegistrationSurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "connector_registry.json")
	now := time.Now()

	r1 := newPersistedRegistry(t, path)
	if _, err := r1.Register(testRegistration("conn_lab_001"), now); err != nil {
		t.Fatalf("Register: %v", err)
	}

	// A fresh Edge process reading the same store = the restart.
	r2 := newPersistedRegistry(t, path)
	got, ok := r2.Get("conn_lab_001")
	if !ok {
		t.Fatal("connector was LOST across the restart — this is the 2026-07-17 outage")
	}
	if got.TenantID != "tenant_a" || got.ConnectorGroupID != "lab-dc" {
		t.Fatalf("registration restored with wrong content: %+v", got)
	}

	// And the thing that actually broke: the heartbeat must be accepted, not 404'd as unknown.
	if _, err := r2.Heartbeat(model.ConnectorHeartbeat{ID: "conn_lab_001", TenantID: "tenant_a"}, now); err != nil {
		t.Fatalf("heartbeat after restart must succeed, got: %v", err)
	}
}

// An operator decommission must not come back from the dead on the next restart.
func TestRemovalSurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "connector_registry.json")
	now := time.Now()

	r1 := newPersistedRegistry(t, path)
	if _, err := r1.Register(testRegistration("conn_gone"), now); err != nil {
		t.Fatalf("Register: %v", err)
	}
	ok, err := r1.RemoveForTenant("tenant_a", "conn_gone")
	if err != nil || !ok {
		t.Fatalf("RemoveForTenant: ok=%v err=%v", ok, err)
	}

	r2 := newPersistedRegistry(t, path)
	if _, ok := r2.Get("conn_gone"); ok {
		t.Fatal("a REMOVED connector came back after restart")
	}
}

// A status transition (the state an operator reads) must survive; a steady beat must not rewrite the file.
func TestStatusTransitionPersistsButSteadyBeatDoesNot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "connector_registry.json")
	now := time.Now()

	r1 := newPersistedRegistry(t, path)
	if _, err := r1.Register(testRegistration("conn_beat"), now); err != nil {
		t.Fatalf("Register: %v", err)
	}
	// registered -> healthy is a transition; it must be written.
	if _, err := r1.Heartbeat(model.ConnectorHeartbeat{ID: "conn_beat", TenantID: "tenant_a"}, now); err != nil {
		t.Fatalf("Heartbeat: %v", err)
	}
	r2 := newPersistedRegistry(t, path)
	got, ok := r2.Get("conn_beat")
	if !ok {
		t.Fatal("connector lost across restart")
	}
	if got.Status != "healthy" {
		t.Fatalf("status transition was not persisted: %q", got.Status)
	}

	// A steady healthy->healthy beat carries no new state; it must not re-serialize the registry (a beat lands
	// every ~10s per connector, and last_heartbeat_at has no value across a restart).
	sizeBefore, err := blobstore.FilePersister{Path: path}.Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if _, err := r1.Heartbeat(model.ConnectorHeartbeat{ID: "conn_beat", TenantID: "tenant_a", Timestamp: "2099-01-01T00:00:00Z"}, now); err != nil {
		t.Fatalf("Heartbeat: %v", err)
	}
	sizeAfter, err := blobstore.FilePersister{Path: path}.Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if string(sizeBefore) != string(sizeAfter) {
		t.Fatal("a steady-state heartbeat rewrote the registry file (write amplification)")
	}
}

func TestSameStatusRouteHeartbeatSurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "connector_registry.json")
	now := time.Now()
	r1 := newPersistedRegistry(t, path)
	conn := testRegistration("conn_route")
	conn.Status = "healthy"
	conn.ReachableRoutes = model.ConnectorReachableRoutes{CIDRs: []string{"10.1.0.0/24"}}
	if _, err := r1.Register(conn, now); err != nil {
		t.Fatalf("Register: %v", err)
	}
	before := r1.ConfigGeneration()
	if _, err := r1.Heartbeat(model.ConnectorHeartbeat{
		ID: "conn_route", TenantID: "tenant_a", Status: "healthy",
		ReachableRoutes: &model.ConnectorReachableRoutes{CIDRs: []string{"10.2.0.0/24"}},
	}, now.Add(time.Minute)); err != nil {
		t.Fatalf("route heartbeat: %v", err)
	}
	if r1.ConfigGeneration() != before+1 {
		t.Fatal("route change must trigger fleet catalog refresh")
	}
	r2 := newPersistedRegistry(t, path)
	got, ok := r2.Get("conn_route")
	if !ok || len(got.ReachableRoutes.CIDRs) != 1 || got.ReachableRoutes.CIDRs[0] != "10.2.0.0/24" {
		t.Fatalf("same-status route change lost across restart: ok=%v routes=%v", ok, got.ReachableRoutes.CIDRs)
	}
}

// Persistence is opt-in: without a persister nothing is written and the old behaviour is unchanged.
func TestNoPersisterKeepsInMemoryBehaviour(t *testing.T) {
	r := NewRegistry()
	if _, err := r.Register(testRegistration("conn_mem"), time.Now()); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if _, ok := r.Get("conn_mem"); !ok {
		t.Fatal("in-memory registry must still work")
	}
}
