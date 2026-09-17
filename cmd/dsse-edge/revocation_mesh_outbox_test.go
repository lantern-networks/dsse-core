package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/revocation"
)

func waitUntil(t *testing.T, within time.Duration, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("condition not met within %s: %s", within, msg)
}

// meshSinkServer is a peer CP that folds every pushed revocation into an overlay (no secret check).
func meshSinkServer(t *testing.T, overlay *revocation.AdmissionRevocations) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var item revocationMeshItem
		if err := json.NewDecoder(r.Body).Decode(&item); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		overlay.RevokeFromMesh(item.Identity, item.Reason)
		w.WriteHeader(http.StatusOK)
	}))
}

// TestRevocationMeshOutboxSurvivesRestartAndResumes is the proof: a cross-region push enqueued but not
// acked before a CP restart is persisted, reloaded by a fresh source, and driven to completion on boot — the peer
// ends up denying the device even though the origin "restarted" between enqueue and delivery.
func TestRevocationMeshOutboxSurvivesRestartAndResumes(t *testing.T) {
	peerOverlay := revocation.NewAdmissionRevocations()
	peer := meshSinkServer(t, peerOverlay)
	defer peer.Close()

	persister := blobstore.FilePersister{Path: filepath.Join(t.TempDir(), "revocation_mesh_outbox.json")}

	// --- "previous process": a push was enqueued (durably) but the process restarted before it was acked. ---
	o1, err := newRevocationMeshOutbox(persister)
	if err != nil {
		t.Fatalf("new outbox: %v", err)
	}
	o1.enqueue(revocationMeshOutboxEntry{
		Region: "region-b", URL: peer.URL, Identity: "dev-roamer", Reason: "admin_kill",
		OriginRegion: "region-a", EnqueuedAt: "2026-07-23T00:00:00Z",
	})
	if peerOverlay != nil {
		if _, ok := peerOverlay.IsRevoked("dev-roamer"); ok {
			t.Fatal("peer must NOT be revoked yet — nothing has been delivered")
		}
	}

	// --- "restart": a fresh outbox on the SAME persister must reload the pending push. ---
	o2, err := newRevocationMeshOutbox(persister)
	if err != nil {
		t.Fatalf("reload outbox: %v", err)
	}
	if got := o2.snapshot(); len(got) != 1 || got[0].Identity != "dev-roamer" {
		t.Fatalf("restart did not reload the pending push: %+v", got)
	}

	// --- boot resume drives delivery to completion and acks the outbox. ---
	src := revocationMeshSource{
		originRegion: "region-a",
		peers:        []revocationMeshPeer{{region: "region-b", url: peer.URL}},
		client:       peer.Client(),
		outbox:       o2,
	}
	if n := src.resumePendingDeliveries(); n != 1 {
		t.Fatalf("resumePendingDeliveries = %d, want 1", n)
	}
	waitUntil(t, 3*time.Second, func() bool {
		_, revoked := peerOverlay.IsRevoked("dev-roamer")
		return revoked && len(o2.snapshot()) == 0
	}, "peer should be revoked and the outbox drained after resume")

	// The durable store is now empty (the acked push is gone), so a further restart re-drives nothing.
	o3, err := newRevocationMeshOutbox(persister)
	if err != nil {
		t.Fatalf("reload after ack: %v", err)
	}
	if got := o3.snapshot(); len(got) != 0 {
		t.Fatalf("acked push must not persist: %+v", got)
	}
}

// TestRevocationMeshReporterEnqueuesBeforeDelivery proves the reporter path persists the push BEFORE attempting
// delivery after a successful save. The peer here is unreachable, so delivery
// never succeeds, yet the confirmed queue snapshot can be reloaded. Save failures
// are covered separately and do not guarantee restart recovery.
func TestRevocationMeshReporterEnqueuesBeforeDelivery(t *testing.T) {
	persister := blobstore.FilePersister{Path: filepath.Join(t.TempDir(), "revocation_mesh_outbox.json")}
	o, err := newRevocationMeshOutbox(persister)
	if err != nil {
		t.Fatalf("new outbox: %v", err)
	}
	src := revocationMeshSource{
		originRegion: "region-a",
		peers:        []revocationMeshPeer{{region: "region-b", url: "http://127.0.0.1:1"}}, // unreachable
		client:       &http.Client{Timeout: 200 * time.Millisecond},
		outbox:       o,
	}
	overlay := revocation.NewAdmissionRevocations()
	overlay.SetMeshReporter(src.pushFunc())

	overlay.Revoke("dev-x", "admin_kill") // reporter enqueues synchronously, then a goroutine retries (and fails)

	// The push is durable immediately, independent of delivery.
	reloaded, err := newRevocationMeshOutbox(persister)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	got := reloaded.snapshot()
	if len(got) != 1 || got[0].Identity != "dev-x" || got[0].Region != "region-b" {
		t.Fatalf("reporter must durably enqueue the pending push before delivery: %+v", got)
	}
}

// TestRevocationMeshOutboxEnqueueAckAndNilPersister covers the outbox mechanics: enqueue is idempotent per
// (region,identity), ack removes, and a nil persister degrades to a working in-memory outbox.
func TestRevocationMeshOutboxEnqueueAckAndNilPersister(t *testing.T) {
	persister := blobstore.FilePersister{Path: filepath.Join(t.TempDir(), "outbox.json")}
	o, err := newRevocationMeshOutbox(persister)
	if err != nil {
		t.Fatal(err)
	}
	e := revocationMeshOutboxEntry{Region: "region-b", URL: "https://cp.b", Identity: "d1", Reason: "kill", OriginRegion: "region-a"}
	o.enqueue(e)
	e, _, _ = o.enqueue(e) // same key -> still 1; capture the latest delivery
	o.enqueue(revocationMeshOutboxEntry{Region: "region-c", URL: "https://cp.c", Identity: "d1", Reason: "kill", OriginRegion: "region-a"})
	if got := o.snapshot(); len(got) != 2 {
		t.Fatalf("want 2 pending (per region), got %d: %+v", len(got), got)
	}
	o.ack(e)
	if got := o.snapshot(); len(got) != 1 || got[0].Region != "region-c" {
		t.Fatalf("ack should remove only region-b: %+v", got)
	}
	o.ack(e) // idempotent no-op

	// nil persister: memory-only, no panic, enqueue/ack still work.
	mem, err := newRevocationMeshOutbox(nil)
	if err != nil {
		t.Fatalf("nil persister: %v", err)
	}
	latest, _, _ := mem.enqueue(e)
	if len(mem.snapshot()) != 1 {
		t.Fatal("nil-persister outbox must still hold entries in memory")
	}
	mem.ack(latest)
	if len(mem.snapshot()) != 0 {
		t.Fatal("nil-persister ack must work")
	}
}
