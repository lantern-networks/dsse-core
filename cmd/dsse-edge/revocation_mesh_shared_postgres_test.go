package main

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/revocation"
)

func TestPostgresMeshCanceledOriginDelivery(t *testing.T) {
	d, _, leader, peerLeader := trustDistributionPostgresFixture(t)
	p := d.store.(postgresBlobPersister)
	p.key = "revocation_mesh_outbox"
	o, err := newRevocationMeshOutbox(p)
	if err != nil {
		t.Fatal(err)
	}
	requests := make(chan bool, 2)
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check independent storage at receipt, before allowing the ACK cleanup.
		fresh, err := newRevocationMeshOutbox(p)
		requests <- err == nil && len(fresh.snapshot()) == 1
	}))
	defer peer.Close()
	s := revocationMeshSource{outbox: o, client: peer.Client(), secret: "synthetic", originRegion: "origin"}
	ctx, cancel := context.WithCancel(captureCPWriteLease(context.Background()))
	cancel()
	target := revocationMeshPeer{region: "peer", url: peer.URL}
	item := revocationMeshItem{Identity: "target", Reason: "block", OriginRegion: "origin"}
	s.deliverToPeerContext(ctx, target, item)
	select {
	case persisted := <-requests:
		if !persisted {
			t.Fatal("delivery preceded durable enqueue")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("canceled origin lost delivery")
	}
	waitUntil(t, 2*time.Second, func() bool { return len(o.snapshot()) == 0 }, "shared ACK cleanup")
	if len(meshOutboxLoaded(t, p)) != 0 {
		t.Fatal("ACK cleanup not durable")
	}
	leader.release()
	peerLeader.tick()
	peerLeader.release()
	leader.tick()
	s.deliverToPeerContext(ctx, target, item)
	select {
	case <-requests:
		t.Fatal("canceled old term delivered after reacquisition")
	case <-time.After(100 * time.Millisecond):
	}
	if len(o.snapshot()) != 0 || len(meshOutboxLoaded(t, p)) != 0 {
		t.Fatal("old term retained delivery")
	}
}

func TestPostgresMeshSharedLifecycleAndPromotion(t *testing.T) {
	d, _, leader, peer := trustDistributionPostgresFixture(t)
	p := d.store.(postgresBlobPersister)
	p.key = "revocation_mesh_outbox"
	a, err := newRevocationMeshOutbox(p)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := newRevocationMeshOutbox(p)
	old, _, err := a.enqueue(meshOutboxEntry("old"))
	if err != nil {
		t.Fatal(err)
	}
	other := meshOutboxEntry("peer")
	other.Identity = "other"
	if _, _, err = b.enqueue(other); err != nil {
		t.Fatal(err)
	}
	if len(meshOutboxLoaded(t, p)) != 2 {
		t.Fatal("peer lost")
	}
	newest, _, err := b.enqueue(meshOutboxEntry("old"))
	if err != nil {
		t.Fatal(err)
	}
	if done, _, err := a.ack(old); done || err != nil {
		t.Fatal("old ACK", done, err)
	}
	stale := meshWriteContext(context.Background())
	leader.release()
	peer.tick()
	peer.release()
	leader.tick()
	before, _ := p.Load()
	beforeLocal := meshSharedWire(b.snapshot()[0])
	if _, _, err = b.ackContext(stale, newest); !errors.Is(err, blobstore.ErrWriteNotCommitted) {
		t.Fatal("old ACK term accepted", err)
	}
	if _, _, err = b.enqueueContext(stale, other); !errors.Is(err, blobstore.ErrWriteNotCommitted) {
		t.Fatal("old enqueue term accepted", err)
	}
	if beforeLocal != meshSharedWire(b.snapshot()[0]) {
		t.Fatal("old enqueue retained for a later term")
	}
	after, _ := p.Load()
	if !bytes.Equal(before, after) {
		t.Fatal("old term changed row")
	}
	if meshWriteContext(stale) != stale {
		t.Fatal("recaptured stale term")
	}
	if _, err = p.db.Exec(`CREATE FUNCTION refuse_mesh() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'refused'; END $$; CREATE TRIGGER refuse_mesh BEFORE UPDATE ON cp_state_blobs FOR EACH ROW EXECUTE FUNCTION refuse_mesh()`); err != nil {
		t.Fatal(err)
	}
	e := meshOutboxEntry("retry")
	e.Identity = "retry"
	e, _, err = a.enqueue(e)
	if !errors.Is(err, blobstore.ErrWriteNotCommitted) {
		t.Fatal("precommit refusal", err)
	}
	if _, err = p.db.Exec(`DROP TRIGGER refuse_mesh ON cp_state_blobs; DROP FUNCTION refuse_mesh()`); err != nil {
		t.Fatal(err)
	}
	if current, _, err := a.retryPending(e); !current || err != nil {
		t.Fatal("retry", current, err)
	}
	// A stale constructor must reload every pending row before resuming. The peer
	// is a local HTTP CP fixture, not an AWS region or an independent Edge.
	var requests atomic.Int64
	sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1); w.WriteHeader(200) }))
	defer sink.Close()
	for _, entry := range meshOutboxLoaded(t, p) {
		entry.URL = sink.URL
		if _, _, err = b.enqueue(entry); err != nil {
			t.Fatal(err)
		}
	}
	source := revocationMeshSource{outbox: a, client: sink.Client()}
	if source.pushPendingContext(stale, revocationMeshPeer{url: sink.URL}, revocationMeshItem{Identity: "old"}, &old) {
		t.Fatal("old worker delivered")
	}
	if requests.Load() != 0 {
		t.Fatal("stale term sent HTTP")
	}
	leader.release()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); source.resumeOnLeadership(ctx) }()
	defer func() { cancel(); <-done }()
	time.Sleep(50 * time.Millisecond)
	if requests.Load() != 0 {
		t.Fatal("standby sent")
	}
	leader.tick()
	waitUntil(t, 6*time.Second, func() bool { return requests.Load() == 3 && len(meshOutboxLoaded(t, p)) == 0 }, "promotion reload and drain")
	// Request authority survives the admission callback, including a stale term
	// introduced between successful admission persistence and outbox enqueue.
	revp := p
	revp.key = "admission_revocations"
	overlay := revocation.NewAdmissionRevocations()
	if err = overlay.SetPersister(revp); err != nil {
		t.Fatal(err)
	}
	req := meshWriteContext(context.Background())
	var received context.Context
	overlay.SetMeshReporterContext(func(c context.Context, id, reason string) { received = c })
	if _, err = overlay.RevokeCheckedContext(req, "ctx-device", "block"); err != nil || received != req {
		t.Fatal("request context lost", err)
	}
}
