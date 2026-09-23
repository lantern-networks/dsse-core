package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/revocation"
)

func TestAdmissionMeshRetryAfterProcessExit(t *testing.T) {
	if path := os.Getenv("DSSE_TEST_ADMISSION_EXIT_PATH"); path != "" {
		a := revocation.NewAdmissionRevocations()
		if err := a.SetStatePath(path); err != nil {
			t.Fatal(err)
		}
		a.SetMeshReporterContext(func(context.Context, string, string) { os.Exit(23) })
		a.RevokeChecked("target", "incident")
		t.Fatal("did not exit at delivery boundary")
	}
	dir := t.TempDir()
	p := blobstore.FilePersister{Path: filepath.Join(dir, "admission.json")}
	child := exec.Command(os.Args[0], "-test.run=^TestAdmissionMeshRetryAfterProcessExit$")
	child.Env = append(os.Environ(), "DSSE_TEST_ADMISSION_EXIT_PATH="+p.Path)
	raw, err := child.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 23 {
		t.Fatalf("child exit: %v %s", err, raw)
	}
	a := revocation.NewAdmissionRevocations()
	if err = a.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	if _, ok := a.IsRevoked("target"); !ok {
		t.Fatal("child did not persist admission")
	}
	outp := blobstore.FilePersister{Path: filepath.Join(dir, "outbox.json")}
	out, err := newRevocationMeshOutbox(outp)
	if err != nil || len(out.snapshot()) != 0 {
		t.Fatal("unexpected saved intent", err)
	}
	peerp := blobstore.FilePersister{Path: filepath.Join(dir, "peer.json")}
	receiver := revocation.NewAdmissionRevocations()
	if err = receiver.SetPersister(peerp); err != nil {
		t.Fatal(err)
	}
	receiver.SetMeshReporter(func(string, string) { t.Error("mesh loop") })
	received := make(chan bool, 1)
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var item revocationMeshItem
		if err := json.NewDecoder(r.Body).Decode(&item); err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		if _, err := receiver.RevokeFromMeshChecked(item.Identity, item.Reason); err != nil {
			t.Error(err)
			w.WriteHeader(500)
			return
		}
		fresh, err := newRevocationMeshOutbox(outp)
		received <- err == nil && len(fresh.snapshot()) == 1
	}))
	defer peer.Close()
	source := revocationMeshSource{originRegion: "origin", peers: []revocationMeshPeer{{region: "peer", url: peer.URL}}, client: peer.Client(), outbox: out}
	a.SetMeshReporterContext(source.pushContext)
	if _, err = a.RevokeCheckedContext(context.Background(), "target", "incident"); err != nil {
		t.Fatal(err)
	}
	select {
	case saved := <-received:
		if !saved {
			t.Fatal("delivery before queue save")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("explicit retry did not recover lost delivery")
	}
	waitUntil(t, 2*time.Second, func() bool { return len(out.snapshot()) == 0 }, "ACK cleanup")
	if len(meshOutboxLoaded(t, outp)) != 0 {
		t.Fatal("cleanup not durable")
	}
	fresh := revocation.NewAdmissionRevocations()
	if err = fresh.SetPersister(peerp); err != nil {
		t.Fatal(err)
	}
	if reason, ok := fresh.IsRevoked("target"); !ok || reason != "incident" {
		t.Fatal("peer not persisted")
	}
}

func TestPostgresAdmissionExplicitMeshRetryAuthority(t *testing.T) {
	d, _, leader, peer := trustDistributionPostgresFixture(t)
	p := d.store.(postgresBlobPersister)
	p.key = "admission_revocations"
	a := revocation.NewAdmissionRevocations()
	if err := a.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	old := captureCPWriteLease(context.Background())
	if _, err := a.RevokeCheckedContext(old, "target", "incident"); err != nil {
		t.Fatal(err)
	}
	// Reconstruct from committed admission with no queue; the previous term
	// ended before it could enqueue. This is a term transition, not OS restart.
	a = revocation.NewAdmissionRevocations()
	if err := a.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	op := p
	op.key = "revocation_mesh_outbox"
	out, err := newRevocationMeshOutbox(op)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	a.SetMeshReporterContext(func(ctx context.Context, id, reason string) {
		calls++
		_, _, err := out.enqueueContext(ctx, revocationMeshOutboxEntry{Region: "peer", URL: "https://peer.example.invalid", Identity: id, Reason: reason, OriginRegion: "origin"})
		if err != nil {
			t.Error(err)
		}
	})
	leader.release()
	peer.tick()
	peer.release()
	leader.tick()
	if applied, err := a.RevokeCheckedContext(old, "target", "incident"); err == nil || applied {
		t.Fatal("old term accepted", applied, err)
	}
	if calls != 0 || len(meshOutboxLoaded(t, op)) != 0 {
		t.Fatal("old term queued")
	}
	if _, err = a.RevokeCheckedContext(captureCPWriteLease(context.Background()), "target", "incident"); err != nil {
		t.Fatal(err)
	}
	if calls != 1 || len(meshOutboxLoaded(t, op)) != 1 {
		t.Fatal("current term did not recover")
	}
}
