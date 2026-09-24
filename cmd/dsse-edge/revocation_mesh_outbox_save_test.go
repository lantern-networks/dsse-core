package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/blobstore"
)

type meshOutboxTestPersister struct {
	mu               sync.Mutex
	data             []byte
	err              error
	retain           bool
	writes           int
	entered, release chan struct{}
}

func (p *meshOutboxTestPersister) Load() ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return bytes.Clone(p.data), nil
}
func (p *meshOutboxTestPersister) Save(b []byte) error {
	p.mu.Lock()
	p.writes++
	err, retain, entered, release := p.err, p.retain, p.entered, p.release
	p.mu.Unlock()
	if entered != nil {
		entered <- struct{}{}
		<-release
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if err == nil || retain {
		p.data = bytes.Clone(b)
	}
	return err
}
func (p *meshOutboxTestPersister) failure(err error, retain bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.err, p.retain = err, retain
}
func (p *meshOutboxTestPersister) count() int { p.mu.Lock(); defer p.mu.Unlock(); return p.writes }
func meshOutboxEntry(reason string) revocationMeshOutboxEntry {
	return revocationMeshOutboxEntry{Region: "peer", URL: "https://peer.invalid", Identity: "target", Reason: reason, OriginRegion: "origin", EnqueuedAt: "2026-09-17T00:00:00Z"}
}
func meshOutboxLoaded(t *testing.T, p blobstore.Persister) []revocationMeshOutboxEntry {
	t.Helper()
	o, e := newRevocationMeshOutbox(p)
	if e != nil {
		t.Fatal(e)
	}
	return o.snapshot()
}
func meshOutboxHas(entries []revocationMeshOutboxEntry, id string) bool {
	for _, e := range entries {
		if e.Identity == id {
			return true
		}
	}
	return false
}
func TestMeshOutboxSaveOutcomesAndRetry(t *testing.T) {
	bridge := errors.Join(blobstore.ErrSavedWithoutAtomicity, blobstore.ErrDurabilityUnconfirmed)
	for _, tc := range []struct {
		name   string
		err    error
		retain bool
		status string
	}{
		{"atomic", nil, true, "saved"}, {"in_place", blobstore.ErrSavedWithoutAtomicity, true, "saved_non_atomic"},
		{"no_write", errors.New("PRIVATE"), false, "unconfirmed"}, {"written_error", errors.New("PRIVATE"), true, "unconfirmed"},
		{"flush_lost", blobstore.ErrDurabilityUnconfirmed, false, "unconfirmed"}, {"flush_retained", blobstore.ErrDurabilityUnconfirmed, true, "unconfirmed"},
		{"dual_lost", bridge, false, "unconfirmed"}, {"dual_retained", bridge, true, "unconfirmed"},
		{"wrapped_lost", fmt.Errorf("PRIVATE: %w", bridge), false, "unconfirmed"}, {"wrapped_retained", fmt.Errorf("PRIVATE: %w", bridge), true, "unconfirmed"},
	} {
		for _, action := range []string{"enqueue", "ack"} {
			t.Run(tc.name+"/"+action, func(t *testing.T) {
				p := &meshOutboxTestPersister{}
				o, e := newRevocationMeshOutbox(p)
				if e != nil {
					t.Fatal(e)
				}
				foreign := meshOutboxEntry("foreign")
				foreign.Region = "other"
				foreign.Identity = "foreign"
				o.enqueue(foreign)
				entry := meshOutboxEntry("old")
				if action == "ack" {
					entry, _, _ = o.enqueue(entry)
				}
				beforeWrites := p.count()
				p.failure(tc.err, tc.retain)
				var status string
				var err error
				var removed bool
				if action == "enqueue" {
					entry, status, err = o.enqueue(entry)
				} else {
					removed, status, err = o.ack(entry)
				}
				failed := tc.status == "unconfirmed"
				if status != tc.status || (err != nil) != failed || (failed && err != errMeshOutboxSave) || p.count() != beforeWrites+1 {
					t.Fatal(status, err, p.count())
				}
				live := o.snapshot()
				disk := meshOutboxLoaded(t, p)
				if !meshOutboxHas(live, "foreign") || !meshOutboxHas(disk, "foreign") {
					t.Fatal("unrelated pending lost")
				}
				if action == "enqueue" {
					if !meshOutboxHas(live, "target") || meshOutboxHas(disk, "target") != tc.retain {
						t.Fatal("enqueue state mismatch")
					}
				} else {
					if removed == failed || meshOutboxHas(live, "target") != failed || meshOutboxHas(disk, "target") == tc.retain {
						t.Fatal("ack published before confirmation")
					}
				}
				p.failure(nil, false)
				if action == "enqueue" {
					current, persistence, e := o.retryPending(entry)
					if e != nil || !current || ((persistence == "saved") != failed) {
						t.Fatal(current, persistence, e)
					}
					if !o.isCurrent(entry) {
						t.Fatal("retry changed delivery revision")
					}
				} else {
					done, persistence, e := o.ack(entry)
					if e != nil || done != failed || ((persistence == "saved") != failed) {
						t.Fatal(done, persistence, e)
					}
				}
				savedWrites := p.count()
				if action == "enqueue" {
					_, status, err = o.retryPending(entry)
				} else {
					_, status, err = o.ack(entry)
				}
				if err != nil || status != "not_attempted" || p.count() != savedWrites {
					t.Fatal("stable retry wrote again")
				}
				a, _ := json.Marshal(o.snapshot())
				b, _ := json.Marshal(meshOutboxLoaded(t, p))
				if !bytes.Equal(a, b) {
					t.Fatal("live/reload mismatch", string(a), string(b))
				}
			})
		}
	}
}
func TestMeshOutboxStaleAcknowledgementIncludesIdenticalReplacement(t *testing.T) {
	for _, same := range []bool{false, true} {
		p := &meshOutboxTestPersister{}
		o, _ := newRevocationMeshOutbox(p)
		old, _, _ := o.enqueue(meshOutboxEntry("same"))
		replacement := old
		if !same {
			replacement.Reason = "new"
			replacement.URL = "https://new.invalid"
		}
		latest, _, _ := o.enqueue(replacement)
		writes := p.count()
		if old.sequence == latest.sequence {
			t.Fatal("replacement reused delivery revision")
		}
		removed, status, e := o.ack(old)
		if e != nil || removed || status != "not_attempted" || !o.isCurrent(latest) || p.count() != writes {
			t.Fatal("old ACK consumed new entry")
		}
		current, _, e := o.retryPending(old)
		if current || e != nil || p.count() != writes {
			t.Fatal("stale persistence retry wrote")
		}
		if removed, _, e := o.ack(latest); e != nil || !removed || len(o.snapshot()) != 0 {
			t.Fatal("current ACK failed")
		}
	}
}
func TestMeshOutboxVolatileLegacyReloadAndSnapshotIsolation(t *testing.T) {
	o, _ := newRevocationMeshOutbox(nil)
	e, persistence, err := o.enqueue(meshOutboxEntry("memory"))
	if err != nil || persistence != "volatile" {
		t.Fatal(err, persistence)
	}
	copy := o.snapshot()
	copy[0].Reason = "changed"
	if !o.isCurrent(e) {
		t.Fatal("snapshot mutates queue")
	}
	if removed, persistence, err := o.ack(e); err != nil || !removed || persistence != "volatile" {
		t.Fatal(removed, persistence, err)
	}
	data, _ := json.Marshal([]revocationMeshOutboxEntry{meshOutboxEntry("legacy")})
	p := &meshOutboxTestPersister{data: data}
	loaded, err := newRevocationMeshOutbox(p)
	if err != nil {
		t.Fatal(err)
	}
	entry := loaded.snapshot()[0]
	if entry.sequence == 0 {
		t.Fatal("legacy pending lacks local revision")
	}
	if removed, _, err := loaded.ack(entry); err != nil || !removed {
		t.Fatal("legacy cleanup failed")
	}
	if string(p.data) != "[]" {
		t.Fatal("queue wire shape changed", string(p.data))
	}
}
func TestMeshOutboxSnapshotDuringSaveAndQueuedReplacement(t *testing.T) {
	for _, action := range []string{"enqueue", "ack"} {
		t.Run(action, func(t *testing.T) {
			p := &meshOutboxTestPersister{}
			o, _ := newRevocationMeshOutbox(p)
			entry, _, _ := o.enqueue(meshOutboxEntry("first"))
			p.entered = make(chan struct{}, 2)
			p.release = make(chan struct{})
			var once sync.Once
			release := func() { once.Do(func() { close(p.release) }) }
			defer release()
			done := make(chan struct{})
			go func() {
				defer close(done)
				if action == "ack" {
					o.ack(entry)
				} else {
					o.enqueue(meshOutboxEntry("new"))
				}
			}()
			select {
			case <-p.entered:
			case <-time.After(2 * time.Second):
				t.Fatal("save not entered")
			}
			read := make(chan []revocationMeshOutboxEntry, 1)
			go func() { read <- o.snapshot() }()
			var pending []revocationMeshOutboxEntry
			select {
			case pending = <-read:
			case <-time.After(2 * time.Second):
				t.Fatal("snapshot blocked on storage")
			}
			if len(pending) != 1 || (action == "enqueue" && pending[0].Reason != "new") || (action == "ack" && pending[0] != entry) {
				t.Fatal("pending state", pending)
			}
			queued := make(chan struct{})
			go func() { defer close(queued); o.enqueue(meshOutboxEntry("queued")) }()
			select {
			case <-done:
				t.Fatal("early completion")
			default:
			}
			select {
			case <-queued:
				t.Fatal("writer overtook save")
			default:
			}
			release()
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("save stuck")
			}
			select {
			case <-queued:
			case <-time.After(2 * time.Second):
				t.Fatal("queued writer stuck")
			}
			if got := o.snapshot(); len(got) != 1 || got[0].Reason != "queued" {
				t.Fatal("queued replacement lost", got)
			}
		})
	}
}
func TestMeshSenderRetriesEnqueuePersistenceWhilePeerUnavailable(t *testing.T) {
	p := &meshOutboxTestPersister{err: errors.New("PRIVATE")}
	o, _ := newRevocationMeshOutbox(p)
	var accept atomic.Bool
	var requests atomic.Int32
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if !accept.Load() {
			w.WriteHeader(503)
		}
	}))
	defer peer.Close()
	s := revocationMeshSource{originRegion: "origin", client: peer.Client(), outbox: o, secret: "synthetic"}
	s.deliverToPeer(revocationMeshPeer{region: "peer", url: peer.URL}, revocationMeshItem{Identity: "target", Reason: "block", OriginRegion: "origin"})
	waitUntil(t, 3*time.Second, func() bool { return requests.Load() > 0 }, "first delivery attempt")
	if len(o.snapshot()) != 1 || len(meshOutboxLoaded(t, p)) != 0 {
		t.Fatal("failed enqueue did not retain live-only pending")
	}
	p.failure(nil, false)
	waitUntil(t, 4*time.Second, func() bool { return len(meshOutboxLoaded(t, p)) == 1 }, "pending save retry without another report")
	accept.Store(true)
	waitUntil(t, 5*time.Second, func() bool { return len(o.snapshot()) == 0 }, "delivery and cleanup")
	if len(meshOutboxLoaded(t, p)) != 0 {
		t.Fatal("cleanup not saved")
	}
}
func TestMeshSenderRetriesAcknowledgedCleanupWithoutResending(t *testing.T) {
	p := &meshOutboxTestPersister{}
	o, _ := newRevocationMeshOutbox(p)
	var requests atomic.Int32
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1); p.failure(errors.New("PRIVATE"), false) }))
	defer peer.Close()
	s := revocationMeshSource{client: peer.Client(), outbox: o}
	s.deliverToPeer(revocationMeshPeer{region: "peer", url: peer.URL}, revocationMeshItem{Identity: "target", Reason: "block"})
	waitUntil(t, 3*time.Second, func() bool { return p.count() >= 2 }, "failed cleanup")
	if len(o.snapshot()) != 1 || len(meshOutboxLoaded(t, p)) != 1 {
		t.Fatal("unconfirmed cleanup disappeared")
	}
	p.failure(nil, false)
	waitUntil(t, 4*time.Second, func() bool { return len(o.snapshot()) == 0 }, "cleanup retry")
	if requests.Load() != 1 || len(meshOutboxLoaded(t, p)) != 0 {
		t.Fatal("peer was resent after ACK or cleanup failed")
	}
}
func TestMeshSenderOldHTTPAckCannotRemoveNewPending(t *testing.T) {
	p := &meshOutboxTestPersister{}
	o, _ := newRevocationMeshOutbox(p)
	oldEntered, newEntered := make(chan struct{}), make(chan struct{})
	oldRelease, newRelease := make(chan struct{}), make(chan struct{})
	var oldOnce, newOnce sync.Once
	releaseOld := func() { oldOnce.Do(func() { close(oldRelease) }) }
	releaseNew := func() { newOnce.Do(func() { close(newRelease) }) }
	defer releaseOld()
	defer releaseNew()
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body revocationMeshItem
		if e := json.NewDecoder(r.Body).Decode(&body); e != nil {
			t.Error(e)
			w.WriteHeader(400)
			return
		}
		if body.Reason == "old" {
			close(oldEntered)
			<-oldRelease
		} else {
			close(newEntered)
			<-newRelease
		}
	}))
	defer peer.Close()
	// Ensure gates are opened before Close waits for active handlers on failure.
	defer releaseOld()
	defer releaseNew()
	s := revocationMeshSource{client: peer.Client(), outbox: o}
	target := revocationMeshPeer{region: "peer", url: peer.URL}
	old := meshOutboxEntry("old")
	old.URL = peer.URL
	old, _, _ = o.enqueue(old)
	oldDone := make(chan bool, 1)
	go func() {
		oldDone <- s.pushPendingToPeerWithRetry(target, revocationMeshItem{Identity: "target", Reason: "old"}, &old)
	}()
	select {
	case <-oldEntered:
	case <-time.After(3 * time.Second):
		t.Fatal("old request absent")
	}
	fresh := old
	fresh.Reason = "new"
	fresh, _, _ = o.enqueue(fresh)
	newDone := make(chan bool, 1)
	go func() {
		newDone <- s.pushPendingToPeerWithRetry(target, revocationMeshItem{Identity: "target", Reason: "new"}, &fresh)
	}()
	select {
	case <-newEntered:
	case <-time.After(3 * time.Second):
		t.Fatal("new request absent")
	}
	releaseOld()
	select {
	case done := <-oldDone:
		if done {
			t.Fatal("old completion claimed cleanup")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("old sender stuck")
	}
	if !o.isCurrent(fresh) || len(meshOutboxLoaded(t, p)) != 1 || meshOutboxLoaded(t, p)[0].Reason != "new" {
		t.Fatal("old HTTP ACK erased new pending")
	}
	releaseNew()
	select {
	case done := <-newDone:
		if !done {
			t.Fatal("new completion rejected")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("new sender stuck")
	}
	if !reflect.DeepEqual(o.snapshot(), []revocationMeshOutboxEntry{}) || len(meshOutboxLoaded(t, p)) != 0 {
		t.Fatal("new pending not cleared")
	}
}
