package revocation

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type admissionGatedStore struct {
	mu          sync.Mutex
	data        []byte
	saves       [][]byte
	gate        chan struct{}
	entered     chan string
	gateLoad    bool
	err         error
	releaseOnce sync.Once
}

func newAdmissionGatedStore(t *testing.T) *admissionGatedStore {
	t.Helper()
	p := &admissionGatedStore{gate: make(chan struct{}), entered: make(chan string, 8)}
	t.Cleanup(p.release)
	return p
}
func (p *admissionGatedStore) release() { p.releaseOnce.Do(func() { close(p.gate) }) }
func (p *admissionGatedStore) Load() ([]byte, error) {
	if p.gateLoad {
		p.entered <- "load"
		<-p.gate
		if p.err != nil {
			return nil, p.err
		}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return bytes.Clone(p.data), nil
}
func (p *admissionGatedStore) Save(data []byte) error {
	p.entered <- "save"
	<-p.gate
	p.mu.Lock()
	defer p.mu.Unlock()
	p.saves = append(p.saves, bytes.Clone(data))
	if p.err == nil {
		p.data = bytes.Clone(data)
	}
	return p.err
}
func admissionWithin[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(2 * time.Second):
		t.Fatal("operation waited for gated storage")
		var zero T
		return zero
	}
}
func admissionAsync[T any](fn func() T) <-chan T {
	done := make(chan T, 1)
	go func() { done <- fn() }()
	return done
}

type admissionReadResult struct {
	target, new, foreign, synced bool
	local, feed                  map[string]string
	list                         []string
	count, syncedCount           int
}

func admissionReadAll(a *AdmissionRevocations) admissionReadResult {
	_, target := a.IsRevoked("target")
	_, fresh := a.IsRevoked("new")
	_, foreign := a.IsRevoked("foreign")
	_, synced := a.IsRevoked("synced")
	return admissionReadResult{target: target, new: fresh, foreign: foreign, synced: synced, local: a.Snapshot(), feed: a.FeedSnapshot(), list: a.List(), count: a.CountDevices([]string{"target", "foreign"}), syncedCount: a.SyncedCount()}
}

func TestAdmissionReadsAndSyncedUpdatesContinueDuringStorage(t *testing.T) {
	for _, action := range []string{"checked_revoke", "legacy_revoke", "mesh", "checked_restore", "legacy_restore", "remove", "load"} {
		for _, failed := range []bool{false, true} {
			name := action + "/ok"
			if failed {
				name = action + "/failed"
			}
			t.Run(name, func(t *testing.T) {
				a := NewAdmissionRevocations()
				a.Revoke("target", "prior")
				a.Revoke("foreign", "keep")
				a.RevokeFromMesh("mesh-kept", "peer")
				a.ReplaceSynced(map[string]string{"synced": "CP"})
				gen := a.ConfigGeneration()
				p := newAdmissionGatedStore(t)
				if failed {
					p.err = errors.New("synthetic storage error")
				}
				if action == "load" {
					p.gateLoad = true
					p.data = []byte(`{"schema_version":"admission_revocations_state.v1","revoked":{"target":"replacement","foreign":"keep"},"mesh_received":{"mesh-kept":"peer"}}`)
				} else {
					if err := a.SetPersister(p); err != nil {
						t.Fatal(err)
					}
				}
				var callbacks atomic.Int32
				a.SetOnRevoked(func(id, reason string) { a.IsRevoked(id); callbacks.Add(1) })
				done := admissionAsync(func() error {
					switch action {
					case "checked_revoke":
						return a.RevokeChecked("new", "deny")
					case "legacy_revoke":
						a.Revoke("new", "deny")
					case "mesh":
						a.RevokeFromMesh("new", "peer")
					case "checked_restore":
						return a.RestoreChecked("target")
					case "legacy_restore":
						a.Restore("target")
					case "remove":
						want := 1
						if failed {
							want = 0
						}
						if n := a.RemoveDevices([]string{"target", "target"}); n != want {
							return errors.New("wrong removal count")
						}
					case "load":
						return a.SetPersister(p)
					}
					return nil
				})
				admissionWithin(t, p.entered)
				during := admissionWithin(t, admissionAsync(func() admissionReadResult { return admissionReadAll(a) }))
				restrictive := action == "checked_revoke" || action == "legacy_revoke" || action == "mesh"
				if !during.target || !during.foreign || !during.synced || during.count != 2 || during.syncedCount != 1 || during.new != restrictive {
					t.Fatalf("unsafe pending read: %+v", during)
				}
				// The independent pulled layer and hook configuration also remain usable.
				admissionWithin(t, admissionAsync(func() bool {
					a.SetReporter(nil)
					a.SetMeshReporter(nil)
					a.ReplaceSynced(map[string]string{"synced-new": "new CP"})
					return true
				}))
				if _, ok := a.IsRevoked("synced-new"); !ok {
					t.Fatal("synced update missing while saving")
				}
				select {
				case <-done:
					t.Fatal("writer acknowledged before storage was released")
				default:
				}
				p.release()
				err := admissionWithin(t, done)
				checked := action == "checked_revoke" || action == "checked_restore" || action == "load"
				if (err != nil) != (failed && checked) {
					t.Fatalf("unexpected result %v", err)
				}
				after := admissionReadAll(a)
				wantTarget := true
				if (action == "remove" || action == "checked_restore" || action == "legacy_restore") && !failed {
					wantTarget = false
				}
				if after.target != wantTarget || !after.foreign || after.new != restrictive {
					t.Fatalf("unsafe completed read: %+v", after)
				}
				if _, ok := a.IsRevoked("synced-new"); !ok {
					t.Fatal("storage completion discarded a concurrent synced update")
				}
				wantGen := gen
				if restrictive || ((action == "checked_restore" || action == "legacy_restore" || action == "load" || action == "remove") && !failed) {
					wantGen++
				}
				if a.ConfigGeneration() != wantGen {
					t.Fatalf("generation got %d want %d", a.ConfigGeneration(), wantGen)
				}
				wantCallbacks := int32(1)
				if restrictive {
					wantCallbacks++
				}
				if callbacks.Load() != wantCallbacks {
					t.Fatalf("callbacks=%d want %d", callbacks.Load(), wantCallbacks)
				}
			})
		}
	}
}

func TestAdmissionPersistedWritersSerializeWithoutLosingLayers(t *testing.T) {
	for _, second := range []string{"revoke", "mesh", "remove"} {
		t.Run(second, func(t *testing.T) {
			a := NewAdmissionRevocations()
			a.Revoke("target", "prior")
			a.Revoke("foreign", "keep")
			a.RevokeFromMesh("mesh-kept", "peer")
			p := newAdmissionGatedStore(t)
			if err := a.SetPersister(p); err != nil {
				t.Fatal(err)
			}
			first := admissionAsync(func() error { return a.RestoreChecked("target") })
			admissionWithin(t, p.entered)
			started := make(chan struct{})
			next := admissionAsync(func() error {
				close(started)
				switch second {
				case "revoke":
					return a.RevokeChecked("later", "second")
				case "mesh":
					a.RevokeFromMesh("later", "second")
				case "remove":
					a.RemoveDevices([]string{"foreign"})
				}
				return nil
			})
			<-started
			a.ReplaceSynced(map[string]string{"synced": "concurrent CP"})
			// A pending permissive write must remain invisible until its storage step completes.
			if _, ok := a.IsRevoked("target"); !ok {
				t.Fatal("pending restore relaxed admission")
			}
			p.release()
			if err := admissionWithin(t, first); err != nil {
				t.Fatal(err)
			}
			if err := admissionWithin(t, next); err != nil {
				t.Fatal(err)
			}
			p.mu.Lock()
			writes := append([][]byte(nil), p.saves...)
			p.mu.Unlock()
			if len(writes) != 2 {
				t.Fatalf("writes=%d", len(writes))
			}
			var saved admissionRevocationsStateFile
			if err := json.Unmarshal(writes[1], &saved); err != nil {
				t.Fatal(err)
			}
			if _, ok := saved.Revoked["target"]; ok {
				t.Fatal("later write resurrected a restored identity")
			}
			if saved.MeshReceived["mesh-kept"] != "peer" {
				t.Fatal("mesh lost")
			}
			if second == "revoke" && saved.Revoked["later"] != "second" {
				t.Fatal("later revoke lost")
			}
			if second == "mesh" && saved.MeshReceived["later"] != "second" {
				t.Fatal("later mesh lost")
			}
			if second == "remove" {
				if _, ok := saved.Revoked["foreign"]; ok {
					t.Fatal("removal lost")
				}
			} else if saved.Revoked["foreign"] != "keep" {
				t.Fatal("foreign lost")
			}
			restored := NewAdmissionRevocations()
			if err := restored.SetPersister(p); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(restored.Snapshot(), a.Snapshot()) || !reflect.DeepEqual(restored.FeedSnapshot(), a.FeedSnapshot()) {
				t.Fatal("saved and live layers diverged")
			}
			if _, ok := a.IsRevoked("synced"); !ok {
				t.Fatal("synced layer overwritten")
			}
		})
	}
}

func TestAdmissionLoadSerializesWithQueuedWriter(t *testing.T) {
	a := NewAdmissionRevocations()
	old := &admissionSavePersister{}
	if err := a.SetPersister(old); err != nil {
		t.Fatal(err)
	}
	a.Revoke("old", "old")
	p := newAdmissionGatedStore(t)
	p.gateLoad = true
	p.data = []byte(`{"schema_version":"admission_revocations_state.v1","revoked":{"replacement":"snapshot"}}`)
	load := admissionAsync(func() error { return a.SetPersister(p) })
	admissionWithin(t, p.entered)
	started := make(chan struct{})
	write := admissionAsync(func() error { close(started); return a.RevokeChecked("later", "queued") })
	<-started
	if _, ok := a.IsRevoked("old"); !ok {
		t.Fatal("old state not readable during load")
	}
	p.release()
	if err := admissionWithin(t, load); err != nil {
		t.Fatal(err)
	}
	if err := admissionWithin(t, write); err != nil {
		t.Fatal(err)
	}
	if old.writes != 1 {
		t.Fatal("queued writer used the old persister")
	}
	want := map[string]string{"replacement": "snapshot", "later": "queued"}
	if !reflect.DeepEqual(a.Snapshot(), want) {
		t.Fatalf("lost write: %v", a.Snapshot())
	}
	p.mu.Lock()
	saved := bytes.Clone(p.data)
	p.mu.Unlock()
	var decoded admissionRevocationsStateFile
	if err := json.Unmarshal(saved, &decoded); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(decoded.Revoked, want) {
		t.Fatal("new persister lost queued write")
	}
}

func TestAdmissionCallbacksCanReenterPersistedWrites(t *testing.T) {
	for _, mesh := range []bool{false, true} {
		t.Run(map[bool]string{true: "mesh", false: "local"}[mesh], func(t *testing.T) {
			a := NewAdmissionRevocations()
			p := &admissionSavePersister{}
			if err := a.SetPersister(p); err != nil {
				t.Fatal(err)
			}
			var calls atomic.Int32
			a.SetOnRevoked(func(id, reason string) {
				calls.Add(1)
				if id == "outer" {
					a.Revoke("inner", "nested")
				}
			})
			done := admissionAsync(func() bool {
				if mesh {
					a.RevokeFromMesh("outer", "peer")
				} else {
					a.Revoke("outer", "local")
				}
				return true
			})
			admissionWithin(t, done)
			if calls.Load() != 2 || len(a.List()) != 2 || p.writes != 2 {
				t.Fatal("callback reentry did not complete")
			}
		})
	}
}
