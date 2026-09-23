package main

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/blobstore"
)

type erasureIOBlocker struct {
	blobstore.FilePersister
	operation       string
	entered, resume chan struct{}
	once            sync.Once
}

func (p *erasureIOBlocker) wait(operation string) {
	if p.operation == operation {
		p.once.Do(func() { close(p.entered); <-p.resume })
	}
}
func (p *erasureIOBlocker) Load() ([]byte, error) { p.wait("load"); return p.FilePersister.Load() }
func (p *erasureIOBlocker) Save(raw []byte) error { p.wait("save"); return p.FilePersister.Save(raw) }

func TestLocalErasureOwnerCancellation(t *testing.T) {
	for _, operation := range []string{"load", "save"} {
		for _, begin := range []bool{true, false} {
			name := operation + "/finish"
			if begin {
				name = operation + "/begin"
			}
			t.Run(name, func(t *testing.T) {
				file := blobstore.FilePersister{Path: filepath.Join(t.TempDir(), "holds.json")}
				h := newLegalHoldStore(file)
				h.deletionGuard = &deletionSafetyGuard{process: "00112233445566778899aabbccddeeff"}
				fence := tenantErasureFence{ID: "112233445566778899aabbccddeeff00", Node: "review", StartedAt: time.Now().UTC().Format(time.RFC3339Nano)}
				fences := map[string]tenantErasureFence{}
				if !begin {
					fences["target"] = fence
				}
				raw, err := encodeHoldSnapshot(map[string]legalHoldRecord{"peer": {TenantID: "peer"}}, fences, 3, &deletionSafetyPermit{Process: h.deletionGuard.process, Term: "local"})
				if err != nil {
					t.Fatal(err)
				}
				if err = file.Save(raw); err != nil {
					t.Fatal(err)
				}
				h.held = map[string]legalHoldRecord{"peer": {TenantID: "peer"}}
				h.erasures = fences
				h.snapshotVersion = 3
				p := &erasureIOBlocker{FilePersister: file, operation: operation, entered: make(chan struct{}), resume: make(chan struct{})}
				h.persister = p
				var once sync.Once
				release := func() { once.Do(func() { close(p.resume) }) }
				defer release()
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				done := make(chan error, 1)
				go func() { done <- h.changeErasure(ctx, "target", fence, begin) }()
				select {
				case <-p.entered:
				case <-time.After(time.Second):
					t.Fatal("I/O not entered")
				}
				cancel()
				select {
				case err = <-done:
					if !errors.Is(err, context.Canceled) {
						t.Errorf("error=%v", err)
					}
				case <-time.After(300 * time.Millisecond):
					release()
					<-done
					t.Fatal("erasure marker caller still blocked after cancellation")
				}
				wait, stop := context.WithTimeout(context.Background(), 30*time.Millisecond)
				err = h.writeMu.LockContext(wait)
				stop()
				if err == nil {
					h.writeMu.Unlock()
					t.Fatal("owner released exclusion before actual I/O ended")
				}
				saved, _ := file.Load()
				if !bytes.Equal(saved, raw) {
					t.Fatal("blocked I/O changed file")
				}
				release()
				wait, stop = context.WithTimeout(context.Background(), time.Second)
				defer stop()
				if err = h.writeMu.LockContext(wait); err != nil {
					t.Fatal(err)
				}
				h.writeMu.Unlock()
				saved, err = file.Load()
				if err != nil {
					t.Fatal(err)
				}
				snapshot, err := decodeHoldSnapshot(saved, true)
				if err != nil {
					t.Fatal(err)
				}
				_, present := snapshot.Erasures["target"]
				expected := !begin
				if operation == "save" {
					expected = begin
				}
				if present != expected {
					t.Fatalf("late durable marker=%v want=%v", present, expected)
				}
				fresh := newLegalHoldStore(file)
				if _, ok := fresh.erasures["target"]; ok != expected {
					t.Fatal("fresh marker mismatch")
				}
				if !fresh.IsHeld("peer") {
					t.Fatal("peer hold lost")
				}
				if present {
					if _, _, err := h.beginErasure(context.Background(), "target", "retry"); !errors.Is(err, errTenantErasureInProgress) {
						t.Fatalf("unreconciled retry=%v", err)
					}
				}
			})
		}
	}
}
