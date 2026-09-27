package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/lantern-networks/dsse-core/blobstore"
)

type meshSharedTestPersister struct {
	mu             sync.Mutex
	raw            []byte
	fail, loadFail error
	commitUnknown  bool
}

func (p *meshSharedTestPersister) Load() ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return bytes.Clone(p.raw), p.loadFail
}
func (p *meshSharedTestPersister) Save(b []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.raw = bytes.Clone(b)
	return nil
}
func (p *meshSharedTestPersister) UpdateContext(ctx context.Context, edit func([]byte) ([]byte, error)) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return errors.Join(blobstore.ErrWriteNotCommitted, err)
	}
	if p.fail != nil {
		return errors.Join(blobstore.ErrWriteNotCommitted, p.fail)
	}
	b, err := edit(bytes.Clone(p.raw))
	if err != nil {
		return errors.Join(blobstore.ErrWriteNotCommitted, err)
	}
	p.raw = bytes.Clone(b)
	if p.commitUnknown {
		return errors.New("commit result unavailable")
	}
	return nil
}
func TestMeshSharedPeerEnqueueAndStaleAck(t *testing.T) {
	for _, action := range []string{"enqueue", "ack", "identical replacement"} {
		t.Run(action, func(t *testing.T) {
			p := &meshSharedTestPersister{}
			a, _ := newRevocationMeshOutbox(p)
			b, _ := newRevocationMeshOutbox(p)
			old, _, err := a.enqueue(meshOutboxEntry("old"))
			if err != nil {
				t.Fatal(err)
			}
			if action == "enqueue" {
				other := meshOutboxEntry("other")
				other.Identity = "other"
				if _, _, err = b.enqueue(other); err != nil {
					t.Fatal(err)
				}
				if got := meshOutboxLoaded(t, p); len(got) != 2 {
					t.Fatalf("peer pending erased: %+v", got)
				}
			} else {
				next := meshOutboxEntry("old")
				if action == "ack" {
					next.Reason = "new"
				}
				if _, _, err = b.enqueue(next); err != nil {
					t.Fatal(err)
				}
				if removed, _, err := a.ack(old); err != nil || removed {
					t.Fatalf("old ACK consumed replacement: removed=%t err=%v", removed, err)
				}
				if got := meshOutboxLoaded(t, p); len(got) != 1 || got[0].Reason != next.Reason {
					t.Fatal(got)
				}
			}
		})
	}
}

// JSON is compared independently of each process's local enqueue counter.
func meshSharedWire(e revocationMeshOutboxEntry) string { b, _ := json.Marshal(e); return string(b) }

func TestMeshSharedRefusalRetryAndPeerReplacement(t *testing.T) {
	for _, replace := range []bool{false, true} {
		t.Run(fmt.Sprint(replace), func(t *testing.T) {
			p := &meshSharedTestPersister{}
			a, _ := newRevocationMeshOutbox(p)
			b, _ := newRevocationMeshOutbox(p)
			other := meshOutboxEntry("keep")
			other.Identity = "other"
			b.enqueue(other)
			p.fail = errors.New("refuse")
			e, status, err := a.enqueue(meshOutboxEntry("retry"))
			if err == nil || status != "unconfirmed" {
				t.Fatal(status, err)
			}
			if !a.isCurrent(e) || len(meshOutboxLoaded(t, p)) != 1 {
				t.Fatal("failed enqueue not retained locally or changed disk")
			}
			p.fail = nil
			if replace {
				b.enqueue(meshOutboxEntry("newer"))
			}
			current, status, err := a.retryPending(e)
			if err != nil || current == replace || status != "saved" {
				t.Fatal(current, status, err)
			}
			got := meshOutboxLoaded(t, p)
			if len(got) != 2 {
				t.Fatal("peer lost", got)
			}
			for _, g := range got {
				if g.Identity == "target" && replace && g.Reason != "newer" {
					t.Fatal("retry overwrote peer", g)
				}
			}
			if !replace {
				p.fail = errors.New("ack refusal")
				before, _ := p.Load()
				if done, _, err := a.ack(e); done || err == nil {
					t.Fatal("unconfirmed removal")
				}
				after, _ := p.Load()
				if !bytes.Equal(before, after) || !a.isCurrent(e) {
					t.Fatal("failed ACK removed queue")
				}
				p.fail = nil
				if done, _, err := a.ack(e); !done || err != nil {
					t.Fatal(done, err)
				}
			}
		})
	}
}
func TestMeshSharedUnknownCommitAndInvalidRead(t *testing.T) {
	for _, action := range []string{"enqueue", "ack"} {
		t.Run(action, func(t *testing.T) {
			p := &meshSharedTestPersister{}
			a, _ := newRevocationMeshOutbox(p)
			e, _, _ := a.enqueue(meshOutboxEntry("old"))
			p.commitUnknown = true
			var err error
			if action == "enqueue" {
				e, _, err = a.enqueue(meshOutboxEntry("unknown"))
			} else {
				_, _, err = a.ack(e)
			}
			if err == nil {
				t.Fatal("unknown commit accepted")
			}
			p.commitUnknown = false
			before, _ := p.Load()
			if _, _, err = a.retryPending(e); err == nil {
				t.Fatal("unknown replay accepted")
			}
			if _, err = a.pendingForResume(); err == nil {
				t.Fatal("uncertain resume accepted")
			}
			after, _ := p.Load()
			if !bytes.Equal(before, after) {
				t.Fatal("unknown rewritten")
			}
			fresh, err := newRevocationMeshOutbox(p)
			if err != nil {
				t.Fatal(err)
			}
			want := 1
			if action == "ack" {
				want = 0
			}
			if len(fresh.snapshot()) != want {
				t.Fatal("committed outcome lost")
			}
		})
	}
	p := &meshSharedTestPersister{}
	a, _ := newRevocationMeshOutbox(p)
	a.enqueue(meshOutboxEntry("known"))
	saved, _ := p.Load()
	for _, bad := range [][]byte{nil, []byte("null"), []byte(`[{}]`)} {
		p.raw = bad
		if _, err := a.pendingForResume(); err == nil {
			t.Fatal("bad queue resumed")
		}
		if _, _, err := a.enqueue(meshOutboxEntry("no overwrite")); err == nil {
			t.Fatal("bad queue overwritten")
		}
		if !bytes.Equal(p.raw, bad) {
			t.Fatal("bad row changed")
		}
	}
	p.raw = saved
	p.loadFail = errors.New("load failure")
	if _, err := a.pendingForResume(); err == nil {
		t.Fatal("failed read resumed old cache")
	}
	p.loadFail = nil
	if _, err := a.pendingForResume(); err != nil {
		t.Fatal("read recovery", err)
	}
}
func TestMeshSharedLegacyAndConcurrentWriters(t *testing.T) {
	p := &meshSharedTestPersister{raw: []byte(meshRestoreValid)}
	a, _ := newRevocationMeshOutbox(p)
	old := a.snapshot()[0]
	b, _ := newRevocationMeshOutbox(p)
	fresh, _, err := b.enqueue(old)
	if err != nil {
		t.Fatal(err)
	}
	if fresh.Revision == "" {
		t.Fatal("no durable revision")
	}
	if done, _, err := a.ack(old); done || err != nil {
		t.Fatal("legacy ACK consumed new generation")
	}
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			o, err := newRevocationMeshOutbox(p)
			if err == nil {
				e := meshOutboxEntry("concurrent")
				e.Identity = fmt.Sprint("device-", i)
				_, _, err = o.enqueue(e)
			}
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if got := meshOutboxLoaded(t, p); len(got) != 9 {
		t.Fatal("concurrent records lost", len(got))
	}
}
