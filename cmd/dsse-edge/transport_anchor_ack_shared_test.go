package main

import (
	"bytes"
	"context"
	"fmt"
	"testing"
	"time"
)

type ackFailureStore struct {
	transactionalCAFixture
	fail bool
}

func (p *ackFailureStore) Save(raw []byte) error {
	if p.fail {
		return fmt.Errorf("save rejected")
	}
	return p.transactionalCAFixture.Save(raw)
}
func (p *ackFailureStore) Load() ([]byte, error) {
	if p.fail {
		return nil, fmt.Errorf("unavailable")
	}
	return p.transactionalCAFixture.Load()
}
func (p *ackFailureStore) UpdateContext(ctx context.Context, edit func([]byte) ([]byte, error)) error {
	if p.fail {
		return fmt.Errorf("unavailable")
	}
	return p.transactionalCAFixture.UpdateContext(ctx, edit)
}

func TestACKFailedSaveMustNotOpenWithdrawalGate(t *testing.T) {
	p := &ackFailureStore{}
	a := newSharedTransportAnchorAcknowledgements(p)
	p.fail = true
	if err := a.Acknowledge("abc", "device", "checked", "admin", time.Now()); err == nil {
		t.Fatal("expected failure")
	}
	if got := a.For("abc"); len(got) != 0 {
		t.Fatal("failed assertion can still open withdrawal gate", got)
	}
}

func TestACKSharedWritersPreservePeerAndWithdrawal(t *testing.T) {
	p := &transactionalCAFixture{}
	a, b := newSharedTransportAnchorAcknowledgements(p), newSharedTransportAnchorAcknowledgements(p)
	for _, v := range []struct {
		s  *transportAnchorAcknowledgements
		id string
	}{{a, "one"}, {b, "two"}} {
		if err := v.s.Acknowledge("abc", v.id, "checked", "admin", time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	if got := newSharedTransportAnchorAcknowledgements(p).For("abc"); len(got) != 2 {
		t.Fatal("peer assertion lost", got)
	}
	if err := a.Withdraw("abc", "two"); err != nil {
		t.Fatal(err)
	}
	if err := b.Acknowledge("abc", "three", "checked", "admin", time.Now()); err != nil {
		t.Fatal(err)
	}
	got := a.For("abc")
	if len(got) != 2 || got[0].Identity != "one" || got[1].Identity != "three" {
		t.Fatal("stale read or resurrected withdrawal", got)
	}
	raw, _ := p.Load()
	if bytes.Contains(raw, []byte(`"identity":"two"`)) {
		t.Fatal("withdrawal resurrected")
	}
}

func TestACKFailedWithdrawalAndCorruptReadStayClosed(t *testing.T) {
	p := &ackFailureStore{}
	a := newSharedTransportAnchorAcknowledgements(p)
	if err := a.Acknowledge("abc", "device", "checked", "admin", time.Now()); err != nil {
		t.Fatal(err)
	}
	p.fail = true
	if _, err := a.ForChecked("abc"); err == nil {
		t.Fatal("read failure hidden")
	}
	if err := a.Withdraw("abc", "device"); err == nil {
		t.Fatal("expected failure")
	}
	p.fail = false
	if len(a.For("abc")) != 0 {
		t.Fatal("failed withdrawal reopened locally after refresh")
	}
	if err := a.Withdraw("abc", "device"); err != nil {
		t.Fatal(err)
	}
	if len(newSharedTransportAnchorAcknowledgements(p).For("abc")) != 0 {
		t.Fatal("withdrawal did not persist")
	}
	for _, raw := range [][]byte{nil, {}, []byte("{}"), []byte(`{"schema_version":"admin_transport_anchor_ack.v1","acknowledgements":[{}]}`)} {
		p.Save(raw)
		if _, err := a.ForChecked("abc"); err == nil {
			t.Fatal("invalid/missing row accepted", string(raw))
		}
		if err := a.Acknowledge("abc", "new", "checked", "admin", time.Now()); err == nil {
			t.Fatal("invalid row overwritten")
		}
	}
}

func TestACKLatestRowExtensionAndCanceledMutation(t *testing.T) {
	p := &transactionalCAFixture{raw: []byte(`{"schema_version":"admin_transport_anchor_ack.v1","acknowledgements":[],"future":"keep"}`)}
	a := newSharedTransportAnchorAcknowledgements(p)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	before, _ := p.Load()
	if err := a.AcknowledgeContext(ctx, "abc", "device", "checked", "admin", time.Now()); err == nil {
		t.Fatal("canceled write succeeded")
	}
	after, _ := p.Load()
	if !bytes.Equal(before, after) {
		t.Fatal("canceled write changed row")
	}
	if err := a.Acknowledge("abc", "device", "checked", "admin", time.Now()); err != nil {
		t.Fatal(err)
	}
	after, _ = p.Load()
	if !bytes.Contains(after, []byte(`"future":"keep"`)) {
		t.Fatal("extension lost")
	}
	p.failCommit = true
	if err := a.Acknowledge("abc", "new", "checked", "admin", time.Now()); err == nil {
		t.Fatal("commit failed")
	}
	if len(a.For("abc")) != 1 {
		t.Fatal("failed commit authorized")
	}
}

type ackWaitingWriter struct {
	transactionalCAFixture
	entered, release chan struct{}
}

func (p *ackWaitingWriter) UpdateContext(ctx context.Context, edit func([]byte) ([]byte, error)) error {
	close(p.entered)
	<-p.release
	return p.transactionalCAFixture.UpdateContext(ctx, edit)
}
func TestACKGateReadDoesNotWaitForWriterLease(t *testing.T) {
	p := &ackWaitingWriter{entered: make(chan struct{}), release: make(chan struct{})}
	a := newSharedTransportAnchorAcknowledgements(p)
	done := make(chan error, 1)
	go func() {
		done <- a.AcknowledgeContext(context.Background(), "abc", "device", "checked", "admin", time.Now())
	}()
	<-p.entered
	read := make(chan error, 1)
	go func() { _, err := a.ForChecked("abc"); read <- err }()
	blocked := false
	select {
	case err := <-read:
		if err != nil {
			t.Error(err)
		}
	case <-time.After(time.Second):
		blocked = true
	}
	close(p.release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if blocked {
		<-read
		t.Fatal("withdrawal gate read waits for writer lease; inverts the trust transaction lock order")
	}
}
