package device

import (
	"errors"
	"github.com/lantern-networks/dsse-core/model"
	"sync"
	"testing"
	"time"
)

type unsavedFactPersister struct {
	saved []byte
	fail  bool
	saves int
}

func (p *unsavedFactPersister) Load() ([]byte, error) { return append([]byte(nil), p.saved...), nil }
func (p *unsavedFactPersister) Save(b []byte) error {
	p.saves++
	if p.fail {
		return errors.New("disk unavailable")
	}
	p.saved = append([]byte(nil), b...)
	return nil
}

func TestAHeartbeatRepeatingAFactThatWasNotSavedIsNotAnsweredAsSaved(t *testing.T) {
	p := &unsavedFactPersister{}
	s := NewStore()
	if err := s.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 13, 0, 0, 0, 0, time.UTC)
	if _, err := s.Register(model.Device{ID: "dev", TenantID: "tenant", Status: "healthy", AgentVersion: "0.4.1"}, model.PolicyBundle{}, now); err != nil {
		t.Fatal(err)
	}
	p.fail = true
	beat := model.DeviceHeartbeat{ID: "dev", TenantID: "tenant", Status: "healthy", AgentVersion: "0.4.2"}
	if _, err := s.Heartbeat(beat, model.PolicyBundle{}, now.Add(time.Second)); err == nil {
		t.Fatal("initial fact write did not fail")
	}
	before := p.saves
	got, err := s.Heartbeat(beat, model.PolicyBundle{}, now.Add(2*time.Second))
	reboot := NewStore()
	if err := reboot.SetPersister(&unsavedFactPersister{saved: p.saved}); err != nil {
		t.Fatal(err)
	}
	durable, _ := reboot.Get("dev")
	t.Logf("retry result: error=%v served_version=%s durable_version=%s synchronous_saves=%d", err, got.AgentVersion, durable.AgentVersion, p.saves-before)
	if err == nil {
		t.Fatalf("same fact was acknowledged while disk still rejects all writes: served=%s durable=%s", got.AgentVersion, durable.AgentVersion)
	}
}

type blockingFactPersister struct {
	mu      sync.Mutex
	saved   []byte
	block   bool
	began   chan struct{}
	release chan struct{}
}

func (p *blockingFactPersister) Load() ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]byte(nil), p.saved...), nil
}
func (p *blockingFactPersister) Save(b []byte) error {
	p.mu.Lock()
	block := p.block
	p.mu.Unlock()
	if block {
		p.began <- struct{}{}
		<-p.release
	}
	p.mu.Lock()
	p.saved = append([]byte(nil), b...)
	p.mu.Unlock()
	return nil
}
func TestAHeartbeatRepeatingAFactStillBeingSavedWaitsForThatSave(t *testing.T) {
	p := &blockingFactPersister{began: make(chan struct{}, 2), release: make(chan struct{})}
	s := NewStore()
	if err := s.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 13, 0, 0, 0, 0, time.UTC)
	if _, err := s.Register(model.Device{ID: "dev", TenantID: "tenant", Status: "healthy", AgentVersion: "0.4.1"}, model.PolicyBundle{}, now); err != nil {
		t.Fatal(err)
	}
	p.mu.Lock()
	p.block = true
	p.mu.Unlock()
	beat := model.DeviceHeartbeat{ID: "dev", TenantID: "tenant", Status: "healthy", AgentVersion: "0.4.2"}
	first := make(chan error, 1)
	go func() { _, err := s.Heartbeat(beat, model.PolicyBundle{}, now.Add(time.Second)); first <- err }()
	select {
	case <-p.began:
	case <-time.After(time.Second):
		t.Fatal("first save never began")
	}
	duplicate := make(chan error, 1)
	go func() { _, err := s.Heartbeat(beat, model.PolicyBundle{}, now.Add(2*time.Second)); duplicate <- err }()
	var early bool
	select {
	case err := <-duplicate:
		early = true
		t.Logf("duplicate returned before disk save: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	durableBytes, _ := p.Load()
	reboot := NewStore()
	if err := reboot.SetPersister(&unsavedFactPersister{saved: durableBytes}); err != nil {
		t.Fatal(err)
	}
	durable, _ := reboot.Get("dev")
	close(p.release)
	if err := <-first; err != nil {
		t.Fatal(err)
	}
	if !early {
		if err := <-duplicate; err != nil {
			t.Fatal(err)
		}
	}
	if early {
		t.Fatalf("duplicate was acknowledged before fact reached disk; durable version=%s", durable.AgentVersion)
	}
}
