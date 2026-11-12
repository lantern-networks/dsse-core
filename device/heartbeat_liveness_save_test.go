package device

import (
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/model"
)

// Every heartbeat used to save the whole inventory under the store lock: 664 KB per heartbeat at 1,000 devices,
// which capped one Edge at about 79 heartbeats a second (2026-11-11 fleet walk). These tests pin both halves of
// the repair: a heartbeat that only says "still here" does not save by itself, and one that changes a fact does.

type countingPersister struct {
	blobstore.FilePersister
	mu    sync.Mutex
	saves int
	fail  error
}

func (p *countingPersister) Save(b []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.saves++
	if p.fail != nil {
		return p.fail
	}
	return p.FilePersister.Save(b)
}

func (p *countingPersister) count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.saves
}

func yes() *bool { b := true; return &b }
func no() *bool  { b := false; return &b }

func agentHeartbeat(id string, at time.Time, firewall *bool) model.DeviceHeartbeat {
	stamp := at.UTC().Format(time.RFC3339)
	return model.DeviceHeartbeat{ID: id, TenantID: "tenant_a", Status: "active", AgentVersion: "0.4.1", Timestamp: stamp,
		Posture: &model.DevicePostureSignals{EnforcementAgentHealthy: yes(), DiskEncryptionEnabled: yes(), FirewallEnabled: firewall,
			OSVersion: "Windows 11", CollectedAt: stamp, Source: "windows_collector"}}
}

func livenessStore(t *testing.T, flushAfter time.Duration) (*Store, *countingPersister, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "device_inventory.json")
	p := &countingPersister{FilePersister: blobstore.FilePersister{Path: path}}
	s := NewStore()
	s.livenessFlushAfter = flushAfter
	if err := s.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	return s, p, path
}

func TestStillHereHeartbeatsShareOneSave(t *testing.T) {
	s, p, path := livenessStore(t, time.Hour) // the timer never fires in this test; Flush stands in for it
	t0 := time.Date(2026, 11, 11, 3, 0, 0, 0, time.UTC)
	for _, id := range []string{"dev_1", "dev_2", "dev_3"} {
		if _, err := s.Register(testDevice(id), model.PolicyBundle{}, t0); err != nil {
			t.Fatal(err)
		}
		// The first heartbeat changes facts (status, posture, version): saved before it is answered.
		if _, err := s.Heartbeat(agentHeartbeat(id, t0, yes()), model.PolicyBundle{}, t0); err != nil {
			t.Fatal(err)
		}
	}
	base := p.count()
	if base != 6 {
		t.Fatalf("3 registrations and 3 fact-changing heartbeats must each save: got %d saves", base)
	}
	last := t0
	for round := 1; round <= 50; round++ {
		last = t0.Add(time.Duration(round) * 15 * time.Second)
		for _, id := range []string{"dev_1", "dev_2", "dev_3"} {
			if _, err := s.Heartbeat(agentHeartbeat(id, last, yes()), model.PolicyBundle{}, last); err != nil {
				t.Fatal(err)
			}
		}
	}
	if got := p.count(); got != base {
		t.Fatalf("150 heartbeats that changed only the time saved the inventory %d times", got-base)
	}
	// Served state is current the moment the heartbeat is answered.
	if d, _ := s.Get("dev_2"); d.LastSeenAt != last.Format(time.RFC3339) || d.Posture.CollectedAt != last.Format(time.RFC3339) {
		t.Fatalf("served device is behind: %+v", d)
	}
	if err := s.Flush(); err != nil {
		t.Fatal(err)
	}
	if got := p.count(); got != base+1 {
		t.Fatalf("150 heartbeats must cost exactly one save, got %d", got-base)
	}
	if err := s.Flush(); err != nil || p.count() != base+1 {
		t.Fatalf("a second Flush with nothing waiting must not save again (saves %d, err %v)", p.count()-base, err)
	}
	restarted := newPersistedStore(t, path)
	if d, ok := restarted.Get("dev_3"); !ok || d.LastSeenAt != last.Format(time.RFC3339) {
		t.Fatalf("the shared save did not carry the heartbeats: %+v", d)
	}
}

func TestHeartbeatThatChangesAFactIsSavedBeforeItIsAnswered(t *testing.T) {
	t0 := time.Date(2026, 11, 11, 3, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name   string
		change func(*model.DeviceHeartbeat)
	}{
		{"posture value", func(h *model.DeviceHeartbeat) { h.Posture.FirewallEnabled = no() }},
		{"posture removed axis", func(h *model.DeviceHeartbeat) { h.Posture.DiskEncryptionEnabled = nil }},
		{"os version", func(h *model.DeviceHeartbeat) { h.Posture.OSVersion = "Windows 12" }},
		{"agent version", func(h *model.DeviceHeartbeat) { h.AgentVersion = "0.4.2" }},
		{"status", func(h *model.DeviceHeartbeat) { h.Status = "degraded" }},
		{"metadata", func(h *model.DeviceHeartbeat) { h.Metadata = map[string]any{"hostname": "pc-7"} }},
		{"policy bundle", func(h *model.DeviceHeartbeat) { h.PolicyBundleVersion = "v2" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, p, path := livenessStore(t, time.Hour)
			if _, err := s.Register(testDevice("dev_1"), model.PolicyBundle{}, t0); err != nil {
				t.Fatal(err)
			}
			if _, err := s.Heartbeat(agentHeartbeat("dev_1", t0, yes()), model.PolicyBundle{}, t0); err != nil {
				t.Fatal(err)
			}
			base := p.count()
			h := agentHeartbeat("dev_1", t0.Add(15*time.Second), yes())
			tc.change(&h)
			want, err := s.Heartbeat(h, model.PolicyBundle{}, t0.Add(15*time.Second))
			if err != nil {
				t.Fatal(err)
			}
			if p.count() != base+1 {
				t.Fatalf("a heartbeat that changed %s was not saved before it was answered", tc.name)
			}
			got, _ := newPersistedStore(t, path).Get("dev_1")
			if got.Status != want.Status || got.AgentVersion != want.AgentVersion || got.DeviceTrustLevel != want.DeviceTrustLevel ||
				got.PolicyBundleVersion != want.PolicyBundleVersion || got.LastSeenAt != want.LastSeenAt {
				t.Fatalf("restart read %+v, the heartbeat was answered with %+v", got, want)
			}
			// and a failing disk is still the caller's to hear about
			p.fail = errors.New("disk is gone")
			h2 := agentHeartbeat("dev_1", t0.Add(30*time.Second), yes())
			h2.AgentVersion = "9.9.9"
			if _, err := s.Heartbeat(h2, model.PolicyBundle{}, t0.Add(30*time.Second)); err == nil {
				t.Fatal("a fact-changing heartbeat whose save failed reported success")
			}
		})
	}
}

func TestRevokedDeviceStaysRevokedAcrossStillHereHeartbeats(t *testing.T) {
	s, _, path := livenessStore(t, time.Hour)
	t0 := time.Date(2026, 11, 11, 3, 0, 0, 0, time.UTC)
	dev := testDevice("dev_1")
	dev.Status = "revoked"
	if _, err := s.Register(dev, model.PolicyBundle{}, t0); err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 3; i++ {
		at := t0.Add(time.Duration(i) * 15 * time.Second)
		if _, err := s.Heartbeat(agentHeartbeat("dev_1", at, yes()), model.PolicyBundle{}, at); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Flush(); err != nil {
		t.Fatal(err)
	}
	if d, _ := newPersistedStore(t, path).Get("dev_1"); d.Status != "revoked" {
		t.Fatalf("revocation did not survive: status %q", d.Status)
	}
}

func TestDeferredSaveHappensByItselfAndRetriesAfterAFailure(t *testing.T) {
	s, p, path := livenessStore(t, 30*time.Millisecond)
	var reported int
	var mu sync.Mutex
	prev := OnPersistError
	OnPersistError = func(error) { mu.Lock(); reported++; mu.Unlock() }
	defer func() { OnPersistError = prev }()

	t0 := time.Date(2026, 11, 11, 3, 0, 0, 0, time.UTC)
	if _, err := s.Register(testDevice("dev_1"), model.PolicyBundle{}, t0); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Heartbeat(agentHeartbeat("dev_1", t0, yes()), model.PolicyBundle{}, t0); err != nil {
		t.Fatal(err)
	}
	base := p.count()
	waitFor := func(what string, ok func() bool) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for !ok() {
			if time.Now().After(deadline) {
				t.Fatalf("timed out waiting for %s", what)
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	beat := func(n int) time.Time {
		at := t0.Add(time.Duration(n) * 15 * time.Second)
		if _, err := s.Heartbeat(agentHeartbeat("dev_1", at, yes()), model.PolicyBundle{}, at); err != nil {
			t.Fatalf("a still-here heartbeat must be answered even when the disk is unhappy: %v", err)
		}
		return at
	}

	at := beat(1)
	waitFor("the deferred save", func() bool { return p.count() == base+1 })
	if d, _ := newPersistedStore(t, path).Get("dev_1"); d.LastSeenAt != at.Format(time.RFC3339) {
		t.Fatalf("deferred save wrote %q", d.LastSeenAt)
	}

	p.mu.Lock()
	p.fail = errors.New("disk is gone")
	p.mu.Unlock()
	beat(2)
	waitFor("the failed save to be reported", func() bool { mu.Lock(); defer mu.Unlock(); return reported == 1 })
	p.mu.Lock()
	p.fail = nil
	p.mu.Unlock()
	saves := p.count()
	at = beat(3) // the snapshot is still behind; this heartbeat arms the next attempt
	waitFor("the retry", func() bool { return p.count() == saves+1 })
	if d, _ := newPersistedStore(t, path).Get("dev_1"); d.LastSeenAt != at.Format(time.RFC3339) {
		t.Fatalf("retry wrote %q", d.LastSeenAt)
	}
}

// slowPersister makes a save take long enough that callers pile up behind it, as they do on a real disk with a
// real fleet.
type slowPersister struct {
	countingPersister
	delay time.Duration
}

func (p *slowPersister) Save(b []byte) error {
	time.Sleep(p.delay)
	return p.countingPersister.Save(b)
}

// A fleet that reports a new fact in the same moment — every agent updated, a policy bundle rolled out — used to
// cost one whole-catalog save per device, one after another under the store lock. Every one of them must still be
// on disk before it is answered; they must not each pay for it.
func TestChangesWaitingTogetherAreCarriedByOneSave(t *testing.T) {
	path := filepath.Join(t.TempDir(), "device_inventory.json")
	p := &slowPersister{countingPersister: countingPersister{FilePersister: blobstore.FilePersister{Path: path}}, delay: 20 * time.Millisecond}
	s := NewStore()
	s.livenessFlushAfter = time.Hour
	if err := s.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	const fleet = 200
	t0 := time.Date(2026, 11, 11, 3, 0, 0, 0, time.UTC)
	ids := make([]string, fleet)
	var wg sync.WaitGroup
	for i := range ids {
		ids[i] = "dev_" + time.Duration(i).String()
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			if _, err := s.Register(testDevice(id), model.PolicyBundle{}, t0); err != nil {
				t.Errorf("Register %s: %v", id, err)
			}
		}(ids[i])
	}
	wg.Wait()
	afterRegister := p.count()
	if afterRegister >= fleet/2 {
		t.Fatalf("%d registrations arriving together cost %d saves", fleet, afterRegister)
	}
	answered := make([]model.Device, fleet)
	for i, id := range ids {
		wg.Add(1)
		go func(i int, id string) {
			defer wg.Done()
			h := agentHeartbeat(id, t0.Add(15*time.Second), yes())
			h.AgentVersion = "0.4.2"
			d, err := s.Heartbeat(h, model.PolicyBundle{}, t0.Add(15*time.Second))
			if err != nil {
				t.Errorf("Heartbeat %s: %v", id, err)
			}
			answered[i] = d
		}(i, id)
	}
	wg.Wait()
	if saves := p.count() - afterRegister; saves >= fleet/2 {
		t.Fatalf("%d fact-changing heartbeats arriving together cost %d saves", fleet, saves)
	}
	// Nothing is waiting: every one of them was answered only after a save that carried it.
	saves := p.count()
	if err := s.Flush(); err != nil || p.count() != saves {
		t.Fatalf("a change was answered before it was saved (Flush saved %d more, err %v)", p.count()-saves, err)
	}
	restarted := newPersistedStore(t, path)
	for i, id := range ids {
		got, ok := restarted.Get(id)
		if !ok || got.AgentVersion != "0.4.2" || got.Status != answered[i].Status || got.DeviceTrustLevel != answered[i].DeviceTrustLevel {
			t.Fatalf("%s: restart read %+v, the heartbeat was answered with %+v", id, got, answered[i])
		}
	}
}

// When the disk refuses, every caller whose change was waiting is told — not only the one whose turn it was.
func TestEveryWaitingChangeHearsAFailedSave(t *testing.T) {
	path := filepath.Join(t.TempDir(), "device_inventory.json")
	p := &slowPersister{countingPersister: countingPersister{FilePersister: blobstore.FilePersister{Path: path}}, delay: 5 * time.Millisecond}
	s := NewStore()
	s.livenessFlushAfter = time.Hour
	if err := s.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	t0 := time.Date(2026, 11, 11, 3, 0, 0, 0, time.UTC)
	const fleet = 40
	for i := 0; i < fleet; i++ {
		if _, err := s.Register(testDevice("dev_"+time.Duration(i).String()), model.PolicyBundle{}, t0); err != nil {
			t.Fatal(err)
		}
	}
	p.mu.Lock()
	p.fail = errors.New("disk is gone")
	p.mu.Unlock()
	var wg sync.WaitGroup
	var mu sync.Mutex
	told := 0
	for i := 0; i < fleet; i++ {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			h := agentHeartbeat(id, t0.Add(15*time.Second), yes())
			if _, err := s.Heartbeat(h, model.PolicyBundle{}, t0.Add(15*time.Second)); err != nil {
				mu.Lock()
				told++
				mu.Unlock()
			}
		}("dev_" + time.Duration(i).String())
	}
	wg.Wait()
	if told != fleet {
		t.Fatalf("%d changes were waiting on a save that failed and only %d were told", fleet, told)
	}
}

// After a restart the inventory is what the file held, and a list read back from JSON is not the Go type the
// heartbeat path builds. Compared as Go values, every device's first heartbeat after a restart looked like a
// changed fact — a whole-catalog save each, in the very seconds the whole fleet reconnects.
func TestFirstHeartbeatAfterRestartIsNotAChangedFact(t *testing.T) {
	s1, _, path := livenessStore(t, time.Hour)
	t0 := time.Date(2026, 11, 11, 3, 0, 0, 0, time.UTC)
	if _, err := s1.Register(testDevice("dev_1"), model.PolicyBundle{}, t0); err != nil {
		t.Fatal(err)
	}
	// firewall off: the Edge records posture_failed_signals, a list.
	first, err := s1.Heartbeat(agentHeartbeat("dev_1", t0, no()), model.PolicyBundle{}, t0)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := first.Metadata["posture_failed_signals"]; !ok {
		t.Fatalf("this test needs a device with failed posture signals: %+v", first.Metadata)
	}

	p2 := &countingPersister{FilePersister: blobstore.FilePersister{Path: path}}
	s2 := NewStore()
	s2.livenessFlushAfter = time.Hour
	if err := s2.SetPersister(p2); err != nil {
		t.Fatal(err)
	}
	at := t0.Add(15 * time.Second)
	if _, err := s2.Heartbeat(agentHeartbeat("dev_1", at, no()), model.PolicyBundle{}, at); err != nil {
		t.Fatal(err)
	}
	if p2.count() != 0 {
		t.Fatalf("the first heartbeat after a restart reported nothing new and was saved %d time(s) as a changed fact", p2.count())
	}
	// and a real change after the restart is still saved at once
	if _, err := s2.Heartbeat(agentHeartbeat("dev_1", at.Add(15*time.Second), yes()), model.PolicyBundle{}, at.Add(15*time.Second)); err != nil {
		t.Fatal(err)
	}
	if p2.count() != 1 {
		t.Fatalf("a posture change after the restart: %d saves, want 1", p2.count())
	}
}
