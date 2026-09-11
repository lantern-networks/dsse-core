package device

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/model"
)

// The device inventory was in-memory only, so a routine Edge restart wiped every registered device: risk
// markings, posture verdicts and the catalog itself vanished until each endpoint re-registered. These tests pin
// the durability that removes that failure mode. They mirror connector/registry_persist_test.go.

func newPersistedStore(t *testing.T, path string) *Store {
	t.Helper()
	s := NewStore()
	if err := s.SetPersister(blobstore.FilePersister{Path: path}); err != nil {
		t.Fatalf("SetPersister: %v", err)
	}
	return s
}

func testDevice(id string) model.Device {
	return model.Device{ID: id, TenantID: "tenant_a"}
}

// THE REGRESSION: a device registered through one store instance must be present in a fresh instance loading the
// same file — i.e. it must survive an Edge restart.
func TestDeviceSurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "device_inventory.json")
	now := time.Now()

	s1 := newPersistedStore(t, path)
	if _, err := s1.Register(testDevice("dev_lab_001"), model.PolicyBundle{}, now); err != nil {
		t.Fatalf("Register: %v", err)
	}

	// A fresh Edge process reading the same store = the restart.
	s2 := newPersistedStore(t, path)
	got, ok := s2.Get("dev_lab_001")
	if !ok {
		t.Fatal("device was LOST across the restart — this is the durability failure this store must prevent")
	}
	if got.TenantID != "tenant_a" {
		t.Fatalf("device restored with wrong content: %+v", got)
	}
}

// A removal-of-state mutation must persist: a risk DE-ESCALATION deletes the enforcement-driving risk metadata,
// and after a restart those keys must stay gone (a cleared high-risk marking must not come back from the dead and
// re-block the device). The device store has no Delete method, so a de-escalation is its removal mutation.
func TestRiskDeEscalationRemovalSurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "device_inventory.json")
	now := time.Now()

	s1 := newPersistedStore(t, path)
	if _, err := s1.Register(testDevice("dev_risky"), model.PolicyBundle{}, now); err != nil {
		t.Fatalf("Register: %v", err)
	}
	// Escalate to high risk (sets admin_high_risk=true + risk_recommended_action).
	if _, ok, high, _ := s1.ApplyRiskSignal("dev_risky", model.RiskSignal{
		EntityID: "dev_risky", Severity: "high", Source: "edr", SuggestedAction: "isolate",
	}, now); !ok || !high {
		t.Fatalf("escalation did not take: ok=%v high=%v", ok, high)
	}
	// De-escalate (severity none): DELETES risk_recommended_action / risk_signal_sources, clears admin_high_risk.
	if _, ok, high, _ := s1.ApplyRiskSignal("dev_risky", model.RiskSignal{
		EntityID: "dev_risky", Severity: "none", Source: "edr",
	}, now); !ok || high {
		t.Fatalf("de-escalation did not take: ok=%v high=%v", ok, high)
	}

	// The restart: the removal must have persisted, not just the in-memory state.
	s2 := newPersistedStore(t, path)
	got, ok := s2.Get("dev_risky")
	if !ok {
		t.Fatal("device lost across restart")
	}
	if v, _ := got.Metadata["admin_high_risk"].(bool); v {
		t.Fatal("a CLEARED high-risk marking came back after restart — the device would stay blocked forever")
	}
	if _, present := got.Metadata["risk_recommended_action"]; present {
		t.Fatal("a removed risk_recommended_action came back after restart")
	}
}

// A save failure must be REPORTED via OnPersistError, never swallowed — and the mutation must still apply. A
// dropped save is the exact silent failure that recreates the outage while the store looks healthy.
func TestSaveFailureIsReportedNotSwallowed(t *testing.T) {
	prev := OnPersistError
	t.Cleanup(func() { OnPersistError = prev })

	var reported []error
	OnPersistError = func(err error) { reported = append(reported, err) }

	s := NewStore()
	if err := s.SetPersister(failingPersister{}); err != nil {
		t.Fatalf("SetPersister on an empty failing persister must not error (nothing to load): %v", err)
	}

	// ★★ THIS TEST REQUIRED THE SWALLOW, AND THAT IS WHAT MADE IT SAFE-LOOKING (2026-08-13, thirtieth review
	// #21). It asserted "Register must not fail because the disk is unhappy" — a reasonable-sounding rule that
	// became a security defect when the round before this one put the REVOKED guard on the same path: Register
	// preserves a device's revoked status across a re-registration, and with a failing persister the caller was
	// told the revocation held while the next restart read a snapshot without it. A device an operator revoked
	// comes back enrolled, and every surface says the revocation was applied.
	//
	// The mutation still applies IN MEMORY — the device is registered and readable, so nothing is lost while the
	// process lives — and the caller is now told that it did not last.
	got, err := s.Register(testDevice("dev_report"), model.PolicyBundle{}, time.Now())
	if err == nil {
		t.Fatal("Register reported success while the snapshot was not written — a revocation preserved by this " +
			"same call would be gone after a restart, with nothing on any screen saying so")
	}
	if got.ID != "dev_report" {
		t.Fatalf("the mutation must still apply in memory: %+v", got)
	}
	if _, ok := s.Get("dev_report"); !ok {
		t.Fatal("mutation must still apply in memory despite the save failure")
	}

	// And the failure must have been surfaced, not silently dropped: a caller that discards the error should
	// not also silence the log.
	if len(reported) == 0 {
		t.Fatal("a failed save was SWALLOWED — the next restart would silently forget this device")
	}
}

// failingPersister loads nothing (empty first boot) and always fails to save, so a mutation exercises the
// persistLocked error path.
type failingPersister struct{}

func (failingPersister) Load() ([]byte, error) { return nil, nil }
func (failingPersister) Save(_ []byte) error   { return fmt.Errorf("simulated disk failure") }

// ★★ SAVED-BUT-NOT-ATOMICALLY IS NOT A FAILURE (2026-08-13, thirty-first review #4). Every sibling store
// downgrades this sentinel. Making persistLocked return its error made this the only store that did not — and
// the edge routes map a persist error to Register=400 and Heartbeat=404, so on a bind-mounted file (the exact
// case the fallback exists for) the data would be written, every registration answered 400, every heartbeat
// 404, and the fleet view would empty while the agents read themselves as unenrolled.
func TestASaveThatWorkedButNotAtomicallyIsNotReportedAsAFailure(t *testing.T) {
	s := NewStore()
	if err := s.SetPersister(nonAtomicPersister{}); err != nil {
		t.Fatal(err)
	}
	got, err := s.Register(testDevice("dev_bind_mount"), model.PolicyBundle{}, time.Now())
	if err != nil {
		t.Fatalf("Register reported %v — the data IS saved, and this error 400s every enrolment on a "+
			"bind-mounted store", err)
	}
	if got.ID != "dev_bind_mount" {
		t.Fatalf("%+v", got)
	}
}

// nonAtomicPersister saves successfully and says the write was not atomic, which is what a bind-mounted
// destination produces.
type nonAtomicPersister struct{}

func (nonAtomicPersister) Load() ([]byte, error) { return nil, nil }
func (nonAtomicPersister) Save(_ []byte) error   { return blobstore.ErrSavedWithoutAtomicity }
