package device

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/model"
)

type Store struct {
	mu            sync.RWMutex
	devices       map[string]model.Device
	posturePolicy PosturePolicy
	// persister, when set, makes the inventory DURABLE. It was in-memory only, so a routine Edge restart wiped
	// every registered device: risk markings, posture verdicts and the device catalog itself vanished and only
	// came back if each endpoint re-registered. Nil = in-memory only.
	persister blobstore.Persister
}

func NewStore() *Store {
	return &Store{devices: map[string]model.Device{}, posturePolicy: DefaultPosturePolicy()}
}

// devicePersistSnapshot is the on-disk shape: the full device catalog plus the Edge-side posture ruleset, which
// is the store's mutable state. (The posture policy is re-applied from env on every boot AFTER the load, so env
// remains the authority; persisting it only keeps the file self-consistent between mutations.)
type devicePersistSnapshot struct {
	Devices       map[string]model.Device `json:"devices"`
	PosturePolicy PosturePolicy           `json:"posture_policy"`
}

// OnPersistError, when set, is called if a snapshot fails to save. A dropped save is invisible and dangerous:
// the mutation returns success and the in-memory store looks correct, but the next Edge restart silently forgets
// it — exactly the durability failure this persistence prevents, recreated while looking healthy. Must not panic.
//
// It does NOT fail the mutation: the in-memory store is already serving the update, and rejecting a heartbeat or
// risk signal because the disk is unhappy is the worse failure.
var OnPersistError func(error)

func reportPersistError(err error) {
	if OnPersistError != nil {
		OnPersistError(err)
	}
}

// SetPersister enables durable persistence so the device inventory survives an Edge restart. It loads any prior
// snapshot immediately, then every mutation re-saves the full set. Nil disables persistence.
//
// FAIL-CLOSED: if a prior snapshot exists but cannot be read or decoded, this returns the error rather than
// starting empty — a durability-critical store that silently comes up blank is worse than one that refuses.
func (s *Store) SetPersister(p blobstore.Persister) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.persister = p
	if p == nil {
		return nil
	}
	data, err := p.Load()
	if err != nil {
		return err
	}
	if len(data) == 0 {
		return nil
	}
	var snap devicePersistSnapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return err
	}
	if snap.Devices != nil {
		s.devices = snap.Devices
	}
	if snap.PosturePolicy != (PosturePolicy{}) {
		s.posturePolicy = snap.PosturePolicy
	}
	return nil
}

// persistLocked writes the full snapshot. The CALLER must hold s.mu. No-op without a persister.
//
// ★★ IT USED TO SWALLOW THE FAILURE (2026-08-13, thirtieth review #21). A marshal or save error was reported
// through OnPersistError and never returned, on the argument that it "must not fail the mutation that
// triggered it". That is the seam the convergence plan ordered removed, and the round before this one put a
// SECURITY guard on top of it: Register keeps a device's `revoked` status across a re-registration, and with a
// failing persister the caller was told the revocation held while the next restart read a snapshot without it.
// A device an operator revoked comes back enrolled, and every surface said the revocation was applied.
//
// The error is returned now. It is still reported through OnPersistError, because a caller that discards it
// should not also silence the log.
func (s *Store) persistLocked() error {
	if s.persister == nil {
		return nil
	}
	data, err := json.Marshal(devicePersistSnapshot{Devices: s.devices, PosturePolicy: s.posturePolicy})
	if err != nil {
		err = fmt.Errorf("marshal device inventory snapshot: %w", err)
		reportPersistError(err)
		return err
	}
	if err := s.persister.Save(data); err != nil {
		// ★★ SAVED-BUT-NOT-ATOMICALLY IS NOT A FAILURE (2026-08-13, thirty-first review #4). Every sibling store
		// downgrades this sentinel; making persistLocked return its error made this the only one that did not,
		// and the edge routes map a persist error to Register=400 and Heartbeat=404. On a bind-mounted file —
		// the exact case the fallback was written for and documented with — the data would be written, every
		// registration answered 400, every heartbeat 404, and the fleet view would empty while the agents read
		// themselves as unenrolled. The error the previous round started returning has to mean "not saved", or
		// callers cannot act on it.
		if errors.Is(err, blobstore.ErrSavedWithoutAtomicity) {
			log.Printf("device inventory persist: saved, but NOT atomically — %v", err)
			return nil
		}
		err = fmt.Errorf("save device inventory snapshot: %w", err)
		reportPersistError(err)
		return err
	}
	return nil
}

// SetPosturePolicy overrides the Edge-side posture ruleset used to derive device trust from reported
// signals.
// PosturePolicy returns the ruleset a device is judged against. It exists so an operator can be SHOWN what
// "compliant" currently means: until 2026-08-05 the policy could only be set through Edge environment
// variables and could not be read back at all, so the product judged every device against conditions the
// person responsible for them could neither see nor change.
func (s *Store) PosturePolicy() PosturePolicy {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.posturePolicy
}

func (s *Store) SetPosturePolicy(policy PosturePolicy) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.posturePolicy = policy
	return s.persistLocked()
}

func (s *Store) Register(dev model.Device, policyBundle model.PolicyBundle, now time.Time) (model.Device, error) {
	if dev.ID == "" {
		return dev, fmt.Errorf("device id is required")
	}
	if dev.TenantID == "" {
		return dev, fmt.Errorf("device tenant_id is required")
	}
	if policyBundle.TenantID != "" && dev.TenantID != policyBundle.TenantID {
		return dev, fmt.Errorf("device tenant_id %s does not match policy bundle tenant_id %s", dev.TenantID, policyBundle.TenantID)
	}
	if dev.PolicyBundleID == "" {
		dev.PolicyBundleID = policyBundle.ID
	}
	if dev.PolicyBundleVersion == "" {
		dev.PolicyBundleVersion = policyBundle.Version
	}
	if dev.Status == "" {
		dev.Status = "registered"
	}
	if dev.RegisteredAt == "" {
		dev.RegisteredAt = now.UTC().Format(time.RFC3339)
	}
	if dev.LastSeenAt == "" {
		dev.LastSeenAt = dev.RegisteredAt
	}
	if dev.Metadata == nil {
		dev.Metadata = map[string]any{}
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	// Trust is DERIVED, never claimed (review #18): the registration body's DeviceTrustLevel comes from
	// the endpoint itself, so honoring it let a device register straight in as "managed". Real posture
	// signals in the registration derive the level exactly as a heartbeat would; without them the device
	// starts "unknown" until its first posture report.
	if dev.Posture != nil {
		derived, _, _ := DerivePostureTrustLevel(dev.Posture, s.posturePolicy)
		dev.DeviceTrustLevel = derived
	} else {
		dev.DeviceTrustLevel = "unknown"
	}
	// ★ A DEVICE RE-REGISTERING MUST NOT UNDO AN OPERATOR (2026-08-13, twenty-ninth review). This is the
	// DEFAULT store — the Postgres one got this guard a review earlier and this is the one the reference
	// deployment runs. A machine an operator had REVOKED could call POST /devices/register with its own
	// transport certificate and clear the revocation by whole-value assignment, silently and
	// indistinguishably from a first registration. The device drives that call; the revocation is the
	// operator's, and un-revoking stays an administrator action on the admin route.
	if prev, ok := s.devices[dev.ID]; ok && strings.EqualFold(strings.TrimSpace(prev.Status), "revoked") {
		dev.Status = prev.Status
	}
	s.devices[dev.ID] = dev
	if err := s.persistLocked(); err != nil {
		// The device IS registered in memory and the caller is told the write did not last. Reporting success
		// here is what let a revoked device come back enrolled after a restart.
		return detachMetadata(dev), err
	}
	return detachMetadata(dev), nil
}

func (s *Store) Heartbeat(heartbeat model.DeviceHeartbeat, policyBundle model.PolicyBundle, now time.Time) (model.Device, error) {
	if heartbeat.ID == "" {
		return model.Device{}, fmt.Errorf("device id is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	dev, ok := s.devices[heartbeat.ID]
	if !ok {
		return dev, fmt.Errorf("device %s is absent", heartbeat.ID)
	}
	if heartbeat.TenantID != "" && heartbeat.TenantID != dev.TenantID {
		return detachMetadata(dev), fmt.Errorf("device tenant_id %s does not match registered tenant_id %s", heartbeat.TenantID, dev.TenantID)
	}
	if policyBundle.TenantID != "" && dev.TenantID != policyBundle.TenantID {
		return detachMetadata(dev), fmt.Errorf("device tenant_id %s does not match policy bundle tenant_id %s", dev.TenantID, policyBundle.TenantID)
	}
	if heartbeat.AgentVersion != "" {
		dev.AgentVersion = heartbeat.AgentVersion
	}
	postureApplied := false
	var postureCompliant bool
	var postureReasons []string
	if heartbeat.Posture != nil {
		// Edge derives the trust level from real posture signals; a client-declared trust string is
		// NOT trusted when signals are present, so a compromised endpoint cannot just claim "managed"
		//. The non-secret compliance verdict is written AFTER the client metadata merge
		// below so the client cannot spoof the audit verdict either.
		dev.Posture = heartbeat.Posture
		derived, compliant, reasons := DerivePostureTrustLevel(heartbeat.Posture, s.posturePolicy)
		dev.DeviceTrustLevel = derived
		postureApplied = true
		postureCompliant = compliant
		postureReasons = reasons
	}
	// A heartbeat WITHOUT posture signals used to fall back to the client-declared trust string — so a
	// compromised endpoint could simply OMIT posture and claim "managed", overwriting the posture-derived
	// verdict (review #18). The claim is now ignored entirely: the stored trust (derived from the last real
	// posture report, or the registration default) stands until real signals say otherwise. Trust only ever
	// changes on evidence.
	if heartbeat.PolicyBundleID != "" {
		dev.PolicyBundleID = heartbeat.PolicyBundleID
	}
	if heartbeat.PolicyBundleVersion != "" {
		dev.PolicyBundleVersion = heartbeat.PolicyBundleVersion
	}
	if dev.PolicyBundleID == "" {
		dev.PolicyBundleID = policyBundle.ID
	}
	if dev.PolicyBundleVersion == "" {
		dev.PolicyBundleVersion = policyBundle.Version
	}
	// Same rule as Register, and for the same reason: a heartbeat is the DEVICE talking.
	if strings.EqualFold(strings.TrimSpace(dev.Status), "revoked") {
		// leave it: only an administrator lifts a revocation
	} else if heartbeat.Status != "" {
		dev.Status = heartbeat.Status
	} else {
		dev.Status = "healthy"
	}
	if heartbeat.Timestamp != "" {
		dev.LastSeenAt = heartbeat.Timestamp
	} else {
		dev.LastSeenAt = now.UTC().Format(time.RFC3339)
	}
	if dev.Metadata == nil {
		dev.Metadata = map[string]any{}
	}
	for key, value := range heartbeat.Metadata {
		if key == "device_group" {
			// device_group is CP-AUTHORITATIVE (assigned at enrollment in the enrolled ledger). A device must
			// not self-assert its group via heartbeat — group selects enforcement/tuning scope, so honoring a
			// client-supplied value would let a device pick its own group. Group-scoped resolution reads the
			// ledger (cpAuthoritativeGroup), never this map; drop the key here so nothing can pick it up.
			continue
		}
		dev.Metadata[key] = value
	}
	delete(dev.Metadata, "device_group") // clear any value a prior (pre-hardening) heartbeat may have persisted
	// Edge-derived posture verdict is written last so a client cannot spoof the audit metadata.
	if postureApplied {
		dev.Metadata["posture_compliant"] = postureCompliant
		dev.Metadata["posture_trust_source"] = "edge_derived_from_signals"
		if len(postureReasons) > 0 {
			dev.Metadata["posture_failed_signals"] = postureReasons
		} else {
			delete(dev.Metadata, "posture_failed_signals")
		}
	}
	s.devices[dev.ID] = dev
	if err := s.persistLocked(); err != nil {
		// The device IS registered in memory and the caller is told the write did not last. Reporting success
		// here is what let a revoked device come back enrolled after a restart.
		return detachMetadata(dev), err
	}
	return detachMetadata(dev), nil
}

// ApplyRiskSignal folds a risk signal into the device's risk metadata so the decision path
// (enrichDecisionRequestWithDeviceRisk -> risk_state_severity / admin_high_risk policy conditions)
// reflects it with no evaluator change. Returns the updated device, whether it exists, and
// whether the device is now HIGH RISK (the caller revokes the device's standing grants). A low/none
// severity signal de-escalates (clears admin_high_risk).
func (s *Store) ApplyRiskSignal(deviceID string, sig model.RiskSignal, now time.Time) (model.Device, bool, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	dev, ok := s.devices[deviceID]
	if !ok {
		return model.Device{}, false, false, nil
	}
	if dev.Metadata == nil {
		dev.Metadata = map[string]any{}
	}
	sev := strings.ToLower(strings.TrimSpace(sig.Severity))
	action := strings.ToLower(strings.TrimSpace(sig.SuggestedAction))
	// admin_high_risk is the risk LEVEL and is driven by SEVERITY only (high|critical). It must NOT be latched by
	// the signal's source string or its recommended ACTION: those are separate dimensions (provenance / what-to-do)
	// stored below, and coupling them to the risk level made a `severity:none` clear silently ineffective whenever
	// the clear reused source=manual_high_risk or an action in {revoke,block,isolate} — the device stayed blocked
	// forever. The recommended action is still RECORDED (risk_recommended_action, stored below) and is readable
	// as a policy condition, but it no longer drives enforcement by itself — the hardcoded overlay that acted on
	// it was removed: honouring a "block"/"isolate" recommendation is now an operator policy decision, not an
	// automatic one.
	high := sev == "high" || sev == "critical"
	dev.Metadata["risk_state_severity"] = sev
	dev.Metadata["admin_high_risk"] = high
	dev.Metadata["risk_state_id"] = "risk_" + strings.TrimSpace(sig.EntityID) + "_" + now.UTC().Format("20060102T150405Z")
	dev.Metadata["risk_state_updated_at"] = now.UTC().Format(time.RFC3339)
	if high {
		dev.Metadata["risk_recommended_action"] = action
		dev.Metadata["risk_signal_sources"] = []any{strings.TrimSpace(sig.Source)}
	} else {
		// De-escalation (severity none/low/medium — anything below HIGH): the device is no longer high-risk, so
		// CLEAR the action/provenance fields rather than letting a clear signal's own source (e.g.
		// source=manual_high_risk on a severity:none clear) or a stale block action linger as misleading state
		// that a policy condition could still match on. Graded policies read risk_state_severity, which is
		// written unconditionally above.
		delete(dev.Metadata, "risk_recommended_action")
		delete(dev.Metadata, "risk_signal_sources")
	}
	s.devices[deviceID] = dev
	err := s.persistLocked()
	return detachMetadata(dev), true, high, err
}

// detachMetadata returns dev with its Metadata map copied. Every Device handed OUT of the store must go
// through this: the store's mutators (Heartbeat, ApplyRiskSignal) write into the stored device's Metadata
// map in place, so returning the internal map by reference lets a caller's read race a concurrent
// heartbeat — a Go-fatal concurrent map read/write that crashes the Edge, not just a stale read. Values
// are not deep-copied: mutators always assign fresh values per key, never mutate a stored value in place.
func detachMetadata(dev model.Device) model.Device {
	if dev.Metadata != nil {
		meta := make(map[string]any, len(dev.Metadata))
		for k, v := range dev.Metadata {
			meta[k] = v
		}
		dev.Metadata = meta
	}
	return dev
}

func (s *Store) Get(id string) (model.Device, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	dev, ok := s.devices[id]
	return detachMetadata(dev), ok
}

func (s *Store) GetByTenant(tenantID, id string) (model.Device, bool, error) {
	dev, ok := s.Get(id)
	if !ok || dev.TenantID != tenantID {
		return model.Device{}, false, nil
	}
	return dev, true, nil
}

func (s *Store) List() []model.Device {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ids := make([]string, 0, len(s.devices))
	for id := range s.devices {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	devices := make([]model.Device, 0, len(ids))
	for _, id := range ids {
		devices = append(devices, detachMetadata(s.devices[id]))
	}
	return devices
}

func (s *Store) ListByTenant(tenantID string) ([]model.Device, error) {
	all := s.List()
	devices := make([]model.Device, 0, len(all))
	for _, dev := range all {
		if dev.TenantID == tenantID {
			devices = append(devices, dev)
		}
	}
	return devices, nil
}
