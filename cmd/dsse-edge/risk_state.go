package main

import (
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/model"
)

// Risk State Management. A risk signal (Manual High Risk Marking / IdP risk / agent
// tamper / auth anomaly / abnormal access) is folded into the entity's risk state. For devices the
// state lives in device metadata, which the decision path already reads
// (enrichDecisionRequestWithDeviceRisk -> risk_state_severity / admin_high_risk policy conditions), so
// risk drives decisions with no evaluator change. Marking does not revoke standing grants; policy
// determines the access decision from the resulting risk state.

// riskSignalDeviceApplier is implemented by the in-memory device store.
//
// ★★ IT IS REACHED BY TYPE ASSERTION, SO A SIGNATURE CHANGE HERE IS A SILENT FEATURE REMOVAL (2026-08-13).
// Widening ApplyRiskSignal to return a persist error compiled cleanly and turned the assertion below false —
// every risk signal would have been answered "device store does not support risk signals" by a store that
// implements it, with nothing failing to build. Recorded because the next person to change that signature gets
// no help from the compiler either.
type riskSignalDeviceApplier interface {
	ApplyRiskSignal(deviceID string, sig model.RiskSignal, now time.Time) (model.Device, bool, bool, error)
}

type adminRiskSignalResponse struct {
	TenantID          string `json:"tenant_id,omitempty"`
	SchemaVersion     string `json:"schema_version"`
	EntityType        string `json:"entity_type"`
	EntityID          string `json:"entity_id"`
	Severity          string `json:"severity"`
	HighRisk          bool   `json:"high_risk"`
	StandingGrantsCut int    `json:"standing_grants_revoked"`
	Applied           bool   `json:"applied"`
	// NotStoredDurably reports runtime, overlay or user-save warnings. It does not
	// attest to independent fleet delivery or a transaction across both device stores.
	NotStoredDurably          string `json:"not_stored_durably,omitempty"`
	RuntimePersistenceWarning bool   `json:"runtime_persistence_warning,omitempty"`
	OverlayPersistenceWarning bool   `json:"overlay_persistence_warning,omitempty"`
	NoSecretAttestation       bool   `json:"no_secret_attestation"`
}

var validRiskSeverity = map[string]bool{"": true, "none": true, "low": true, "medium": true, "high": true, "critical": true}

// validateAdminRiskSignal checks input and runtime capability without changing either store.
func validateAdminRiskSignal(deviceStore deviceRuntimeStore, sig model.RiskSignal) (string, string, error) {
	entityType := strings.ToLower(strings.TrimSpace(sig.EntityType))
	entityID := strings.TrimSpace(sig.EntityID)
	if entityID == "" {
		return "", "", fmt.Errorf("entity_id is required")
	}
	if !validRiskSeverity[strings.ToLower(strings.TrimSpace(sig.Severity))] {
		return "", "", fmt.Errorf("invalid severity %q (want none|low|medium|high|critical)", sig.Severity)
	}

	switch entityType {
	case "device":
		if _, ok := deviceStore.(riskSignalDeviceApplier); !ok {
			return "", "", fmt.Errorf("device store does not support risk signals")
		}
	case "user", "human":
	default:
		return "", "", fmt.Errorf("invalid entity_type %q (want device|user)", sig.EntityType)
	}
	return entityType, entityID, nil
}

// applyAdminRiskSignal updates runtime risk metadata. The HTTP handler saves the
// shared overlay first. Risk signals do not themselves revoke standing grants;
// configured policy determines how the resulting risk affects access.
func applyAdminRiskSignal(deviceStore deviceRuntimeStore, tenantID string, sig model.RiskSignal, now time.Time) (adminRiskSignalResponse, error) {
	entityType, entityID, err := validateAdminRiskSignal(deviceStore, sig)
	if err != nil {
		return adminRiskSignalResponse{}, err
	}
	if sig.Timestamp == "" {
		sig.Timestamp = now.UTC().Format(time.RFC3339)
	}

	switch entityType {
	case "device":
		applier, ok := deviceStore.(riskSignalDeviceApplier)
		if !ok {
			return adminRiskSignalResponse{}, fmt.Errorf("device store does not support risk signals")
		}
		dev, found, high, perr := applier.ApplyRiskSignal(entityID, sig, now)
		// The HTTP handler confirms the overlay save before calling this runtime
		// applier. Runtime errors are partial outcomes: its live metadata changed,
		// and the already accepted overlay remains available for distribution.
		notStored := ""
		if perr != nil {
			notStored = "Device runtime metadata was updated but its save failed. The risk overlay is updated separately " +
				"and may retain the change after restart. Re-apply once the runtime store is healthy."
			log.Printf("★ risk signal for %s applied in memory and NOT persisted: %v", entityID, perr)
		}
		if !found {
			// The device is enrolled but not in the RUNTIME store (its agent hasn't reported yet). The high-risk
			// OVERLAY is authoritative fleet-wide — enrichDecisionRequestWithDeviceRisk consults it BEFORE the
			// device lookup, so a mark still bites — so overlay-mark it (via the handler) instead of failing.
			sev := strings.ToLower(strings.TrimSpace(sig.Severity))
			return adminRiskSignalResponse{
				SchemaVersion: "admin_risk_signal.v1", EntityType: "device", EntityID: entityID,
				Severity: sev, HighRisk: sev == "high" || sev == "critical", Applied: true, NoSecretAttestation: true,
				NotStoredDurably: notStored, RuntimePersistenceWarning: perr != nil,
			}, nil
		}
		_ = dev
		return adminRiskSignalResponse{
			SchemaVersion: "admin_risk_signal.v1", EntityType: "device", EntityID: entityID,
			Severity: strings.ToLower(strings.TrimSpace(sig.Severity)), HighRisk: high,
			StandingGrantsCut: 0, Applied: true, NoSecretAttestation: true,
			NotStoredDurably: notStored, RuntimePersistenceWarning: perr != nil,
		}, nil
	case "user", "human":
		// User-scoped marking: no device-store row, but the shared overlay (keyed by the user id) makes every
		// node's decision path treat the user as high-risk, so a policy gating on risk_state_severity refuses
		// them. Marking only — see the note above on why this no longer drops standing grants.
		sev := strings.ToLower(strings.TrimSpace(sig.Severity))
		high := sev == "high" || sev == "critical"
		return adminRiskSignalResponse{
			SchemaVersion: "admin_risk_signal.v1", EntityType: "user", EntityID: entityID,
			Severity: sev, HighRisk: high, StandingGrantsCut: 0, Applied: true, NoSecretAttestation: true,
		}, nil
	default:
		return adminRiskSignalResponse{}, fmt.Errorf("invalid entity_type %q (want device|user)", sig.EntityType)
	}
}
