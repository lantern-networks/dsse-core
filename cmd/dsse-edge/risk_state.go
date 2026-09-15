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
	SchemaVersion     string `json:"schema_version"`
	EntityType        string `json:"entity_type"`
	EntityID          string `json:"entity_id"`
	Severity          string `json:"severity"`
	HighRisk          bool   `json:"high_risk"`
	StandingGrantsCut int    `json:"standing_grants_revoked"`
	Applied           bool   `json:"applied"`
	// NotStoredDurably reports a runtime inventory save failure. An empty value does not attest to
	// overlay durability or independent fleet delivery; those stores have separate lifecycles.
	NotStoredDurably    string `json:"not_stored_durably,omitempty"`
	NoSecretAttestation bool   `json:"no_secret_attestation"`
}

var validRiskSeverity = map[string]bool{"": true, "none": true, "low": true, "medium": true, "high": true, "critical": true}

// applyAdminRiskSignal validates and applies a risk signal. It MARKS, and marking is all it does.
//
// It used to cut. A device or user that came back high-risk lost its standing east-west grants immediately,
// on the theory that the next internal hop should have to re-authenticate. That was enforcement decided by an
// ingested signal rather than by policy, and it is not how access is supposed to be decided here: a high-risk
// device is denied when a policy says high-risk devices are denied, and not otherwise. The severity lands in
// the risk overlay, every node's decision path reads it, and a rule that gates on risk_state_severity is what
// turns it into a refusal — visibly, in the policy an operator wrote, at the moment of the request.
//
// The difference matters most when the signal is wrong. A mark that policy evaluates can be scoped, staged and
// overridden by the rules an operator already understands; a mark that silently tore down grants could not be
// reasoned about from the policy at all, and the person losing access had no rule to point at.
//
// Non-secret: raw evidence is never accepted, only a reference.
func applyAdminRiskSignal(deviceStore deviceRuntimeStore, tenantID string, sig model.RiskSignal, now time.Time) (adminRiskSignalResponse, error) {
	entityType := strings.ToLower(strings.TrimSpace(sig.EntityType))
	entityID := strings.TrimSpace(sig.EntityID)
	if entityID == "" {
		return adminRiskSignalResponse{}, fmt.Errorf("entity_id is required")
	}
	if !validRiskSeverity[strings.ToLower(strings.TrimSpace(sig.Severity))] {
		return adminRiskSignalResponse{}, fmt.Errorf("invalid severity %q (want none|low|medium|high|critical)", sig.Severity)
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
		// ★★ THE DURABILITY PROBLEM IS REPORTED, BUT NOT BEFORE THE FLEET HEARS ABOUT THE MARK (2026-08-13,
		// thirty-first review #5). The previous round returned here, and the caller sets the fleet-wide
		// HighRiskOverlay only on a non-error response — so a compromised device was marked on THIS node,
		// answered with an error, and left un-marked everywhere else: the other nodes went on admitting it. The
		// clear direction was worse still: a severity=none clear skipped the overlay Clear, so the store said
		// "cleared" while the fleet kept blocking the device.
		//
		// A mark that did not reach the disk is weaker than one that did. A mark that did not reach the FLEET
		// does not exist. So the response is built and the failure travels with it, in the field an operator
		// reads, rather than in place of the action.
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
				NotStoredDurably: notStored,
			}, nil
		}
		_ = dev
		return adminRiskSignalResponse{
			SchemaVersion: "admin_risk_signal.v1", EntityType: "device", EntityID: entityID,
			Severity: strings.ToLower(strings.TrimSpace(sig.Severity)), HighRisk: high,
			StandingGrantsCut: 0, Applied: true, NoSecretAttestation: true,
			NotStoredDurably: notStored,
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
