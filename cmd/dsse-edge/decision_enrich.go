package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	_ "net/http/pprof" // DIAGNOSTIC: registers /debug/pprof on http.DefaultServeMux; served only when -pprof-listen is set
	"strings"
	"time"

	enrolledinventory "github.com/lantern-networks/dsse-core/enrolledinventory"
	nhi "github.com/lantern-networks/dsse-core/nhi"
	"github.com/lantern-networks/dsse-core/revocation"

	// The IANA timezone database, compiled in. The runtime image is FROM scratch, so there is no
	// /usr/share/zoneinfo and time.LoadLocation would fail for EVERY zone — including the ones an operator
	// just typed into the Console. Validation that passes on a developer's machine and rejects everything in
	// the container is worse than no validation, because it looks like the operator's mistake.
	_ "time/tzdata"

	"github.com/lantern-networks/dsse-core/model"
	sessionstore "github.com/lantern-networks/dsse-core/session"
)

func enrichDecisionRequestWithRuntimeAttestation(r *http.Request, req model.DecisionRequest, connectorSecret string, devMode bool, replayCache runtimeWorkloadAttestationNonceStore, now time.Time) (model.DecisionRequest, runtimeWorkloadAttestationEvidence, error) {
	if devMode {
		return req, runtimeWorkloadAttestationEvidence{}, nil
	}
	req.WorkloadAttestationState = ""
	state := strings.TrimSpace(r.Header.Get(workloadAttestationStateHeader))
	timestamp := strings.TrimSpace(r.Header.Get(workloadAttestationTimestampHeader))
	nonce := strings.TrimSpace(r.Header.Get(workloadAttestationNonceHeader))
	signature := strings.TrimSpace(r.Header.Get(workloadAttestationSignatureHeader))
	if state == "" && timestamp == "" && nonce == "" && signature == "" {
		return req, runtimeWorkloadAttestationEvidence{}, nil
	}
	if state == "" || timestamp == "" || nonce == "" || signature == "" {
		return req, runtimeWorkloadAttestationEvidence{}, fmt.Errorf("runtime workload attestation state, timestamp, nonce, and signature are required together")
	}
	if !runtimeWorkloadAttestationStateAllowed(state) {
		return req, runtimeWorkloadAttestationEvidence{}, fmt.Errorf("runtime workload attestation state %q is not accepted", state)
	}
	if len(nonce) > 128 {
		return req, runtimeWorkloadAttestationEvidence{}, fmt.Errorf("runtime workload attestation nonce is too long")
	}
	attestationTime, err := time.Parse(time.RFC3339, timestamp)
	if err != nil {
		return req, runtimeWorkloadAttestationEvidence{}, fmt.Errorf("runtime workload attestation timestamp is invalid")
	}
	if skew := now.UTC().Sub(attestationTime.UTC()); skew < -maxRuntimeWorkloadAttestationSkew || skew > maxRuntimeWorkloadAttestationSkew {
		return req, runtimeWorkloadAttestationEvidence{}, fmt.Errorf("runtime workload attestation timestamp is outside allowed skew")
	}
	if connectorSecret == "" {
		return req, runtimeWorkloadAttestationEvidence{}, fmt.Errorf("runtime workload attestation verifier is not configured")
	}
	if !runtimeWorkloadAttestationSignatureValid(connectorSecret, req, state, timestamp, nonce, signature) {
		return req, runtimeWorkloadAttestationEvidence{}, fmt.Errorf("runtime workload attestation signature is invalid")
	}
	expiresAt := attestationTime.UTC().Add(maxRuntimeWorkloadAttestationSkew)
	minExpiresAt := now.UTC().Add(maxRuntimeWorkloadAttestationSkew)
	if expiresAt.Before(minExpiresAt) {
		expiresAt = minExpiresAt
	}
	if err := replayCache.Remember(req.TenantID, nonce, now, expiresAt); err != nil {
		return req, runtimeWorkloadAttestationEvidence{}, err
	}
	req.WorkloadAttestationState = state
	return req, runtimeWorkloadAttestationEvidence{
		Source:    "runtime_signed_header",
		Timestamp: attestationTime.UTC().Format(time.RFC3339),
		NonceHash: runtimeWorkloadAttestationNonceHash(req.TenantID, nonce),
		Algorithm: "hmac-sha256",
	}, nil
}

func recordNonHumanIdentityRuntimeUse(ctx context.Context, store nhi.RuntimeStore, dec *model.AccessDecision, now time.Time) {
	if store == nil || dec == nil || dec.Decision != "allow" || !isDelegatedActorType(dec.ActorType) || dec.ActorNHIID == nil || strings.TrimSpace(*dec.ActorNHIID) == "" {
		return
	}
	tenantID := strings.TrimSpace(dec.TenantID)
	actorNHIID := strings.TrimSpace(*dec.ActorNHIID)
	updated, err := store.MarkUsed(ctx, tenantID, actorNHIID, now)
	if err != nil {
		log.Printf("mark non-human identity last_used_at failed for tenant=%s nhi=%s: %v", tenantID, actorNHIID, err)
		if dec.Metadata == nil {
			dec.Metadata = map[string]any{}
		}
		dec.Metadata["nhi_registry_last_used_result"] = "error"
		return
	}
	if !updated {
		return
	}
	if dec.Metadata == nil {
		dec.Metadata = map[string]any{}
	}
	dec.Metadata["nhi_registry_last_used_result"] = "updated"
	dec.Metadata["nhi_registry_last_used_at"] = now.UTC().Format(time.RFC3339)
}

func enrichDecisionRequestWithSession(req model.DecisionRequest, sessionStore *sessionstore.Store) model.DecisionRequest {
	if req.SessionID == "" {
		return req
	}
	session, ok := sessionStore.Get(req.SessionID)
	if !ok || session.Status != "active" {
		return req
	}
	req.TenantID = valueOrDefault(req.TenantID, session.TenantID)
	req.UserID = valueOrDefault(req.UserID, session.UserID)
	if session.SubjectUserID != nil {
		req.SubjectUserID = valueOrDefault(req.SubjectUserID, *session.SubjectUserID)
	}
	if session.DeviceID != nil {
		req.DeviceID = valueOrDefault(req.DeviceID, *session.DeviceID)
	}
	req.AuthenticationEventID = valueOrDefault(req.AuthenticationEventID, session.AuthenticationEventID)
	req.MFAState = valueOrDefault(req.MFAState, stringMetadata(session.Metadata, "mfa_state"))
	req.AuthTime = valueOrDefault(req.AuthTime, stringMetadata(session.Metadata, "auth_time"))
	req.ACR = valueOrDefault(req.ACR, stringMetadata(session.Metadata, "acr"))
	req.AuthMethod = valueOrDefault(req.AuthMethod, stringMetadata(session.Metadata, "auth_method"))
	req.BreakGlassRequestID = valueOrDefault(req.BreakGlassRequestID, stringMetadata(session.Metadata, "break_glass_request_id"))
	req.BreakGlassReasonPresent = req.BreakGlassReasonPresent || stringMetadata(session.Metadata, "break_glass_reason") != ""
	req.BreakGlassTicketIDPresent = req.BreakGlassTicketIDPresent || stringMetadata(session.Metadata, "ticket_id") != ""
	if len(req.AMR) == 0 {
		req.AMR = stringSliceMetadata(session.Metadata, "amr")
	}
	if len(req.UserGroups) == 0 {
		req.UserGroups = stringSliceMetadata(session.Metadata, "groups")
	}
	return req
}

func enrichDecisionRequestWithDeviceRisk(req model.DecisionRequest, deviceStore deviceRuntimeStore, highRisk *revocation.HighRiskOverlay) model.DecisionRequest {
	// Phase 3 shared high-risk overlay: a device marked high-risk on the control plane is treated
	// high-risk by EVERY node — even one whose local device store never saw it. Consulted BEFORE the device
	// lookup so it bites regardless of local registration (reconnect-elsewhere can't dodge a high-risk mark).
	if highRisk != nil && req.DeviceID != "" {
		if sev, ok := highRisk.IsHighRisk(req.DeviceID); ok {
			req.RiskStateSeverity = valueOrDefault(req.RiskStateSeverity, sev)
			if sev == "high" || sev == "critical" { // AdminHighRisk (revocation-class behaviours) is high/critical only
				req.AdminHighRisk = true
			}
		}
	}
	// A USER marked at ANY level sets risk_state_severity on ANY device within that tenant,
	// so a risk-gated policy (e.g. risk >= high -> re-authenticate, or >= medium -> something) bites regardless of
	// which device they use; high/critical additionally raise AdminHighRisk.
	if highRisk != nil && req.UserID != "" {
		if sev, ok := highRisk.UserSeverity(req.TenantID, req.UserID); ok {
			req.RiskStateSeverity = maxRiskSeverity(req.RiskStateSeverity, sev)
			if sev == "high" || sev == "critical" {
				req.AdminHighRisk = true
			}
		}
	}
	if deviceStore == nil || req.DeviceID == "" {
		return req
	}
	var dev model.Device
	var ok bool
	if req.TenantID != "" {
		var err error
		dev, ok, err = deviceForTenant(deviceStore, req.TenantID, req.DeviceID)
		if err != nil || !ok {
			return req
		}
	} else {
		dev, ok = deviceStore.Get(req.DeviceID)
		if !ok {
			return req
		}
		req.TenantID = valueOrDefault(req.TenantID, dev.TenantID)
	}

	req.DeviceTrustLevel = valueOrDefault(req.DeviceTrustLevel, dev.DeviceTrustLevel)
	req.RiskStateID = valueOrDefault(req.RiskStateID, stringMetadata(dev.Metadata, "risk_state_id"))
	req.RiskStateSeverity = valueOrDefault(req.RiskStateSeverity, stringMetadata(dev.Metadata, "risk_state_severity"))
	req.RiskRecommendedAction = valueOrDefault(req.RiskRecommendedAction, stringMetadata(dev.Metadata, "risk_recommended_action"))
	if len(req.RiskSignalSources) == 0 {
		req.RiskSignalSources = stringSliceMetadata(dev.Metadata, "risk_signal_sources")
	}
	req.AdminHighRisk = req.AdminHighRisk || boolMetadata(dev.Metadata, "admin_high_risk") || boolMetadata(dev.Metadata, "manual_high_risk")
	req.IDPRiskLevel = valueOrDefault(req.IDPRiskLevel, stringMetadata(dev.Metadata, "idp_risk_level"))
	req.AgentTamperSignal = req.AgentTamperSignal || boolMetadata(dev.Metadata, "agent_tamper_signal")
	req.AuthenticationAnomaly = req.AuthenticationAnomaly || boolMetadata(dev.Metadata, "authentication_anomaly")
	return req
}

// enrichDecisionRequestWithRisk is enrichDecisionRequestWithDeviceRisk PLUS the device-group RISK FLOOR (union
// model): a member device's effective risk_state_severity becomes max(its resolved severity, its group's floor).
// The floor is CONDITION-ONLY — it raises risk_state_severity so risk-gated POLICIES react (including on the
// re-evaluation of existing sessions), but it does NOT set AdminHighRisk and does NOT trigger revocation. All
// enforcement is explicit policy .
func enrichDecisionRequestWithRisk(req model.DecisionRequest, deviceStore deviceRuntimeStore, highRisk *revocation.HighRiskOverlay, ledger *enrolledinventory.Ledger) model.DecisionRequest {
	req = enrichDecisionRequestWithDeviceRisk(req, deviceStore, highRisk)
	if ledger != nil && req.DeviceID != "" {
		// Floor resolved WITHIN the device's own tenant (GroupRiskForDevice keys on the entry's TenantID), so a
		// device never inherits another tenant's same-named group floor (multi-tenant premise).
		if floor := ledger.GroupRiskForDevice(req.DeviceID); floor != "" {
			req.RiskStateSeverity = maxRiskSeverity(req.RiskStateSeverity, floor)
		}
	}
	return req
}
