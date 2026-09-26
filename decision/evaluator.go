package decision

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/lantern-networks/dsse-core/model"
)

var modelIDFallbackCounter atomic.Uint64

type tlsInspectionReadinessContext struct {
	Configured     bool
	Profile        model.InspectionProfile
	TrustProfile   *model.TrustProfile
	TenantRootCA   *model.TenantRootCA
	QUICApplicable bool
}

type breakGlassPolicyContext struct {
	Configured              bool
	IdentityID              string
	MaxSessionSeconds       int
	StrongAuthRequired      bool
	StrongAuthSatisfied     bool
	AuditRequired           bool
	AuthAgeSeconds          int
	AuthAgeKnown            bool
	AuthFreshness           string
	ReasonPresent           bool
	TicketIDPresent         bool
	RequestID               string
	RequirementReasonCodes  []string
	ReauthenticationReasons []string
}

type Evaluator struct {
	// Immutable values captured with the rules, excluded from serialized decisions.
	TenantRestrictionHeaderValues map[string]string `json:"-"`
	Policies                      []model.Policy
	PolicyBundle                  model.PolicyBundle
	EdgeRegionID                  string
	EdgeClusterID                 string
	// EastWestEnabled gates east-west (internal/lateral) per-hop authorization. When false (default) the
	// east-west layer is inert and decisions are byte-identical to legacy behaviour (Observe stage of the
	// learning lifecycle). When true, requests for east-west protocols are governed by EastWestRules.
	EastWestEnabled bool
	// EastWestAllowUnmatched decouples rule-enforcement from the default-deny (the S4/S5 learning-lifecycle
	// step). When true (Partial Enforce), enabled rules bite BUT a flow that matches NO rule is ALLOWED
	// (allow-all default) instead of denied — safe adoption before the terminal flip. When false (Full
	// Enforce, the default), an unmatched east-west flow is denied. Only meaningful when EastWestEnabled.
	EastWestAllowUnmatched bool
	// EastWestInternalNetworks is the operator's declaration of what counts as inside the estate, ON TOP OF
	// private address space (which is always internal and cannot be declared away). It exists because plane
	// membership needs the DESTINATION, not just the protocol: before this, the service family alone decided,
	// so every SSH was lateral movement by construction and `ssh git@github.com` was held for an IdP ceremony
	// nobody would complete. Empty is valid and correct for a flat private estate — see decision/locality.go.
	EastWestInternalNetworks InternalNetworks
	EastWestRules            []EastWestRule
	// EastWestGrants are the active ephemeral grants that RELEASE an authenticate-mode hold for a matching
	// (identity x device x destination x protocol) until they expire (E3). A grant only releases an
	// authenticate hold; it never overrides an explicit deny.
	EastWestGrants []EastWestGrant
	// ServerInitiatedEnabled gates server-initiated (server->client) access control. When true,
	// a server-initiated flow is default-deny unless a matching active LegacyException allows it.
	ServerInitiatedEnabled bool
	LegacyExceptions       []LegacyException
}

// LegacyException is an explicit, governed allow for an otherwise default-deny
// server-initiated (server->client) connection. Mirrors model.LegacyException for evaluation.
type LegacyException struct {
	ID            string
	SourceServer  string
	DeviceGroup   string
	ServiceFamily string
	Protocol      string
	Port          int
	Mode          string // observe | warn | deny | allow
	ExpiresAt     time.Time
	Active        bool
}

// Evaluate expects req.ActorType to be set by the caller's trust-boundary
// derivation step. Edge runtime callers must run deriveDecisionRequestActor so
// client-supplied actor_type values are not used as security or billing facts.
func (e Evaluator) Evaluate(req model.DecisionRequest) model.AccessDecision {
	now := time.Now().UTC()
	req = e.decisionRequestWithSaaSContext(req)
	actorType := valueOrDefault(req.ActorType, "human")
	tenantID := valueOrDefault(req.TenantID, e.firstPolicyTenantID())

	decisionValue := "deny"
	reason := "No active policy matched the request."
	reasonCodes := []string{"no_policy_match"}
	matched := []string{}
	actions := []model.DecisionAction{}
	// A default denial has no matching policy. The first configured policy may
	// be unrelated, disabled or owned by another tenant; never attribute it to
	// this decision. Matching and dedicated authorization branches set the ID.
	policyID := ""
	tokenBindingState := req.TokenBindingState
	workloadAttestationState := req.WorkloadAttestationState
	metadata := decisionMetadata(req)
	var inspectionProfileID *string
	var inspectionMode *string
	var inspectionRouteCategory *string
	var inspectionExecutionScope *string
	bypass := false

	// NOTE: there is deliberately NO risk-driven deny branch here. Device risk is ingested (API / manual
	// marking / DLP) and exposed to the policy matcher as CONDITIONS (risk_state_severity, admin_high_risk,
	// idp_risk_level, agent_tamper_signal, authentication_anomaly, risk_recommended_action,
	// risk_signal_sources — see fieldValues below). Authorization based on that risk is the POLICY's job:
	// an operator writes a rule (e.g. risk_at_least: high -> deny/authenticate) and it is evaluated in the
	// normal policy branch. The product must never detect-and-block on its own.
	//
	// A hardcoded "Ransomware Protection Mode" overlay used to sit here and deny BEFORE any policy was
	// consulted, with no toggle, a Go-literal protocol list, and a hardcoded decision/reason/policy id. It
	// was removed as a requirement violation: risk must reach a decision only through operator-authored policy.
	if e.ServerInitiatedEnabled && isServerInitiated(req) {
		// server-initiated (server->client) access control: default-deny; allowed only by an
		// active, non-expired Legacy Exception. Governs server-initiated flows on its own, bypassing the
		// north-bound policy match.
		decisionValue, reason, reasonCodes = e.serverInitiatedDecisionFor(req, now)
		policyID = "server_initiated_policy"
		metadata["server_initiated_authorization"] = true
	} else if e.EastWestEnabled && e.isEastWestFlow(req) {
		// East-west per-hop authorization (E1): default-deny internal/lateral access; each hop must be
		// explicitly allowed/authenticated by an east-west rule. Governs east-west protocols on its own,
		// bypassing the north-bound policy match.
		var ewActions []model.DecisionAction
		decisionValue, reason, reasonCodes, ewActions = e.eastWestDecisionFor(req, now)
		actions = append(actions, ewActions...)
		policyID = "east_west_policy"
		metadata["east_west_authorization"] = true
		metadata["east_west_protocol"] = strings.ToLower(strings.TrimSpace(req.ServiceFamily))
		metadata["destination_locality"] = ClassifyDestinationLocality(req, e.EastWestInternalNetworks).String()
	} else if matchedPolicy, names, ok, whyNot := e.firstMatchedPolicyWithDiagnosis(req, actorType); !ok && whyNot != "" {
		// Nothing matched, and the nearest candidate is worth naming — see firstUnmetConditionMarker. The
		// decision is unchanged; only the sentence a person reads is.
		reason = "No active policy matched the request. " + whyNot + "."
	} else if ok {
		policyID = matchedPolicy.ID
		// A matched policy with an EMPTY decision is a MISCONFIGURATION, not an allow (fail-open review #16). The
		// authoring paths already reject an empty decision (policy.Store.Upsert / the policy loader require
		// action.decision), so an empty value reaching the evaluator means a policy bypassed validation — treat it
		// as invalid and fail closed WITH a visible reason (surface the misconfig; never silently allow).
		decisionValue = strings.TrimSpace(matchedPolicy.Action.Decision)
		if decisionValue == "" {
			// Surface the misconfiguration via a log line; the flow fails closed to deny (the deny's reason codes
			// are derived downstream from decisionValue).
			log.Printf("decision: matched policy %q has an EMPTY action.decision — treating as deny (misconfigured policy; authoring should have rejected it)", matchedPolicy.ID)
			decisionValue = "deny"
		}
		// Policy-driven access logging: carry this rule's explicit log choice (if set) so the egress path logs
		// (or drops) its matched traffic per the rule. nil = fall to the default (AI + actions).
		if matchedPolicy.Log != nil {
			metadata["log_traffic"] = *matchedPolicy.Log
		}
		if decisionValue == "allow" && matchedPolicy.RequiredWorkloadAttestation && !workloadAttestationSatisfied(workloadAttestationState) {
			decisionValue = "require_workload_attestation"
			workloadAttestationState = "required"
		}
		// Authentication Freshness: a matched policy can require re-authentication when the last
		// authentication is older than authentication_max_age_seconds (or unknown = unprovable freshness,
		// fail-closed). Stale -> require_reauthentication; reason/codes/actions are derived below.
		if decisionValue == "allow" {
			if maxAge := intMetadata(matchedPolicy.Metadata, "authentication_max_age_seconds", 0); maxAge > 0 {
				if age, known := breakGlassAuthAgeSeconds(req.AuthTime); !known || age > maxAge {
					decisionValue = "require_reauthentication"
					metadata["reauthentication_reason"] = "authentication_max_age_exceeded"
					metadata["authentication_max_age_seconds"] = maxAge
				}
			}
		}
		reason = reasonForPolicyDecision(decisionValue, actorType)
		reasonCodes = reasonCodesForPolicyDecision(decisionValue, actorType)
		matched = names
		actions = actionsForPolicyDecision(decisionValue, req, matchedPolicy)
		if tokenBindingState == "" && matchedPolicy.RequiredTokenBinding {
			tokenBindingState = "required"
		}
		// / Agentic Tool Action Boundary: when the matched policy declares a tool boundary
		// (AllowedToolIDs / AllowedToolActions), a tool call outside that boundary is denied before
		// execution (pre-execution policy check). An empty allowlist is unconstrained. This is a hard deny that
		// takes precedence over any step-up (human approval / workload attestation), so it is evaluated
		// before those blocks.
		if decisionValue == "allow" {
			if code, violated := toolActionBoundaryViolation(matchedPolicy, req); violated {
				decisionValue = "deny"
				reason = "Request matched a policy but the tool action is outside the permitted agentic boundary."
				reasonCodes = []string{"policy_matched", "tool_action_out_of_boundary", code}
				actions = nil
				metadata["tool_action_boundary_enforced"] = true
				metadata["tool_action_boundary_violation"] = code
			}
		}
		if decisionValue == "allow" && matchedPolicy.RequiredHumanApproval {
			approvalRequirementReasonCodes := humanApprovalRequirementReasonCodes(req, matchedPolicy)
			if len(approvalRequirementReasonCodes) > 0 {
				decisionValue = "require_human_approval"
				reason = "Request matched a policy that requires human approval."
				reasonCodes = append([]string{"policy_matched", "human_approval_required"}, approvalRequirementReasonCodes...)
				actions = []model.DecisionAction{humanApprovalRequestAction(req, matchedPolicy)}
				metadata["human_approval_required"] = true
				metadata["human_approval_request_scope"] = "metadata_only"
				applyHumanApprovalEventContractMetadata(metadata, req, matchedPolicy, false)
			} else {
				applyHumanApprovalEventContractMetadata(metadata, req, matchedPolicy, true)
			}
		}
		breakGlassCtx := breakGlassPolicyContextFor(matchedPolicy, req)
		if breakGlassCtx.Configured {
			applyBreakGlassPolicyMetadata(metadata, breakGlassCtx)
			decisionValue, reason, reasonCodes, actions = applyBreakGlassPolicyGuard(decisionValue, reason, reasonCodes, actions, matchedPolicy, req, breakGlassCtx)
		}
		inspectionCtx := e.tlsInspectionReadinessContextFor(matchedPolicy, req)
		if inspectionCtx.Configured {
			inspectionProfileID = stringPtr(inspectionCtx.Profile.ID)
			if inspectionCtx.Profile.InspectionMode != "" {
				inspectionMode = stringPtr(inspectionCtx.Profile.InspectionMode)
			}
			applyTLSInspectionReadinessMetadata(metadata, inspectionCtx)
			routeCategory, executionScope := inspectionRoutingForTLSInspectionContext(inspectionCtx)
			inspectionRouteCategory = stringPtr(routeCategory)
			inspectionExecutionScope = stringPtr(executionScope)
			applyEdgeInspectionRoutingMetadata(metadata, routeCategory, executionScope, "inspection_profile", false)
			reasonCodes = appendTLSInspectionReadinessReasonCodes(reasonCodes, inspectionCtx)
			actions = appendTLSInspectionReadinessActions(actions, inspectionCtx, req, matchedPolicy)
		} else if matchedPolicy.InspectionProfileID != nil && strings.TrimSpace(*matchedPolicy.InspectionProfileID) != "" {
			inspectionProfileID = stringPtr(strings.TrimSpace(*matchedPolicy.InspectionProfileID))
			metadata["inspection_profile_resolution"] = "missing"
		}
		swgCtx := e.swgTenantEnforcementContextFor(matchedPolicy, req, inspectionCtx)
		if swgCtx.Configured {
			applySWGTenantEnforcementMetadata(metadata, swgCtx)
			if swgCtx.TLSBypassRule != nil {
				bypass = true
				inspectionRouteCategory = stringPtr("passthrough")
				inspectionExecutionScope = stringPtr("not_executed_metadata_only")
				applyEdgeInspectionRoutingMetadata(metadata, "passthrough", "not_executed_metadata_only", "swg_tls_bypass_rule", true)
			}
			reasonCodes = appendSWGTenantEnforcementReasonCodes(reasonCodes, swgCtx)
			actions = appendSWGTenantEnforcementActions(actions, swgCtx, req, matchedPolicy)
		}
		// DLP as an egress-rule option: when a DLP rule matches this destination AND the flow is intercepted
		// (not a TLS bypass — a no-decrypt flow has no plaintext to inspect), surface a dlp_inspect directive so
		// the egress handler scans the decrypted body/files. Ties DLP to the policy/destination.
		if swgCtx.TLSBypassRule == nil {
			if matchedPolicy.DLP != nil {
				actions = append(actions, dlpInspectActionFromSpec(matchedPolicy.ID, *matchedPolicy.DLP))
				metadata["dlp_rule_id"] = matchedPolicy.ID
			} else if dlpRule, ok := e.firstDLPRule(req, matchedPolicy); ok {
				actions = append(actions, dlpInspectAction(dlpRule))
				metadata["dlp_rule_id"] = dlpRule.ID
			}
		}
	}
	return model.AccessDecision{
		ID:                        randomModelID("dec_", now),
		TenantID:                  tenantID,
		SessionID:                 stringPtr(req.SessionID),
		AuthenticationEventID:     stringPtr(req.AuthenticationEventID),
		UserID:                    stringPtr(req.UserID),
		SubjectUserID:             stringPtr(valueOrDefault(req.SubjectUserID, req.UserID)),
		ActorType:                 actorType,
		ActorNHIID:                stringPtr(req.ActorNHIID),
		DelegatedAccessGrantID:    stringPtr(req.DelegatedAccessGrantID),
		AgentTaskSessionID:        stringPtr(req.AgentTaskSessionID),
		ToolID:                    stringPtr(req.ToolID),
		ToolActionType:            stringPtr(req.ToolActionType),
		ToolPermissionProfile:     stringPtr(req.ToolPermissionProfile),
		ToolVersion:               stringPtr(req.ToolVersion),
		ToolSignatureState:        stringPtr(req.ToolSignatureState),
		MCPServerID:               stringPtr(req.MCPServerID),
		MCPResourceURI:            stringPtr(req.MCPResourceURI),
		MCPAudience:               stringPtr(req.MCPAudience),
		MCPTokenPassthroughPolicy: stringPtr(req.MCPTokenPassthroughPolicy),
		RuntimeEnvironmentID:      stringPtr(req.RuntimeEnvironmentID),
		ContextBoundaryID:         stringPtr(req.ContextBoundaryID),
		DataClassification:        stringPtr(req.DataClassification),
		DeviceID:                  stringPtr(req.DeviceID),
		ApplicationID:             req.ApplicationID,
		PolicyID:                  policyID,
		PolicyBundleID:            e.PolicyBundle.ID,
		PolicyBundleVersion:       e.PolicyBundle.Version,
		RiskStateID:               stringPtr(req.RiskStateID),
		SourceIP:                  stringPtr(req.SourceIP),
		SourcePort:                intPtr(req.SourcePort),
		Destination:               stringPtr(req.Destination),
		DestinationIP:             stringPtr(req.DestinationIP),
		DestinationPort:           intPtr(req.DestinationPort),
		Protocol:                  stringPtr(req.Protocol),
		FQDN:                      stringPtr(req.FQDN),
		SNI:                       stringPtr(req.SNI),
		ServiceFamily:             stringPtr(req.ServiceFamily),
		SaaSContext:               saasContextFromRequest(req),
		ConnectionInitiator:       stringPtr(req.ConnectionInitiator),
		SourceRole:                stringPtr(req.SourceRole),
		DestinationRole:           stringPtr(req.DestinationRole),
		SourceVLANID:              nil,
		DestinationVLANID:         nil,
		MatchedConditions:         matched,
		TokenBindingState:         stringPtr(tokenBindingState),
		WorkloadAttestationState:  stringPtr(workloadAttestationState),
		HumanApprovalEventID:      stringPtr(req.HumanApprovalEventID),
		Decision:                  decisionValue,
		Reason:                    &reason,
		ReasonCodes:               reasonCodes,
		Actions:                   actions,
		Bypass:                    bypass,
		InspectionProfileID:       inspectionProfileID,
		InspectionMode:            inspectionMode,
		InspectionRouteCategory:   inspectionRouteCategory,
		InspectionExecutionScope:  inspectionExecutionScope,
		EdgeRegionID:              stringPtr(e.EdgeRegionID),
		EdgeClusterID:             stringPtr(e.EdgeClusterID),
		ConnectorID:               stringPtr(req.ConnectorID),
		CacheStatus:               "miss",
		TTLSeconds:                60,
		Timestamp:                 now.Format(time.RFC3339),
		Metadata:                  metadata,
	}
}

func AccessLogFromDecision(dec model.AccessDecision) model.AccessLog {
	// Field floor: the record carries a config_generation_id instead of restating the tenant's
	// inspection/trust/CA config on every decision. The snapshot itself is written once per generation by the
	// caller (see ConfigGenerationFromDecision) — strip here only AFTER the id is captured, or the config
	// becomes unrecoverable for this record. dec.Metadata is the evaluator's working map and other consumers
	// read it, so the copy is pruned, never the source.
	generationID := ""
	if snapshot, ok := ConfigGenerationFromDecision(dec); ok {
		generationID = snapshot.ID
	}
	metadata := stripConfigGenerationKeys(copyMetadata(dec.Metadata))
	return model.AccessLog{
		ConfigGenerationID:     generationID,
		ID:                     randomModelID("alog_", time.Now().UTC()),
		TenantID:               dec.TenantID,
		AccessDecisionID:       dec.ID,
		SessionID:              dec.SessionID,
		UserID:                 dec.UserID,
		SubjectUserID:          dec.SubjectUserID,
		ActorType:              dec.ActorType,
		ActorNHIID:             dec.ActorNHIID,
		DelegatedAccessGrantID: dec.DelegatedAccessGrantID,
		HumanApprovalEventID:   dec.HumanApprovalEventID,
		AgentTaskSessionID:     dec.AgentTaskSessionID,
		ToolID:                 dec.ToolID,
		ToolActionType:         dec.ToolActionType,
		MCPServerID:            dec.MCPServerID,
		RuntimeEnvironmentID:   dec.RuntimeEnvironmentID,
		DeviceID:               dec.DeviceID,
		ApplicationID:          &dec.ApplicationID,
		SourceIP:               dec.SourceIP,
		Destination:            dec.Destination,
		RequestMethod:          dec.RequestMethod,
		RequestPath:            dec.RequestPath,
		ServiceFamily:          dec.ServiceFamily,
		Decision:               dec.Decision,
		Reason:                 dec.Reason,
		ReasonCodes:            dec.ReasonCodes,
		PolicyID:               stringPtr(dec.PolicyID),
		PolicyBundleID:         stringPtr(dec.PolicyBundleID),
		MatchedConditions:      dec.MatchedConditions,
		// CacheStatus was the ONLY field the separate decision_trace record carried that the access log did
		// not; folding it in makes the access log a strict superset of the trace, so the trace's redundant
		// second write is removed (the double-write collapse).
		CacheStatus:   dec.CacheStatus,
		EdgeRegionID:  dec.EdgeRegionID,
		EdgeClusterID: dec.EdgeClusterID,
		ConnectorID:   dec.ConnectorID,
		Timestamp:     dec.Timestamp,
		Metadata:      metadata,
	}
}

func DecisionTraceFromDecision(dec model.AccessDecision) model.DecisionTrace {
	return model.DecisionTrace{
		ID:                randomModelID("trace_", time.Now().UTC()),
		AccessDecisionID:  dec.ID,
		PolicyID:          dec.PolicyID,
		PolicyBundleID:    dec.PolicyBundleID,
		MatchedConditions: dec.MatchedConditions,
		CacheStatus:       dec.CacheStatus,
		ReasonCodes:       dec.ReasonCodes,
		Timestamp:         dec.Timestamp,
		Metadata:          decisionTraceMetadata(dec.Metadata),
	}
}

func decisionTraceMetadata(metadata map[string]any) map[string]any {
	trace := map[string]any{}
	for _, key := range []string{
		"saas_application_id",
		"saas_name",
		"saas_provider",
		"saas_category",
		"saas_risk_tier",
		"saas_matched_domain",
		"saas_matched_pattern",
		"saas_match_type",
		"tls_inspection_readiness",
		"tls_interception_enabled",
		"certificate_issuance_mode",
		"inspection_profile_id",
		"inspection_mode",
		"inspection_route_category",
		"inspection_execution_scope",
		"edge_tls_policy_decision",
		"edge_tls_policy_decision_source",
		"edge_tls_policy_bypass",
		"inspection_profile_resolution",
		"payload_policy",
		"network_extension_dependency",
		"trust_profile_id",
		"trust_profile_status",
		"trust_store_state",
		"certificate_pinning_policy",
		"tenant_root_ca_id",
		"tenant_root_ca_status",
		"tenant_root_ca_distribution_mode",
		"tenant_root_ca_trust_store_target",
		"tenant_root_ca_private_key_status",
		"quic_policy_mode",
		"quic_policy_action",
		"quic_tcp_tls_redirect_required",
		"network_extension_runtime_used",
		"break_glass_policy",
		"break_glass_identity_id",
		"break_glass_max_session_seconds",
		"break_glass_strong_auth_required",
		"break_glass_strong_auth_satisfied",
		"break_glass_audit_required",
		"break_glass_audit_event_required",
		"break_glass_auth_age_seconds",
		"break_glass_auth_freshness",
		"break_glass_request_id",
		"break_glass_reason_present",
		"break_glass_ticket_id_present",
		"subject_user_id",
		"actor_type",
		"actor_nhi_id",
		"delegated_access_grant_id",
		"agent_task_session_id",
		"tool_id",
		"tool_action_type",
		"tool_permission_profile",
		"tool_version",
		"tool_signature_state",
		"agent_tool_metadata_scope",
		"mcp_server_id",
		"mcp_resource_uri",
		"mcp_audience",
		"mcp_token_passthrough_policy",
		"mcp_metadata_scope",
		"runtime_environment_id",
		"tool_payload_recorded",
		"tool_secret_recorded",
		"tool_credentials_recorded",
		"context_boundary_id",
		"data_classification",
		"human_approval_event_id",
		"runtime_evidence_result",
		"delegated_grant_status",
		"delegated_grant_expires_at",
		"approval_result",
		"approval_expires_at",
		"nhi_registry_last_used_result",
		"nhi_registry_last_used_at",
		"swg_tenant_enforcement_preflight",
		"swg_default_tls_decryption_required",
		"swg_tls_bypass_policy",
		"swg_tls_bypass_applied",
		"swg_tls_runtime_decryption_observed",
		"swg_header_injection_runtime_observed",
		"swg_macos_ca_trust_required",
		"swg_macos_ca_trust_observed",
		"swg_tenant_restriction_rule_id",
		"swg_tenant_restriction_header_name",
		"swg_tenant_restriction_header_value_ref",
		"swg_tenant_restriction_header_value_kind",
		"swg_tenant_restriction_header_value_material_in_decision",
		"swg_tenant_restriction_header_injection_applicable",
		"swg_tenant_restriction_header_injection_applied",
		"swg_tenant_restriction_header_injection_suppressed_by_bypass",
		"swg_tls_bypass_rule_id",
		"swg_tls_bypass_match_type",
		"swg_tls_bypass_reason",
	} {
		if value, ok := metadata[key]; ok {
			trace[key] = value
		}
	}
	return trace
}

func randomModelID(prefix string, fallback time.Time) string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err == nil {
		return prefix + hex.EncodeToString(b[:])
	} else {
		log.Printf("WARN: crypto/rand failed for model id, falling back to process-local entropy: %v", err)
	}
	return fmt.Sprintf("%s%d_%d_%d", prefix, fallback.UnixNano(), os.Getpid(), modelIDFallbackCounter.Add(1))
}

func BundleLoadedAuditLog(bundle model.PolicyBundle, edgeRegionID, edgeClusterID string) model.AuditLog {
	now := time.Now().UTC().Format(time.RFC3339)
	targetType := "policy_bundle"
	action := "load"
	result := "success"
	reason := "Local Edge loaded standard policy bundle."
	sourceIP := "127.0.0.1"

	return model.AuditLog{
		ID:             randomModelID("audit_", time.Now().UTC()),
		TenantID:       bundle.TenantID,
		EventType:      "policy_bundle_loaded",
		TargetType:     &targetType,
		TargetID:       &bundle.ID,
		Action:         &action,
		Result:         &result,
		Reason:         &reason,
		PolicyBundleID: &bundle.ID,
		EdgeRegionID:   &edgeRegionID,
		EdgeClusterID:  &edgeClusterID,
		SourceIP:       &sourceIP,
		Timestamp:      now,
		Metadata:       map[string]any{},
	}
}

func (e Evaluator) firstMatchedPolicy(req model.DecisionRequest, actorType string) (model.Policy, []string, bool) {
	policy, names, ok, _ := e.firstMatchedPolicyWithDiagnosis(req, actorType)
	return policy, names, ok
}

// firstMatchedPolicyWithDiagnosis also returns why the FIRST candidate this request could plausibly have
// matched did not — see firstUnmetConditionMarker. "Plausibly" means the same organization and active: a rule
// belonging to somebody else, or one an operator switched off, is not a near miss and saying so would send the
// reader to the wrong rule.
func (e Evaluator) firstMatchedPolicyWithDiagnosis(req model.DecisionRequest, actorType string) (model.Policy, []string, bool, string) {
	diagnosis := ""
	for _, policy := range e.orderedPolicies() {
		matches, names := matchPolicy(policy, req, actorType)
		if matches {
			return policy, names, true, ""
		}
		if diagnosis == "" && policy.Status == "active" && policyTenantAppliesTo(policy, req) {
			if unmet, ok := unmetConditionFrom(names); ok {
				diagnosis = "the closest rule is " + strconv.Quote(policy.ID) + ", and it requires " + unmet
			}
		}
	}
	return model.Policy{}, nil, false, diagnosis
}

// policyTenantAppliesTo is the tenant half of matchPolicy, so the diagnosis above only ever names a rule that
// belongs to the organization this request is for.
func policyTenantAppliesTo(policy model.Policy, req model.DecisionRequest) bool {
	pt := strings.TrimSpace(policy.TenantID)
	rt := strings.TrimSpace(req.TenantID)
	return pt == "" || rt == "" || strings.EqualFold(pt, rt)
}

func (e Evaluator) orderedPolicies() []model.Policy {
	policies := append([]model.Policy(nil), e.Policies...)
	sort.SliceStable(policies, func(i, j int) bool {
		if policies[i].Priority != policies[j].Priority {
			return policies[i].Priority < policies[j].Priority
		}
		// Same priority: the MORE RESTRICTIVE decision wins the tie, so an authored override beats a built-in
		// allow that happens to share its priority. Previously only "deny" was privileged here, so an authored
		// require_reauthentication rule (e.g. an egress "Authenticate" on accounts.google.com, priority 100)
		// silently lost the tie to a base SaaS allow policy at the same priority (ID "pol_..." sorts before
		// "rule-egress-...") and appeared to do nothing — while the same rule as a Deny worked. Rank
		// deny > step-up/re-authentication > allow so authored Authenticate behaves like authored Deny.
		if ri, rj := policyDecisionRestrictivenessRank(policies[i].Action.Decision), policyDecisionRestrictivenessRank(policies[j].Action.Decision); ri != rj {
			return ri < rj
		}
		return policies[i].ID < policies[j].ID
	})
	return policies
}

// policyDecisionRestrictivenessRank orders decisions from most to least restrictive for breaking a priority
// tie: deny (0) > step-up / re-authentication (1) > everything permissive (2). A lower rank sorts first (wins
// the tie). This generalises the historical deny-first tie-break so an authored re-authentication rule also
// overrides a built-in allow sharing its priority — matching the step-up decision set the edge treats as an
// OIDC-redirect challenge.
func policyDecisionRestrictivenessRank(decision string) int {
	switch decision {
	case "deny":
		return 0
	case "require_reauthentication", "require_step_up_mfa", "require_interactive_mfa", "authenticate_required":
		return 1
	default:
		return 2
	}
}

func (e Evaluator) firstPolicyTenantID() string {
	for _, policy := range e.orderedPolicies() {
		if policy.TenantID != "" {
			return policy.TenantID
		}
	}
	return ""
}

func matchPolicy(policy model.Policy, req model.DecisionRequest, actorType string) (bool, []string) {
	if policy.Status != "active" {
		return false, nil
	}
	// Tenant isolation (review finding #1): the shared RuntimeEvaluator flattens EVERY tenant's policies into one
	// cache, so a flow must never match another tenant's policy. Gate on tenant equality when BOTH sides are known;
	// an empty tenant on either side is treated as global/unscoped (lockout-safe — this preserves single-tenant and
	// deliberately tenant-less "global" policies, and only ADDS filtering between two DISTINCT known tenants).
	if pt := strings.TrimSpace(policy.TenantID); pt != "" {
		if rt := strings.TrimSpace(req.TenantID); rt != "" && !strings.EqualFold(pt, rt) {
			return false, nil
		}
	}

	matched := []string{}
	for _, key := range sortedConditionKeys(policy.Conditions) {
		expected := policy.Conditions[key]
		actual := fieldValues(req, actorType, key)
		ok := conditionMatches(actual, expected)
		// Hostname conditions (fqdn/sni) additionally accept a leading "*." wildcard in the EXPECTED value
		// (e.g. an endpoint authored as *.google.com), so one rule covers every sub-domain. Try the wildcard
		// matcher when the exact comparison above did not match.
		if !ok && isHostnameConditionKey(key) {
			ok = hostnameConditionMatches(actual, expected)
			// An endpoint authored as an IP LITERAL (the Console's own example is "10.0.0.10") compiles to an
			// fqdn/sni condition, but a steered flow to a bare IP carries that IP in Destination and leaves
			// FQDN empty — DNS recovery only fills FQDN when the conntrack store has an answer, and a client
			// that dialled an address never asked. So the condition could not match its own request: an egress
			// rule naming an IP was inert on every steered flow, and the Console offers exactly that shape.
			//
			// Found on 2026-08-05 by authoring a rule for the lab's own management address and watching it
			// stay denied with no_policy_match while /admin/effective-policy (which fills FQDN from its
			// `destination` query parameter) reported the same rule as the winner. Two views of one decision
			// disagreeing is the tell.
			//
			// Narrow on purpose: only when the AUTHORED value is an IP literal, which is never a hostname, so
			// no fqdn/sni rule written for a real name changes meaning.
			if !ok {
				ok = ipLiteralConditionMatchesDestination(req.Destination, expected)
			}
		}
		if !ok {
			return false, []string{firstUnmetConditionMarker + key + "=" + conditionExpectedForMessage(expected) +
				" (this request has " + conditionActualForMessage(actual) + ")"}
		}
		matched = append(matched, key)
	}

	return true, matched
}

// isHostnameConditionKey reports whether a condition key carries a hostname whose expected value supports a
// leading "*." wildcard.
func isHostnameConditionKey(key string) bool { return key == "fqdn" || key == "sni" }

// hostnameConditionMatches matches actual hostnames against the expected condition value, honouring a leading
// "*." wildcard pattern. It accepts the same expected shapes conditionMatches does for hostnames: a plain
// string, a []any list, or a map with op eq/equals/contains/in. Wildcard semantics match the rest of the
// codebase (saasDomainPatternMatches / interception): "*.suffix" matches any sub-domain of suffix (foo.suffix)
// but NOT the apex (suffix) itself — author an exact endpoint for the apex.
func hostnameConditionMatches(actual []string, expected any) bool {
	if len(actual) == 0 {
		return false
	}
	var patterns []string
	switch typed := expected.(type) {
	case map[string]any:
		switch fmt.Sprint(typed["op"]) {
		case "eq", "equals", "contains":
			patterns = []string{fmt.Sprint(typed["value"])}
		case "in":
			if values, ok := typed["values"].([]any); ok {
				for _, v := range values {
					patterns = append(patterns, fmt.Sprint(v))
				}
			}
		default:
			return false
		}
	case []any:
		for _, v := range typed {
			patterns = append(patterns, fmt.Sprint(v))
		}
	default:
		patterns = []string{fmt.Sprint(expected)}
	}
	for _, host := range actual {
		for _, pattern := range patterns {
			if hostMatchesPattern(host, pattern) {
				return true
			}
		}
	}
	return false
}

// hostMatchesPattern reports whether host matches pattern, where pattern may be a "*." wildcard (sub-domains
// only) or an exact hostname. Comparison is case-insensitive on the trimmed values.
func hostMatchesPattern(host, pattern string) bool {
	host = strings.TrimSpace(strings.ToLower(host))
	pattern = strings.TrimSpace(strings.ToLower(pattern))
	if host == "" || pattern == "" {
		return false
	}
	if strings.HasPrefix(pattern, "*.") {
		suffix := strings.TrimPrefix(pattern, "*.")
		if suffix == "" || host == suffix {
			return false
		}
		return strings.HasSuffix(host, "."+suffix)
	}
	return host == pattern
}

// toolActionBoundaryViolation reports whether a tool call is outside the matched policy's declared
// agentic tool boundary. An empty allowlist is unconstrained. When AllowedToolIDs is
// set, the request must carry a ToolID within it; when AllowedToolActions is set, the request's
// ToolActionType must be within it. A policy that declares a boundary is explicitly tool-scoped, so a
// request that does not carry the matching tool field is treated as out-of-boundary (zero-trust
// default). Comparison is case-insensitive on the trimmed value.
func toolActionBoundaryViolation(policy model.Policy, req model.DecisionRequest) (string, bool) {
	if len(policy.AllowedToolIDs) > 0 && !toolBoundaryListContains(policy.AllowedToolIDs, req.ToolID) {
		return "tool_id_not_allowed", true
	}
	if len(policy.AllowedToolActions) > 0 && !toolBoundaryListContains(policy.AllowedToolActions, req.ToolActionType) {
		return "tool_action_not_allowed", true
	}
	return "", false
}

func toolBoundaryListContains(list []string, value string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return false
	}
	for _, item := range list {
		if strings.EqualFold(strings.TrimSpace(item), value) {
			return true
		}
	}
	return false
}

func reasonCodesForPolicyDecision(decisionValue, actorType string) []string {
	switch decisionValue {
	case "deny":
		return []string{"policy_matched", "application_denied"}
	case "require_reauthentication":
		return []string{"policy_matched", "reauthentication_required"}
	case "require_workload_attestation":
		return []string{"policy_matched", "workload_attestation_required"}
	default:
		if actorType == "delegated_agent" || actorType == "nhi" {
			return []string{"policy_matched", "delegated_grant_valid", "scope_allowed", "approval_valid", "tool_allowed"}
		}
		return []string{"policy_matched", "application_allowed"}
	}
}

func reasonForPolicyDecision(decisionValue, actorType string) string {
	switch decisionValue {
	case "require_reauthentication":
		return "Request matched a policy that requires re-authentication."
	case "require_workload_attestation":
		return "Request matched a policy that requires verified workload attestation."
	case "deny":
		return "Request matched an active deny policy."
	default:
		if actorType == "delegated_agent" || actorType == "nhi" {
			return "Delegated agent request matched the active lab policy."
		}
		return "Request matched the active lab policy."
	}
}

func actionsForPolicyDecision(decisionValue string, req model.DecisionRequest, policy model.Policy) []model.DecisionAction {
	switch decisionValue {
	case "require_reauthentication":
		target := req.ApplicationID
		ttl := intMetadata(policy.Metadata, "reauth_interval_seconds", 300)
		// Federated re-auth requirements (which IdP + how strong) the OIDC broker uses to build the redirect.
		// Read from the authored policy. Empty => re-authenticate against the tenant DEFAULT IdP at the default
		// assurance — back-compatible with a bare require_reauthentication. (require_authentication is the same
		// decision with these requirements set.)
		meta := map[string]any{"service_family": req.ServiceFamily}
		if idp := stringMetadataValue(policy.Metadata, "required_idp_id"); idp != "" {
			meta["required_idp_id"] = idp
		}
		if acr := stringMetadataValue(policy.Metadata, "min_acr"); acr != "" {
			meta["min_acr"] = acr
		}
		if amr := splitCommaList(stringMetadataValue(policy.Metadata, "required_amr")); len(amr) > 0 {
			meta["required_amr"] = amr
		}
		if maxAge := intMetadata(policy.Metadata, "max_age_seconds", 0); maxAge > 0 {
			meta["max_age_seconds"] = maxAge
		}
		return []model.DecisionAction{
			{
				Type:       "prompt_reauthentication",
				Target:     stringPtr(target),
				TTLSeconds: intPtr(ttl),
				Metadata:   meta,
			},
		}
	case "require_workload_attestation":
		target := req.ActorNHIID
		if target == "" {
			target = req.AgentTaskSessionID
		}
		return []model.DecisionAction{
			{
				Type:   "request_workload_attestation",
				Target: stringPtr(target),
				Metadata: map[string]any{
					"actor_nhi_id":           req.ActorNHIID,
					"agent_task_session_id":  req.AgentTaskSessionID,
					"application_id":         req.ApplicationID,
					"required_by_policy_id":  policy.ID,
					"attestation_acceptance": []string{"verified", "valid"},
				},
			},
		}
	default:
		return []model.DecisionAction{}
	}
}

func humanApprovalRequestAction(req model.DecisionRequest, policy model.Policy) model.DecisionAction {
	metadata := map[string]any{
		"required_by_policy_id":     policy.ID,
		"application_id":            req.ApplicationID,
		"human_approval_required":   true,
		"human_approval_scope":      "metadata_only",
		"tool_payload_recorded":     false,
		"tool_secret_recorded":      false,
		"tool_credentials_recorded": false,
	}
	if req.ActorNHIID != "" {
		metadata["actor_nhi_id"] = req.ActorNHIID
	}
	if req.DelegatedAccessGrantID != "" {
		metadata["delegated_access_grant_id"] = req.DelegatedAccessGrantID
	}
	if req.AgentTaskSessionID != "" {
		metadata["agent_task_session_id"] = req.AgentTaskSessionID
	}
	if req.ToolID != "" {
		metadata["tool_id"] = req.ToolID
	}
	if req.ToolActionType != "" {
		metadata["tool_action_type"] = req.ToolActionType
	}
	if req.DataClassification != "" {
		metadata["data_classification"] = req.DataClassification
	}
	ttl := intMetadata(policy.Metadata, "human_approval_ttl_seconds", 300)
	return model.DecisionAction{
		Type:       "request_human_approval",
		Target:     stringPtr(req.ApplicationID),
		TTLSeconds: intPtr(ttl),
		Metadata:   metadata,
	}
}

func breakGlassPolicyContextFor(policy model.Policy, req model.DecisionRequest) breakGlassPolicyContext {
	if !breakGlassPolicyConfigured(policy) {
		return breakGlassPolicyContext{}
	}
	ctx := breakGlassPolicyContext{
		Configured:          true,
		IdentityID:          stringMetadataValue(policy.Metadata, "break_glass_identity_id"),
		MaxSessionSeconds:   breakGlassMaxSessionSeconds(policy),
		StrongAuthRequired:  policy.BreakGlassStrongAuthRequired || boolMetadataValue(policy.Metadata, "break_glass_strong_auth_required"),
		AuditRequired:       policy.BreakGlassAuditRequired || boolMetadataValue(policy.Metadata, "break_glass_audit_required"),
		StrongAuthSatisfied: breakGlassStrongAuthSatisfied(req),
		ReasonPresent:       req.BreakGlassReasonPresent,
		TicketIDPresent:     req.BreakGlassTicketIDPresent,
		RequestID:           req.BreakGlassRequestID,
	}
	if policy.BreakGlassIdentityID != nil && strings.TrimSpace(*policy.BreakGlassIdentityID) != "" {
		ctx.IdentityID = strings.TrimSpace(*policy.BreakGlassIdentityID)
	}
	ctx.AuthAgeSeconds, ctx.AuthAgeKnown = breakGlassAuthAgeSeconds(req.AuthTime)
	ctx.AuthFreshness = breakGlassAuthFreshness(ctx)
	ctx.RequirementReasonCodes = breakGlassRequirementReasonCodes(ctx)
	ctx.ReauthenticationReasons = breakGlassReauthenticationReasonCodes(ctx)
	return ctx
}

func breakGlassPolicyConfigured(policy model.Policy) bool {
	if policy.BreakGlassPolicy {
		return true
	}
	if conditionRequiresBreakGlassAuth(policy.Conditions["auth_method"]) {
		return true
	}
	switch normalizedRiskValue(stringMetadataValue(policy.Metadata, "purpose")) {
	case "break_glass", "break_glass_lab":
		return true
	default:
		return false
	}
}

func conditionRequiresBreakGlassAuth(condition any) bool {
	switch typed := condition.(type) {
	case map[string]any:
		if conditionContainsBreakGlassValue(typed["value"]) || conditionContainsBreakGlassValue(typed["values"]) {
			return true
		}
		return false
	default:
		return conditionContainsBreakGlassValue(condition)
	}
}

func conditionContainsBreakGlassValue(value any) bool {
	for _, conditionValue := range conditionValues(value) {
		if normalizedRiskValue(conditionValue) == "break_glass" {
			return true
		}
	}
	return false
}

func breakGlassMaxSessionSeconds(policy model.Policy) int {
	if policy.BreakGlassMaxSessionSeconds != nil {
		return *policy.BreakGlassMaxSessionSeconds
	}
	return intMetadata(policy.Metadata, "break_glass_max_session_seconds", 0)
}

func breakGlassAuthAgeSeconds(authTime string) (int, bool) {
	if strings.TrimSpace(authTime) == "" {
		return 0, false
	}
	parsed, err := time.Parse(time.RFC3339, authTime)
	if err != nil {
		return 0, false
	}
	age := int(time.Since(parsed).Seconds())
	if age < 0 {
		age = 0
	}
	return age, true
}

func breakGlassAuthFreshness(ctx breakGlassPolicyContext) string {
	if !ctx.AuthAgeKnown {
		return "missing_auth_time"
	}
	if ctx.MaxSessionSeconds <= 0 {
		return "missing_ttl"
	}
	if ctx.AuthAgeSeconds > ctx.MaxSessionSeconds {
		return "ttl_expired"
	}
	return "fresh"
}

func breakGlassStrongAuthSatisfied(req model.DecisionRequest) bool {
	if normalizedRiskValue(req.AuthMethod) != "break_glass" {
		return false
	}
	switch normalizedRiskValue(req.MFAState) {
	case "fresh", "verified", "satisfied":
	default:
		return false
	}
	for _, method := range req.AMR {
		switch normalizedRiskValue(method) {
		case "otp", "totp", "hotp", "webauthn", "fido2", "passkey", "hardware_key", "phishing_resistant", "mfa":
			return true
		}
	}
	switch normalizedRiskValue(req.ACR) {
	case "urn:break_glass:admin", "urn:break_glass:strong_auth", "break_glass_strong_auth":
		return true
	default:
		return false
	}
}

func breakGlassRequirementReasonCodes(ctx breakGlassPolicyContext) []string {
	reasonCodes := []string{}
	if ctx.MaxSessionSeconds <= 0 {
		reasonCodes = appendUniqueString(reasonCodes, "break_glass_ttl_missing")
	} else if ctx.MaxSessionSeconds > 3600 {
		reasonCodes = appendUniqueString(reasonCodes, "break_glass_ttl_too_long")
	} else {
		reasonCodes = appendUniqueString(reasonCodes, "break_glass_short_ttl_valid")
	}
	if !ctx.StrongAuthRequired {
		reasonCodes = appendUniqueString(reasonCodes, "break_glass_strong_auth_requirement_missing")
	}
	if !ctx.AuditRequired {
		reasonCodes = appendUniqueString(reasonCodes, "break_glass_audit_requirement_missing")
	} else {
		reasonCodes = appendUniqueString(reasonCodes, "break_glass_audit_required")
	}
	return reasonCodes
}

func breakGlassReauthenticationReasonCodes(ctx breakGlassPolicyContext) []string {
	reasonCodes := []string{}
	if !ctx.StrongAuthSatisfied {
		reasonCodes = appendUniqueString(reasonCodes, "break_glass_strong_auth_required")
	} else {
		reasonCodes = appendUniqueString(reasonCodes, "break_glass_strong_auth_satisfied")
	}
	switch ctx.AuthFreshness {
	case "missing_auth_time":
		reasonCodes = appendUniqueString(reasonCodes, "break_glass_auth_time_missing")
	case "missing_ttl":
	case "ttl_expired":
		reasonCodes = appendUniqueString(reasonCodes, "break_glass_ttl_expired")
	case "fresh":
	default:
		reasonCodes = appendUniqueString(reasonCodes, "break_glass_auth_time_missing")
	}
	return reasonCodes
}

func applyBreakGlassPolicyMetadata(metadata map[string]any, ctx breakGlassPolicyContext) {
	metadata["break_glass_policy"] = true
	if ctx.IdentityID != "" {
		metadata["break_glass_identity_id"] = ctx.IdentityID
	}
	if ctx.MaxSessionSeconds > 0 {
		metadata["break_glass_max_session_seconds"] = ctx.MaxSessionSeconds
	}
	metadata["break_glass_strong_auth_required"] = ctx.StrongAuthRequired
	metadata["break_glass_strong_auth_satisfied"] = ctx.StrongAuthSatisfied
	metadata["break_glass_audit_required"] = ctx.AuditRequired
	metadata["break_glass_audit_event_required"] = true
	if ctx.AuthAgeKnown {
		metadata["break_glass_auth_age_seconds"] = ctx.AuthAgeSeconds
	}
	if ctx.AuthFreshness != "" {
		metadata["break_glass_auth_freshness"] = ctx.AuthFreshness
	}
	if ctx.RequestID != "" {
		metadata["break_glass_request_id"] = ctx.RequestID
	}
	if ctx.ReasonPresent {
		metadata["break_glass_reason_present"] = true
	}
	if ctx.TicketIDPresent {
		metadata["break_glass_ticket_id_present"] = true
	}
}

func applyBreakGlassPolicyGuard(decisionValue, reason string, reasonCodes []string, actions []model.DecisionAction, policy model.Policy, req model.DecisionRequest, ctx breakGlassPolicyContext) (string, string, []string, []model.DecisionAction) {
	reasonCodes = appendUniqueString(reasonCodes, "break_glass_policy_matched")
	for _, code := range ctx.RequirementReasonCodes {
		reasonCodes = appendUniqueString(reasonCodes, code)
	}
	for _, code := range ctx.ReauthenticationReasons {
		reasonCodes = appendUniqueString(reasonCodes, code)
	}

	guardResult := "allowed"
	if !breakGlassPolicyRequirementsSatisfied(ctx) {
		guardResult = "blocked_policy_configuration"
		decisionValue = "deny"
		reason = "Break-glass policy is missing required short TTL, strong authentication, or audit safeguards."
		reasonCodes = appendUniqueString(reasonCodes, "break_glass_policy_guard_failed")
	} else if decisionValue == "allow" && !breakGlassRuntimeSatisfied(ctx) {
		guardResult = "reauthentication_required"
		decisionValue = "require_reauthentication"
		reason = "Break-glass access requires fresh strong authentication within the policy TTL."
		reasonCodes = appendUniqueString(reasonCodes, "reauthentication_required")
		actions = append(actions, breakGlassReauthenticationAction(ctx, req, policy))
	}
	actions = append(actions, breakGlassAuditAction(ctx, req, policy, guardResult))
	return decisionValue, reason, reasonCodes, actions
}

func breakGlassPolicyRequirementsSatisfied(ctx breakGlassPolicyContext) bool {
	return ctx.MaxSessionSeconds > 0 &&
		ctx.MaxSessionSeconds <= 3600 &&
		ctx.StrongAuthRequired &&
		ctx.AuditRequired
}

func breakGlassRuntimeSatisfied(ctx breakGlassPolicyContext) bool {
	return ctx.StrongAuthSatisfied && ctx.AuthFreshness == "fresh"
}

func breakGlassReauthenticationAction(ctx breakGlassPolicyContext, req model.DecisionRequest, policy model.Policy) model.DecisionAction {
	return model.DecisionAction{
		Type:       "prompt_reauthentication",
		Target:     stringPtr(req.ApplicationID),
		TTLSeconds: intPtr(ctx.MaxSessionSeconds),
		Metadata: map[string]any{
			"break_glass_policy":         true,
			"required_by_policy_id":      policy.ID,
			"required_auth_method":       "break_glass",
			"strong_auth_required":       true,
			"max_session_seconds":        ctx.MaxSessionSeconds,
			"accepted_mfa_factors":       []string{"otp", "webauthn", "fido2", "passkey", "hardware_key"},
			"audit_event_type":           "break_glass_policy_decision",
			"break_glass_auth_freshness": ctx.AuthFreshness,
		},
	}
}

func breakGlassAuditAction(ctx breakGlassPolicyContext, req model.DecisionRequest, policy model.Policy, guardResult string) model.DecisionAction {
	metadata := map[string]any{
		"audit_event_type":                  "break_glass_policy_decision",
		"policy_id":                         policy.ID,
		"application_id":                    req.ApplicationID,
		"break_glass_policy":                true,
		"break_glass_policy_guard_result":   guardResult,
		"break_glass_strong_auth_required":  ctx.StrongAuthRequired,
		"break_glass_strong_auth_satisfied": ctx.StrongAuthSatisfied,
		"break_glass_audit_required":        ctx.AuditRequired,
		"break_glass_auth_freshness":        ctx.AuthFreshness,
	}
	if ctx.IdentityID != "" {
		metadata["break_glass_identity_id"] = ctx.IdentityID
	}
	if ctx.MaxSessionSeconds > 0 {
		metadata["break_glass_max_session_seconds"] = ctx.MaxSessionSeconds
	}
	if ctx.AuthAgeKnown {
		metadata["break_glass_auth_age_seconds"] = ctx.AuthAgeSeconds
	}
	if ctx.RequestID != "" {
		metadata["break_glass_request_id"] = ctx.RequestID
	}
	if ctx.ReasonPresent {
		metadata["break_glass_reason_present"] = true
	}
	if ctx.TicketIDPresent {
		metadata["break_glass_ticket_id_present"] = true
	}
	return model.DecisionAction{
		Type:     "emit_audit_event",
		Metadata: metadata,
	}
}

func (e Evaluator) tlsInspectionReadinessContextFor(policy model.Policy, req model.DecisionRequest) tlsInspectionReadinessContext {
	if policy.InspectionProfileID == nil || strings.TrimSpace(*policy.InspectionProfileID) == "" {
		return tlsInspectionReadinessContext{}
	}
	profileID := strings.TrimSpace(*policy.InspectionProfileID)
	profile, ok := e.inspectionProfileByID(profileID)
	if !ok || !tenantMatches(profile.TenantID, e.PolicyBundle.TenantID, policy.TenantID, req.TenantID) {
		return tlsInspectionReadinessContext{}
	}
	ctx := tlsInspectionReadinessContext{
		Configured:     true,
		Profile:        profile,
		QUICApplicable: requestIndicatesQUIC(req),
	}
	if trustProfile, ok := e.trustProfileByID(profile.TrustProfileID); ok && tenantMatches(trustProfile.TenantID, e.PolicyBundle.TenantID, policy.TenantID, req.TenantID) {
		ctx.TrustProfile = &trustProfile
	}
	rootCAID := profile.TenantRootCAID
	if rootCAID == "" && ctx.TrustProfile != nil {
		rootCAID = ctx.TrustProfile.TenantRootCAID
	}
	if rootCA, ok := e.tenantRootCAByID(rootCAID); ok && tenantMatches(rootCA.TenantID, e.PolicyBundle.TenantID, policy.TenantID, req.TenantID) {
		ctx.TenantRootCA = &rootCA
	}
	return ctx
}

func (e Evaluator) inspectionProfileByID(id string) (model.InspectionProfile, bool) {
	for _, profile := range e.PolicyBundle.InspectionProfiles {
		if strings.TrimSpace(profile.ID) == strings.TrimSpace(id) {
			return profile, true
		}
	}
	return model.InspectionProfile{}, false
}

func (e Evaluator) trustProfileByID(id string) (model.TrustProfile, bool) {
	for _, profile := range e.PolicyBundle.TrustProfiles {
		if strings.TrimSpace(profile.ID) == strings.TrimSpace(id) {
			return profile, true
		}
	}
	return model.TrustProfile{}, false
}

func (e Evaluator) tenantRootCAByID(id string) (model.TenantRootCA, bool) {
	for _, rootCA := range e.PolicyBundle.TenantRootCAs {
		if strings.TrimSpace(rootCA.ID) == strings.TrimSpace(id) {
			return rootCA, true
		}
	}
	return model.TenantRootCA{}, false
}

func tenantMatches(candidate string, allowed ...string) bool {
	candidate = strings.TrimSpace(candidate)
	if candidate == "" {
		return true
	}
	for _, value := range allowed {
		if strings.TrimSpace(value) == candidate {
			return true
		}
	}
	return false
}

func applyTLSInspectionReadinessMetadata(metadata map[string]any, ctx tlsInspectionReadinessContext) {
	metadata["tls_inspection_readiness"] = "policy_layer"
	metadata["tls_interception_enabled"] = ctx.Profile.TLSInterceptionEnabled
	metadata["certificate_issuance_mode"] = valueOrDefault(ctx.Profile.CertificateIssuanceMode, "not_issued")
	metadata["inspection_profile_id"] = ctx.Profile.ID
	metadata["inspection_mode"] = valueOrDefault(ctx.Profile.InspectionMode, "metadata_only")
	metadata["payload_policy"] = valueOrDefault(ctx.Profile.PayloadPolicy, "metadata_only")
	metadata["network_extension_runtime_used"] = false
	if ctx.Profile.NetworkExtensionDependency != "" {
		metadata["network_extension_dependency"] = ctx.Profile.NetworkExtensionDependency
	}
	if ctx.Profile.TrustProfileID != "" {
		metadata["trust_profile_id"] = ctx.Profile.TrustProfileID
	}
	if ctx.Profile.TenantRootCAID != "" {
		metadata["tenant_root_ca_id"] = ctx.Profile.TenantRootCAID
	}
	if ctx.TrustProfile != nil {
		metadata["trust_profile_id"] = ctx.TrustProfile.ID
		metadata["trust_profile_status"] = valueOrDefault(ctx.TrustProfile.Status, "unknown")
		if ctx.TrustProfile.TrustStoreState != "" {
			metadata["trust_store_state"] = ctx.TrustProfile.TrustStoreState
		}
		if ctx.TrustProfile.CertificatePinningPolicy != "" {
			metadata["certificate_pinning_policy"] = ctx.TrustProfile.CertificatePinningPolicy
		}
	}
	if ctx.TenantRootCA != nil {
		metadata["tenant_root_ca_id"] = ctx.TenantRootCA.ID
		metadata["tenant_root_ca_status"] = valueOrDefault(ctx.TenantRootCA.Status, "unknown")
		if ctx.TenantRootCA.DistributionMode != "" {
			metadata["tenant_root_ca_distribution_mode"] = ctx.TenantRootCA.DistributionMode
		}
		if ctx.TenantRootCA.TrustStoreTarget != "" {
			metadata["tenant_root_ca_trust_store_target"] = ctx.TenantRootCA.TrustStoreTarget
		}
		if ctx.TenantRootCA.PrivateKeyStatus != "" {
			metadata["tenant_root_ca_private_key_status"] = ctx.TenantRootCA.PrivateKeyStatus
		}
	}
	if ctx.Profile.QUICPolicyMode != "" {
		metadata["quic_policy_mode"] = ctx.Profile.QUICPolicyMode
	}
	if ctx.Profile.QUICPolicyAction != "" {
		metadata["quic_policy_action"] = ctx.Profile.QUICPolicyAction
	}
	if ctx.QUICApplicable && quicPolicyRequiresTCPTLS(ctx.Profile) {
		metadata["quic_tcp_tls_redirect_required"] = true
	}
}

func inspectionRoutingForTLSInspectionContext(ctx tlsInspectionReadinessContext) (string, string) {
	if !ctx.Configured {
		return "", ""
	}
	if ctx.Profile.TLSInterceptionEnabled {
		return "tls_readiness_candidate", "post_mvp_tls"
	}
	switch normalizedRiskValue(ctx.Profile.InspectionMode) {
	case "passthrough":
		return "passthrough", "not_executed_metadata_only"
	case "metadata_only", "tls_readiness":
		return "metadata_inspection", "metadata_inspection_only"
	default:
		return "metadata_inspection", "metadata_inspection_only"
	}
}

func applyEdgeInspectionRoutingMetadata(metadata map[string]any, routeCategory, executionScope, source string, bypass bool) {
	if metadata == nil || strings.TrimSpace(routeCategory) == "" || strings.TrimSpace(executionScope) == "" {
		return
	}
	decision := "metadata_inspection"
	if bypass {
		decision = "bypass"
	} else {
		switch routeCategory {
		case "tls_readiness_candidate":
			decision = "intercept_candidate"
		case "passthrough":
			decision = "passthrough"
		}
	}
	metadata["inspection_route_category"] = routeCategory
	metadata["inspection_execution_scope"] = executionScope
	metadata["edge_tls_policy_decision"] = decision
	metadata["edge_tls_policy_decision_source"] = source
	metadata["edge_tls_policy_bypass"] = bypass
}

func appendTLSInspectionReadinessReasonCodes(reasonCodes []string, ctx tlsInspectionReadinessContext) []string {
	reasonCodes = appendUniqueString(reasonCodes, "tls_inspection_readiness_policy_layer")
	if ctx.QUICApplicable && quicPolicyRequiresTCPTLS(ctx.Profile) {
		reasonCodes = appendUniqueString(reasonCodes, "quic_tcp_tls_required")
	}
	return reasonCodes
}

func appendTLSInspectionReadinessActions(actions []model.DecisionAction, ctx tlsInspectionReadinessContext, req model.DecisionRequest, policy model.Policy) []model.DecisionAction {
	if !ctx.QUICApplicable || !quicPolicyRequiresTCPTLS(ctx.Profile) {
		return actions
	}
	return append(actions, model.DecisionAction{
		Type: "emit_audit_event",
		Metadata: map[string]any{
			"audit_event_type":               "tls_inspection_readiness_quic_policy",
			"application_id":                 req.ApplicationID,
			"inspection_profile_id":          ctx.Profile.ID,
			"policy_id":                      policy.ID,
			"quic_policy_action":             ctx.Profile.QUICPolicyAction,
			"recommended_transport":          "tcp_tls",
			"network_extension_runtime_used": false,
		},
	})
}

func requestIndicatesQUIC(req model.DecisionRequest) bool {
	switch normalizedRiskValue(req.Protocol) {
	case "udp", "quic":
		return true
	}
	switch normalizedRiskValue(req.ServiceFamily) {
	case "quic", "http3", "http_3", "https_quic":
		return true
	}
	return false
}

func quicPolicyRequiresTCPTLS(profile model.InspectionProfile) bool {
	switch normalizedRiskValue(profile.QUICPolicyAction) {
	case "tcp_tls_required", "prefer_tcp_tls", "redirect_to_tcp_tls", "disable_http3":
		return true
	default:
		return false
	}
}

func workloadAttestationSatisfied(state string) bool {
	switch strings.ToLower(strings.TrimSpace(state)) {
	case "verified", "valid":
		return true
	default:
		return false
	}
}

func humanApprovalRequirementReasonCodes(req model.DecisionRequest, policy model.Policy) []string {
	if strings.TrimSpace(req.HumanApprovalEventID) == "" {
		return []string{"approval_absent"}
	}
	if !humanApprovalEventTrustBindingFreshnessRequired(policy) {
		return nil
	}
	reasonCodes := []string{}
	if !humanApprovalEventTrustSatisfied(req.HumanApprovalEventTrustState) {
		reasonCodes = append(reasonCodes, "approval_untrusted")
	}
	if !humanApprovalEventBindingSatisfied(req.HumanApprovalEventBindingState) {
		reasonCodes = append(reasonCodes, "approval_unbound")
	}
	if !humanApprovalEventFreshnessSatisfied(req.HumanApprovalEventFreshnessState) {
		reasonCodes = append(reasonCodes, "approval_not_fresh")
	}
	return reasonCodes
}

func humanApprovalEventTrustBindingFreshnessRequired(policy model.Policy) bool {
	if boolMetadataValue(policy.Metadata, "human_approval_event_require_trusted_binding_freshness") {
		return true
	}
	return strings.EqualFold(stringMetadataValue(policy.Metadata, "human_approval_event_contract"), "trust_binding_freshness")
}

func humanApprovalEventTrustSatisfied(state string) bool {
	switch strings.ToLower(strings.TrimSpace(state)) {
	case "trusted", "valid":
		return true
	default:
		return false
	}
}

func humanApprovalEventBindingSatisfied(state string) bool {
	switch strings.ToLower(strings.TrimSpace(state)) {
	case "bound", "matched", "valid":
		return true
	default:
		return false
	}
}

func humanApprovalEventFreshnessSatisfied(state string) bool {
	switch strings.ToLower(strings.TrimSpace(state)) {
	case "fresh", "valid":
		return true
	default:
		return false
	}
}

func applyHumanApprovalEventContractMetadata(metadata map[string]any, req model.DecisionRequest, policy model.Policy, valid bool) {
	if !humanApprovalEventTrustBindingFreshnessRequired(policy) {
		return
	}
	metadata["human_approval_event_contract"] = "trust_binding_freshness"
	metadata["human_approval_event_contract_result"] = mapBool(valid, "valid", "invalid")
	metadata["human_approval_event_trust_state"] = stateOrMissing(req.HumanApprovalEventTrustState)
	metadata["human_approval_event_binding_state"] = stateOrMissing(req.HumanApprovalEventBindingState)
	metadata["human_approval_event_freshness_state"] = stateOrMissing(req.HumanApprovalEventFreshnessState)
}

func mapBool(value bool, whenTrue, whenFalse string) string {
	if value {
		return whenTrue
	}
	return whenFalse
}

func stateOrMissing(value string) string {
	if trimmed := strings.TrimSpace(value); trimmed != "" {
		return trimmed
	}
	return "missing"
}

func intMetadata(metadata map[string]any, key string, fallback int) int {
	value, ok := metadata[key]
	if !ok {
		return fallback
	}
	switch typed := value.(type) {
	case int:
		return typed
	case float64:
		return int(typed)
	case string:
		parsed, err := strconv.Atoi(typed)
		if err == nil {
			return parsed
		}
	}
	return fallback
}

func boolMetadataValue(metadata map[string]any, key string) bool {
	value, ok := metadata[key]
	if !ok {
		return false
	}
	switch typed := value.(type) {
	case bool:
		return typed
	case string:
		return strings.EqualFold(strings.TrimSpace(typed), "true")
	default:
		return false
	}
}

func sortedConditionKeys(conditions map[string]any) []string {
	keys := make([]string, 0, len(conditions))
	for key := range conditions {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func conditionMatches(actual []string, expected any) bool {
	if len(actual) == 0 {
		return false
	}

	switch typed := expected.(type) {
	case map[string]any:
		op := fmt.Sprint(typed["op"])
		switch op {
		case "eq", "equals":
			return anyActualEquals(actual, fmt.Sprint(typed["value"]))
		case "in":
			return anyActualInExpectedValues(actual, typed["values"])
		case "contains":
			return anyActualEquals(actual, fmt.Sprint(typed["value"]))
		case "lte":
			return anyActualNumberCompare(actual, typed["value"], func(actual, expected float64) bool { return actual <= expected })
		case "gte":
			return anyActualNumberCompare(actual, typed["value"], func(actual, expected float64) bool { return actual >= expected })
		case "cidr_contains":
			return anyActualCIDRContains(actual, typed["value"]) || anyActualCIDRContains(actual, typed["values"])
		default:
			return false
		}
	case []any:
		return anyActualInExpectedValues(actual, typed)
	default:
		return anyActualEquals(actual, fmt.Sprint(expected))
	}
}

func anyActualEquals(actual []string, expected string) bool {
	for _, value := range actual {
		if value == expected {
			return true
		}
	}
	return false
}

func anyActualInExpectedValues(actual []string, expectedValues any) bool {
	values, ok := expectedValues.([]any)
	if !ok {
		return false
	}
	allowed := map[string]struct{}{}
	for _, value := range values {
		allowed[fmt.Sprint(value)] = struct{}{}
	}
	for _, value := range actual {
		if _, ok := allowed[value]; ok {
			return true
		}
	}
	return false
}

func anyActualNumberCompare(actual []string, expectedValue any, compare func(float64, float64) bool) bool {
	expected, err := strconv.ParseFloat(fmt.Sprint(expectedValue), 64)
	if err != nil {
		return false
	}
	for _, value := range actual {
		actualNumber, err := strconv.ParseFloat(value, 64)
		if err == nil && compare(actualNumber, expected) {
			return true
		}
	}
	return false
}

func anyActualCIDRContains(actual []string, expectedValue any) bool {
	prefixes := conditionValues(expectedValue)
	if len(prefixes) == 0 {
		return false
	}
	for _, value := range actual {
		addr, err := netip.ParseAddr(value)
		if err != nil {
			continue
		}
		for _, prefixValue := range prefixes {
			prefix, err := netip.ParsePrefix(prefixValue)
			if err == nil && prefix.Masked().Contains(addr) {
				return true
			}
		}
	}
	return false
}

func conditionValues(value any) []string {
	switch typed := value.(type) {
	case []any:
		values := make([]string, 0, len(typed))
		for _, item := range typed {
			values = append(values, fmt.Sprint(item))
		}
		return values
	case []string:
		return append([]string(nil), typed...)
	case nil:
		return nil
	default:
		return []string{fmt.Sprint(typed)}
	}
}

func fieldValues(req model.DecisionRequest, actorType, key string) []string {
	switch key {
	case "actor_type":
		return singleValue(actorType)
	case "actor_nhi_id":
		return singleValue(req.ActorNHIID)
	case "nhi_risk_severity":
		return singleValue(req.NHIRiskSeverity)
	case "transport_client_cert_verified":
		return singleValue(strconv.FormatBool(req.TransportClientCertVerified))
	case "transport_device_identity":
		return singleValue(req.TransportDeviceIdentity)
	case "delegated_access_grant_id":
		return singleValue(req.DelegatedAccessGrantID)
	case "agent_task_session_id":
		return singleValue(req.AgentTaskSessionID)
	case "tool_id":
		return singleValue(req.ToolID)
	case "tool_action_type":
		return singleValue(req.ToolActionType)
	case "tool_permission_profile":
		return singleValue(req.ToolPermissionProfile)
	case "tool_version":
		return singleValue(req.ToolVersion)
	case "tool_signature_state":
		return singleValue(req.ToolSignatureState)
	case "mcp_server_id":
		return singleValue(req.MCPServerID)
	case "mcp_resource_uri":
		return singleValue(req.MCPResourceURI)
	case "mcp_audience":
		return singleValue(req.MCPAudience)
	case "mcp_token_passthrough_policy":
		return singleValue(req.MCPTokenPassthroughPolicy)
	case "runtime_environment_id":
		return singleValue(req.RuntimeEnvironmentID)
	case "context_boundary_id":
		return singleValue(req.ContextBoundaryID)
	case "data_classification":
		return singleValue(req.DataClassification)
	case "tenant_id":
		return singleValue(req.TenantID)
	case "session_id_present":
		return singleValue(strconv.FormatBool(strings.TrimSpace(req.SessionID) != ""))
	case "application_id":
		return singleValue(req.ApplicationID)
	case "service_family":
		return singleValue(req.ServiceFamily)
	case "fqdn":
		return singleValue(req.FQDN)
	case "sni":
		return singleValue(req.SNI)
	case "saas_application_id":
		return singleValue(req.SaaSApplicationID)
	case "saas_name":
		return singleValue(req.SaaSName)
	case "saas_provider":
		return singleValue(req.SaaSProvider)
	case "saas_category":
		return singleValue(req.SaaSCategory)
	case "saas_risk_tier":
		return singleValue(req.SaaSRiskTier)
	case "saas_match_type":
		return singleValue(req.SaaSMatchType)
	case "inspection_profile_id":
		return singleValue(req.InspectionProfileID)
	case "inspection_mode":
		return singleValue(req.InspectionMode)
	case "trust_profile_id":
		return singleValue(req.TrustProfileID)
	case "tenant_root_ca_id":
		return singleValue(req.TenantRootCAID)
	case "quic_policy_mode":
		return singleValue(req.QUICPolicyMode)
	case "quic_policy_action":
		return singleValue(req.QUICPolicyAction)
	case "protocol":
		return singleValue(req.Protocol)
	case "steering_mode":
		return singleValue(req.SteeringMode)
	case "destination_port":
		if req.DestinationPort == 0 {
			return nil
		}
		return singleValue(strconv.Itoa(req.DestinationPort))
	case "user_groups":
		return req.UserGroups
	case "user_id":
		// An individual IdP user source (iduser:<id>) matches the request's user_id, with the subject_user_id as
		// an alternate so a rule authored against either identifier still binds to the right person.
		ids := []string{}
		if req.UserID != "" {
			ids = append(ids, req.UserID)
		}
		if req.SubjectUserID != "" && req.SubjectUserID != req.UserID {
			ids = append(ids, req.SubjectUserID)
		}
		return ids
	case "mfa_state":
		return singleValue(req.MFAState)
	case "acr":
		return singleValue(req.ACR)
	case "amr":
		return req.AMR
	case "idp_id":
		return singleValue(req.IDPID)
	case "issuer":
		return singleValue(req.Issuer)
	case "authentication_event_id":
		return singleValue(req.AuthenticationEventID)
	case "auth_time":
		return singleValue(req.AuthTime)
	case "auth_age_seconds":
		return singleValue(authAgeSeconds(req.AuthTime))
	case "auth_method":
		return singleValue(req.AuthMethod)
	case "source_ip":
		return singleValue(req.SourceIP)
	case "device_id":
		return singleValue(req.DeviceID)
	case "device_trust_level":
		return singleValue(req.DeviceTrustLevel)
	case "source_role":
		return singleValue(req.SourceRole)
	case "destination_role":
		return singleValue(req.DestinationRole)
	case "connection_initiator":
		return singleValue(req.ConnectionInitiator)
	case "source_server":
		return singleValue(req.SourceServer)
	case "destination_address_scope":
		return singleValue(destinationAddressScope(req))
	case "token_binding_state":
		return singleValue(req.TokenBindingState)
	case "workload_attestation_state":
		return singleValue(req.WorkloadAttestationState)
	case "human_approval_event_id":
		return singleValue(req.HumanApprovalEventID)
	case "human_approval_event_trust_state":
		return singleValue(req.HumanApprovalEventTrustState)
	case "human_approval_event_binding_state":
		return singleValue(req.HumanApprovalEventBindingState)
	case "human_approval_event_freshness_state":
		return singleValue(req.HumanApprovalEventFreshnessState)
	case "risk_state_id":
		return singleValue(req.RiskStateID)
	case "risk_state_severity":
		return singleValue(req.RiskStateSeverity)
	case "risk_recommended_action":
		return singleValue(req.RiskRecommendedAction)
	case "risk_signal_sources":
		return req.RiskSignalSources
	case "admin_high_risk":
		return trueValue(req.AdminHighRisk)
	case "idp_risk_level":
		return singleValue(req.IDPRiskLevel)
	case "agent_tamper_signal":
		return trueValue(req.AgentTamperSignal)
	case "authentication_anomaly":
		return trueValue(req.AuthenticationAnomaly)
	default:
		return nil
	}
}

func authAgeSeconds(authTime string) string {
	if authTime == "" {
		return ""
	}
	parsed, err := time.Parse(time.RFC3339, authTime)
	if err != nil {
		return ""
	}
	age := int(time.Since(parsed).Seconds())
	if age < 0 {
		age = 0
	}
	return strconv.Itoa(age)
}

func decisionMetadata(req model.DecisionRequest) map[string]any {
	metadata := map[string]any{}
	if req.ActorType != "" {
		metadata["actor_type"] = req.ActorType
	}
	if subjectUserID := valueOrDefault(req.SubjectUserID, req.UserID); subjectUserID != "" {
		metadata["subject_user_id"] = subjectUserID
	}
	if req.MFAState != "" {
		metadata["mfa_state"] = req.MFAState
	}
	if req.AuthTime != "" {
		metadata["auth_time"] = req.AuthTime
	}
	if req.ACR != "" {
		metadata["acr"] = req.ACR
	}
	if len(req.AMR) > 0 {
		metadata["amr"] = req.AMR
	}
	if req.AuthMethod != "" {
		metadata["auth_method"] = req.AuthMethod
	}
	if req.IDPID != "" {
		metadata["idp_id"] = req.IDPID
	}
	if req.Issuer != "" {
		metadata["issuer"] = req.Issuer
	}
	if req.DeviceTrustLevel != "" {
		metadata["device_trust_level"] = req.DeviceTrustLevel
	}
	if req.ActorNHIID != "" {
		metadata["actor_nhi_id"] = req.ActorNHIID
	}
	if req.DelegatedAccessGrantID != "" {
		metadata["delegated_access_grant_id"] = req.DelegatedAccessGrantID
	}
	if req.ToolID != "" {
		metadata["tool_id"] = req.ToolID
	}
	if req.ToolActionType != "" {
		metadata["tool_action_type"] = req.ToolActionType
	}
	if req.ToolPermissionProfile != "" {
		metadata["tool_permission_profile"] = req.ToolPermissionProfile
	}
	if req.ToolVersion != "" {
		metadata["tool_version"] = req.ToolVersion
	}
	if req.ToolSignatureState != "" {
		metadata["tool_signature_state"] = req.ToolSignatureState
	}
	if req.MCPServerID != "" {
		metadata["mcp_server_id"] = req.MCPServerID
	}
	if req.MCPResourceURI != "" {
		metadata["mcp_resource_uri"] = req.MCPResourceURI
	}
	if req.MCPAudience != "" {
		metadata["mcp_audience"] = req.MCPAudience
	}
	if req.MCPTokenPassthroughPolicy != "" {
		metadata["mcp_token_passthrough_policy"] = req.MCPTokenPassthroughPolicy
	}
	if req.RuntimeEnvironmentID != "" {
		metadata["runtime_environment_id"] = req.RuntimeEnvironmentID
	}
	if decisionRequestHasToolMCPContext(req) {
		metadata["agent_tool_metadata_scope"] = "metadata_only"
		metadata["mcp_metadata_scope"] = "metadata_only"
		metadata["tool_payload_recorded"] = false
		metadata["tool_secret_recorded"] = false
		metadata["tool_credentials_recorded"] = false
	}
	if req.ContextBoundaryID != "" {
		metadata["context_boundary_id"] = req.ContextBoundaryID
	}
	if req.DataClassification != "" {
		metadata["data_classification"] = req.DataClassification
	}
	if req.HumanApprovalEventID != "" {
		metadata["human_approval_event_id"] = req.HumanApprovalEventID
	}
	if req.HumanApprovalEventTrustState != "" {
		metadata["human_approval_event_trust_state"] = req.HumanApprovalEventTrustState
	}
	if req.HumanApprovalEventBindingState != "" {
		metadata["human_approval_event_binding_state"] = req.HumanApprovalEventBindingState
	}
	if req.HumanApprovalEventFreshnessState != "" {
		metadata["human_approval_event_freshness_state"] = req.HumanApprovalEventFreshnessState
	}
	if req.WorkloadAttestationState != "" {
		metadata["workload_attestation_state"] = req.WorkloadAttestationState
	}
	if req.RiskStateID != "" {
		metadata["risk_state_id"] = req.RiskStateID
	}
	if req.RiskStateSeverity != "" {
		metadata["risk_state_severity"] = req.RiskStateSeverity
	}
	if req.RiskRecommendedAction != "" {
		metadata["risk_recommended_action"] = req.RiskRecommendedAction
	}
	if len(req.RiskSignalSources) > 0 {
		metadata["risk_signal_sources"] = append([]string(nil), req.RiskSignalSources...)
	}
	if req.AdminHighRisk {
		metadata["admin_high_risk"] = true
	}
	if req.IDPRiskLevel != "" {
		metadata["idp_risk_level"] = req.IDPRiskLevel
	}
	if req.AgentTamperSignal {
		metadata["agent_tamper_signal"] = true
	}
	if req.AuthenticationAnomaly {
		metadata["authentication_anomaly"] = true
	}
	if req.SaaSApplicationID != "" {
		metadata["saas_application_id"] = req.SaaSApplicationID
	}
	if req.SaaSName != "" {
		metadata["saas_name"] = req.SaaSName
	}
	if req.SaaSProvider != "" {
		metadata["saas_provider"] = req.SaaSProvider
	}
	if req.SaaSCategory != "" {
		metadata["saas_category"] = req.SaaSCategory
	}
	if req.SaaSRiskTier != "" {
		metadata["saas_risk_tier"] = req.SaaSRiskTier
	}
	if req.SaaSMatchedDomain != "" {
		metadata["saas_matched_domain"] = req.SaaSMatchedDomain
	}
	if req.SaaSMatchedPattern != "" {
		metadata["saas_matched_pattern"] = req.SaaSMatchedPattern
	}
	if req.SaaSMatchType != "" {
		metadata["saas_match_type"] = req.SaaSMatchType
	}
	if req.InspectionProfileID != "" {
		metadata["requested_inspection_profile_id"] = req.InspectionProfileID
	}
	if req.InspectionMode != "" {
		metadata["requested_inspection_mode"] = req.InspectionMode
	}
	if req.TrustProfileID != "" {
		metadata["requested_trust_profile_id"] = req.TrustProfileID
	}
	if req.TenantRootCAID != "" {
		metadata["requested_tenant_root_ca_id"] = req.TenantRootCAID
	}
	if req.QUICPolicyMode != "" {
		metadata["requested_quic_policy_mode"] = req.QUICPolicyMode
	}
	if req.QUICPolicyAction != "" {
		metadata["requested_quic_policy_action"] = req.QUICPolicyAction
	}
	return metadata
}

func decisionRequestHasToolMCPContext(req model.DecisionRequest) bool {
	return req.ToolID != "" ||
		req.ToolActionType != "" ||
		req.ToolPermissionProfile != "" ||
		req.ToolVersion != "" ||
		req.ToolSignatureState != "" ||
		req.MCPServerID != "" ||
		req.MCPResourceURI != "" ||
		req.MCPAudience != "" ||
		req.MCPTokenPassthroughPolicy != "" ||
		req.RuntimeEnvironmentID != ""
}

func saasContextFromRequest(req model.DecisionRequest) *model.SaaSContext {
	if req.SaaSApplicationID == "" {
		return nil
	}
	return &model.SaaSContext{
		SaaSApplicationID: req.SaaSApplicationID,
		Name:              req.SaaSName,
		Provider:          req.SaaSProvider,
		Category:          req.SaaSCategory,
		RiskTier:          req.SaaSRiskTier,
		MatchedDomain:     req.SaaSMatchedDomain,
		MatchedPattern:    req.SaaSMatchedPattern,
		MatchType:         req.SaaSMatchType,
	}
}

func copyMetadata(metadata map[string]any) map[string]any {
	copied := map[string]any{}
	for key, value := range metadata {
		copied[key] = value
	}
	return copied
}

func singleValue(value string) []string {
	if value == "" {
		return nil
	}
	return []string{value}
}

// destinationAddressScope classifies the destination's address scope. Product model:
// private ranges (RFC1918 / IPv6 ULA) are subject to Default-Deny (internal resources),
// the public internet is allow+intercept. A non-IP-literal destination (FQDN) is treated as public
// (public SaaS/Web; internal FQDNs are expected to be allowed via an explicit private-app policy).
func destinationAddressScope(req model.DecisionRequest) string {
	candidate := strings.TrimSpace(req.DestinationIP)
	if candidate == "" {
		candidate = strings.TrimSpace(req.Destination)
	}
	candidate = strings.Trim(candidate, "[]")
	addr, err := netip.ParseAddr(candidate)
	if err != nil {
		return "public"
	}
	switch {
	case addr.IsLoopback():
		return "loopback"
	case addr.IsLinkLocalUnicast(), addr.IsLinkLocalMulticast():
		return "link_local"
	case addr.IsPrivate():
		return "private"
	default:
		return "public"
	}
}

func trueValue(value bool) []string {
	if !value {
		return nil
	}
	return []string{"true"}
}

func normalizedRiskValue(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.ReplaceAll(value, "-", "_")
	value = strings.ReplaceAll(value, " ", "_")
	return value
}

func appendUniqueString(values []string, value string) []string {
	if value == "" {
		return values
	}
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

func containsString(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

// splitCommaList parses a comma-separated metadata value (e.g. required_amr="mfa,phr") into a trimmed,
// non-empty list. Returns nil for an empty/blank value.
func splitCommaList(value string) []string {
	var out []string
	for _, part := range strings.Split(value, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func stringMetadataValue(metadata map[string]any, key string) string {
	if len(metadata) == 0 {
		return ""
	}
	value, ok := metadata[key]
	if !ok || value == nil {
		return ""
	}
	return strings.TrimSpace(fmt.Sprint(value))
}

func valueOrDefault(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func stringPtr(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

func intPtr(value int) *int {
	if value == 0 {
		return nil
	}
	return &value
}

// IsDefaultDeny reports whether a decision is the catch-all refusal — denied because NO policy matched, as
// opposed to denied by a rule an operator wrote. The two read the same on the wire and mean opposite things
// to an operator: one is a gap in the policy set, the other is the policy set working.
//
// It exists because Policy Learning used to answer this question implicitly. Its deferred default-deny turned
// exactly this case into decision "observe", so callers could test for that string instead of for the
// condition. Policy Learning was removed on 2026-08-05 (East-West already carries the observe → partial →
// full ramp, with a Console banner that drives it), and the callers that were keying off "observe" now ask
// for the thing they actually meant.
func IsDefaultDeny(dec model.AccessDecision) bool {
	if dec.Decision != "deny" {
		return false
	}
	if len(dec.MatchedConditions) > 0 {
		return false
	}
	return containsString(dec.ReasonCodes, "no_policy_match")
}

// ipLiteralConditionMatchesDestination retries an fqdn/sni condition against the request's Destination, but
// ONLY when the client dialled a bare IP address. See the call site for why: such a flow carries the address
// in Destination and leaves FQDN empty, so a rule authored for that address could never match its own request.
//
// Both address shapes the Console's endpoint form offers are handled: a single address ("10.0.0.10") by exact
// comparison, and a RANGE ("10.0.0.0/24") by prefix containment. The range case was still dead after the
// single-address fix — a CIDR compiles to the same fqdn condition and exact-compares against nothing, so a
// rule for a subnet matched no flow in it. Verified by running it, not by reading it.
//
// The narrowing is the IP check on the REQUEST. A named destination still matches on FQDN/SNI exactly as
// before, and a hostname condition tested against an IP simply does not compare equal — so nothing an
// operator wrote for a real name changes meaning.
func ipLiteralConditionMatchesDestination(destination string, expected any) bool {
	dst := strings.TrimSpace(destination)
	if dst == "" {
		return false
	}
	if _, err := netip.ParseAddr(dst); err != nil {
		return false
	}
	if conditionMatches([]string{dst}, expected) {
		return true
	}
	return anyActualCIDRContains([]string{dst}, expected)
}

// ★★★ A POLICY THAT IS LOADED, ACTIVE, NAMED BY THE BUNDLE AND STILL DOES NOT MATCH SAYS NOTHING ABOUT WHY
// (2026-09-05, measured by walking the getting-started path as somebody who had never seen this product).
//
// The walk wrote one policy — `conditions: {actor_type: "user"}` — started an Edge with it, confirmed through
// the admin API that it was loaded, active and in the right organization, and got:
//
//	decision: deny   reason: "No active policy matched the request."
//
// The cause was that `actor_type` is derived at the trust boundary and never taken from the caller
// (deriveDecisionRequestActor sets it to ""), so it is "human" on every request and a rule written for "user"
// can never match anything. That is correct behaviour — a client must not be able to name its own actor type
// — and it is invisible: the operator sees a rule they can read, in a list that says active, denying.
//
// So the refusal now names the first condition that stopped the highest-priority candidate. It is a
// diagnostic, not a decision: the decision is unchanged, and no policy is matched by it.
const firstUnmetConditionMarker = "\x00unmet:"

// conditionExpectedForMessage and conditionActualForMessage render a condition for a human, without
// promising a stable shape. They are for the sentence a person reads when a rule they wrote does not fire.
func conditionExpectedForMessage(expected any) string {
	switch v := expected.(type) {
	case string:
		return strconv.Quote(v)
	case []any:
		parts := make([]string, 0, len(v))
		for _, e := range v {
			parts = append(parts, fmt.Sprint(e))
		}
		return "one of [" + strings.Join(parts, ", ") + "]"
	default:
		return fmt.Sprint(v)
	}
}

func conditionActualForMessage(actual []string) string {
	switch len(actual) {
	case 0:
		return "no value for it"
	case 1:
		if strings.TrimSpace(actual[0]) == "" {
			return "an empty value"
		}
		return strconv.Quote(actual[0])
	default:
		return "[" + strings.Join(actual, ", ") + "]"
	}
}

// unmetConditionFrom returns the diagnostic matchPolicy attached, if it attached one.
func unmetConditionFrom(names []string) (string, bool) {
	if len(names) == 1 && strings.HasPrefix(names[0], firstUnmetConditionMarker) {
		return strings.TrimPrefix(names[0], firstUnmetConditionMarker), true
	}
	return "", false
}
