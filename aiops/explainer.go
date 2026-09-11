package aiops

import (
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/model"
)

// AI Operations Assistant — Decision Explainer. This is the DETERMINISTIC core of the
// AI Ops assistant: it explains why a recorded access decision was allowed/denied/stepped-up by mapping
// the decision's structured reason_codes (enums emitted by the decision engine) to human-readable
// text + remediation. No LLM, no external call, no data leaves the Edge — the decision record IS the
// source of truth, so the explanation cannot hallucinate. The optional LLM narrative layer (report
// generation, self-hosted OSS LLM, never an AI SaaS) builds ON TOP of this grounded output.
//
// Non-secret: operates on the already-redacted decision record; emits enums + fixed templates only.

type ReasonCodeExplanation struct {
	Code        string `json:"code"`
	Category    string `json:"category"`
	Severity    string `json:"severity"` // info | warning | critical
	EN          string `json:"en"`
	Remediation string `json:"remediation,omitempty"`
	Known       bool   `json:"known"`
}

type decisionExplanation struct {
	SchemaVersion       string                  `json:"schema_version"`
	DecisionID          string                  `json:"decision_id"`
	TenantID            string                  `json:"tenant_id"`
	Decision            string                  `json:"decision"`
	PolicyID            string                  `json:"policy_id,omitempty"`
	SummaryEN           string                  `json:"summary_en"`
	MatchedConditions   []string                `json:"matched_conditions"`
	ReasonCodes         []ReasonCodeExplanation `json:"reason_codes"`
	GeneratedAt         string                  `json:"generated_at"`
	GenerationMethod    string                  `json:"generation_method"`
	NoSecretAttestation bool                    `json:"no_secret_attestation"`
}

// reasonCodeExplanationTable maps the decision engine's reason_code enums to grounded explanations.
// Codes absent from the table are explained generically (Known=false) — never fabricated.
var reasonCodeExplanationTable = map[string]ReasonCodeExplanation{
	// --- policy outcome ---
	"policy_matched":      {Category: "policy", Severity: "info", EN: "Request matched an active policy."},
	"application_allowed": {Category: "policy", Severity: "info", EN: "Access to the application was allowed by policy."},
	"application_denied":  {Category: "policy", Severity: "warning", EN: "Access was denied by the matched policy.", Remediation: "To allow access, review the relevant deny policy or its conditions."},
	"no_policy_match":     {Category: "policy", Severity: "warning", EN: "No policy matched; default-deny was applied.", Remediation: "If the access is required, add an explicit allow policy."},

	// --- step-up requirements ---
	"reauthentication_required":     {Category: "reauth", Severity: "warning", EN: "Re-authentication is required because the authentication is stale or its freshness is unprovable.", Remediation: "Prompt the user to re-authenticate (with MFA if needed)."},
	"workload_attestation_required": {Category: "attestation", Severity: "warning", EN: "Verified workload attestation is required.", Remediation: "Present a signed workload attestation."},
	"human_approval_required":       {Category: "approval", Severity: "warning", EN: "This access requires human approval.", Remediation: "Obtain a Human Approval Event from an approver."},
	"strong_auth_required":          {Category: "approval", Severity: "warning", EN: "Stronger (break-glass) authentication is required."},

	// --- delegated grant (NHI delegated access) ---
	"delegated_grant_valid":    {Category: "identity", Severity: "info", EN: "The delegated access grant is valid."},
	"delegated_grant_absent":   {Category: "identity", Severity: "critical", EN: "A delegated access grant is required for delegated agent access but is absent.", Remediation: "Issue a valid Delegated Access Grant for the NHI."},
	"delegated_grant_revoked":  {Category: "identity", Severity: "critical", EN: "The delegated access grant has been revoked."},
	"delegated_grant_expired":  {Category: "identity", Severity: "critical", EN: "The delegated access grant is no longer active (expired).", Remediation: "Issue a new grant or review the TTL."},
	"delegated_grant_mismatch": {Category: "identity", Severity: "critical", EN: "The delegated access grant context (tenant/application/scope) does not match the request."},

	// --- NHI runtime evidence ---
	"nhi_inactive":                {Category: "identity", Severity: "critical", EN: "The Non-Human Identity is not active."},
	"nhi_application_not_allowed": {Category: "identity", Severity: "critical", EN: "This NHI is not allowed for the requested application.", Remediation: "Review the NHI's allowed_application_ids."},
	"nhi_scope_not_allowed":       {Category: "identity", Severity: "critical", EN: "This NHI is not allowed for the requested scope."},
	"nhi_registry_absent":         {Category: "identity", Severity: "critical", EN: "The Non-Human Identity is required but absent/unregistered.", Remediation: "Register the NHI and include actor_nhi_id in the request."},
	"nhi_registry_unavailable":    {Category: "identity", Severity: "critical", EN: "The Non-Human Identity registry was unavailable."},

	// --- human approval evidence ---
	"approval_valid":    {Category: "approval", Severity: "info", EN: "The human approval event is valid."},
	"approval_absent":   {Category: "approval", Severity: "critical", EN: "A required human approval event is absent.", Remediation: "Obtain an approval event from an approver."},
	"approval_revoked":  {Category: "approval", Severity: "critical", EN: "The human approval event has been revoked."},
	"approval_expired":  {Category: "approval", Severity: "critical", EN: "The human approval event is no longer active (expired)."},
	"approval_mismatch": {Category: "approval", Severity: "critical", EN: "The human approval event context does not match the request."},

	// --- agentic tool action boundary ---
	"scope_allowed":               {Category: "tool", Severity: "info", EN: "The requested scope is within the allowed set."},
	"tool_allowed":                {Category: "tool", Severity: "info", EN: "The requested tool is within the allowed set."},
	"tool_action_out_of_boundary": {Category: "tool", Severity: "critical", EN: "The agent tool action is outside the policy-permitted boundary."},
	"tool_id_not_allowed":         {Category: "tool", Severity: "critical", EN: "This tool id is not in the policy's allowlist.", Remediation: "Add it to the policy's allowed_tool_ids or use an allowed tool."},
	"tool_action_not_allowed":     {Category: "tool", Severity: "critical", EN: "This tool action is not in the policy's allowlist.", Remediation: "Review the policy's allowed_tool_actions."},

	// --- risk state ---
	"risk_signal_manual_high_risk":           {Category: "risk", Severity: "critical", EN: "Manually marked as high risk."},
	"risk_signal_idp_high_risk":              {Category: "risk", Severity: "critical", EN: "The identity provider reported high risk."},
	"risk_signal_agent_tamper":               {Category: "risk", Severity: "critical", EN: "Agent tampering was detected."},
	"risk_signal_authentication_anomaly":     {Category: "risk", Severity: "warning", EN: "An authentication anomaly was detected."},
	"risk_state_recommended_emergency_block": {Category: "risk", Severity: "critical", EN: "The risk state recommends an emergency block."},
	"nhi_risk_severity":                      {Category: "identity", Severity: "info", EN: "The NHI risk severity was used in the policy decision."},

	// --- risk (legacy codes; no longer emitted) ---
	// The hardcoded risk-enforcement overlay that produced these was removed — the product must not
	// detect-and-block on its own; risk-based authorization is expressed as policy conditions
	// authored by the operator. These two entries are retained ONLY so historical audit records that already
	// carry the codes still render an explanation. Nothing emits them now.
	"ransomware_protection_mode_active": {Category: "risk", Severity: "critical", EN: "Legacy: a removed risk-enforcement overlay applied restrictions. No longer emitted."},
	"high_sensitivity_application":      {Category: "risk", Severity: "warning", EN: "Legacy: access targeted a high-sensitivity application. No longer emitted."},

	// --- east-west (per-hop) ---
	"east_west_authorization": {Category: "policy", Severity: "info", EN: "East-west authorization was applied."},
}

// ExplainDecisionRecord builds a grounded explanation of an access decision from its structured fields.
func ExplainDecisionRecord(dec model.AccessDecision, generatedAt string) decisionExplanation {
	codes := make([]ReasonCodeExplanation, 0, len(dec.ReasonCodes))
	for _, code := range dec.ReasonCodes {
		codes = append(codes, ExplainReasonCode(code))
	}
	summaryEN := decisionSummary(dec.Decision, codes)
	matched := dec.MatchedConditions
	if matched == nil {
		matched = []string{}
	}
	return decisionExplanation{
		SchemaVersion:       "ai_ops_decision_explanation.v1",
		DecisionID:          dec.ID,
		TenantID:            dec.TenantID,
		Decision:            dec.Decision,
		PolicyID:            dec.PolicyID,
		SummaryEN:           summaryEN,
		MatchedConditions:   matched,
		ReasonCodes:         codes,
		GeneratedAt:         generatedAt,
		GenerationMethod:    "deterministic_no_llm",
		NoSecretAttestation: true,
	}
}

func ExplainReasonCode(code string) ReasonCodeExplanation {
	if tmpl, ok := reasonCodeExplanationTable[code]; ok {
		tmpl.Code = code
		tmpl.Known = true
		return tmpl
	}
	// Unknown code: restate it without fabricating meaning (grounded, never invented).
	return ReasonCodeExplanation{
		Code:     code,
		Category: "other",
		Severity: "info",
		EN:       "Decision factor code \"" + code + "\" was recorded.",
		Known:    false,
	}
}

// decisionSummary composes a top-level sentence from the decision value plus the most salient
// (critical, then warning) explained reason code.
func decisionSummary(decision string, codes []ReasonCodeExplanation) string {
	var head string
	switch decision {
	case "allow":
		head = "Access was allowed."
	case "deny":
		head = "Access was denied."
	case "require_reauthentication":
		head = "Re-authentication is required."
	case "require_human_approval":
		head = "Human approval is required."
	case "require_workload_attestation":
		head = "Workload attestation is required."
	default:
		head = "Decision: " + decision + "."
	}
	if salient, ok := mostSalientCode(codes); ok {
		head += " Primary factor: " + salient.EN
		if strings.TrimSpace(salient.Remediation) != "" {
			head += " Remediation: " + salient.Remediation
		}
	}
	return head
}

func mostSalientCode(codes []ReasonCodeExplanation) (ReasonCodeExplanation, bool) {
	for _, sev := range []string{"critical", "warning"} {
		for _, c := range codes {
			// Skip the generic "policy_matched" so the salient factor is the meaningful one.
			if c.Code == "policy_matched" {
				continue
			}
			if c.Severity == sev {
				return c, true
			}
		}
	}
	return ReasonCodeExplanation{}, false
}

// AiOpsDecisionExplanation fetches a tenant-scoped decision and explains it. Returns ok=false when the
// decision is unknown for the tenant (the caller maps that to 404).
func AiOpsDecisionExplanation(decisionStore DecisionGetter, tenantID, decisionID string, now time.Time) (decisionExplanation, bool) {
	tenantID = strings.TrimSpace(tenantID)
	decisionID = strings.TrimSpace(decisionID)
	if decisionStore == nil || tenantID == "" || decisionID == "" {
		return decisionExplanation{}, false
	}
	dec, ok := decisionStore.Get(decisionID)
	if !ok || dec.TenantID != tenantID {
		return decisionExplanation{}, false
	}
	return ExplainDecisionRecord(dec, now.UTC().Format(time.RFC3339)), true
}
