package model

type Policy struct {
	ID         string         `json:"id"`
	TenantID   string         `json:"tenant_id"`
	Name       string         `json:"name"`
	Priority   int            `json:"priority"`
	Conditions map[string]any `json:"conditions"`
	Action     PolicyAction   `json:"action"`
	// DLP, when set, makes this egress rule ALSO inspect the decrypted body/files for the listed identifiers
	// and apply OnMatch — DLP configured as an option ON the rule (the rule's own conditions are the selector).
	// The evaluator surfaces a dlp_inspect directive when the rule matches AND the flow is intercepted. nil =
	// no DLP on this rule.
	DLP *DLPSpec `json:"dlp,omitempty"`
	// Log opts this rule's matched traffic into the access log (policy-driven access logging). nil = use the
	// default (log classified AI + policy actions, drop routine allows); true = always log matched traffic;
	// false = never log it (a deny/step-up is still logged — security actions are not suppressible). See
	// docs/policy_driven_access_logging_design.md.
	Log                          *bool          `json:"log,omitempty"`
	RequiredTokenBinding         bool           `json:"required_token_binding"`
	RequiredHumanApproval        bool           `json:"required_human_approval"`
	RequiredWorkloadAttestation  bool           `json:"required_workload_attestation"`
	BreakGlassPolicy             bool           `json:"break_glass_policy"`
	BreakGlassIdentityID         *string        `json:"break_glass_identity_id"`
	BreakGlassMaxSessionSeconds  *int           `json:"break_glass_max_session_seconds"`
	BreakGlassStrongAuthRequired bool           `json:"break_glass_strong_auth_required"`
	BreakGlassAuditRequired      bool           `json:"break_glass_audit_required"`
	AllowedTaskPurposes          []string       `json:"allowed_task_purposes"`
	AllowedToolIDs               []string       `json:"allowed_tool_ids"`
	AllowedToolActions           []string       `json:"allowed_tool_actions"`
	AllowedContextScopeIDs       []string       `json:"allowed_context_scope_ids"`
	AllowedMemoryScopeIDs        []string       `json:"allowed_memory_scope_ids"`
	AllowedDataClassifications   []string       `json:"allowed_data_classifications"`
	InspectionProfileID          *string        `json:"inspection_profile_id"`
	ServiceFamily                *string        `json:"service_family"`
	ConnectionInitiator          *string        `json:"connection_initiator"`
	SourceRole                   *string        `json:"source_role"`
	DestinationRole              *string        `json:"destination_role"`
	Status                       string         `json:"status"`
	CreatedBy                    *string        `json:"created_by"`
	UpdatedAt                    *string        `json:"updated_at"`
	Metadata                     map[string]any `json:"metadata"`
}

type PolicyAction struct {
	Decision string `json:"decision"`
}

type PolicyBundle struct {
	ID                        string                     `json:"id"`
	TenantID                  string                     `json:"tenant_id"`
	Version                   string                     `json:"version"`
	PolicySchemaVersion       string                     `json:"policy_schema_version"`
	Checksum                  string                     `json:"checksum"`
	Signature                 string                     `json:"signature"`
	SigningKeyID              string                     `json:"signing_key_id"`
	TargetScope               TargetScope                `json:"target_scope"`
	PolicyIDs                 []string                   `json:"policy_ids"`
	CompiledPolicyRef         string                     `json:"compiled_policy_ref"`
	BundleType                string                     `json:"bundle_type"`
	ExpiresAt                 string                     `json:"expires_at"`
	RevokedAt                 *string                    `json:"revoked_at"`
	CreatedAt                 string                     `json:"created_at"`
	ActivatedAt               *string                    `json:"activated_at"`
	Status                    string                     `json:"status"`
	SaaSCatalog               []SaaSCatalogEntry         `json:"saas_catalog,omitempty"`
	SWGTenantRestrictionRules []SWGTenantRestrictionRule `json:"swg_tenant_restriction_rules,omitempty"`
	DLPRules                  []DLPRule                  `json:"dlp_rules,omitempty"`
	SWGTLSBypassRules         []SWGTLSBypassRule         `json:"swg_tls_bypass_rules,omitempty"`
	TenantRootCAs             []TenantRootCA             `json:"tenant_root_cas,omitempty"`
	TrustProfiles             []TrustProfile             `json:"trust_profiles,omitempty"`
	InspectionProfiles        []InspectionProfile        `json:"inspection_profiles,omitempty"`
	Metadata                  map[string]any             `json:"metadata"`
}

type SaaSCatalogEntry struct {
	TenantID          string   `json:"tenant_id"`
	SaaSApplicationID string   `json:"saas_application_id"`
	Name              string   `json:"name"`
	Provider          string   `json:"provider"`
	Category          string   `json:"category"`
	RiskTier          string   `json:"risk_tier"`
	DomainPatterns    []string `json:"domain_patterns"`
	SNIPatterns       []string `json:"sni_patterns"`
	Tags              []string `json:"tags"`
	// AIService marks a generative-AI service; AIGovernance is the org classification
	// (approved|tolerated|prohibited) surfaced in the AI usage report. Empty AIGovernance
	// falls back to a built-in default for known AI services.
	AIService    bool   `json:"ai_service,omitempty"`
	AIGovernance string `json:"ai_governance,omitempty"`
	// IdentityRule is reference data (like AIService: carried here, ignored by the OSS decision engine, read only by
	// the proprietary edge) describing WHERE this service exposes the signed-in user's email and display name. nil =
	// use the built-in code default. See docs/ai_identity_attribution_ui_design.md.
	IdentityRule *SaaSIdentityRule `json:"identity_rule,omitempty"`
}

// SaaSIdentitySource is one place to read an identity field from a decrypted request: a source (bearer | cookie) +
// a JWT claim. For cookie sources, cookies whose name contains a SkipCookiePatterns entry are ignored ("anon").
type SaaSIdentitySource struct {
	Source             string   `json:"source"`
	Claim              string   `json:"claim"`
	SkipCookiePatterns []string `json:"skip_cookie_patterns,omitempty"`
}

// SaaSIdentityRule fixes, per service, where email and the display name are read. Either list empty = the service
// does not expose that field. Within a list, the first source that yields a value wins.
type SaaSIdentityRule struct {
	EmailFrom []SaaSIdentitySource `json:"email_from"`
	NameFrom  []SaaSIdentitySource `json:"name_from"`
}

type SaaSContext struct {
	SaaSApplicationID string `json:"saas_application_id"`
	Name              string `json:"name"`
	Provider          string `json:"provider"`
	Category          string `json:"category"`
	RiskTier          string `json:"risk_tier"`
	MatchedDomain     string `json:"matched_domain"`
	MatchedPattern    string `json:"matched_pattern"`
	MatchType         string `json:"match_type"`
}

type SWGTenantRestrictionRule struct {
	ID                string         `json:"id"`
	TenantID          string         `json:"tenant_id"`
	SaaSApplicationID string         `json:"saas_application_id"`
	Provider          string         `json:"provider"`
	HeaderName        string         `json:"header_name"`
	HeaderValueRef    string         `json:"header_value_ref"`
	HeaderValueKind   string         `json:"header_value_kind"`
	EnforcementMode   string         `json:"enforcement_mode"`
	Status            string         `json:"status"`
	Metadata          map[string]any `json:"metadata"`
}

// DLPSpec is the DLP configuration carried by an egress policy rule (Policy.DLP): which identifiers to detect
// and what to do on a match. No selector — the policy rule's own conditions select the traffic.
type DLPSpec struct {
	Identifiers []string `json:"identifiers"`
	MinCount    int      `json:"min_count,omitempty"`
	OnMatch     string   `json:"on_match"` // observe | block | authenticate
	// InstanceScope binds the action to the destination instance class (the sovereign "here not there"): "" / "any"
	// everywhere, "corporate" only to the tenant's verified corporate instance, "personal" only to a confirmed
	// non-corporate account. See DLPRule.InstanceScope.
	InstanceScope string `json:"instance_scope,omitempty"`
	// PolicyID references a reusable named DLP Policy object (see DLPPolicyObject). When set, the egress rule
	// inherits that policy's detectors + action + instance scope + device-risk conditions; the inline fields
	// above are ignored. This is the recommended model (define once, select on many rules).
	PolicyID string `json:"policy_id,omitempty"`
}

// DLPDeviceRiskCondition is one composite rule that raises a DEVICE's risk from its recent DLP detections. It is
// an AND of the set signals — a raw count is meaningless because false positives dominate, so a device is only
// flagged when its detections are diverse AND concentrated AND bursty enough to be real exfiltration, not routine
// FP noise. A zero field means "no constraint on that signal".
type DLPDeviceRiskCondition struct {
	MinCount         int    `json:"min_count"`                   // at least N detections in the window
	MinDistinctTypes int    `json:"min_distinct_types"`          // at least K distinct confidential-data types (strongest FP filter)
	SameDestination  bool   `json:"same_destination"`            // all detections to ONE destination (single-place exfil)
	WindowSeconds    int    `json:"window_seconds"`              // the sliding window (burst detection)
	DestinationClass string `json:"destination_class,omitempty"` // "" / "any" | "personal" (only count personal/outside-org)
	Severity         string `json:"severity"`                    // risk severity to set (e.g. "high")
}

// DLPPolicyObject is a reusable, NAMED DLP policy: detectors (identifiers from the Sensitive-Data Library) + an
// action + instance scope + optional device-risk conditions. Egress rules SELECT it by id (a rule's
// DLPSpec.PolicyID) rather than repeating inline config, so it is defined once and applied to many rules. It has
// no traffic selector — the referencing egress rule supplies the where/who.
type DLPPolicyObject struct {
	ID            string                   `json:"id"`
	TenantID      string                   `json:"tenant_id"`
	Name          string                   `json:"name"`
	Identifiers   []string                 `json:"identifiers"`
	MinCount      int                      `json:"min_count,omitempty"`
	OnMatch       string                   `json:"on_match"` // observe | warn | block | authenticate
	InstanceScope string                   `json:"instance_scope,omitempty"`
	DeviceRisk    []DLPDeviceRiskCondition `json:"device_risk,omitempty"`
	Status        string                   `json:"status"`
	Metadata      map[string]any           `json:"metadata,omitempty"`
}

// DLPRule ties DLP inspection to an egress destination using the same selector dimensions as tenant
// restriction (SaaSApplicationID / provider). When a matching flow is INTERCEPTED (decrypt-all; a
// no-decrypt/bypass flow has no plaintext to inspect), the evaluator surfaces a dlp_inspect directive so the
// egress handler scans the decrypted body/files for the listed identifiers and applies OnMatch. DLP is thus an
// option ON an egress rule, not a separate policy. Identifiers/OnMatch are strings here (model is the leaf
// package); the handler maps them to the dlp engine's types.
type DLPRule struct {
	ID                string   `json:"id"`
	TenantID          string   `json:"tenant_id"`
	SaaSApplicationID string   `json:"saas_application_id,omitempty"`
	Provider          string   `json:"provider,omitempty"`
	Identifiers       []string `json:"identifiers"`
	MinCount          int      `json:"min_count,omitempty"`
	OnMatch           string   `json:"on_match"` // observe | block | authenticate
	// InstanceScope binds the rule to the destination INSTANCE class (the sovereign "here not there"): "" / "any"
	// applies everywhere (default), "corporate" applies only when the signed-in account is one of the tenant's
	// verified corporate domains, "personal" applies only when it is confidently NOT (a non-corporate account).
	// The class is derived from the account the substrate already extracts; when it can't be determined a scoped
	// rule does not fire (never over-blocks an unclassifiable destination).
	InstanceScope string         `json:"instance_scope,omitempty"`
	Status        string         `json:"status"`
	Metadata      map[string]any `json:"metadata,omitempty"`
}

type SWGTLSBypassRule struct {
	ID                string         `json:"id"`
	TenantID          string         `json:"tenant_id"`
	Name              string         `json:"name"`
	MatchType         string         `json:"match_type"`
	Pattern           string         `json:"pattern"`
	SaaSApplicationID string         `json:"saas_application_id"`
	Category          string         `json:"category"`
	Reason            string         `json:"reason"`
	Status            string         `json:"status"`
	Metadata          map[string]any `json:"metadata"`
}

type TenantRootCA struct {
	ID               string         `json:"id"`
	TenantID         string         `json:"tenant_id"`
	Name             string         `json:"name"`
	Status           string         `json:"status"`
	DistributionMode string         `json:"distribution_mode"`
	TrustStoreTarget string         `json:"trust_store_target"`
	CertificateRef   *string        `json:"certificate_ref"`
	PrivateKeyStatus string         `json:"private_key_status"`
	CreatedAt        *string        `json:"created_at"`
	UpdatedAt        *string        `json:"updated_at"`
	Metadata         map[string]any `json:"metadata"`
}

type TrustProfile struct {
	ID                       string         `json:"id"`
	TenantID                 string         `json:"tenant_id"`
	Name                     string         `json:"name"`
	TenantRootCAID           string         `json:"tenant_root_ca_id"`
	TrustStoreState          string         `json:"trust_store_state"`
	CertificatePinningPolicy string         `json:"certificate_pinning_policy"`
	BypassPolicyID           *string        `json:"bypass_policy_id"`
	Status                   string         `json:"status"`
	Metadata                 map[string]any `json:"metadata"`
}

type InspectionProfile struct {
	ID                         string         `json:"id"`
	TenantID                   string         `json:"tenant_id"`
	Name                       string         `json:"name"`
	InspectionMode             string         `json:"inspection_mode"`
	TrustProfileID             string         `json:"trust_profile_id"`
	TenantRootCAID             string         `json:"tenant_root_ca_id"`
	QUICPolicyMode             string         `json:"quic_policy_mode"`
	QUICPolicyAction           string         `json:"quic_policy_action"`
	PayloadPolicy              string         `json:"payload_policy"`
	CertificateIssuanceMode    string         `json:"certificate_issuance_mode"`
	TLSInterceptionEnabled     bool           `json:"tls_interception_enabled"`
	NetworkExtensionDependency string         `json:"network_extension_dependency"`
	Status                     string         `json:"status"`
	Metadata                   map[string]any `json:"metadata"`
}

type TargetScope struct {
	TargetType       string  `json:"target_type"`
	EdgeRegionID     *string `json:"edge_region_id"`
	EdgeClusterID    *string `json:"edge_cluster_id"`
	DeviceGroupID    *string `json:"device_group_id"`
	ConnectorGroupID *string `json:"connector_group_id"`
}

type ConnectorRegistration struct {
	ID               string   `json:"id"`
	TenantID         string   `json:"tenant_id"`
	ConnectorGroupID string   `json:"connector_group_id"`
	Name             string   `json:"name"`
	EdgeRegionID     string   `json:"edge_region_id"`
	EdgeClusterID    string   `json:"edge_cluster_id"`
	ApplicationIDs   []string `json:"application_ids"`
	PrivateBaseURL   string   `json:"private_base_url"`
	Status           string   `json:"status"`
	RegisteredAt     string   `json:"registered_at"`
	LastHeartbeatAt  string   `json:"last_heartbeat_at"`
	// AttachedRegionID is where this connector's tunnel LAST TERMINATED, as observed by the Edge that
	// terminated it — not what the connector declared when it first registered.
	//
	// ★★★ EdgeRegionID IS WHERE IT STARTED; THIS IS WHERE IT IS (2026-08-26). A connector with more than one
	// door fails over when its home region stops answering, and the registration written at enrolment goes on
	// naming the region it left. Every Edge then routes to that region, the far side answers "fronts this
	// destination but has no live tunnel", and the private estate behind the connector is unreachable while the
	// connector itself is healthy one region away. The node holding the tunnel is the only party that knows the
	// truth, so it is the one that reports it.
	//
	// ★ RUNTIME, NOT ROUTE. It must never count as a catalog change: a connector that flaps between regions
	// would otherwise move the deployment's config generation on every reconnect, and a generation that never
	// settles closes every gate that waits for one. See connectorCatalogChanged.
	AttachedRegionID string         `json:"attached_region_id,omitempty"`
	Metadata         map[string]any `json:"metadata"`
	// ReachableRoutes is the destination set this connector fronts (connector_network_routing_design.md): the
	// route LAYER, kept separate from policy (which still authorizes every flow). FQDNDomains is the first slice;
	// CIDRs + Namespace (overlapping private ranges across sites) are a later slice.
	ReachableRoutes ConnectorReachableRoutes `json:"reachable_routes,omitempty"`
}

// ConnectorReachableRoutes declares which destinations a connector can reach. Matching prefers NAME (a DNS name
// is unique even when private IPs overlap across sites); CIDRs + Namespace cover IP-addressed resources and the
// overlap scoping, resolved by a later slice.
type ConnectorReachableRoutes struct {
	FQDNDomains []string `json:"fqdn_domains,omitempty"` // DNS domains fronted, incl. "*.suffix" wildcards
	CIDRs       []string `json:"cidrs,omitempty"`        // later slice — needs Namespace scoping
	Namespace   string   `json:"namespace,omitempty"`    // site / virtual-network id for overlapping ranges
}

type ConnectorHeartbeat struct {
	ID                  string         `json:"id"`
	TenantID            string         `json:"tenant_id"`
	Status              string         `json:"status"`
	PolicyBundleID      string         `json:"policy_bundle_id"`
	PolicyBundleVersion string         `json:"policy_bundle_version"`
	Timestamp           string         `json:"timestamp"`
	Metadata            map[string]any `json:"metadata"`
	// Version and UptimeSeconds are optional runtime metrics a connector may report. They are additive
	// (omitempty): an older connector that omits them leaves the surfaced value empty (UI shows "unknown").
	// Neither carries a secret; both are merged into the registration metadata for admin-safe display.
	Version       string `json:"version,omitempty"`
	UptimeSeconds int64  `json:"uptime_seconds,omitempty"`
	// ReachableRoutes lets a connector re-report the subnets it can see on its ongoing heartbeat, so the Edge's
	// DISCOVERY list stays current without a reconnect (non-authoritative — routing is CP-configured). Optional
	// (pointer, omitempty): an older connector that omits it leaves the registered routes unchanged.
	ReachableRoutes *ConnectorReachableRoutes `json:"reachable_routes,omitempty"`
}

type AuthenticationEvent struct {
	ID            string         `json:"id"`
	TenantID      string         `json:"tenant_id"`
	UserID        string         `json:"user_id"`
	SubjectUserID *string        `json:"subject_user_id"`
	SessionID     string         `json:"session_id"`
	IDPID         string         `json:"idp_id"`
	Method        string         `json:"method"`
	AMR           []string       `json:"amr"`
	ACR           *string        `json:"acr"`
	MFAState      string         `json:"mfa_state"`
	AuthTime      string         `json:"auth_time"`
	ExpiresAt     *string        `json:"expires_at"`
	SourceIP      *string        `json:"source_ip"`
	DeviceID      *string        `json:"device_id"`
	Result        string         `json:"result"`
	Timestamp     string         `json:"timestamp"`
	Metadata      map[string]any `json:"metadata"`
}

type Session struct {
	ID                    string         `json:"id"`
	TenantID              string         `json:"tenant_id"`
	UserID                string         `json:"user_id"`
	SubjectUserID         *string        `json:"subject_user_id"`
	DeviceID              *string        `json:"device_id"`
	AuthenticationEventID string         `json:"authentication_event_id"`
	PolicyBundleID        string         `json:"policy_bundle_id"`
	CreatedAt             string         `json:"created_at"`
	ExpiresAt             string         `json:"expires_at"`
	LastActiveAt          string         `json:"last_active_at"`
	Status                string         `json:"status"`
	Metadata              map[string]any `json:"metadata"`
}

type Device struct {
	ID                  string `json:"id"`
	TenantID            string `json:"tenant_id"`
	UserID              string `json:"user_id"`
	Hostname            string `json:"hostname"`
	OS                  string `json:"os"`
	OSVersion           string `json:"os_version"`
	AgentVersion        string `json:"agent_version"`
	DeviceTrustLevel    string `json:"device_trust_level"`
	PolicyBundleID      string `json:"policy_bundle_id"`
	PolicyBundleVersion string `json:"policy_bundle_version"`
	Status              string `json:"status"`
	RegisteredAt        string `json:"registered_at"`
	LastSeenAt          string `json:"last_seen_at"`
	// Posture holds the last real OS posture signals reported by the device agent. The
	// Edge DERIVES DeviceTrustLevel from these — a client-declared trust string is not trusted when
	// signals are present, so a compromised endpoint cannot simply claim it is "managed".
	Posture  *DevicePostureSignals `json:"posture,omitempty"`
	Metadata map[string]any        `json:"metadata"`
}

// DevicePostureSignals are the real OS posture signals a device agent collects and reports in a
// heartbeat. Bools are pointers so "not reported" (nil) is distinct from "false": the
// Edge treats an unknown required signal as non-compliant.
type DevicePostureSignals struct {
	DiskEncryptionEnabled *bool `json:"disk_encryption_enabled,omitempty"`
	FirewallEnabled       *bool `json:"firewall_enabled,omitempty"`
	// EnforcementAgentHealthy (W-3, tamper-evident): the endpoint's own NE/WFP enforcement agent reports
	// whether it is healthy + actively enforcing. A tamper attempt (service-stop/unload/config-clobber that
	// a watchdog or the agent's pre-disable integrity check catches) sets it false; missing => unknown =>
	// fail-closed (non-compliant). Degrading trust on tamper triggers the existing posture-regression ->
	// grant revocation path (/E5). Complements W-2 (full silence) — see w3 design.
	EnforcementAgentHealthy *bool  `json:"enforcement_agent_healthy,omitempty"`
	OSVersion               string `json:"os_version,omitempty"`
	CollectedAt             string `json:"collected_at,omitempty"`
	Source                  string `json:"source,omitempty"` // e.g. "macos_collector"
}

// LegacyException is an explicit, governed allow for an otherwise default-deny
// server-initiated (server->client) connection. Required governance fields: business_owner,
// expires_at. Matching is by source_server / device_group / service_family / protocol / port.
type LegacyException struct {
	ID                string `json:"id"`
	TenantID          string `json:"tenant_id"`
	BusinessOwner     string `json:"business_owner"`
	ExpiresAt         string `json:"expires_at"`
	SourceServer      string `json:"source_server"`
	DeviceGroup       string `json:"device_group"`
	ServiceFamily     string `json:"service_family"`
	Protocol          string `json:"protocol"`
	Port              int    `json:"port"`
	MaxSessionSeconds int    `json:"max_session_seconds"`
	ApprovalRequired  bool   `json:"approval_required"`
	Mode              string `json:"mode"`   // observe | warn | deny | allow
	Status            string `json:"status"` // active | disabled
}

// VLANObject classifies a network segment for VLAN boundary control. Class is one of
// managed_endpoint | unmanaged_endpoint | server | management. CIDRs are the segment's subnets.
type VLANObject struct {
	ID       string         `json:"id"`
	TenantID string         `json:"tenant_id"`
	Name     string         `json:"name"`
	Class    string         `json:"class"`
	CIDRs    []string       `json:"cidrs"`
	Metadata map[string]any `json:"metadata,omitempty"`
}

// VLANBoundaryPolicy controls inter-VLAN traffic by source/destination class + service
// family + ports, with mode observe|warn|deny. Exported to existing Firewall/L3 as concrete rules.
type VLANBoundaryPolicy struct {
	ID            string `json:"id"`
	TenantID      string `json:"tenant_id"`
	SourceClass   string `json:"source_class"`
	DestClass     string `json:"dest_class"`
	ServiceFamily string `json:"service_family"`
	Ports         []int  `json:"ports"`
	Mode          string `json:"mode"` // observe | warn | deny
	Status        string `json:"status"`
}

// RiskSignal is a Risk State input. MVP sources: Manual High Risk Marking, IdP Risk, Agent
// Tamper Signal, Authentication Anomaly, Abnormal Access Attempt. The Edge folds a signal into the
// entity's risk state, which decisions read (risk_state_severity / admin_high_risk policy conditions)
// and which accelerates access reduction (high risk revokes standing grants). Non-secret enums only;
// RawEvidenceReference is a pointer/URI, never raw evidence.
type RiskSignal struct {
	Source               string `json:"source"`      // manual_high_risk | idp_risk | agent_tamper | auth_anomaly | abnormal_access | <connector>
	EntityType           string `json:"entity_type"` // device | user
	EntityID             string `json:"entity_id"`
	Severity             string `json:"severity"`   // none | low | medium | high | critical
	Confidence           string `json:"confidence"` // low | medium | high
	Timestamp            string `json:"timestamp"`
	SuggestedAction      string `json:"suggested_action"`       // observe | reauthenticate | revoke | block | isolate
	RawEvidenceReference string `json:"raw_evidence_reference"` // URI/ID pointer, never raw evidence
}

type DeviceHeartbeat struct {
	ID                  string                `json:"id"`
	TenantID            string                `json:"tenant_id"`
	AgentVersion        string                `json:"agent_version"`
	DeviceTrustLevel    string                `json:"device_trust_level"`
	PolicyBundleID      string                `json:"policy_bundle_id"`
	PolicyBundleVersion string                `json:"policy_bundle_version"`
	Status              string                `json:"status"`
	Timestamp           string                `json:"timestamp"`
	Posture             *DevicePostureSignals `json:"posture,omitempty"`
	Metadata            map[string]any        `json:"metadata"`
}

type AgentUpdateEvent struct {
	ID                  string         `json:"id"`
	TenantID            string         `json:"tenant_id"`
	DeviceID            string         `json:"device_id"`
	UserID              string         `json:"user_id"`
	CurrentAgentVersion string         `json:"current_agent_version"`
	TargetAgentVersion  string         `json:"target_agent_version"`
	ReleaseChannel      string         `json:"release_channel"`
	UpdateStatus        string         `json:"update_status"`
	UpdateSource        string         `json:"update_source"`
	PackageChecksum     *string        `json:"package_checksum"`
	PackageSignature    *string        `json:"package_signature"`
	FailureReason       *string        `json:"failure_reason"`
	Timestamp           string         `json:"timestamp"`
	Metadata            map[string]any `json:"metadata"`
}

type AgentStatus struct {
	DeviceID            string         `json:"device_id"`
	TenantID            string         `json:"tenant_id"`
	PolicyBundleID      string         `json:"policy_bundle_id"`
	PolicyBundleVersion string         `json:"policy_bundle_version"`
	BundleSource        string         `json:"bundle_source"`
	DeviceTrustLevel    string         `json:"device_trust_level"`
	Status              string         `json:"status"`
	Timestamp           string         `json:"timestamp"`
	Metadata            map[string]any `json:"metadata"`
}

type HumanApprovalEvent struct {
	ID                     string         `json:"id"`
	TenantID               string         `json:"tenant_id"`
	ApprovalSource         string         `json:"approval_source"`
	ApproverUserID         *string        `json:"approver_user_id"`
	SubjectUserID          *string        `json:"subject_user_id"`
	ActorNHIID             *string        `json:"actor_nhi_id"`
	DelegatedAccessGrantID *string        `json:"delegated_access_grant_id"`
	AgentTaskSessionID     *string        `json:"agent_task_session_id"`
	ApplicationID          *string        `json:"application_id"`
	Audience               *string        `json:"audience"`
	Resource               *string        `json:"resource"`
	ActionType             *string        `json:"action_type"`
	TaskID                 *string        `json:"task_id"`
	RunID                  *string        `json:"run_id"`
	RequestedScopes        []string       `json:"requested_scopes"`
	Reason                 *string        `json:"reason"`
	ApprovalResult         string         `json:"approval_result"`
	EvidenceLink           *string        `json:"evidence_link"`
	ActivatedAt            *string        `json:"activated_at"`
	ExpiresAt              *string        `json:"expires_at"`
	CreatedAt              string         `json:"created_at"`
	Metadata               map[string]any `json:"metadata"`
}

type DelegatedAccessGrant struct {
	ID                   string         `json:"id"`
	TenantID             string         `json:"tenant_id"`
	SubjectUserID        string         `json:"subject_user_id"`
	ActorNHIID           string         `json:"actor_nhi_id"`
	DeviceID             *string        `json:"device_id"`
	ApplicationID        *string        `json:"application_id"`
	Audience             *string        `json:"audience"`
	Resource             *string        `json:"resource"`
	Scopes               []string       `json:"scopes"`
	Purpose              *string        `json:"purpose"`
	TaskID               *string        `json:"task_id"`
	RunID                *string        `json:"run_id"`
	ToolIDs              []string       `json:"tool_ids"`
	ApprovalEventID      *string        `json:"approval_event_id"`
	TokenBindingRequired bool           `json:"token_binding_required"`
	MaxSessionDuration   *int           `json:"max_session_duration"`
	ExpiresAt            string         `json:"expires_at"`
	CreatedAt            *string        `json:"created_at"`
	RevokedAt            *string        `json:"revoked_at"`
	RevocationReason     *string        `json:"revocation_reason"`
	Status               string         `json:"status"`
	Metadata             map[string]any `json:"metadata"`
}

type NonHumanIdentity struct {
	ID                    string         `json:"id"`
	TenantID              string         `json:"tenant_id"`
	Name                  string         `json:"name"`
	NHIType               string         `json:"nhi_type"`
	OwnerUserID           string         `json:"owner_user_id"`
	TrustDomain           *string        `json:"trust_domain"`
	Issuer                *string        `json:"issuer"`
	Subject               *string        `json:"subject"`
	CredentialType        *string        `json:"credential_type"`
	AllowedApplicationIDs []string       `json:"allowed_application_ids"`
	AllowedScopes         []string       `json:"allowed_scopes"`
	AllowlistEnforced     bool           `json:"allowlist_enforced"`
	LastUsedAt            *string        `json:"last_used_at"`
	ExpiresAt             *string        `json:"expires_at"`
	Status                string         `json:"status"`
	Metadata              map[string]any `json:"metadata"`
}

type HumanIdentity struct {
	ID          string         `json:"id"`
	TenantID    string         `json:"tenant_id"`
	Subject     string         `json:"subject"`
	Email       *string        `json:"email"`
	DisplayName *string        `json:"display_name"`
	Source      string         `json:"source"`
	Department  *string        `json:"department"`
	LastSeenAt  *string        `json:"last_seen_at"`
	ExpiresAt   *string        `json:"expires_at"`
	Status      string         `json:"status"`
	Metadata    map[string]any `json:"metadata"`
}

type AgentTool struct {
	ID                         string         `json:"id"`
	TenantID                   string         `json:"tenant_id"`
	Name                       string         `json:"name"`
	Description                *string        `json:"description"`
	OwnerUserID                *string        `json:"owner_user_id"`
	Publisher                  *string        `json:"publisher"`
	Version                    *string        `json:"version"`
	SignatureState             *string        `json:"signature_state"`
	PermissionProfile          *string        `json:"permission_profile"`
	ActionType                 string         `json:"action_type"`
	MCPServerID                *string        `json:"mcp_server_id"`
	AllowedApplicationIDs      []string       `json:"allowed_application_ids"`
	AllowedDestinations        []string       `json:"allowed_destinations"`
	AllowedDataClassifications []string       `json:"allowed_data_classifications"`
	HumanApprovalRequired      bool           `json:"human_approval_required"`
	RuntimeEnvironmentID       *string        `json:"runtime_environment_id"`
	LastUsedAt                 *string        `json:"last_used_at"`
	Status                     string         `json:"status"`
	Metadata                   map[string]any `json:"metadata"`
}

type MCPServer struct {
	ID                     string         `json:"id"`
	TenantID               string         `json:"tenant_id"`
	Name                   string         `json:"name"`
	OwnerUserID            *string        `json:"owner_user_id"`
	Publisher              *string        `json:"publisher"`
	Version                *string        `json:"version"`
	SupportedTransport     *string        `json:"supported_transport"`
	ResourceURI            string         `json:"resource_uri"`
	Audience               string         `json:"audience"`
	AuthorizationServerRef *string        `json:"authorization_server_ref"`
	AllowedToolIDs         []string       `json:"allowed_tool_ids"`
	TokenBindingState      *string        `json:"token_binding_state"`
	TokenPassthroughPolicy *string        `json:"token_passthrough_policy"`
	NetworkDestination     *string        `json:"network_destination"`
	DataClassification     *string        `json:"data_classification"`
	Status                 string         `json:"status"`
	Metadata               map[string]any `json:"metadata"`
}

type ToolCallEvent struct {
	ID                     string         `json:"id"`
	TenantID               string         `json:"tenant_id"`
	AgentTaskSessionID     *string        `json:"agent_task_session_id"`
	ActorNHIID             string         `json:"actor_nhi_id"`
	SubjectUserID          *string        `json:"subject_user_id"`
	DelegatedAccessGrantID *string        `json:"delegated_access_grant_id"`
	TaskID                 *string        `json:"task_id"`
	RunID                  *string        `json:"run_id"`
	ToolID                 string         `json:"tool_id"`
	MCPServerID            *string        `json:"mcp_server_id"`
	RuntimeEnvironmentID   *string        `json:"runtime_environment_id"`
	ActionType             string         `json:"action_type"`
	ApplicationID          *string        `json:"application_id"`
	ContextBoundaryID      *string        `json:"context_boundary_id"`
	DataClassification     *string        `json:"data_classification"`
	Destination            *string        `json:"destination"`
	TokenAudience          *string        `json:"token_audience"`
	HumanApprovalEventID   *string        `json:"human_approval_event_id"`
	AccessDecisionID       *string        `json:"access_decision_id"`
	InspectionEventID      *string        `json:"inspection_event_id"`
	PolicyID               *string        `json:"policy_id"`
	Decision               *string        `json:"decision"`
	ResultSummary          *string        `json:"result_summary"`
	ResultSummaryScope     string         `json:"result_summary_scope"`
	Masked                 bool           `json:"masked"`
	PayloadRef             *string        `json:"payload_ref"`
	RetentionPolicy        *string        `json:"retention_policy"`
	Timestamp              string         `json:"timestamp"`
	Status                 *string        `json:"status"`
	Metadata               map[string]any `json:"metadata"`
}

type InspectionEvent struct {
	ID                  string         `json:"id"`
	TenantID            string         `json:"tenant_id"`
	AccessDecisionID    *string        `json:"access_decision_id"`
	ToolCallEventID     *string        `json:"tool_call_event_id"`
	SessionID           *string        `json:"session_id"`
	UserID              *string        `json:"user_id"`
	DeviceID            *string        `json:"device_id"`
	ApplicationID       *string        `json:"application_id"`
	InspectionProfileID *string        `json:"inspection_profile_id"`
	InspectionMode      *string        `json:"inspection_mode"`
	ContentType         *string        `json:"content_type"`
	FindingType         *string        `json:"finding_type"`
	Severity            *string        `json:"severity"`
	PayloadStored       bool           `json:"payload_stored"`
	PayloadRef          *string        `json:"payload_ref"`
	Masked              bool           `json:"masked"`
	RetentionPolicy     *string        `json:"retention_policy"`
	Timestamp           string         `json:"timestamp"`
	Metadata            map[string]any `json:"metadata"`
}

type AgentRolloutPolicy struct {
	DeviceID            string         `json:"device_id"`
	TenantID            string         `json:"tenant_id"`
	CurrentAgentVersion string         `json:"current_agent_version"`
	TargetAgentVersion  string         `json:"target_agent_version"`
	ReleaseChannel      string         `json:"release_channel"`
	UpdateSource        string         `json:"update_source"`
	UpdateRequired      bool           `json:"update_required"`
	Timestamp           string         `json:"timestamp"`
	Metadata            map[string]any `json:"metadata"`
}

type TrustedKeyring struct {
	TenantID string              `json:"tenant_id"`
	Version  string              `json:"version"`
	Keys     []TrustedKeyringKey `json:"keys"`
	Metadata map[string]any      `json:"metadata"`
}

type TrustedKeyringKey struct {
	ID        string         `json:"id"`
	PublicKey string         `json:"public_key"`
	Status    string         `json:"status"`
	CreatedAt *string        `json:"created_at"`
	ExpiresAt *string        `json:"expires_at"`
	Metadata  map[string]any `json:"metadata"`
}

type DecisionRequest struct {
	TenantID                    string   `json:"tenant_id"`
	SessionID                   string   `json:"session_id"`
	AuthenticationEventID       string   `json:"authentication_event_id"`
	UserID                      string   `json:"user_id"`
	SubjectUserID               string   `json:"subject_user_id"`
	UserGroups                  []string `json:"user_groups"`
	ActorType                   string   `json:"actor_type"`
	ActorNHIID                  string   `json:"actor_nhi_id"`
	NHIRiskSeverity             string   `json:"nhi_risk_severity"`              // : Edge-derived risk of the Actor NHI (none|medium|high)
	TransportDeviceIdentity     string   `json:"transport_device_identity"`      // W2: device identity from the verified mTLS transport client cert (authoritative, not client-claimed)
	TransportClientCertVerified bool     `json:"transport_client_cert_verified"` // W2: true when the (T) transport presented a verified device client cert (mTLS)
	DelegatedAccessGrantID      string   `json:"delegated_access_grant_id"`
	AgentTaskSessionID          string   `json:"agent_task_session_id"`
	ToolID                      string   `json:"tool_id"`
	ToolActionType              string   `json:"tool_action_type"`
	ToolPermissionProfile       string   `json:"tool_permission_profile"`
	ToolVersion                 string   `json:"tool_version"`
	ToolSignatureState          string   `json:"tool_signature_state"`
	MCPServerID                 string   `json:"mcp_server_id"`
	MCPResourceURI              string   `json:"mcp_resource_uri"`
	MCPAudience                 string   `json:"mcp_audience"`
	MCPTokenPassthroughPolicy   string   `json:"mcp_token_passthrough_policy"`
	RuntimeEnvironmentID        string   `json:"runtime_environment_id"`
	ContextBoundaryID           string   `json:"context_boundary_id"`
	DataClassification          string   `json:"data_classification"`
	AMR                         []string `json:"amr"`
	ACR                         string   `json:"acr"`
	MFAState                    string   `json:"mfa_state"`
	AuthTime                    string   `json:"auth_time"`
	AuthMethod                  string   `json:"auth_method"`
	// IDPID / Issuer identify WHICH IdP issued the end-user identity, so a policy can require a specific
	// registered IdP (idp_id condition) or match on the token issuer. Populated once the federated-auth broker
	// carries an end-user identity into the decision (today they are empty on device-only steered flows).
	IDPID                  string `json:"idp_id"`
	Issuer                 string `json:"issuer"`
	DeviceID               string `json:"device_id"`
	DeviceTrustLevel       string `json:"device_trust_level"`
	ApplicationID          string `json:"application_id"`
	ApplicationSensitivity string `json:"application_sensitivity"`
	ConnectorID            string `json:"connector_id"`
	SourceIP               string `json:"source_ip"`
	SourcePort             int    `json:"source_port"`
	Destination            string `json:"destination"`
	DestinationIP          string `json:"destination_ip"`
	// DestinationResolvedIP is an address the EDGE resolved for this destination's name, recorded so plane
	// membership can be decided about a host given only as a name.
	//
	// ★ SEPARATE FROM DestinationIP ON PURPOSE (2026-08-14). DestinationIP is what the client asked for, and
	// several decisions read it — destinationAddressScope treats an FQDN as public and a private literal as
	// Default-Deny, so filling DestinationIP with a resolved address would silently move every internal host
	// reached BY NAME from allow+intercept to default-deny. That is a different decision, in the deny
	// direction, and it is not the one being made here.
	//
	// Only the locality classifier reads this. Empty means nothing was resolved, which is not the same as a
	// destination having no address.
	DestinationResolvedIP            string   `json:"destination_resolved_ip,omitempty"`
	DestinationPort                  int      `json:"destination_port"`
	Protocol                         string   `json:"protocol"`
	SteeringMode                     string   `json:"steering_mode"`
	FQDN                             string   `json:"fqdn"`
	SNI                              string   `json:"sni"`
	ServiceFamily                    string   `json:"service_family"`
	SaaSApplicationID                string   `json:"saas_application_id"`
	SaaSName                         string   `json:"saas_name"`
	SaaSProvider                     string   `json:"saas_provider"`
	SaaSCategory                     string   `json:"saas_category"`
	SaaSRiskTier                     string   `json:"saas_risk_tier"`
	SaaSMatchedDomain                string   `json:"saas_matched_domain"`
	SaaSMatchedPattern               string   `json:"saas_matched_pattern"`
	SaaSMatchType                    string   `json:"saas_match_type"`
	InspectionProfileID              string   `json:"inspection_profile_id"`
	InspectionMode                   string   `json:"inspection_mode"`
	TrustProfileID                   string   `json:"trust_profile_id"`
	TenantRootCAID                   string   `json:"tenant_root_ca_id"`
	QUICPolicyMode                   string   `json:"quic_policy_mode"`
	QUICPolicyAction                 string   `json:"quic_policy_action"`
	BreakGlassRequestID              string   `json:"break_glass_request_id"`
	BreakGlassReasonPresent          bool     `json:"break_glass_reason_present"`
	BreakGlassTicketIDPresent        bool     `json:"break_glass_ticket_id_present"`
	ConnectionInitiator              string   `json:"connection_initiator"`
	SourceServer                     string   `json:"source_server"` // : the initiating server's identity for server-initiated flows
	DeviceGroup                      string   `json:"device_group"`  // : destination endpoint's device group
	SourceRole                       string   `json:"source_role"`
	DestinationRole                  string   `json:"destination_role"`
	TokenBindingState                string   `json:"token_binding_state"`
	WorkloadAttestationState         string   `json:"workload_attestation_state"`
	HumanApprovalEventID             string   `json:"human_approval_event_id"`
	HumanApprovalEventTrustState     string   `json:"human_approval_event_trust_state"`
	HumanApprovalEventBindingState   string   `json:"human_approval_event_binding_state"`
	HumanApprovalEventFreshnessState string   `json:"human_approval_event_freshness_state"`
	RiskStateID                      string   `json:"risk_state_id"`
	RiskStateSeverity                string   `json:"risk_state_severity"`
	RiskRecommendedAction            string   `json:"risk_recommended_action"`
	RiskSignalSources                []string `json:"risk_signal_sources"`
	AdminHighRisk                    bool     `json:"admin_high_risk"`
	IDPRiskLevel                     string   `json:"idp_risk_level"`
	AgentTamperSignal                bool     `json:"agent_tamper_signal"`
	AuthenticationAnomaly            bool     `json:"authentication_anomaly"`
}

type AccessDecision struct {
	ID                        string  `json:"id"`
	TenantID                  string  `json:"tenant_id"`
	SessionID                 *string `json:"session_id"`
	AuthenticationEventID     *string `json:"authentication_event_id"`
	UserID                    *string `json:"user_id"`
	SubjectUserID             *string `json:"subject_user_id"`
	ActorType                 string  `json:"actor_type"`
	ActorNHIID                *string `json:"actor_nhi_id"`
	DelegatedAccessGrantID    *string `json:"delegated_access_grant_id"`
	AgentTaskSessionID        *string `json:"agent_task_session_id"`
	ToolID                    *string `json:"tool_id"`
	ToolActionType            *string `json:"tool_action_type"`
	ToolPermissionProfile     *string `json:"tool_permission_profile"`
	ToolVersion               *string `json:"tool_version"`
	ToolSignatureState        *string `json:"tool_signature_state"`
	MCPServerID               *string `json:"mcp_server_id"`
	MCPResourceURI            *string `json:"mcp_resource_uri"`
	MCPAudience               *string `json:"mcp_audience"`
	MCPTokenPassthroughPolicy *string `json:"mcp_token_passthrough_policy"`
	RuntimeEnvironmentID      *string `json:"runtime_environment_id"`
	ContextBoundaryID         *string `json:"context_boundary_id"`
	DataClassification        *string `json:"data_classification"`
	DeviceID                  *string `json:"device_id"`
	ApplicationID             string  `json:"application_id"`
	PolicyID                  string  `json:"policy_id"`
	PolicyBundleID            string  `json:"policy_bundle_id"`
	PolicyBundleVersion       string  `json:"policy_bundle_version"`
	RiskStateID               *string `json:"risk_state_id"`
	SourceIP                  *string `json:"source_ip"`
	SourcePort                *int    `json:"source_port"`
	Destination               *string `json:"destination"`
	DestinationIP             *string `json:"destination_ip"`
	DestinationPort           *int    `json:"destination_port"`
	// Per-request identity of a decrypted HTTP flow: the method + URL path. Under log-all every request to the
	// same host earns a row; without the path those rows are indistinguishable. Path only — the query string is
	// NOT recorded by default (it carries tokens/PII and is unbounded; gate it behind a logging policy).
	RequestMethod            *string          `json:"request_method"`
	RequestPath              *string          `json:"request_path"`
	Protocol                 *string          `json:"protocol"`
	FQDN                     *string          `json:"fqdn"`
	SNI                      *string          `json:"sni"`
	ServiceFamily            *string          `json:"service_family"`
	SaaSContext              *SaaSContext     `json:"saas_context,omitempty"`
	ConnectionInitiator      *string          `json:"connection_initiator"`
	SourceRole               *string          `json:"source_role"`
	DestinationRole          *string          `json:"destination_role"`
	SourceVLANID             *string          `json:"source_vlan_id"`
	DestinationVLANID        *string          `json:"destination_vlan_id"`
	MatchedConditions        []string         `json:"matched_conditions"`
	TokenBindingState        *string          `json:"token_binding_state"`
	WorkloadAttestationState *string          `json:"workload_attestation_state"`
	HumanApprovalEventID     *string          `json:"human_approval_event_id"`
	Decision                 string           `json:"decision"`
	Reason                   *string          `json:"reason"`
	ReasonCodes              []string         `json:"reason_codes"`
	Actions                  []DecisionAction `json:"actions"`
	Bypass                   bool             `json:"bypass"`
	InspectionProfileID      *string          `json:"inspection_profile_id"`
	InspectionMode           *string          `json:"inspection_mode"`
	InspectionRouteCategory  *string          `json:"inspection_route_category"`
	InspectionExecutionScope *string          `json:"inspection_execution_scope"`
	EdgeRegionID             *string          `json:"edge_region_id"`
	EdgeClusterID            *string          `json:"edge_cluster_id"`
	ConnectorID              *string          `json:"connector_id"`
	CacheStatus              string           `json:"cache_status"`
	TTLSeconds               int              `json:"ttl_seconds"`
	Timestamp                string           `json:"timestamp"`
	Metadata                 map[string]any   `json:"metadata"`
}

type DecisionAction struct {
	Type       string         `json:"type"`
	Target     *string        `json:"target"`
	TTLSeconds *int           `json:"ttl_seconds"`
	Metadata   map[string]any `json:"metadata"`
}

type AccessLog struct {
	ID       string `json:"id"`
	TenantID string `json:"tenant_id"`
	// ConfigGenerationID resolves against the config_generations stream to the tenant's inspection/trust/CA
	// config AS IT WAS at decision time. It replaces ~20 config keys that were restated on every record.
	// Resolve through this, not through the live profile: the profile is mutable, the generation row is not.
	ConfigGenerationID     string   `json:"config_generation_id,omitempty"`
	AccessDecisionID       string   `json:"access_decision_id"`
	SessionID              *string  `json:"session_id"`
	UserID                 *string  `json:"user_id"`
	SubjectUserID          *string  `json:"subject_user_id"`
	ActorType              string   `json:"actor_type"`
	ActorNHIID             *string  `json:"actor_nhi_id"`
	DelegatedAccessGrantID *string  `json:"delegated_access_grant_id"`
	HumanApprovalEventID   *string  `json:"human_approval_event_id"`
	AgentTaskSessionID     *string  `json:"agent_task_session_id"`
	ToolID                 *string  `json:"tool_id"`
	ToolActionType         *string  `json:"tool_action_type"`
	MCPServerID            *string  `json:"mcp_server_id"`
	RuntimeEnvironmentID   *string  `json:"runtime_environment_id"`
	DeviceID               *string  `json:"device_id"`
	ApplicationID          *string  `json:"application_id"`
	SourceIP               *string  `json:"source_ip"`
	Destination            *string  `json:"destination"`
	RequestMethod          *string  `json:"request_method"`
	RequestPath            *string  `json:"request_path"`
	ServiceFamily          *string  `json:"service_family"`
	Decision               string   `json:"decision"`
	Reason                 *string  `json:"reason"`
	ReasonCodes            []string `json:"reason_codes"`
	// Policy attribution — WHICH rule decided this flow. Without these the access log said "policy_matched"
	// in reason_codes but never recorded the deciding policy, so an operator could not verify which rule
	// allowed/denied a flow. Populated from the AccessDecision.
	PolicyID          *string  `json:"policy_id"`
	PolicyBundleID    *string  `json:"policy_bundle_id"`
	MatchedConditions []string `json:"matched_conditions"`
	// CacheStatus folded in from the former separate DecisionTrace record (the double-write collapse) — its only
	// field the access log did not already carry.
	CacheStatus   string         `json:"cache_status,omitempty"`
	EdgeRegionID  *string        `json:"edge_region_id"`
	EdgeClusterID *string        `json:"edge_cluster_id"`
	ConnectorID   *string        `json:"connector_id"`
	Timestamp     string         `json:"timestamp"`
	Metadata      map[string]any `json:"metadata"`
}

type AuditLog struct {
	ID                    string         `json:"id"`
	TenantID              string         `json:"tenant_id"`
	ActorUserID           *string        `json:"actor_user_id"`
	ActorNHIID            *string        `json:"actor_nhi_id"`
	EventType             string         `json:"event_type"`
	TargetType            *string        `json:"target_type"`
	TargetID              *string        `json:"target_id"`
	Action                *string        `json:"action"`
	Result                *string        `json:"result"`
	Reason                *string        `json:"reason"`
	AccessDecisionID      *string        `json:"access_decision_id"`
	PolicyID              *string        `json:"policy_id"`
	PolicyBundleID        *string        `json:"policy_bundle_id"`
	EdgeRegionID          *string        `json:"edge_region_id"`
	EdgeClusterID         *string        `json:"edge_cluster_id"`
	SessionID             *string        `json:"session_id"`
	AuthenticationEventID *string        `json:"authentication_event_id"`
	SourceIP              *string        `json:"source_ip"`
	Timestamp             string         `json:"timestamp"`
	Metadata              map[string]any `json:"metadata"`
}

type DecisionTrace struct {
	ID                string         `json:"id"`
	AccessDecisionID  string         `json:"access_decision_id"`
	PolicyID          string         `json:"policy_id"`
	PolicyBundleID    string         `json:"policy_bundle_id"`
	MatchedConditions []string       `json:"matched_conditions"`
	CacheStatus       string         `json:"cache_status"`
	ReasonCodes       []string       `json:"reason_codes"`
	Timestamp         string         `json:"timestamp"`
	Metadata          map[string]any `json:"metadata"`
}
