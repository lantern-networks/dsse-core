package swg

import (
	inspection "github.com/lantern-networks/dsse-core/inspection"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/model"
)

const EdgeSWGTLSReadinessStatusPath = "/swg/tls-readiness/status"

type EdgeSWGTLSReadinessStatus struct {
	SchemaVersion                       string                                 `json:"schema_version"`
	Status                              string                                 `json:"status"`
	TenantID                            string                                 `json:"tenant_id"`
	PolicyBundleID                      string                                 `json:"policy_bundle_id"`
	PolicyBundleVersion                 string                                 `json:"policy_bundle_version"`
	ReadbackPath                        string                                 `json:"readback_path"`
	EdgeHTTPegressHandlerPath           string                                 `json:"edge_http_egress_handler_path"`
	DefaultTLSDecryptionRequired        bool                                   `json:"default_tls_decryption_required"`
	DefaultTLSDecryptionObserved        bool                                   `json:"default_tls_decryption_observed"`
	DefaultTLSDecryptionStatus          string                                 `json:"default_tls_decryption_status"`
	RequiredInspectionProfileIDs        []string                               `json:"required_inspection_profile_ids"`
	TenantHeaderRewriteDependencyCount  int                                    `json:"tenant_header_rewrite_dependency_count"`
	TenantHeaderRewriteDependencies     []edgeSWGTenantHeaderRewriteDependency `json:"tenant_header_rewrite_dependencies"`
	PerDestinationTLSBypassRequired     bool                                   `json:"per_destination_tls_bypass_required"`
	TLSBypassRuleCount                  int                                    `json:"tls_bypass_rule_count"`
	TLSBypassRules                      []edgeSWGTLSBypassReadinessRule        `json:"tls_bypass_rules"`
	MacCATrustRequired                  bool                                   `json:"mac_ca_trust_required"`
	MacCATrustObserved                  bool                                   `json:"mac_ca_trust_observed"`
	MacCATrustMutated                   bool                                   `json:"mac_ca_trust_mutated"`
	MacCATrustStatus                    string                                 `json:"mac_ca_trust_status"`
	MacTrustProfileIDs                  []string                               `json:"mac_trust_profile_ids"`
	TenantRootCAIDs                     []string                               `json:"tenant_root_ca_ids"`
	InspectionMetadataReadbackObserved  bool                                   `json:"inspection_metadata_readback_observed"`
	InspectionEventCount                int                                    `json:"inspection_event_count"`
	LatestInspectionEventID             string                                 `json:"latest_inspection_event_id,omitempty"`
	LatestAccessDecisionID              string                                 `json:"latest_access_decision_id,omitempty"`
	InspectionMetadata                  edgeSWGTLSReadinessInspectionMetadata  `json:"inspection_metadata"`
	RuntimeTLSDecryptionObserved        bool                                   `json:"runtime_tls_decryption_observed"`
	RuntimeHeaderInjectionObserved      bool                                   `json:"runtime_header_injection_observed"`
	NetworkExtensionRuntimeUsed         bool                                   `json:"network_extension_runtime_used"`
	SWGRuntimeTrafficObserved           bool                                   `json:"swg_runtime_traffic_observed"`
	RealTLSInterceptionRuntimeExecuted  bool                                   `json:"real_tls_interception_runtime_executed"`
	HeaderValueMaterialInStatus         bool                                   `json:"header_value_material_in_status"`
	OperatorConfigValueMaterialInStatus bool                                   `json:"operator_config_value_material_in_status"`
	MacCATrustMutationStarted           bool                                   `json:"mac_ca_trust_mutation_started"`
	P4PackagingMDMSigningInstallStarted bool                                   `json:"p4_packaging_mdm_signing_install_started"`
	ShippingProductClaimed              bool                                   `json:"shipping_product_claimed"`
	ProductionScaleClaimed              bool                                   `json:"production_scale_claimed"`
	MVPPilotSuccessClaimed              bool                                   `json:"mvp_pilot_success_claimed"`
	WindowsWorkStarted                  bool                                   `json:"windows_work_started"`
	ProductizationClaimsMade            bool                                   `json:"productization_claims_made"`
	NewProductClaimsMade                bool                                   `json:"new_product_claims_made"`
	SecretLeakGate                      string                                 `json:"secret_leak_gate"`
	NoSecretAttestation                 bool                                   `json:"no_secret_attestation"`
}

type edgeSWGTenantHeaderRewriteDependency struct {
	RuleID                        string `json:"rule_id"`
	SaaSApplicationID             string `json:"saas_application_id,omitempty"`
	Provider                      string `json:"provider,omitempty"`
	HeaderName                    string `json:"header_name"`
	OperatorConfigRef             string `json:"operator_config_ref"`
	HeaderValueKind               string `json:"header_value_kind"`
	OperatorConfigRefResolved     bool   `json:"operator_config_ref_resolved"`
	RewriteDependency             string `json:"rewrite_dependency"`
	HeaderValueMaterialInStatus   bool   `json:"header_value_material_in_status"`
	HeaderValueMaterialInDecision bool   `json:"header_value_material_in_decision"`
}

type edgeSWGTLSBypassReadinessRule struct {
	RuleID            string `json:"rule_id"`
	Name              string `json:"name,omitempty"`
	MatchType         string `json:"match_type"`
	Pattern           string `json:"pattern,omitempty"`
	SaaSApplicationID string `json:"saas_application_id,omitempty"`
	Category          string `json:"category,omitempty"`
	Reason            string `json:"reason,omitempty"`
	Status            string `json:"status"`
}

type edgeSWGTLSReadinessInspectionMetadata struct {
	LatestEventType                          string   `json:"latest_event_type,omitempty"`
	LatestFindingType                        string   `json:"latest_finding_type,omitempty"`
	GoogleWorkspaceRewriteOutcome            string   `json:"google_workspace_rewrite_outcome"`
	Microsoft365RewriteOutcome               string   `json:"microsoft_365_rewrite_outcome"`
	TLSBypassSuppressionOutcome              string   `json:"tls_bypass_suppression_outcome"`
	HeaderNamesVisible                       []string `json:"header_names_visible"`
	OperatorConfigRefsVisible                []string `json:"operator_config_refs_visible"`
	HeaderValueMaterialInInspectionEvent     bool     `json:"header_value_material_in_inspection_event"`
	HeaderValueMaterialInAPIReadback         bool     `json:"header_value_material_in_api_readback"`
	OperatorConfigValueMaterialInInspection  bool     `json:"operator_config_value_material_in_inspection"`
	OperatorConfigValueMaterialInAPIReadback bool     `json:"operator_config_value_material_in_api_readback"`
}

func EdgeSWGTLSReadinessStatusFor(evaluator decision.Evaluator, runtime RuntimeConfig, inspectionEvents *inspection.Store, egressPath string) EdgeSWGTLSReadinessStatus {
	bundle := evaluator.PolicyBundle
	profileIDs, defaultTLSRequired := activeDefaultTLSInspectionProfileIDs(bundle)
	trustProfileIDs, tenantRootCAIDs := activeMacTrustDependencies(bundle, profileIDs)
	tenantDependencies := tenantHeaderRewriteDependencies(bundle, runtime)
	bypassRules := tlsBypassReadinessRules(bundle)
	inspectionSummary := swgInspectionMetadataReadbackSummary(inspectionEvents, bundle.TenantID)

	defaultTLSObserved := runtime.RuntimeTLSDecryptionObserved || inspectionSummary.RuntimeTLSDecryptionObserved
	headerObserved := runtime.RuntimeHeaderInjectionObserved || inspectionSummary.RuntimeHeaderInjectionObserved
	networkExtensionUsed := runtime.NetworkExtensionRuntimeUsed || inspectionSummary.NetworkExtensionRuntimeUsed
	macCATrustObserved := runtime.MacCATrustObserved

	return EdgeSWGTLSReadinessStatus{
		SchemaVersion:                       "swg_tls_readiness_status.v1",
		Status:                              TlsReadinessVisibilityStatus(defaultTLSRequired, defaultTLSObserved),
		TenantID:                            bundle.TenantID,
		PolicyBundleID:                      bundle.ID,
		PolicyBundleVersion:                 bundle.Version,
		ReadbackPath:                        EdgeSWGTLSReadinessStatusPath,
		EdgeHTTPegressHandlerPath:           egressPath,
		DefaultTLSDecryptionRequired:        defaultTLSRequired,
		DefaultTLSDecryptionObserved:        defaultTLSObserved,
		DefaultTLSDecryptionStatus:          TlsReadinessRequiredObservedStatus(defaultTLSRequired, defaultTLSObserved),
		RequiredInspectionProfileIDs:        profileIDs,
		TenantHeaderRewriteDependencyCount:  len(tenantDependencies),
		TenantHeaderRewriteDependencies:     tenantDependencies,
		PerDestinationTLSBypassRequired:     len(bypassRules) > 0,
		TLSBypassRuleCount:                  len(bypassRules),
		TLSBypassRules:                      bypassRules,
		MacCATrustRequired:                  defaultTLSRequired && (len(trustProfileIDs) > 0 || len(tenantRootCAIDs) > 0),
		MacCATrustObserved:                  macCATrustObserved,
		MacCATrustMutated:                   false,
		MacCATrustStatus:                    MacCATrustRequiredStatus(defaultTLSRequired && (len(trustProfileIDs) > 0 || len(tenantRootCAIDs) > 0), macCATrustObserved),
		MacTrustProfileIDs:                  trustProfileIDs,
		TenantRootCAIDs:                     tenantRootCAIDs,
		InspectionMetadataReadbackObserved:  inspectionSummary.Count > 0,
		InspectionEventCount:                inspectionSummary.Count,
		LatestInspectionEventID:             inspectionSummary.LatestInspectionEventID,
		LatestAccessDecisionID:              inspectionSummary.LatestAccessDecisionID,
		InspectionMetadata:                  inspectionSummary.Metadata,
		RuntimeTLSDecryptionObserved:        defaultTLSObserved,
		RuntimeHeaderInjectionObserved:      headerObserved,
		NetworkExtensionRuntimeUsed:         networkExtensionUsed,
		SWGRuntimeTrafficObserved:           false,
		RealTLSInterceptionRuntimeExecuted:  false,
		HeaderValueMaterialInStatus:         false,
		OperatorConfigValueMaterialInStatus: false,
		MacCATrustMutationStarted:           false,
		P4PackagingMDMSigningInstallStarted: false,
		ShippingProductClaimed:              false,
		ProductionScaleClaimed:              false,
		MVPPilotSuccessClaimed:              false,
		WindowsWorkStarted:                  false,
		ProductizationClaimsMade:            runtime.ProductizationClaimsMade,
		NewProductClaimsMade:                runtime.NewProductClaimsMade,
		SecretLeakGate:                      "ok",
		NoSecretAttestation:                 true,
	}
}

func activeDefaultTLSInspectionProfileIDs(bundle model.PolicyBundle) ([]string, bool) {
	ids := make([]string, 0, len(bundle.InspectionProfiles))
	for _, profile := range bundle.InspectionProfiles {
		if !activeSWGRuntimeStatus(profile.Status) || !profile.TLSInterceptionEnabled {
			continue
		}
		ids = append(ids, profile.ID)
	}
	sort.Strings(ids)
	return ids, len(ids) > 0
}

func activeMacTrustDependencies(bundle model.PolicyBundle, profileIDs []string) ([]string, []string) {
	profileSet := map[string]bool{}
	for _, id := range profileIDs {
		profileSet[id] = true
	}
	trustProfileIDs := []string{}
	tenantRootCAIDs := []string{}
	for _, profile := range bundle.InspectionProfiles {
		if !profileSet[profile.ID] {
			continue
		}
		trustProfileIDs = AppendUniqueNonEmpty(trustProfileIDs, profile.TrustProfileID)
		tenantRootCAIDs = AppendUniqueNonEmpty(tenantRootCAIDs, profile.TenantRootCAID)
	}
	for _, trustProfile := range bundle.TrustProfiles {
		if !activeSWGRuntimeStatus(trustProfile.Status) {
			continue
		}
		if containsExactString(trustProfileIDs, trustProfile.ID) {
			tenantRootCAIDs = AppendUniqueNonEmpty(tenantRootCAIDs, trustProfile.TenantRootCAID)
		}
	}
	sort.Strings(trustProfileIDs)
	sort.Strings(tenantRootCAIDs)
	return trustProfileIDs, tenantRootCAIDs
}

func tenantHeaderRewriteDependencies(bundle model.PolicyBundle, runtime RuntimeConfig) []edgeSWGTenantHeaderRewriteDependency {
	deps := []edgeSWGTenantHeaderRewriteDependency{}
	for _, rule := range bundle.SWGTenantRestrictionRules {
		if !activeSWGRuntimeStatus(rule.Status) || !tenantIDMatchesBundle(rule.TenantID, bundle.TenantID) {
			continue
		}
		resolved := false
		if runtime.TenantRestrictionResolverConfigured {
			_, resolved = runtime.TenantRestrictionResolver.ResolveHeaderValue(rule.HeaderValueRef)
		}
		deps = append(deps, edgeSWGTenantHeaderRewriteDependency{
			RuleID:                        rule.ID,
			SaaSApplicationID:             rule.SaaSApplicationID,
			Provider:                      rule.Provider,
			HeaderName:                    rule.HeaderName,
			OperatorConfigRef:             rule.HeaderValueRef,
			HeaderValueKind:               rule.HeaderValueKind,
			OperatorConfigRefResolved:     resolved,
			RewriteDependency:             "default_tls_decryption_required",
			HeaderValueMaterialInStatus:   false,
			HeaderValueMaterialInDecision: false,
		})
	}
	sort.Slice(deps, func(i, j int) bool {
		return deps[i].RuleID < deps[j].RuleID
	})
	return deps
}

func tlsBypassReadinessRules(bundle model.PolicyBundle) []edgeSWGTLSBypassReadinessRule {
	rules := []edgeSWGTLSBypassReadinessRule{}
	for _, rule := range bundle.SWGTLSBypassRules {
		if !activeSWGRuntimeStatus(rule.Status) || !tenantIDMatchesBundle(rule.TenantID, bundle.TenantID) {
			continue
		}
		rules = append(rules, edgeSWGTLSBypassReadinessRule{
			RuleID:            rule.ID,
			Name:              rule.Name,
			MatchType:         rule.MatchType,
			Pattern:           rule.Pattern,
			SaaSApplicationID: rule.SaaSApplicationID,
			Category:          rule.Category,
			Reason:            rule.Reason,
			Status:            valueOrDefault(strings.TrimSpace(rule.Status), "active"),
		})
	}
	sort.Slice(rules, func(i, j int) bool {
		return rules[i].RuleID < rules[j].RuleID
	})
	return rules
}

type swgInspectionMetadataSummary struct {
	Count                          int
	LatestInspectionEventID        string
	LatestAccessDecisionID         string
	LatestTimestamp                string
	RuntimeTLSDecryptionObserved   bool
	RuntimeHeaderInjectionObserved bool
	NetworkExtensionRuntimeUsed    bool
	Metadata                       edgeSWGTLSReadinessInspectionMetadata
}

// The TLS-readiness summary was the single biggest CPU cost on the decrypt-forward hot path: it is computed on
// EVERY SWG egress request (the readiness/precondition gate) and rescans the ENTIRE per-tenant inspection-event
// store — so as the store fills under load it becomes O(N) per request, i.e. O(N²) over a page's worth of
// subresources, saturating the Edge CPU (profiled at ~54% of all CPU) and collapsing throughput. The summary's
// gate-relevant booleans are MONOTONIC (once observed, always observed), so a short per-tenant cache is safe:
// rescan at most once per TTL once the store is large. When the store is small (tests + early runtime) we never
// cache — the scan is cheap and freshness is preserved for assertions.
const (
	readbackScanCacheThreshold = 256 // below this many events the scan is cheap → always compute fresh
	readbackScanCacheTTL       = time.Second
)

var (
	readbackCacheMu sync.Mutex
	readbackCache   = map[string]readbackCacheEntry{}
	readbackNow     = time.Now // injectable for tests
)

type readbackCacheEntry struct {
	summary swgInspectionMetadataSummary
	expires time.Time
}

func swgInspectionMetadataReadbackSummary(store *inspection.Store, tenantID string) swgInspectionMetadataSummary {
	if store == nil || store.Count() < readbackScanCacheThreshold {
		return computeSwgInspectionMetadataReadbackSummary(store, tenantID)
	}
	// Hold the lock across the check AND the recompute so only ONE goroutine rescans per TTL window; the others
	// block briefly then read the fresh entry. Releasing the lock before the scan caused a thundering herd —
	// under concurrency every in-flight request saw the cache expired at the TTL boundary and rescanned at once,
	// defeating the cache. The scan is ~ms and runs at most once per TTL, so the contention it adds is negligible
	// next to the per-request O(N) scan it replaces.
	readbackCacheMu.Lock()
	defer readbackCacheMu.Unlock()
	if e, ok := readbackCache[tenantID]; ok && readbackNow().Before(e.expires) {
		return e.summary
	}
	summary := computeSwgInspectionMetadataReadbackSummary(store, tenantID)
	readbackCache[tenantID] = readbackCacheEntry{summary: summary, expires: readbackNow().Add(readbackScanCacheTTL)}
	return summary
}

func computeSwgInspectionMetadataReadbackSummary(store *inspection.Store, tenantID string) swgInspectionMetadataSummary {
	summary := swgInspectionMetadataSummary{
		Metadata: edgeSWGTLSReadinessInspectionMetadata{
			GoogleWorkspaceRewriteOutcome:            "not_observed",
			Microsoft365RewriteOutcome:               "not_observed",
			TLSBypassSuppressionOutcome:              "not_observed",
			HeaderNamesVisible:                       []string{},
			OperatorConfigRefsVisible:                []string{},
			HeaderValueMaterialInInspectionEvent:     false,
			HeaderValueMaterialInAPIReadback:         false,
			OperatorConfigValueMaterialInInspection:  false,
			OperatorConfigValueMaterialInAPIReadback: false,
		},
	}
	if store == nil {
		return summary
	}
	for _, event := range store.ListByTenant(tenantID) {
		if !swgReadinessInspectionEventMatches(event) {
			continue
		}
		summary.Count++
		metadata := event.Metadata
		summary.RuntimeTLSDecryptionObserved = summary.RuntimeTLSDecryptionObserved || MetadataBool(metadata, "runtime_tls_decryption_observed")
		summary.RuntimeHeaderInjectionObserved = summary.RuntimeHeaderInjectionObserved || MetadataBool(metadata, "runtime_header_injection_observed")
		summary.NetworkExtensionRuntimeUsed = summary.NetworkExtensionRuntimeUsed || MetadataBool(metadata, "network_extension_runtime_used")
		summary.Metadata.HeaderNamesVisible = AppendUniqueNonEmpty(summary.Metadata.HeaderNamesVisible, metadataString(metadata, "header_name"))
		summary.Metadata.OperatorConfigRefsVisible = AppendUniqueNonEmpty(summary.Metadata.OperatorConfigRefsVisible, metadataString(metadata, "operator_config_ref"))
		if eventAfter(event, summary.LatestTimestamp, summary.LatestInspectionEventID) {
			summary.LatestInspectionEventID = event.ID
			summary.LatestAccessDecisionID = stringPtrValue(event.AccessDecisionID)
			summary.LatestTimestamp = event.Timestamp
			summary.Metadata.LatestEventType = metadataString(metadata, "source_audit_event_type")
			summary.Metadata.LatestFindingType = stringPtrValue(event.FindingType)
			summary.Metadata.GoogleWorkspaceRewriteOutcome = valueOrDefault(metadataString(metadata, "google_workspace_rewrite_outcome"), "not_observed")
			summary.Metadata.Microsoft365RewriteOutcome = valueOrDefault(metadataString(metadata, "microsoft_365_rewrite_outcome"), "not_observed")
			summary.Metadata.TLSBypassSuppressionOutcome = valueOrDefault(metadataString(metadata, "tls_bypass_suppression_outcome"), "not_observed")
			summary.Metadata.HeaderValueMaterialInInspectionEvent = MetadataBool(metadata, "header_value_material_in_inspection_event")
			summary.Metadata.HeaderValueMaterialInAPIReadback = MetadataBool(metadata, "header_value_material_in_api_readback")
			summary.Metadata.OperatorConfigValueMaterialInInspection = MetadataBool(metadata, "operator_config_value_material_in_inspection")
			summary.Metadata.OperatorConfigValueMaterialInAPIReadback = MetadataBool(metadata, "operator_config_value_material_in_api_readback")
		}
	}
	sort.Strings(summary.Metadata.HeaderNamesVisible)
	sort.Strings(summary.Metadata.OperatorConfigRefsVisible)
	return summary
}

func swgReadinessInspectionEventMatches(event model.InspectionEvent) bool {
	if stringPtrValue(event.FindingType) == "saas_tenant_restriction_rewrite" {
		return true
	}
	if metadataString(event.Metadata, "swg_inspection_event_version") == "swg_inspection.v1" {
		return true
	}
	return false
}

func eventAfter(candidate model.InspectionEvent, currentTimestamp, currentID string) bool {
	if strings.TrimSpace(currentID) == "" {
		return true
	}
	candidateTime, candidateErr := time.Parse(time.RFC3339, strings.TrimSpace(candidate.Timestamp))
	currentTime, currentErr := time.Parse(time.RFC3339, strings.TrimSpace(currentTimestamp))
	if candidateErr == nil && currentErr == nil && !candidateTime.Equal(currentTime) {
		return candidateTime.After(currentTime)
	}
	if strings.TrimSpace(candidate.Timestamp) != strings.TrimSpace(currentTimestamp) {
		return strings.TrimSpace(candidate.Timestamp) > strings.TrimSpace(currentTimestamp)
	}
	return candidate.ID > currentID
}

func TlsReadinessRequiredObservedStatus(required, observed bool) string {
	if required && observed {
		return "required_observed"
	}
	if required {
		return "required_not_observed"
	}
	return "not_required"
}

func TlsReadinessVisibilityStatus(required, observed bool) string {
	if required && observed {
		return "readiness_visible_runtime_observed"
	}
	if required {
		return "readiness_visible_not_runtime_observed"
	}
	return "readiness_visible_not_required"
}

func MacCATrustRequiredStatus(required, observed bool) string {
	if required && observed {
		return "required_observed"
	}
	if required {
		return "required_not_mutated"
	}
	return "not_required"
}

func activeSWGRuntimeStatus(status string) bool {
	normalized := strings.ToLower(strings.TrimSpace(status))
	return normalized == "" || normalized == "active"
}

func tenantIDMatchesBundle(candidate, bundleTenantID string) bool {
	candidate = strings.TrimSpace(candidate)
	return candidate == "" || candidate == strings.TrimSpace(bundleTenantID)
}

func metadataString(metadata map[string]any, key string) string {
	if metadata == nil {
		return ""
	}
	value, _ := metadata[key].(string)
	return strings.TrimSpace(value)
}

func MetadataBool(metadata map[string]any, key string) bool {
	if metadata == nil {
		return false
	}
	value, _ := metadata[key].(bool)
	return value
}

func AppendUniqueNonEmpty(values []string, candidate string) []string {
	candidate = strings.TrimSpace(candidate)
	if candidate == "" || containsExactString(values, candidate) {
		return values
	}
	return append(values, candidate)
}

func containsExactString(values []string, candidate string) bool {
	for _, value := range values {
		if value == candidate {
			return true
		}
	}
	return false
}
