package main

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	agenttool "github.com/lantern-networks/dsse-core/agenttool"
	appcatalog "github.com/lantern-networks/dsse-core/appcatalog"
	"github.com/lantern-networks/dsse-core/assetcatalog"
	endpointinventory "github.com/lantern-networks/dsse-core/endpointinventory"
	humanidentity "github.com/lantern-networks/dsse-core/humanidentity"
	policycandidate "github.com/lantern-networks/dsse-core/policycandidate"
	"github.com/lantern-networks/dsse-core/policyrule"
	toolcallaudit "github.com/lantern-networks/dsse-core/toolcallaudit"

	"github.com/lantern-networks/dsse-core/model"
)

func TestControlPlaneAuditEmittersNonSecretInvariant(t *testing.T) {
	now := time.Date(2026, 6, 7, 2, 15, 0, 0, time.UTC)
	evaluator := testEvaluator()
	rawActorUserID := "raw_actor_user_forbidden_cp0020"
	rawActorNHIID := "raw_actor_nhi_forbidden_cp0020"
	rawSubject := "raw_subject_forbidden_cp0020"
	rawSession := "raw_session_forbidden_cp0020"
	rawPayloadRef := "s3://raw-payload-forbidden-cp0020"
	rawDestination := "https://raw-destination-forbidden-cp0020.example.invalid"
	rawTokenAudience := "raw_token_audience_forbidden_cp0020"
	rawMetadataValue := "raw_metadata_value_forbidden_cp0020"
	rawSourceIP := "203.0.113.99"
	rawEmail := "raw-email-forbidden-cp0020@example.invalid"
	sentinels := []string{
		rawActorUserID,
		rawActorNHIID,
		rawSubject,
		rawSession,
		rawPayloadRef,
		rawDestination,
		rawTokenAudience,
		rawMetadataValue,
		rawSourceIP,
		rawEmail,
	}
	actionType := "tool.execute"
	statusRecorded := "recorded"
	decisionAllow := "allow"
	auditID := "audit_object_cp0020"

	audits := []struct {
		name  string
		audit model.AuditLog
	}{
		{
			name:  "adminPolicyMutationAuditLog",
			audit: adminPolicyMutationAuditLog(httptest.NewRequest("POST", "/admin/policies", nil), model.Policy{ID: auditID, TenantID: "tenant_audit_cp0020", Name: rawSubject, Conditions: map[string]any{"purpose": rawMetadataValue}}, evaluator, now, "upsert", "unconfirmed"),
		},
		{
			name: "adminPolicyAuditLog",
			audit: adminPolicyAuditLog(model.Policy{
				ID:         auditID,
				TenantID:   "tenant_audit_cp0020",
				Conditions: map[string]any{"purpose": rawMetadataValue},
				Action:     model.PolicyAction{Decision: "allow"},
				Status:     "active",
				Metadata:   map[string]any{"safe_label": rawMetadataValue},
			}, evaluator, now),
		},
		{
			name: "adminApplicationCatalogAuditLog",
			audit: adminApplicationCatalogAuditLog(appcatalog.Entry{
				ApplicationID:          auditID,
				TenantID:               "tenant_audit_cp0020",
				ApplicationType:        "private_app",
				ServiceFamily:          "https",
				Protocol:               "https",
				DestinationRole:        "private_app",
				ApplicationSensitivity: "internal",
				RouteRef:               rawDestination,
				Status:                 "active",
			}, evaluator, now),
		},
		{
			name: "adminApplicationPublishAuditLog",
			audit: adminApplicationPublishAuditLog(appcatalog.Entry{
				ApplicationID:          auditID,
				TenantID:               "tenant_audit_cp0020",
				ApplicationType:        "private_app",
				ServiceFamily:          "https",
				Protocol:               "tcp",
				ApplicationSensitivity: "internal",
				Destination:            rawDestination,
				DestinationPort:        443,
				PublishProtocol:        "web",
				ConnectorGroupID:       "site-tokyo",
				Published:              true,
				Status:                 "active",
			}, evaluator, now, true),
		},
		{
			name:  "adminApplicationDeleteAuditLog",
			audit: adminApplicationDeleteAuditLog("tenant_audit_cp0020", auditID, evaluator, now),
		},
		{
			name:  "authoredRuleAuditLog",
			audit: authoredRuleAuditLog(httptest.NewRequest("POST", "/admin/rules", nil), policyrule.Rule{ID: auditID, TenantID: "tenant_audit_cp0020", Name: rawSubject, Source: []string{rawSubject}, Destination: []string{rawSubject}}, "upsert", "saved", evaluator, now),
		},
		{
			name: "assetCatalogAuditLog/endpoint",
			audit: assetCatalogAuditLog(httptest.NewRequest("POST", "/admin/assets/endpoints", nil), "endpoint", auditID, "upsert", "saved",
				assetcatalog.Endpoint{ID: auditID, TenantID: "tenant_audit_cp0020", Alias: rawSubject, Address: rawDestination, Identity: rawActorUserID, Tags: []string{rawTokenAudience}}, evaluator, now),
		},
		{
			name: "assetCatalogAuditLog/group",
			audit: assetCatalogAuditLog(httptest.NewRequest("POST", "/admin/assets/groups", nil), "group", auditID, "upsert", "persistence_unconfirmed",
				assetcatalog.Group{ID: auditID, TenantID: "tenant_audit_cp0020", Alias: rawSubject, StaticMembers: []string{rawTokenAudience}}, evaluator, now),
		},
		{
			name: "assetCatalogAuditLog/service",
			audit: assetCatalogAuditLog(httptest.NewRequest("POST", "/admin/assets/services", nil), "service", auditID, "upsert", "saved",
				assetcatalog.Service{ID: auditID, TenantID: "tenant_audit_cp0020", Alias: rawSubject, Ports: []assetcatalog.PortProto{{Protocol: rawMetadataValue, Port: 443}}}, evaluator, now),
		},
		{
			name: "adminPolicyCandidateAuditLog",
			audit: adminPolicyCandidateAuditLog("admin_policy_candidate_upserted", policycandidate.Candidate{
				CandidateID:      auditID,
				TenantID:         "tenant_audit_cp0020",
				CandidateType:    "allow_policy",
				Source:           "policy_learning",
				ProposedAction:   "allow",
				ApplicationID:    rawDestination,
				ServiceFamily:    "https",
				ReasonCodes:      []string{rawMetadataValue},
				Status:           "proposed",
				ReviewReasonCode: rawMetadataValue,
			}, evaluator, now),
		},
		{
			name: "adminAgentToolAuditLog",
			audit: adminAgentToolAuditLog(agenttool.Tool{
				ToolID:                     auditID,
				TenantID:                   "tenant_audit_cp0020",
				Publisher:                  rawActorUserID,
				PermissionProfile:          rawMetadataValue,
				ActionType:                 actionType,
				MCPServerID:                rawTokenAudience,
				AllowedApplicationIDs:      []string{rawDestination},
				AllowedDataClassifications: []string{rawMetadataValue},
				RuntimeEnvironmentID:       rawSession,
				Status:                     "active",
				MetadataKeyCount:           1,
			}, evaluator, now),
		},
		{
			name: "adminDelegatedAccessGrantAuditLog",
			audit: adminDelegatedAccessGrantAuditLog("admin_delegated_access_grant_upserted", adminDelegatedAccessGrant{
				ID:                   auditID,
				TenantID:             "tenant_audit_cp0020",
				SubjectUserID:        rawSubject,
				ActorNHIID:           rawActorNHIID,
				DeviceID:             &rawMetadataValue,
				ApplicationID:        &rawDestination,
				Audience:             &rawTokenAudience,
				Resource:             &rawPayloadRef,
				Scopes:               []string{rawTokenAudience},
				TaskID:               &rawSession,
				RunID:                &rawMetadataValue,
				ToolIDs:              []string{rawMetadataValue},
				ApprovalEventID:      &rawActorUserID,
				ExpiresAt:            now.Add(time.Hour).Format(time.RFC3339),
				RevocationReasonCode: &rawMetadataValue,
				Status:               "active",
			}, evaluator, now),
		},
		{
			name: "adminHumanApprovalEventAuditLog",
			audit: adminHumanApprovalEventAuditLog("admin_human_approval_event_upserted", adminHumanApprovalEvent{
				ID:                     auditID,
				TenantID:               "tenant_audit_cp0020",
				ApproverUserID:         &rawActorUserID,
				SubjectUserID:          &rawSubject,
				ActorNHIID:             &rawActorNHIID,
				DelegatedAccessGrantID: &rawMetadataValue,
				AgentTaskSessionID:     &rawSession,
				ApplicationID:          &rawDestination,
				Audience:               &rawTokenAudience,
				Resource:               &rawPayloadRef,
				ActionType:             &actionType,
				TaskID:                 &rawMetadataValue,
				RunID:                  &rawMetadataValue,
				RequestedScopes:        []string{rawTokenAudience},
				ReasonCode:             &rawMetadataValue,
				ApprovalResult:         "approved",
			}, evaluator, now),
		},
		{
			name: "adminEndpointInventoryAuditLog",
			audit: adminEndpointInventoryAuditLog(endpointinventory.Entry{
				EndpointID:          auditID,
				TenantID:            "tenant_audit_cp0020",
				UserID:              rawActorUserID,
				Hostname:            rawMetadataValue,
				OS:                  rawMetadataValue,
				OSVersion:           rawMetadataValue,
				AgentVersion:        rawMetadataValue,
				DeviceTrustLevel:    "managed",
				PolicyBundleID:      rawMetadataValue,
				PolicyBundleVersion: rawMetadataValue,
				Status:              "active",
				RegisteredAt:        now.Format(time.RFC3339),
				LastSeenAt:          now.Format(time.RFC3339),
				MetadataKeyCount:    1,
				Source:              "admin",
			}, evaluator, now),
		},
		{
			name: "adminTenantModelAuditLog",
			audit: adminTenantModelAuditLog(adminTenantModel{
				TenantID:            "tenant_audit_cp0020",
				DisplayName:         rawMetadataValue,
				Region:              rawMetadataValue,
				DataResidency:       rawMetadataValue,
				Plan:                rawMetadataValue,
				Status:              "active",
				PolicyBundleID:      rawMetadataValue,
				PolicyBundleVersion: rawMetadataValue,
				MetadataKeyCount:    1,
			}, evaluator, now),
		},
		{
			name: "adminTenantModelLifecycleAuditLog",
			audit: adminTenantModelLifecycleAuditLog(adminTenantModel{
				TenantID:            "tenant_audit_cp0020",
				DisplayName:         rawMetadataValue,
				Region:              rawMetadataValue,
				DataResidency:       rawMetadataValue,
				Plan:                rawMetadataValue,
				Status:              "suspended",
				PolicyBundleID:      rawMetadataValue,
				PolicyBundleVersion: rawMetadataValue,
				MetadataKeyCount:    1,
			}, "create", evaluator, now),
		},
		{
			name: "adminConnectorManagementAuditLog",
			audit: adminConnectorManagementAuditLog("admin_connector_runtime_secret_rotated", adminConnector{
				ID:                      auditID,
				TenantID:                "tenant_audit_cp0020",
				ConnectorGroupID:        rawMetadataValue,
				EdgeRegionID:            rawMetadataValue,
				EdgeClusterID:           rawMetadataValue,
				ApplicationIDs:          []string{rawDestination},
				Status:                  "healthy",
				RuntimeSecretConfigured: true,
				MetadataKeyCount:        1,
			}, nil, evaluator, now),
		},
		{
			name: "adminSiteAuditLog",
			audit: adminSiteAuditLog("admin_site_enrollment_command_issued", adminSiteModel{
				SiteID:                 "site_audit_cp0020",
				TenantID:               "tenant_audit_cp0020",
				Name:                   rawMetadataValue,
				Region:                 rawMetadataValue,
				RoutingNamespace:       rawMetadataValue,
				DeploymentType:         rawMetadataValue,
				HAPolicy:               rawMetadataValue,
				ExpectedConnectorCount: 1,
				BootstrapSecretHash:    rawMetadataValue,
			}, nil, evaluator, now),
		},
		{
			name: "adminToolCallEventAuditLog",
			audit: adminToolCallEventAuditLog(toolcallaudit.Event{
				ID:                         auditID,
				TenantID:                   "tenant_audit_cp0020",
				AgentTaskSessionID:         &rawSession,
				ActorNHIID:                 rawActorNHIID,
				SubjectUserIDPresent:       true,
				DelegatedAccessGrantID:     &rawMetadataValue,
				ToolID:                     "tool_cp0020",
				MCPServerID:                &rawTokenAudience,
				RuntimeEnvironmentID:       &rawSession,
				ActionType:                 actionType,
				ApplicationID:              &rawDestination,
				ContextBoundaryID:          &rawMetadataValue,
				DataClassification:         &rawMetadataValue,
				DestinationPresent:         true,
				TokenAudiencePresent:       true,
				HumanApprovalEventID:       &rawActorUserID,
				AccessDecisionID:           &rawMetadataValue,
				InspectionEventID:          &rawMetadataValue,
				PolicyID:                   &rawMetadataValue,
				Decision:                   &decisionAllow,
				ResultSummaryPresent:       true,
				ResultSummaryScope:         "metadata_only",
				PayloadRefPresent:          true,
				RetentionPolicy:            &rawMetadataValue,
				Timestamp:                  now.Format(time.RFC3339),
				Status:                     &statusRecorded,
				MetadataKeyCount:           1,
				ToolCallMetadataValueScope: "none",
			}, evaluator, now),
		},
		{
			name: "nonHumanIdentityAuditLog",
			audit: nonHumanIdentityAuditLog(model.NonHumanIdentity{
				ID:                    auditID,
				TenantID:              "tenant_audit_cp0020",
				Name:                  rawMetadataValue,
				NHIType:               "ai_agent",
				OwnerUserID:           rawActorUserID,
				TrustDomain:           &rawMetadataValue,
				Issuer:                &rawMetadataValue,
				Subject:               &rawSubject,
				CredentialType:        &rawMetadataValue,
				AllowedApplicationIDs: []string{rawDestination},
				AllowedScopes:         []string{rawTokenAudience},
				Status:                "active",
				Metadata:              map[string]any{"safe_label": rawMetadataValue},
			}, nil, evaluator, now),
		},
		{
			name: "humanIdentityAuditLog",
			audit: humanIdentityAuditLog(model.HumanIdentity{
				ID:          auditID,
				TenantID:    "tenant_audit_cp0020",
				Subject:     rawSubject,
				Email:       &rawEmail,
				DisplayName: &rawActorUserID,
				Source:      "scim",
				Department:  &rawMetadataValue,
				Status:      "active",
				Metadata:    map[string]any{"safe_label": rawMetadataValue},
			}, nil, evaluator, now),
		},
		{
			name: "humanIdentityImportAuditLog",
			audit: humanIdentityImportAuditLog(humanidentity.HumanIdentityDirectoryImportResponse{
				TenantID:              "tenant_audit_cp0020",
				Source:                "scim",
				ImportRunID:           rawMetadataValue,
				Checkpoint:            rawPayloadRef,
				Requested:             1,
				Upserted:              1,
				ActiveCount:           1,
				Identities:            []model.HumanIdentity{{ID: "human_cp0020", TenantID: "tenant_audit_cp0020", Subject: rawSubject, Email: &rawEmail, Status: "active"}},
				DeactivatedIdentities: []model.HumanIdentity{{ID: "human_inactive_cp0020", TenantID: "tenant_audit_cp0020", Subject: rawSubject, Status: "suspended"}},
			}, nil, evaluator, now),
		},
		{
			name: "humanIdentitySourcePolicyAuditLog",
			audit: humanIdentitySourcePolicyAuditLog(humanidentity.HumanIdentitySourcePolicy{
				TenantID:      "tenant_audit_cp0020",
				Source:        "scim",
				ConnectorType: rawMetadataValue,
				Enabled:       true,
				Metadata:      map[string]any{"safe_label": rawMetadataValue},
				UpdatedAt:     now.Format(time.RFC3339),
			}, nil, evaluator, now),
		},
		{
			name: "humanApprovalEventAuditLog",
			audit: humanApprovalEventAuditLog(model.HumanApprovalEvent{
				ID:                     auditID,
				TenantID:               "tenant_audit_cp0020",
				ApprovalSource:         "admin_console",
				ApproverUserID:         &rawActorUserID,
				SubjectUserID:          &rawSubject,
				ActorNHIID:             &rawActorNHIID,
				DelegatedAccessGrantID: &rawMetadataValue,
				AgentTaskSessionID:     &rawSession,
				ApplicationID:          &rawDestination,
				Audience:               &rawTokenAudience,
				Resource:               &rawPayloadRef,
				ActionType:             &actionType,
				TaskID:                 &rawMetadataValue,
				RunID:                  &rawMetadataValue,
				RequestedScopes:        []string{rawTokenAudience},
				ApprovalResult:         "approved",
				Reason:                 &rawMetadataValue,
				EvidenceLink:           &rawPayloadRef,
				CreatedAt:              now.Format(time.RFC3339),
				Metadata:               map[string]any{"safe_label": rawMetadataValue},
			}, evaluator, now),
		},
		{
			name: "delegatedAccessGrantAuditLog",
			audit: delegatedAccessGrantAuditLog("delegated_access_grant_recorded", model.DelegatedAccessGrant{
				ID:               auditID,
				TenantID:         "tenant_audit_cp0020",
				SubjectUserID:    rawSubject,
				ActorNHIID:       rawActorNHIID,
				DeviceID:         &rawMetadataValue,
				ApplicationID:    &rawDestination,
				Audience:         &rawTokenAudience,
				Resource:         &rawPayloadRef,
				Scopes:           []string{rawTokenAudience},
				Purpose:          &rawMetadataValue,
				TaskID:           &rawMetadataValue,
				RunID:            &rawMetadataValue,
				ToolIDs:          []string{rawMetadataValue},
				ApprovalEventID:  &rawActorUserID,
				ExpiresAt:        now.Add(time.Hour).Format(time.RFC3339),
				CreatedAt:        &rawMetadataValue,
				RevocationReason: &rawMetadataValue,
				Status:           "active",
				Metadata:         map[string]any{"safe_label": rawMetadataValue},
			}, evaluator, now),
		},
		{
			name: "inspectionEventAuditLog",
			audit: inspectionEventAuditLog(model.InspectionEvent{
				ID:                  auditID,
				TenantID:            "tenant_audit_cp0020",
				ToolCallEventID:     &rawMetadataValue,
				SessionID:           &rawSession,
				UserID:              &rawActorUserID,
				DeviceID:            &rawMetadataValue,
				ApplicationID:       &rawDestination,
				InspectionProfileID: &rawMetadataValue,
				InspectionMode:      &rawMetadataValue,
				ContentType:         &rawMetadataValue,
				FindingType:         &rawMetadataValue,
				Severity:            &rawMetadataValue,
				PayloadStored:       true,
				PayloadRef:          &rawPayloadRef,
				RetentionPolicy:     &rawMetadataValue,
				Timestamp:           now.Format(time.RFC3339),
				Metadata:            map[string]any{"safe_label": rawMetadataValue},
			}, evaluator, now),
		},
		{
			name: "toolCallEventAuditLog",
			audit: toolCallEventAuditLog(model.ToolCallEvent{
				ID:                     auditID,
				TenantID:               "tenant_audit_cp0020",
				AgentTaskSessionID:     &rawSession,
				ActorNHIID:             rawActorNHIID,
				SubjectUserID:          &rawSubject,
				DelegatedAccessGrantID: &rawMetadataValue,
				TaskID:                 &rawMetadataValue,
				RunID:                  &rawMetadataValue,
				ToolID:                 "tool_cp0020",
				MCPServerID:            &rawTokenAudience,
				RuntimeEnvironmentID:   &rawSession,
				ActionType:             actionType,
				ApplicationID:          &rawDestination,
				ContextBoundaryID:      &rawMetadataValue,
				DataClassification:     &rawMetadataValue,
				Destination:            &rawDestination,
				TokenAudience:          &rawTokenAudience,
				HumanApprovalEventID:   &rawActorUserID,
				InspectionEventID:      &rawMetadataValue,
				Decision:               &decisionAllow,
				ResultSummary:          &rawMetadataValue,
				ResultSummaryScope:     "metadata_only",
				PayloadRef:             &rawPayloadRef,
				RetentionPolicy:        &rawMetadataValue,
				Timestamp:              now.Format(time.RFC3339),
				Status:                 &statusRecorded,
				Metadata:               map[string]any{"safe_label": rawMetadataValue},
			}, evaluator, now),
		},
	}

	for _, tc := range audits {
		t.Run(tc.name, func(t *testing.T) {
			assertAuditLogNonSecretInvariant(t, tc.audit, sentinels)
		})
	}
}

func TestAuditEmitterInventoryClassified(t *testing.T) {
	found := mustAuditEmitterFunctionNames(t)
	covered := coveredAuditEmitterInvariantFunctions()
	deferred := deferredAuditEmitterInvariantFunctions()
	for _, name := range found {
		if covered[name] || deferred[name] {
			continue
		}
		t.Fatalf("audit emitter %s is neither covered by the invariant test nor explicitly deferred", name)
	}
	for name := range covered {
		if !stringSliceContains(found, name) {
			t.Fatalf("covered audit emitter %s was not found in source inventory", name)
		}
	}
	for name := range deferred {
		if !stringSliceContains(found, name) {
			t.Fatalf("deferred audit emitter %s was not found in source inventory", name)
		}
	}
}

func assertAuditLogNonSecretInvariant(t *testing.T, audit model.AuditLog, sentinels []string) {
	t.Helper()
	if audit.SourceIP != nil && strings.TrimSpace(*audit.SourceIP) != "" {
		t.Fatalf("%s included source_ip: %#v", audit.EventType, audit)
	}
	if audit.ActorUserID != nil && strings.TrimSpace(*audit.ActorUserID) != "" {
		t.Fatalf("%s included actor_user_id: %#v", audit.EventType, audit)
	}
	if audit.ActorNHIID != nil && strings.TrimSpace(*audit.ActorNHIID) != "" {
		t.Fatalf("%s included actor_nhi_id: %#v", audit.EventType, audit)
	}
	if audit.SessionID != nil && strings.TrimSpace(*audit.SessionID) != "" {
		t.Fatalf("%s included session_id: %#v", audit.EventType, audit)
	}
	if audit.Metadata == nil {
		t.Fatalf("%s metadata is nil", audit.EventType)
	}
	forbiddenExactKeys := map[string]bool{
		"source_ip":        true,
		"actor_user_id":    true,
		"actor_nhi_id":     true,
		"session_id":       true,
		"user_id":          true,
		"subject_user_id":  true,
		"approver_user_id": true,
		"owner_user_id":    true,
		"payload_ref":      true,
		"destination":      true,
		"token_audience":   true,
		"raw_payload":      true,
		"raw_material":     true,
		"credential":       true,
		"credentials":      true,
		"secret":           true,
	}
	for key, value := range audit.Metadata {
		if forbiddenExactKeys[key] {
			t.Fatalf("%s metadata included forbidden key %q: %#v", audit.EventType, key, audit.Metadata)
		}
		if (strings.HasSuffix(key, "_metadata_recorded_scope") || strings.HasSuffix(key, "_metadata_scope")) && value != "none" {
			t.Fatalf("%s metadata scope %q = %#v, want none", audit.EventType, key, value)
		}
	}
	encoded, err := json.Marshal(audit)
	if err != nil {
		t.Fatalf("marshal audit: %v", err)
	}
	body := string(encoded)
	for _, sentinel := range sentinels {
		if strings.Contains(body, sentinel) {
			t.Fatalf("%s leaked sentinel %q in audit JSON: %s", audit.EventType, sentinel, body)
		}
	}
}

func mustAuditEmitterFunctionNames(t *testing.T) []string {
	t.Helper()
	functionExpr := regexp.MustCompile(`func ([A-Za-z0-9]+AuditLog)\(`)
	files, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package directory: %v", err)
	}
	seen := map[string]bool{}
	for _, file := range files {
		name := file.Name()
		if file.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		if name != "main.go" && !strings.HasPrefix(name, "admin_") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(".", name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		for _, match := range functionExpr.FindAllStringSubmatch(string(data), -1) {
			seen[match[1]] = true
		}
	}
	names := make([]string, 0, len(seen))
	for name := range seen {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func coveredAuditEmitterInvariantFunctions() map[string]bool {
	return map[string]bool{
		"adminAgentToolAuditLog":            true,
		"adminApplicationCatalogAuditLog":   true,
		"adminApplicationDeleteAuditLog":    true,
		"adminApplicationPublishAuditLog":   true,
		"authoredRuleAuditLog":              true,
		"assetCatalogAuditLog":              true,
		"adminConnectorManagementAuditLog":  true,
		"adminDelegatedAccessGrantAuditLog": true,
		"adminEndpointInventoryAuditLog":    true,
		"adminHumanApprovalEventAuditLog":   true,
		"adminPolicyMutationAuditLog":       true,
		"adminPolicyAuditLog":               true,
		"adminPolicyCandidateAuditLog":      true,
		"adminSiteAuditLog":                 true,
		"adminTenantModelAuditLog":          true,
		"adminTenantModelLifecycleAuditLog": true,
		"adminToolCallEventAuditLog":        true,
		"delegatedAccessGrantAuditLog":      true,
		"humanApprovalEventAuditLog":        true,
		"humanIdentityAuditLog":             true,
		"humanIdentityImportAuditLog":       true,
		"humanIdentitySourcePolicyAuditLog": true,
		"inspectionEventAuditLog":           true,
		"nonHumanIdentityAuditLog":          true,
		"toolCallEventAuditLog":             true,
	}
}

func deferredAuditEmitterInvariantFunctions() map[string]bool {
	return map[string]bool{
		// Dedicated user-risk HTTP tests verify attribution and reject evidence,
		// subject aliases, and bearer credentials in the audit record.
		"userRiskAuditLog":              true,
		"adminAccountLifecycleAuditLog": true,
		// ★ THE BREAK-GLASS USE RECORD deliberately names the actor and the route (the machine-credential separation). The whole point is
		// that this act cannot say WHO — the shared token names a synthetic principal — so the record carries
		// everything that narrows it: the principal id it does have, the method and path, the source IP and the
		// user agent. A redacted version of this row would answer nothing at all.
		"adminBreakGlassUseAuditLog": true,
		// ★★ ISSUING A FLEET'S CONFIGURATION names the administrator who did it and where from. What this act
		// decides — what every device taking the profile steers, and whether it carries traffic with no Edge at
		// all — is only accountable if the record answers "who". Redacting it would leave the same blank this
		// deployment keeps finding in its own audits.
		"agentProfileIssuedAuditLog":                 true,
		"adminAPITokenAuditLog":                      true,
		"adminAuditOutboxReplayAuditLog":             true,
		"adminAuthFailureAuditLog":                   true,
		"adminDownloadAuditLog":                      true,
		"adminExportDeadLetterBridgeFailureAuditLog": true,
		"adminExportJobAuditLog":                     true,
		"adminExportWorkerTaskAuditLog":              true,
		"adminLoginAuditLog":                         true,
		// Multi-Tenant Admin Console: operator-accountability audit deliberately records the operator
		// principal + source IP (who acted within which tenant), like adminRBACDeniedAuditLog/adminLoginAuditLog.
		"adminOperateWithinTenantAuditLog": true,
		// PKI material changes deliberately record WHO and from where, on the same grounds as the login and
		// operate-within-tenant audits. Rotating the CA every steered endpoint trusts, or replacing the
		// certificate a component serves, are acts somebody will be asked about months later; an entry saying
		// only that it happened answers the wrong half of the question. The metadata carries names,
		// fingerprints and counts — never key material.
		"pkiMaterialAuditLog": true,
		//b uniform API-write audit: deliberately records WHO (principal + email/roles) + source IP + the
		// method/path they mutated — the whole point is operator accountability, so it carries actor/source like
		// the other identity-bearing admin audits above.
		"adminConfigChangeAuditLog": true,
		"adminRBACDeniedAuditLog":   true,
		"agentRolloutAuditLog":      true,
		// Same family, and the reason it is separate: this one carries WHAT MOVED — the wave schedule and the
		// maintenance window, before and after. An operator who changes the pilot ring's start date leaves an
		// entry that can be read back into the change, which agentRolloutAuditLog could not express.
		"agentRolloutScheduleAuditLog": true,
		// Publishing a build for a fleet: same family again. It carries the source IP and the acting admin's
		// tenant deliberately, because the question after a bad release is WHO put it in front of the fleet —
		// and it carries the artifact digest and signing key id, which are public identifiers of a signed
		// artifact, not secrets.
		"agentUpdatePublishAuditLog":         true,
		"enrolledInventoryAuditLog":          true,
		"agentStatusAuditLog":                true,
		"agentUpdateAuditLog":                true,
		"authenticationEventAuditLog":        true,
		"authenticationEventFailureAuditLog": true,
		"breakGlassDecisionAuditLog":         true,
		"breakGlassExportAuditLog":           true,
		"breakGlassLifecycleAuditLog":        true,
		"delegatedAccessDecisionAuditLog":    true,
		"deviceAuditLog":                     true,
		"domainEventOutboxReplayAuditLog":    true,
	}
}
