package main

import (
	"context"
	"strings"
	"testing"
	"time"

	agenttelemetry "github.com/lantern-networks/dsse-core/agenttelemetry"
	agenttool "github.com/lantern-networks/dsse-core/agenttool"
	appcatalog "github.com/lantern-networks/dsse-core/appcatalog"
	endpointinventory "github.com/lantern-networks/dsse-core/endpointinventory"
	humanidentity "github.com/lantern-networks/dsse-core/humanidentity"
	nhi "github.com/lantern-networks/dsse-core/nhi"
	"github.com/lantern-networks/dsse-core/policy"
	policycandidate "github.com/lantern-networks/dsse-core/policycandidate"
	toolcallaudit "github.com/lantern-networks/dsse-core/toolcallaudit"
	usagemeter "github.com/lantern-networks/dsse-core/usagemeter"

	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/model"
)

const (
	tenantIsolationPrimaryTenant = "tenant_iso_primary"
	tenantIsolationOtherTenant   = "tenant_iso_other"
	tenantIsolationSharedID      = "tenant_iso_shared"
)

func TestProcessLocalControlPlaneStoresTenantIsolation(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 6, 7, 2, 5, 0, 0, time.UTC)
	future := now.Add(time.Hour).Format(time.RFC3339)
	actorNHIID := "nhi_tenant_iso"
	actionType := "tool.execute"

	cases := []struct {
		name string
		run  func(t *testing.T)
	}{
		{
			name: "admin policy store",
			run: func(t *testing.T) {
				store := policy.NewStore(nil)
				pol := model.Policy{
					ID:         tenantIsolationSharedID,
					TenantID:   tenantIsolationPrimaryTenant,
					Conditions: map[string]any{"purpose": "tenant_isolation"},
					Action:     model.PolicyAction{Decision: "allow"},
					Status:     "active",
				}
				if _, err := store.Upsert(ctx, pol, tenantIsolationPrimaryTenant, now); err != nil {
					t.Fatalf("upsert primary policy: %v", err)
				}
				if _, ok, err := store.Get(ctx, tenantIsolationOtherTenant, tenantIsolationSharedID); err != nil || ok {
					t.Fatalf("other tenant Get ok=%v err=%v, want not found nil error", ok, err)
				}
				otherList, err := store.List(ctx, tenantIsolationOtherTenant, policy.ListOptions{Limit: 10})
				if err != nil {
					t.Fatalf("other tenant List: %v", err)
				}
				if otherList.Count != 0 || len(otherList.Policies) != 0 {
					t.Fatalf("other tenant policy list = %#v, want empty", otherList)
				}
				pol.TenantID = tenantIsolationOtherTenant
				if _, err := store.Upsert(ctx, pol, tenantIsolationPrimaryTenant, now); err == nil {
					t.Fatalf("cross-tenant Upsert returned nil error")
				}
			},
		},
		{
			name: "application catalog store",
			run: func(t *testing.T) {
				store := newAdminApplicationCatalogStore("", nil, nil)
				application := appcatalog.Entry{
					ApplicationID:   tenantIsolationSharedID,
					TenantID:        tenantIsolationPrimaryTenant,
					ApplicationType: "private_app",
					ServiceFamily:   "https",
					Protocol:        "https",
					Status:          "active",
				}
				if _, err := store.Upsert(ctx, application, tenantIsolationPrimaryTenant, now); err != nil {
					t.Fatalf("upsert primary application: %v", err)
				}
				if _, ok, err := store.Get(ctx, tenantIsolationOtherTenant, tenantIsolationSharedID); err != nil || ok {
					t.Fatalf("other tenant Get ok=%v err=%v, want not found nil error", ok, err)
				}
				otherList, err := store.List(ctx, tenantIsolationOtherTenant, appcatalog.ListOptions{Limit: 10})
				if err != nil {
					t.Fatalf("other tenant List: %v", err)
				}
				if otherList.Count != 0 || len(otherList.Applications) != 0 {
					t.Fatalf("other tenant application list = %#v, want empty", otherList)
				}
				application.TenantID = tenantIsolationOtherTenant
				if _, err := store.Upsert(ctx, application, tenantIsolationPrimaryTenant, now); err == nil {
					t.Fatalf("cross-tenant Upsert returned nil error")
				}
			},
		},
		{
			name: "policy candidate store",
			run: func(t *testing.T) {
				store := policycandidate.NewStore()
				candidate := policycandidate.Candidate{
					CandidateID:   tenantIsolationSharedID,
					TenantID:      tenantIsolationPrimaryTenant,
					ApplicationID: "app_tenant_iso",
					ServiceFamily: "https",
				}
				if _, err := store.Upsert(ctx, candidate, tenantIsolationPrimaryTenant, now); err != nil {
					t.Fatalf("upsert primary candidate: %v", err)
				}
				if _, ok, err := store.Get(ctx, tenantIsolationOtherTenant, tenantIsolationSharedID); err != nil || ok {
					t.Fatalf("other tenant Get ok=%v err=%v, want not found nil error", ok, err)
				}
				otherList, err := store.List(ctx, tenantIsolationOtherTenant, policycandidate.ListOptions{Limit: 10})
				if err != nil {
					t.Fatalf("other tenant List: %v", err)
				}
				if otherList.Count != 0 || len(otherList.Candidates) != 0 {
					t.Fatalf("other tenant candidate list = %#v, want empty", otherList)
				}
				if _, ok, err := store.Review(ctx, tenantIsolationOtherTenant, tenantIsolationSharedID, policycandidate.ReviewRequest{Decision: "approved"}, now); err != nil || ok {
					t.Fatalf("other tenant Review ok=%v err=%v, want not found nil error", ok, err)
				}
			},
		},
		{
			name: "agent tool store",
			run: func(t *testing.T) {
				store := agenttool.NewStore("", nil)
				tool := agenttool.Tool{
					ToolID:     tenantIsolationSharedID,
					TenantID:   tenantIsolationPrimaryTenant,
					ActionType: "tool.execute",
					Status:     "active",
				}
				if _, err := store.Upsert(ctx, tool, tenantIsolationPrimaryTenant, now); err != nil {
					t.Fatalf("upsert primary tool: %v", err)
				}
				if _, ok, err := store.Get(ctx, tenantIsolationOtherTenant, tenantIsolationSharedID); err != nil || ok {
					t.Fatalf("other tenant Get ok=%v err=%v, want not found nil error", ok, err)
				}
				otherList, err := store.List(ctx, tenantIsolationOtherTenant, agenttool.ListOptions{Limit: 10})
				if err != nil {
					t.Fatalf("other tenant List: %v", err)
				}
				if otherList.Count != 0 || len(otherList.Tools) != 0 {
					t.Fatalf("other tenant tool list = %#v, want empty", otherList)
				}
				tool.TenantID = tenantIsolationOtherTenant
				if _, err := store.Upsert(ctx, tool, tenantIsolationPrimaryTenant, now); err == nil {
					t.Fatalf("cross-tenant Upsert returned nil error")
				}
			},
		},
		{
			name: "tool call event audit store",
			run: func(t *testing.T) {
				store := toolcallaudit.NewStore()
				event := model.ToolCallEvent{
					ID:                 tenantIsolationSharedID,
					TenantID:           tenantIsolationPrimaryTenant,
					ActorNHIID:         actorNHIID,
					ToolID:             "tool_tenant_iso",
					ActionType:         actionType,
					ResultSummaryScope: "metadata_only",
					Timestamp:          now.Format(time.RFC3339),
					Metadata:           map[string]any{},
				}
				if _, err := store.Upsert(ctx, event, tenantIsolationPrimaryTenant, now); err != nil {
					t.Fatalf("upsert primary tool call audit: %v", err)
				}
				if _, ok, err := store.Get(ctx, tenantIsolationOtherTenant, tenantIsolationSharedID); err != nil || ok {
					t.Fatalf("other tenant Get ok=%v err=%v, want not found nil error", ok, err)
				}
				otherList, err := store.List(ctx, tenantIsolationOtherTenant, toolcallaudit.ListOptions{Limit: 10})
				if err != nil {
					t.Fatalf("other tenant List: %v", err)
				}
				if otherList.Count != 0 || len(otherList.Events) != 0 {
					t.Fatalf("other tenant tool call event list = %#v, want empty", otherList)
				}
				event.TenantID = tenantIsolationOtherTenant
				if _, err := store.Upsert(ctx, event, tenantIsolationPrimaryTenant, now); err == nil {
					t.Fatalf("cross-tenant Upsert returned nil error")
				}
			},
		},
		{
			name: "delegated access grant store",
			run: func(t *testing.T) {
				store := newDelegatedAccessGrantStore()
				grant := adminDelegatedAccessGrant{
					ID:            tenantIsolationSharedID,
					TenantID:      tenantIsolationPrimaryTenant,
					SubjectUserID: "user_tenant_iso",
					ActorNHIID:    actorNHIID,
					ExpiresAt:     future,
					Status:        "active",
				}
				if _, err := adminUpsertDelegatedAccessGrant(store, ctx, grant, tenantIsolationPrimaryTenant, now); err != nil {
					t.Fatalf("upsert primary grant: %v", err)
				}
				if _, ok, err := adminGetDelegatedAccessGrant(store, ctx, tenantIsolationOtherTenant, tenantIsolationSharedID); err != nil || ok {
					t.Fatalf("other tenant AdminGet ok=%v err=%v, want not found nil error", ok, err)
				}
				otherList, err := adminListDelegatedAccessGrant(store, ctx, tenantIsolationOtherTenant, adminDelegatedAccessGrantListOptions{Limit: 10})
				if err != nil {
					t.Fatalf("other tenant AdminList: %v", err)
				}
				if otherList.Count != 0 || len(otherList.Grants) != 0 {
					t.Fatalf("other tenant grant list = %#v, want empty", otherList)
				}
				if _, ok, err := adminRevokeDelegatedAccessGrant(store, ctx, tenantIsolationOtherTenant, tenantIsolationSharedID, adminDelegatedAccessGrantRevokeRequest{RevocationReasonCode: "tenant_isolation"}, now); err != nil || ok {
					t.Fatalf("other tenant AdminRevoke ok=%v err=%v, want not found nil error", ok, err)
				}
			},
		},
		{
			name: "human approval event store",
			run: func(t *testing.T) {
				store := newHumanApprovalEventStore()
				approverUserID := "approver_tenant_iso"
				approval := adminHumanApprovalEvent{
					ID:             tenantIsolationSharedID,
					TenantID:       tenantIsolationPrimaryTenant,
					ApproverUserID: &approverUserID,
					ActorNHIID:     &actorNHIID,
					ActionType:     &actionType,
					ApprovalResult: "approved",
				}
				if _, err := adminUpsertHumanApprovalEvent(store, ctx, approval, tenantIsolationPrimaryTenant, now); err != nil {
					t.Fatalf("upsert primary approval: %v", err)
				}
				if _, ok, err := adminGetHumanApprovalEvent(store, ctx, tenantIsolationOtherTenant, tenantIsolationSharedID); err != nil || ok {
					t.Fatalf("other tenant AdminGet ok=%v err=%v, want not found nil error", ok, err)
				}
				otherList, err := adminListHumanApprovalEvent(store, ctx, tenantIsolationOtherTenant, adminHumanApprovalEventListOptions{Limit: 10})
				if err != nil {
					t.Fatalf("other tenant AdminList: %v", err)
				}
				if otherList.Count != 0 || len(otherList.Approvals) != 0 {
					t.Fatalf("other tenant approval list = %#v, want empty", otherList)
				}
				if _, ok, err := adminRevokeHumanApprovalEvent(store, ctx, tenantIsolationOtherTenant, tenantIsolationSharedID, adminHumanApprovalEventRevokeRequest{ReasonCode: "tenant_isolation"}, now); err != nil || ok {
					t.Fatalf("other tenant AdminRevoke ok=%v err=%v, want not found nil error", ok, err)
				}
			},
		},
		{
			name: "endpoint inventory store",
			run: func(t *testing.T) {
				store := newAdminEndpointInventoryStore("", nil, now)
				endpoint := endpointinventory.Entry{
					EndpointID: tenantIsolationSharedID,
					TenantID:   tenantIsolationPrimaryTenant,
					Status:     "active",
				}
				if _, err := store.Upsert(ctx, endpoint, tenantIsolationPrimaryTenant, now); err != nil {
					t.Fatalf("upsert primary endpoint: %v", err)
				}
				if _, ok, err := store.Get(ctx, tenantIsolationOtherTenant, tenantIsolationSharedID); err != nil || ok {
					t.Fatalf("other tenant Get ok=%v err=%v, want not found nil error", ok, err)
				}
				otherList, err := store.List(ctx, tenantIsolationOtherTenant, endpointinventory.ListOptions{Limit: 10})
				if err != nil {
					t.Fatalf("other tenant List: %v", err)
				}
				if otherList.Count != 0 || len(otherList.Endpoints) != 0 {
					t.Fatalf("other tenant endpoint list = %#v, want empty", otherList)
				}
				endpoint.TenantID = tenantIsolationOtherTenant
				if _, err := store.Upsert(ctx, endpoint, tenantIsolationPrimaryTenant, now); err == nil {
					t.Fatalf("cross-tenant Upsert returned nil error")
				}
			},
		},
		{
			name: "tenant model store",
			run: func(t *testing.T) {
				store := newAdminTenantModelStore(model.PolicyBundle{TenantID: tenantIsolationPrimaryTenant}, now)
				if _, err := store.Update(ctx, adminTenantModel{TenantID: tenantIsolationPrimaryTenant, DisplayName: "Primary Tenant", Status: "active"}, tenantIsolationPrimaryTenant, now); err != nil {
					t.Fatalf("update primary tenant model: %v", err)
				}
				other, err := store.Get(ctx, tenantIsolationOtherTenant)
				if err != nil {
					t.Fatalf("other tenant Get: %v", err)
				}
				if other.TenantID != tenantIsolationOtherTenant || strings.Contains(other.DisplayName, "Primary") {
					t.Fatalf("other tenant model = %#v, want generated other tenant model without primary fields", other)
				}
				if _, err := store.Update(ctx, adminTenantModel{TenantID: tenantIsolationOtherTenant, DisplayName: "Other Tenant", Status: "active"}, tenantIsolationPrimaryTenant, now); err == nil {
					t.Fatalf("cross-tenant Update returned nil error")
				}
			},
		},
		{
			name: "non-human identity store",
			run: func(t *testing.T) {
				store := nhi.NewStore()
				identity := model.NonHumanIdentity{
					ID:          tenantIsolationSharedID,
					TenantID:    tenantIsolationPrimaryTenant,
					Name:        "Tenant Isolation NHI",
					NHIType:     "ai_agent",
					OwnerUserID: "user_tenant_iso",
					Status:      "active",
				}
				if _, err := store.Upsert(ctx, identity, tenantIsolationPrimaryTenant, now); err != nil {
					t.Fatalf("upsert primary NHI: %v", err)
				}
				otherList, err := store.List(ctx, tenantIsolationOtherTenant)
				if err != nil {
					t.Fatalf("other tenant List: %v", err)
				}
				if len(otherList) != 0 {
					t.Fatalf("other tenant NHI list = %#v, want empty", otherList)
				}
				if updated, err := store.MarkUsed(ctx, tenantIsolationOtherTenant, tenantIsolationSharedID, now); err != nil || updated {
					t.Fatalf("other tenant MarkUsed updated=%v err=%v, want false nil error", updated, err)
				}
				identity.TenantID = tenantIsolationOtherTenant
				if _, err := store.Upsert(ctx, identity, tenantIsolationPrimaryTenant, now); err == nil {
					t.Fatalf("cross-tenant Upsert returned nil error")
				}
			},
		},
		{
			name: "human identity directory store",
			run: func(t *testing.T) {
				store := humanidentity.NewHumanIdentityDirectoryStore()
				identity := model.HumanIdentity{
					ID:       tenantIsolationSharedID,
					TenantID: tenantIsolationPrimaryTenant,
					Subject:  "user_tenant_iso",
					Source:   "scim",
					Status:   "active",
				}
				if _, err := store.Upsert(ctx, identity, tenantIsolationPrimaryTenant, now); err != nil {
					t.Fatalf("upsert primary human identity: %v", err)
				}
				otherList, err := store.List(ctx, tenantIsolationOtherTenant)
				if err != nil {
					t.Fatalf("other tenant List: %v", err)
				}
				if len(otherList) != 0 {
					t.Fatalf("other tenant human identity list = %#v, want empty", otherList)
				}
				otherStats, err := store.Stats(ctx, tenantIsolationOtherTenant, now)
				if err != nil {
					t.Fatalf("other tenant Stats: %v", err)
				}
				if otherStats.Total != 0 || otherStats.Active != 0 {
					t.Fatalf("other tenant stats = %#v, want zero", otherStats)
				}
				if _, err := store.Upsert(ctx, model.HumanIdentity{ID: tenantIsolationSharedID, TenantID: tenantIsolationOtherTenant, Subject: "user_other", Status: "active"}, tenantIsolationPrimaryTenant, now); err == nil {
					t.Fatalf("cross-tenant Upsert returned nil error")
				}
				if err := store.RecordSourceImport(ctx, humanidentity.HumanIdentitySourceState{TenantID: tenantIsolationPrimaryTenant, Source: "scim", Status: "success", UpdatedAt: now.Format(time.RFC3339)}); err != nil {
					t.Fatalf("record primary source import: %v", err)
				}
				otherStates, err := store.ListSourceStates(ctx, tenantIsolationOtherTenant)
				if err != nil {
					t.Fatalf("other tenant source states: %v", err)
				}
				if len(otherStates) != 0 {
					t.Fatalf("other tenant source states = %#v, want empty", otherStates)
				}
				if _, err := store.UpsertSourcePolicy(ctx, humanidentity.HumanIdentitySourcePolicy{TenantID: tenantIsolationPrimaryTenant, Source: "scim", Enabled: true, UpdatedAt: now.Format(time.RFC3339)}); err != nil {
					t.Fatalf("upsert primary source policy: %v", err)
				}
				otherPolicies, err := store.ListSourcePolicies(ctx, tenantIsolationOtherTenant)
				if err != nil {
					t.Fatalf("other tenant source policies: %v", err)
				}
				if len(otherPolicies) != 0 {
					t.Fatalf("other tenant source policies = %#v, want empty", otherPolicies)
				}
			},
		},
		{
			name: "connector registry admin accessors",
			run: func(t *testing.T) {
				registry := connector.NewRegistry()
				if _, err := registry.Register(model.ConnectorRegistration{ID: tenantIsolationSharedID, TenantID: tenantIsolationPrimaryTenant, PrivateBaseURL: "http://tenant-isolation-connector.example.invalid", Status: "healthy"}, now); err != nil {
					t.Fatalf("register primary connector: %v", err)
				}
				if _, ok, err := adminConnectorGet(ctx, registry, tenantIsolationOtherTenant, tenantIsolationSharedID, nil); err != nil || ok {
					t.Fatalf("other tenant adminConnectorGet ok=%v err=%v, want not found nil error", ok, err)
				}
				otherList, err := adminConnectorList(ctx, registry, tenantIsolationOtherTenant, nil)
				if err != nil {
					t.Fatalf("other tenant adminConnectorList: %v", err)
				}
				if otherList.Count != 0 || len(otherList.Connectors) != 0 {
					t.Fatalf("other tenant connector list = %#v, want empty", otherList)
				}
			},
		},
		{
			name: "admin auth store",
			run: func(t *testing.T) {
				store := newAdminAuthStore()
				rawToken := "synthetic-tenant-isolation-token"
				store.UpsertPrincipal(adminPrincipal{ID: tenantIsolationSharedID, TenantID: tenantIsolationPrimaryTenant, Subject: "sub_iso", Email: "tenant-isolation@example.invalid", Roles: []string{"admin"}, IDPID: "idp_iso", Status: "active", CreatedAt: now.Format(time.RFC3339)})
				store.UpsertSession(adminSession{ID: tenantIsolationSharedID, TenantID: tenantIsolationPrimaryTenant, AdminPrincipalID: tenantIsolationSharedID, Subject: "sub_iso", Roles: []string{"admin"}, MFAState: "complete", CreatedAt: now.Format(time.RFC3339), ExpiresAt: future, LastActiveAt: now.Format(time.RFC3339), Status: "active"})
				store.UpsertAPIToken(adminAPIToken{ID: tenantIsolationSharedID, TenantID: tenantIsolationPrimaryTenant, Name: "tenant-isolation", TokenHash: adminTokenHash(rawToken), Roles: []string{"admin"}, Scopes: []string{"*"}, CreatedByAdminPrincipalID: tenantIsolationSharedID, CreatedAt: now.Format(time.RFC3339), ExpiresAt: future, Status: "active"})
				if _, ok := store.Principal(tenantIsolationSharedID, tenantIsolationOtherTenant); ok {
					t.Fatalf("other tenant Principal returned ok")
				}
				stats := store.Stats(tenantIsolationOtherTenant)
				if stats.Total != 0 || stats.Principals != 0 || stats.Sessions != 0 || stats.APITokens != 0 {
					t.Fatalf("other tenant stats = %#v, want zero", stats)
				}
				if tokens := store.ListAPITokens(tenantIsolationOtherTenant); len(tokens) != 0 {
					t.Fatalf("other tenant tokens = %#v, want empty", tokens)
				}
				if _, ok := store.IdentityForSession(tenantIsolationSharedID, tenantIsolationOtherTenant, now); ok {
					t.Fatalf("other tenant session identity returned ok")
				}
				if _, ok := store.IdentityForAPIToken(rawToken, tenantIsolationOtherTenant, now); ok {
					t.Fatalf("other tenant API token identity returned ok")
				}
			},
		},
		{
			name: "admin export job store",
			run: func(t *testing.T) {
				store := newAdminExportJobStore()
				job := store.Create(adminExportJobRequest{Stream: "access_decisions", Format: "ndjson", Limit: 10}, tenantIsolationPrimaryTenant, "admin_tenant_iso", now)
				if _, ok, err := store.GetByTenant(ctx, tenantIsolationOtherTenant, job.ID); err != nil || ok {
					t.Fatalf("other tenant GetByTenant ok=%v err=%v, want not found nil error", ok, err)
				}
				if jobs, err := store.ListByTenant(ctx, tenantIsolationOtherTenant, 10); err != nil || len(jobs) != 0 {
					t.Fatalf("other tenant ListByTenant jobs=%#v err=%v, want empty nil error", jobs, err)
				}
				if _, err := store.MarkCancelled(job.ID, tenantIsolationOtherTenant, "admin_other", "tenant_isolation", now); err == nil {
					t.Fatalf("other tenant MarkCancelled returned nil error")
				}
			},
		},
		{
			name: "usage meter store",
			run: func(t *testing.T) {
				store := usagemeter.NewUsageMeterStore()
				store.Record(usagemeter.UsageMeterRecord{ID: tenantIsolationSharedID, TenantID: tenantIsolationPrimaryTenant, PeriodStart: now.Add(-time.Hour), PeriodEnd: now.Add(time.Hour), MeterType: "connector", Quantity: 1, Unit: "count", CollectedAt: now})
				records, err := store.UsageMeterRecords(tenantIsolationOtherTenant, now.Add(-time.Hour), now.Add(time.Hour))
				if err != nil {
					t.Fatalf("other tenant UsageMeterRecords: %v", err)
				}
				if len(records) != 0 {
					t.Fatalf("other tenant usage records = %#v, want empty", records)
				}
				summary := store.Summary(tenantIsolationOtherTenant, now.Add(-time.Hour), now.Add(time.Hour))
				if summary.Records != 0 {
					t.Fatalf("other tenant summary = %#v, want zero records", summary)
				}
			},
		},
		{
			name: "agent telemetry store",
			run: func(t *testing.T) {
				store := agenttelemetry.NewStore()
				if err := store.RecordUpdate(ctx, model.AgentUpdateEvent{ID: tenantIsolationSharedID, TenantID: tenantIsolationPrimaryTenant, DeviceID: "device_iso", UpdateStatus: "installed", Timestamp: now.Format(time.RFC3339)}); err != nil {
					t.Fatalf("record primary update: %v", err)
				}
				if err := store.RecordStatus(ctx, model.AgentStatus{DeviceID: tenantIsolationSharedID, TenantID: tenantIsolationPrimaryTenant, Status: "healthy", Timestamp: now.Format(time.RFC3339)}); err != nil {
					t.Fatalf("record primary status: %v", err)
				}
				updateSummary, err := store.UpdateSummary(ctx, tenantIsolationOtherTenant)
				if err != nil {
					t.Fatalf("other tenant update summary: %v", err)
				}
				if updateSummary["total"] != 0 {
					t.Fatalf("other tenant update summary = %#v, want zero total", updateSummary)
				}
				statusSummary, err := store.StatusSummary(ctx, tenantIsolationOtherTenant)
				if err != nil {
					t.Fatalf("other tenant status summary: %v", err)
				}
				if statusSummary["total"] != 0 {
					t.Fatalf("other tenant status summary = %#v, want zero total", statusSummary)
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, tc.run)
	}
}
