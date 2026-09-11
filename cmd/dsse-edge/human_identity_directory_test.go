package main

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	humanidentity "github.com/lantern-networks/dsse-core/humanidentity"

	"github.com/lantern-networks/dsse-core/model"
)

func TestHumanIdentityDirectoryStatsCountsActiveHumans(t *testing.T) {
	now := time.Date(2026, 5, 25, 1, 2, 3, 0, time.UTC)
	expiresAt := now.Add(time.Hour).Format(time.RFC3339)
	expiredAt := now.Add(-time.Hour).Format(time.RFC3339)
	store := humanidentity.NewHumanIdentityDirectoryStore()
	for _, user := range []model.HumanIdentity{
		{ID: "human_active_001", TenantID: "tenant_lab_001", Subject: "sub_active_001", Status: "active", ExpiresAt: &expiresAt},
		{ID: "human_active_002", TenantID: "tenant_lab_001", Subject: "sub_active_002", Status: "active"},
		{ID: "human_suspended_001", TenantID: "tenant_lab_001", Subject: "sub_suspended_001", Status: "suspended"},
		{ID: "human_expired_001", TenantID: "tenant_lab_001", Subject: "sub_expired_001", Status: "active", ExpiresAt: &expiredAt},
		{ID: "human_other_tenant_001", TenantID: "tenant_other_001", Subject: "sub_other_001", Status: "active"},
	} {
		if _, err := store.Upsert(context.Background(), user, user.TenantID, now); err != nil {
			t.Fatalf("Upsert(%s) returned error: %v", user.ID, err)
		}
	}
	stats, err := store.Stats(context.Background(), "tenant_lab_001", now)
	if err != nil {
		t.Fatalf("Stats returned error: %v", err)
	}
	if stats.Total != 4 || stats.Active != 2 {
		t.Fatalf("stats = %#v, want total=4 active=2", stats)
	}
	sources, err := humanidentity.HumanIdentityDirectorySourceList(context.Background(), store, "tenant_lab_001", now)
	if err != nil {
		t.Fatalf("source list returned error: %v", err)
	}
	if sources.Count != 1 || len(sources.Sources) != 1 {
		t.Fatalf("source list = %#v", sources)
	}
	if got := sources.Sources[0]; got.Source != "identity_directory" || got.Total != 4 || got.Active != 2 || got.Suspended != 1 || got.Deleted != 0 || got.Expired != 1 {
		t.Fatalf("source summary = %#v", got)
	}
	health, err := humanidentity.HumanIdentityDirectorySourceHealth(context.Background(), store, "tenant_lab_001", now, time.Hour)
	if err != nil {
		t.Fatalf("source health returned error: %v", err)
	}
	if health.Status != "unknown" || health.SourceCount != 1 || len(health.Sources) != 1 || health.Sources[0].Status != "unknown" {
		t.Fatalf("source health = %#v, want unknown for source without import observation", health)
	}
}

func TestHumanIdentityDirectorySourceHealthIncludesErrorState(t *testing.T) {
	now := time.Date(2026, 5, 25, 1, 2, 3, 0, time.UTC)
	store := humanidentity.NewHumanIdentityDirectoryStore()
	if err := store.RecordSourceImport(context.Background(), humanidentity.HumanIdentitySourceState{
		TenantID:        "tenant_lab_001",
		Source:          "scim",
		Status:          "error",
		LastImportRunID: "human_import_run_error_001",
		Checkpoint:      "cursor_error_001",
		LastErrorAt:     now.UTC().Format(time.RFC3339),
		LastError:       "forced import error",
		UpdatedAt:       now.UTC().Format(time.RFC3339),
	}); err != nil {
		t.Fatalf("RecordSourceImport returned error: %v", err)
	}
	health, err := humanidentity.HumanIdentityDirectorySourceHealth(context.Background(), store, "tenant_lab_001", now, time.Hour)
	if err != nil {
		t.Fatalf("source health returned error: %v", err)
	}
	if health.Status != "degraded" || health.SourceCount != 1 || len(health.Sources) != 1 || health.Sources[0].Source != "scim" || health.Sources[0].Status != "degraded" || health.Sources[0].LatestImportRunID != "human_import_run_error_001" {
		t.Fatalf("source health = %#v, want degraded source import error", health)
	}
	if !stringSliceContains(health.Reasons, "source_import_error") || !stringSliceContains(health.Sources[0].Reasons, "source_import_error") {
		t.Fatalf("source health reasons = %#v / %#v, want source_import_error", health.Reasons, health.Sources[0].Reasons)
	}
}

func TestHumanIdentityDirectorySourcePolicyListAndHealth(t *testing.T) {
	now := time.Date(2026, 5, 25, 1, 2, 3, 0, time.UTC)
	store := humanidentity.NewHumanIdentityDirectoryStore()
	if _, err := humanidentity.HumanIdentityDirectoryUpsertSourcePolicy(context.Background(), store, "tenant_lab_001", humanidentity.HumanIdentitySourcePolicy{
		Source:                  "scim",
		ConnectorType:           "scim",
		Enabled:                 true,
		ReconcileMissing:        true,
		ExpectedIntervalSeconds: 3600,
		StaleAfterSeconds:       7200,
		Metadata:                map[string]any{"connector_id": "scim_lab"},
	}, now); err != nil {
		t.Fatalf("upsert source policy returned error: %v", err)
	}
	if _, err := humanidentity.HumanIdentityDirectoryUpsertSourcePolicy(context.Background(), store, "tenant_lab_001", humanidentity.HumanIdentitySourcePolicy{
		Source:        "manual",
		ConnectorType: "manual",
		Enabled:       false,
	}, now); err != nil {
		t.Fatalf("upsert disabled source policy returned error: %v", err)
	}
	list, err := humanidentity.HumanIdentityDirectorySourcePolicyList(context.Background(), store, "tenant_lab_001")
	if err != nil {
		t.Fatalf("source policy list returned error: %v", err)
	}
	if list.Count != 2 || len(list.Policies) != 2 || list.Policies[0].Source != "manual" || list.Policies[1].Source != "scim" {
		t.Fatalf("source policy list = %#v", list)
	}
	if list.Policies[1].UpdatedAt != now.UTC().Format(time.RFC3339) {
		t.Fatalf("source policy updated_at = %q, want server time", list.Policies[1].UpdatedAt)
	}
	health, err := humanidentity.HumanIdentityDirectorySourceHealth(context.Background(), store, "tenant_lab_001", now, time.Hour)
	if err != nil {
		t.Fatalf("source health returned error: %v", err)
	}
	if health.Status != "degraded" || health.SourceCount != 2 {
		t.Fatalf("source health = %#v, want degraded for unobserved enabled policy", health)
	}
	if got := health.Sources[0]; got.Source != "manual" || got.Status != "unknown" || !got.Configured || got.Enabled || got.ConnectorType != "manual" || !stringSliceContains(got.Reasons, "source_disabled") {
		t.Fatalf("disabled source policy health = %#v", got)
	}
	if got := health.Sources[1]; got.Source != "scim" || got.Status != "degraded" || !got.Configured || !got.Enabled || got.ConnectorType != "scim" || got.StaleAfterSeconds != 7200 || !stringSliceContains(got.Reasons, "source_policy_unobserved") {
		t.Fatalf("enabled source policy health = %#v", got)
	}
}

func TestHumanIdentityDirectorySourceHealthReportsExpectedImportDue(t *testing.T) {
	now := time.Date(2026, 5, 25, 3, 0, 0, 0, time.UTC)
	observedAt := now.Add(-2 * time.Hour).UTC().Format(time.RFC3339)
	store := humanidentity.NewHumanIdentityDirectoryStore()
	if _, err := humanidentity.HumanIdentityDirectoryUpsertSourcePolicy(context.Background(), store, "tenant_lab_001", humanidentity.HumanIdentitySourcePolicy{
		Source:                  "scim",
		ConnectorType:           "scim",
		Enabled:                 true,
		ExpectedIntervalSeconds: 3600,
		StaleAfterSeconds:       10800,
	}, now); err != nil {
		t.Fatalf("upsert source policy returned error: %v", err)
	}
	if _, err := store.Upsert(context.Background(), model.HumanIdentity{
		ID:       "human_due_001",
		TenantID: "tenant_lab_001",
		Subject:  "sub_due_001",
		Source:   "scim",
		Status:   "active",
		Metadata: map[string]any{
			"import_run_id": "human_import_run_due_001",
			"imported_at":   observedAt,
		},
	}, "tenant_lab_001", now); err != nil {
		t.Fatalf("seed source identity returned error: %v", err)
	}
	health, err := humanidentity.HumanIdentityDirectorySourceHealth(context.Background(), store, "tenant_lab_001", now, 24*time.Hour)
	if err != nil {
		t.Fatalf("source health returned error: %v", err)
	}
	if health.Status != "ok" || health.SourceCount != 1 {
		t.Fatalf("source health = %#v, want ok observed source", health)
	}
	got := health.Sources[0]
	if got.Source != "scim" || !got.Configured || got.ExpectedInterval != 3600 || !got.Due || got.NextExpectedAt != now.Add(-time.Hour).UTC().Format(time.RFC3339) || got.StaleAfterSeconds != 10800 {
		t.Fatalf("source due health = %#v", got)
	}
}

func TestHumanIdentityDirectorySourceDueList(t *testing.T) {
	now := time.Date(2026, 5, 25, 3, 0, 0, 0, time.UTC)
	store := humanidentity.NewHumanIdentityDirectoryStore()
	for _, policy := range []humanidentity.HumanIdentitySourcePolicy{
		{Source: "scim_due", ConnectorType: "scim", Enabled: true, ReconcileMissing: true, ExpectedIntervalSeconds: 3600, StaleAfterSeconds: 7200, Metadata: map[string]any{"connector_id": "scim_due_connector"}},
		{Source: "scim_recent", ConnectorType: "scim", Enabled: true, ExpectedIntervalSeconds: 3600},
		{Source: "hris_unobserved", ConnectorType: "hris", Enabled: true, ExpectedIntervalSeconds: 3600},
		{Source: "manual_disabled", ConnectorType: "manual", Enabled: false, ExpectedIntervalSeconds: 3600},
		{Source: "csv_unscheduled", ConnectorType: "csv", Enabled: true},
	} {
		if _, err := humanidentity.HumanIdentityDirectoryUpsertSourcePolicy(context.Background(), store, "tenant_lab_001", policy, now); err != nil {
			t.Fatalf("upsert source policy %s returned error: %v", policy.Source, err)
		}
	}
	if err := store.RecordSourceImport(context.Background(), humanidentity.HumanIdentitySourceState{
		TenantID:        "tenant_lab_001",
		Source:          "scim_due",
		Status:          "success",
		LastImportRunID: "human_import_run_due",
		Checkpoint:      "cursor_due",
		LastSuccessAt:   now.Add(-2 * time.Hour).UTC().Format(time.RFC3339),
		UpdatedAt:       now.Add(-2 * time.Hour).UTC().Format(time.RFC3339),
	}); err != nil {
		t.Fatalf("record due source state returned error: %v", err)
	}
	if err := store.RecordSourceImport(context.Background(), humanidentity.HumanIdentitySourceState{
		TenantID:        "tenant_lab_001",
		Source:          "scim_recent",
		Status:          "success",
		LastImportRunID: "human_import_run_recent",
		Checkpoint:      "cursor_recent",
		LastSuccessAt:   now.Add(-30 * time.Minute).UTC().Format(time.RFC3339),
		UpdatedAt:       now.Add(-30 * time.Minute).UTC().Format(time.RFC3339),
	}); err != nil {
		t.Fatalf("record recent source state returned error: %v", err)
	}
	result, err := humanidentity.HumanIdentityDirectorySourceDueList(context.Background(), store, "tenant_lab_001", now)
	if err != nil {
		t.Fatalf("source due list returned error: %v", err)
	}
	if result.TenantID != "tenant_lab_001" || result.CheckedAt != now.UTC().Format(time.RFC3339) || result.Count != 2 || len(result.Sources) != 2 {
		t.Fatalf("source due list = %#v, want two due sources", result)
	}
	if got := result.Sources[0]; got.Source != "hris_unobserved" || got.ConnectorType != "hris" || got.DueReason != "source_policy_unobserved" {
		t.Fatalf("unobserved due source = %#v", got)
	}
	if got := result.Sources[1]; got.Source != "scim_due" || got.ConnectorType != "scim" || !got.ReconcileMissing || got.DueReason != "source_import_due" || got.NextExpectedAt != now.Add(-time.Hour).UTC().Format(time.RFC3339) || got.LatestImportRunID != "human_import_run_due" || got.Checkpoint != "cursor_due" || got.StaleAfterSeconds != 7200 || fmt.Sprint(got.Metadata["connector_id"]) != "scim_due_connector" {
		t.Fatalf("observed due source = %#v", got)
	}
}

func TestHumanIdentityDirectoryListFiltersSourceStatusAndLimit(t *testing.T) {
	now := time.Date(2026, 5, 25, 1, 2, 3, 0, time.UTC)
	store := humanidentity.NewHumanIdentityDirectoryStore()
	for _, user := range []model.HumanIdentity{
		{ID: "human_filter_001", TenantID: "tenant_lab_001", Subject: "sub_filter_001", Email: stringPtr("filter001@example.jp"), Source: "scim", Status: "active", Metadata: map[string]any{"import_run_id": "import_filter_001"}},
		{ID: "human_filter_002", TenantID: "tenant_lab_001", Subject: "sub_filter_002", Email: stringPtr("filter002@example.jp"), Source: "scim", Status: "suspended", Metadata: map[string]any{"import_run_id": "import_filter_001"}},
		{ID: "human_filter_003", TenantID: "tenant_lab_001", Subject: "sub_filter_003", Email: stringPtr("filter003@example.jp"), Source: "hris", Status: "active", Metadata: map[string]any{"import_run_id": "import_filter_002"}},
	} {
		if _, err := store.Upsert(context.Background(), user, user.TenantID, now); err != nil {
			t.Fatalf("Upsert(%s) returned error: %v", user.ID, err)
		}
	}
	result, err := humanidentity.HumanIdentityDirectoryList(context.Background(), store, "tenant_lab_001", now, humanidentity.HumanIdentityDirectoryListOptions{
		Source:      "scim",
		Status:      "active",
		Subject:     "sub_filter_001",
		Email:       "filter001@example.jp",
		ImportRunID: "import_filter_001",
		Limit:       1,
	})
	if err != nil {
		t.Fatalf("humanidentity.HumanIdentityDirectoryList returned error: %v", err)
	}
	if result.Source != "scim" || result.Status != "active" || result.Subject != "sub_filter_001" || result.Email != "filter001@example.jp" || result.ImportRunID != "import_filter_001" || result.Limit != 1 || result.Count != 1 || result.ActiveCount != 1 || result.Identities[0].ID != "human_filter_001" {
		t.Fatalf("filtered result = %#v", result)
	}
}

func TestHumanIdentityDirectoryListUsesOpaqueCursor(t *testing.T) {
	now := time.Date(2026, 5, 25, 1, 2, 3, 0, time.UTC)
	store := humanidentity.NewHumanIdentityDirectoryStore()
	for _, user := range []model.HumanIdentity{
		{ID: "human_cursor_001", TenantID: "tenant_lab_001", Subject: "sub_cursor_001", Source: "scim", Status: "active"},
		{ID: "human_cursor_002", TenantID: "tenant_lab_001", Subject: "sub_cursor_002", Source: "scim", Status: "active"},
		{ID: "human_cursor_003", TenantID: "tenant_lab_001", Subject: "sub_cursor_003", Source: "scim", Status: "active"},
	} {
		if _, err := store.Upsert(context.Background(), user, user.TenantID, now); err != nil {
			t.Fatalf("Upsert(%s) returned error: %v", user.ID, err)
		}
	}
	first, err := humanidentity.HumanIdentityDirectoryList(context.Background(), store, "tenant_lab_001", now, humanidentity.HumanIdentityDirectoryListOptions{Limit: 2})
	if err != nil {
		t.Fatalf("first list returned error: %v", err)
	}
	if first.Count != 2 || first.NextCursor == "" || first.Identities[0].ID != "human_cursor_001" || first.Identities[1].ID != "human_cursor_002" {
		t.Fatalf("first page = %#v", first)
	}
	afterID, err := humanidentity.DecodeHumanIdentityDirectoryCursor(first.NextCursor)
	if err != nil {
		t.Fatalf("decode next cursor returned error: %v", err)
	}
	second, err := humanidentity.HumanIdentityDirectoryList(context.Background(), store, "tenant_lab_001", now, humanidentity.HumanIdentityDirectoryListOptions{Limit: 2, AfterID: afterID})
	if err != nil {
		t.Fatalf("second list returned error: %v", err)
	}
	if second.Count != 1 || second.NextCursor != "" || second.Identities[0].ID != "human_cursor_003" {
		t.Fatalf("second page = %#v", second)
	}
	if _, err := humanidentity.DecodeHumanIdentityDirectoryCursor("not valid cursor"); err == nil {
		t.Fatal("invalid human identity cursor accepted")
	}
}

func TestHumanIdentityDirectoryImportRunListSummarizesMetadata(t *testing.T) {
	now := time.Date(2026, 5, 25, 1, 2, 3, 0, time.UTC)
	store := humanidentity.NewHumanIdentityDirectoryStore()
	for _, user := range []model.HumanIdentity{
		{ID: "human_import_summary_001", TenantID: "tenant_lab_001", Subject: "sub_import_summary_001", Source: "scim", Status: "active", Metadata: map[string]any{"import_run_id": "human_import_summary_old", "import_source": "scim", "imported_at": "2026-05-25T01:00:00Z"}},
		{ID: "human_import_summary_002", TenantID: "tenant_lab_001", Subject: "sub_import_summary_002", Source: "scim", Status: "deleted", Metadata: map[string]any{"import_run_id": "human_import_summary_old", "import_source": "scim", "imported_at": "2026-05-25T01:01:00Z"}},
		{ID: "human_import_summary_003", TenantID: "tenant_lab_001", Subject: "sub_import_summary_003", Source: "scim", Status: "deleted", Metadata: map[string]any{"deactivated_by_import_run_id": "human_import_summary_new", "deactivated_by_import_source": "scim", "deactivated_at": "2026-05-25T02:00:00Z"}},
		{ID: "human_import_summary_other_tenant", TenantID: "tenant_other_001", Subject: "sub_import_summary_other", Source: "scim", Status: "active", Metadata: map[string]any{"import_run_id": "human_import_summary_other", "imported_at": "2026-05-25T03:00:00Z"}},
	} {
		if _, err := store.Upsert(context.Background(), user, user.TenantID, now); err != nil {
			t.Fatalf("Upsert(%s) returned error: %v", user.ID, err)
		}
	}
	result, err := humanidentity.HumanIdentityDirectoryImportRunList(context.Background(), store, "tenant_lab_001", humanidentity.HumanIdentityImportRunListOptions{Limit: 10})
	if err != nil {
		t.Fatalf("humanidentity.HumanIdentityDirectoryImportRunList returned error: %v", err)
	}
	if result.TenantID != "tenant_lab_001" || result.Limit != 10 || result.Count != 2 {
		t.Fatalf("import run list metadata = %#v", result)
	}
	if got := result.Runs[0]; got.ImportRunID != "human_import_summary_new" || got.Deactivated != 1 || got.Deleted != 1 || got.Upserted != 0 || got.ObservedAt != "2026-05-25T02:00:00Z" {
		t.Fatalf("new import run summary = %#v", got)
	}
	if got := result.Runs[1]; got.ImportRunID != "human_import_summary_old" || got.Upserted != 2 || got.Active != 1 || got.Deleted != 1 || got.Deactivated != 0 || got.ObservedAt != "2026-05-25T01:01:00Z" {
		t.Fatalf("old import run summary = %#v", got)
	}
	filteredRuns, err := humanidentity.HumanIdentityDirectoryImportRunList(context.Background(), store, "tenant_lab_001", humanidentity.HumanIdentityImportRunListOptions{Limit: 10, Source: "scim"})
	if err != nil {
		t.Fatalf("source-filtered import run list returned error: %v", err)
	}
	if filteredRuns.Source != "scim" || filteredRuns.Count != 2 {
		t.Fatalf("source-filtered import runs = %#v", filteredRuns)
	}
	sourceList, err := humanidentity.HumanIdentityDirectorySourceList(context.Background(), store, "tenant_lab_001", now)
	if err != nil {
		t.Fatalf("humanidentity.HumanIdentityDirectorySourceList returned error: %v", err)
	}
	if sourceList.Count != 1 || len(sourceList.Sources) != 1 {
		t.Fatalf("source list = %#v", sourceList)
	}
	if got := sourceList.Sources[0]; got.Source != "scim" || got.Total != 3 || got.Active != 1 || got.Deleted != 2 || got.ObservedAt != "2026-05-25T02:00:00Z" || got.LatestImportRunID != "human_import_summary_new" {
		t.Fatalf("source summary = %#v", got)
	}
	sourceHealth, err := humanidentity.HumanIdentityDirectorySourceHealth(context.Background(), store, "tenant_lab_001", time.Date(2026, 5, 25, 3, 0, 0, 0, time.UTC), 30*time.Minute)
	if err != nil {
		t.Fatalf("source health returned error: %v", err)
	}
	if sourceHealth.Status != "degraded" || sourceHealth.SourceCount != 1 || len(sourceHealth.Sources) != 1 || sourceHealth.Sources[0].Status != "degraded" || sourceHealth.Sources[0].AgeSeconds != 3600 {
		t.Fatalf("source health = %#v, want stale scim source", sourceHealth)
	}
	filteredByRun, err := humanidentity.HumanIdentityDirectoryList(context.Background(), store, "tenant_lab_001", now, humanidentity.HumanIdentityDirectoryListOptions{ImportRunID: "human_import_summary_new"})
	if err != nil {
		t.Fatalf("humanidentity.HumanIdentityDirectoryList by deactivation run returned error: %v", err)
	}
	if filteredByRun.Count != 1 || filteredByRun.Identities[0].ID != "human_import_summary_003" {
		t.Fatalf("deactivation import run filter = %#v", filteredByRun)
	}
	detail, found, err := humanidentity.HumanIdentityDirectoryImportRunDetail(context.Background(), store, "tenant_lab_001", "human_import_summary_old")
	if err != nil {
		t.Fatalf("humanidentity.HumanIdentityDirectoryImportRunDetail returned error: %v", err)
	}
	if !found || detail.ImportRunID != "human_import_summary_old" || detail.Summary.Upserted != 2 || len(detail.UpsertedIdentities) != 2 || len(detail.DeactivatedIdentities) != 0 {
		t.Fatalf("import run detail = %#v, found=%v", detail, found)
	}
	detail, found, err = humanidentity.HumanIdentityDirectoryImportRunDetail(context.Background(), store, "tenant_lab_001", "human_import_summary_new")
	if err != nil {
		t.Fatalf("deactivation detail returned error: %v", err)
	}
	if !found || detail.Summary.Deactivated != 1 || len(detail.DeactivatedIdentities) != 1 || detail.DeactivatedIdentities[0].ID != "human_import_summary_003" {
		t.Fatalf("deactivation detail = %#v, found=%v", detail, found)
	}
	if _, _, err := humanidentity.HumanIdentityDirectoryImportRunDetail(context.Background(), store, "tenant_lab_001", "bad/run"); err == nil {
		t.Fatal("unsafe import run detail ID accepted")
	}
	_, found, err = humanidentity.HumanIdentityDirectoryImportRunDetail(context.Background(), store, "tenant_lab_001", "human_import_summary_absent")
	if err != nil {
		t.Fatalf("absent detail returned error: %v", err)
	}
	if found {
		t.Fatal("absent import run detail reported found")
	}
	limited := humanidentity.SummarizeHumanIdentityImportRuns(resultRunSummaryUsersForTest(), humanidentity.HumanIdentityImportRunListOptions{Limit: 1})
	if len(limited) != 1 || limited[0].ImportRunID != "human_import_summary_new" {
		t.Fatalf("limited summaries = %#v", limited)
	}
	sourceOrder := humanidentity.SummarizeHumanIdentityImportRuns([]model.HumanIdentity{
		{ID: "human_import_summary_newer_source", TenantID: "tenant_lab_001", Subject: "sub_newer_source", Status: "active", Metadata: map[string]any{"import_run_id": "human_import_summary_source_order", "import_source": "aaa_newer", "import_checkpoint": "cursor_newer", "imported_at": "2026-05-25T02:00:00Z"}},
		{ID: "human_import_summary_older_source", TenantID: "tenant_lab_001", Subject: "sub_older_source", Status: "active", Metadata: map[string]any{"import_run_id": "human_import_summary_source_order", "import_source": "zzz_older", "import_checkpoint": "cursor_older", "imported_at": "2026-05-25T01:00:00Z"}},
	}, humanidentity.HumanIdentityImportRunListOptions{Limit: 10})
	if len(sourceOrder) != 1 || sourceOrder[0].Source != "aaa_newer" || sourceOrder[0].Checkpoint != "cursor_newer" || sourceOrder[0].ObservedAt != "2026-05-25T02:00:00Z" {
		t.Fatalf("source order summary = %#v, want latest source", sourceOrder)
	}
	sourceFiltered := humanidentity.SummarizeHumanIdentityImportRuns([]model.HumanIdentity{
		{ID: "human_import_summary_scim_filter", TenantID: "tenant_lab_001", Subject: "sub_scim_filter", Status: "active", Metadata: map[string]any{"import_run_id": "human_import_summary_scim_filter", "import_source": "scim", "imported_at": "2026-05-25T02:00:00Z"}},
		{ID: "human_import_summary_hris_filter", TenantID: "tenant_lab_001", Subject: "sub_hris_filter", Status: "active", Metadata: map[string]any{"import_run_id": "human_import_summary_hris_filter", "import_source": "hris", "imported_at": "2026-05-25T03:00:00Z"}},
		{ID: "human_import_summary_hris_deactivation", TenantID: "tenant_lab_001", Subject: "sub_hris_deactivation", Status: "deleted", Metadata: map[string]any{"deactivated_by_import_run_id": "human_import_summary_hris_deactivation", "deactivated_by_import_source": "hris", "deactivated_at": "2026-05-25T04:00:00Z"}},
	}, humanidentity.HumanIdentityImportRunListOptions{Limit: 10, Source: "scim"})
	if len(sourceFiltered) != 1 || sourceFiltered[0].ImportRunID != "human_import_summary_scim_filter" || sourceFiltered[0].Source != "scim" {
		t.Fatalf("source-filtered summaries = %#v, want only scim import run", sourceFiltered)
	}
}

func resultRunSummaryUsersForTest() []model.HumanIdentity {
	return []model.HumanIdentity{
		{ID: "human_import_summary_old", TenantID: "tenant_lab_001", Subject: "sub_old", Status: "active", Metadata: map[string]any{"import_run_id": "human_import_summary_old", "imported_at": "2026-05-25T01:00:00Z"}},
		{ID: "human_import_summary_new", TenantID: "tenant_lab_001", Subject: "sub_new", Status: "active", Metadata: map[string]any{"import_run_id": "human_import_summary_new", "imported_at": "2026-05-25T02:00:00Z"}},
	}
}

func TestNormalizeHumanIdentityRejectsInvalidInput(t *testing.T) {
	if _, err := humanidentity.NormalizeHumanIdentity(model.HumanIdentity{ID: "human_001", Subject: "sub_001", Status: "active"}, "tenant_lab_001", time.Now()); err != nil {
		t.Fatalf("valid identity rejected: %v", err)
	}
	if _, err := humanidentity.NormalizeHumanIdentity(model.HumanIdentity{ID: "human_001", Subject: "sub_001", Status: "blocked"}, "tenant_lab_001", time.Now()); err == nil {
		t.Fatal("invalid status accepted")
	}
	invalidTime := "not-a-time"
	if _, err := humanidentity.NormalizeHumanIdentity(model.HumanIdentity{ID: "human_001", Subject: "sub_001", Status: "active", ExpiresAt: &invalidTime}, "tenant_lab_001", time.Now()); err == nil {
		t.Fatal("invalid expires_at accepted")
	}
	if _, err := humanidentity.NormalizeHumanIdentity(model.HumanIdentity{ID: "human_001", TenantID: "tenant_a", Subject: "sub_001", Status: "active"}, "tenant_b", time.Now()); err == nil {
		t.Fatal("tenant mismatch accepted")
	}
}

func TestNormalizeHumanIdentityImportRunIDBoundsTraceLabel(t *testing.T) {
	now := time.Date(2026, 5, 25, 1, 2, 3, 0, time.UTC)
	generated, err := humanidentity.NormalizeHumanIdentityImportRunID("", now)
	if err != nil {
		t.Fatalf("empty import_run_id returned error: %v", err)
	}
	if !strings.HasPrefix(generated, "human_import_") {
		t.Fatalf("generated import_run_id = %q, want human_import_ prefix", generated)
	}
	provided, err := humanidentity.NormalizeHumanIdentityImportRunID(" scim-2026.05.25:run@001 ", now)
	if err != nil {
		t.Fatalf("provided import_run_id returned error: %v", err)
	}
	if provided != "scim-2026.05.25:run@001" {
		t.Fatalf("provided import_run_id = %q, want trimmed value", provided)
	}
	if _, err := humanidentity.NormalizeHumanIdentityImportRunID("bad/run", now); err == nil {
		t.Fatal("import_run_id with slash accepted")
	}
	if _, err := humanidentity.NormalizeHumanIdentityImportRunID(strings.Repeat("a", humanidentity.MaxHumanIdentityImportRunIDLength+1), now); err == nil {
		t.Fatal("oversized import_run_id accepted")
	}
}

func TestHumanIdentityDirectoryImportAppliesSourceAndBounds(t *testing.T) {
	now := time.Date(2026, 5, 25, 1, 2, 3, 0, time.UTC)
	store := humanidentity.NewHumanIdentityDirectoryStore()
	result, err := humanidentity.HumanIdentityDirectoryImport(context.Background(), store, humanidentity.HumanIdentityDirectoryImportRequest{
		Source:      "scim",
		ImportRunID: "human_import_run_unit_001",
		Checkpoint:  "cursor_unit_001",
		Identities: []model.HumanIdentity{
			{ID: "human_import_unit_001", Subject: "sub_human_import_unit_001"},
			{ID: "human_import_unit_002", Subject: "sub_human_import_unit_002", Status: "suspended"},
		},
	}, "tenant_lab_001", now)
	if err != nil {
		t.Fatalf("humanidentity.HumanIdentityDirectoryImport returned error: %v", err)
	}
	if result.Requested != 2 || result.Upserted != 2 || result.ActiveCount != 1 {
		t.Fatalf("import result = %#v, want requested=2 upserted=2 active=1", result)
	}
	if result.ImportRunID != "human_import_run_unit_001" {
		t.Fatalf("import_run_id = %q, want caller provided ID", result.ImportRunID)
	}
	if result.Checkpoint != "cursor_unit_001" {
		t.Fatalf("checkpoint = %q, want caller provided cursor", result.Checkpoint)
	}
	if result.Identities[0].Source != "scim" || result.Identities[1].Source != "scim" {
		t.Fatalf("import source not applied: %#v", result.Identities)
	}
	if result.Identities[0].Metadata["import_run_id"] != "human_import_run_unit_001" || result.Identities[0].Metadata["import_source"] != "scim" || result.Identities[0].Metadata["import_checkpoint"] != "cursor_unit_001" || result.Identities[0].Metadata["imported_at"] != now.UTC().Format(time.RFC3339) {
		t.Fatalf("import metadata not applied: %#v", result.Identities[0].Metadata)
	}
	states, err := store.ListSourceStates(context.Background(), "tenant_lab_001")
	if err != nil {
		t.Fatalf("ListSourceStates returned error: %v", err)
	}
	if len(states) != 1 || states[0].Source != "scim" || states[0].Status != "success" || states[0].LastImportRunID != "human_import_run_unit_001" || states[0].Checkpoint != "cursor_unit_001" || states[0].Requested != 2 || states[0].Upserted != 2 || states[0].ActiveCount != 1 {
		t.Fatalf("source states = %#v, want scim success checkpoint", states)
	}
	if _, err := humanidentity.HumanIdentityDirectoryImport(context.Background(), store, humanidentity.HumanIdentityDirectoryImportRequest{}, "tenant_lab_001", now); err == nil {
		t.Fatal("empty import accepted")
	}
	tooMany := make([]model.HumanIdentity, humanidentity.MaxHumanIdentityImportItems+1)
	for index := range tooMany {
		tooMany[index] = model.HumanIdentity{ID: "human_too_many_" + randomEdgeID("", now.Add(time.Duration(index))), Subject: "sub_too_many"}
	}
	if _, err := humanidentity.HumanIdentityDirectoryImport(context.Background(), store, humanidentity.HumanIdentityDirectoryImportRequest{Identities: tooMany}, "tenant_lab_001", now); err == nil {
		t.Fatal("oversized import accepted")
	}
	if _, err := humanidentity.HumanIdentityDirectoryImport(context.Background(), store, humanidentity.HumanIdentityDirectoryImportRequest{
		Identities: []model.HumanIdentity{
			{ID: "human_duplicate_001", Subject: "sub_duplicate_001"},
			{ID: " human_duplicate_001 ", Subject: "sub_duplicate_002"},
		},
	}, "tenant_lab_001", now); err == nil {
		t.Fatal("duplicate identity import accepted")
	}
	if _, err := humanidentity.HumanIdentityDirectoryImport(context.Background(), store, humanidentity.HumanIdentityDirectoryImportRequest{
		ImportRunID: "bad/run",
		Identities: []model.HumanIdentity{
			{ID: "human_bad_run_001", Subject: "sub_bad_run_001"},
		},
	}, "tenant_lab_001", now); err == nil {
		t.Fatal("unsafe import_run_id accepted")
	}
	if _, err := humanidentity.HumanIdentityDirectoryImport(context.Background(), store, humanidentity.HumanIdentityDirectoryImportRequest{
		Checkpoint: strings.Repeat("x", humanidentity.MaxHumanIdentitySourceCheckpoint+1),
		Identities: []model.HumanIdentity{
			{ID: "human_bad_checkpoint_001", Subject: "sub_bad_checkpoint_001"},
		},
	}, "tenant_lab_001", now); err == nil {
		t.Fatal("oversized checkpoint accepted")
	}
}

func TestHumanIdentityDirectoryImportReconcilesMissingBySource(t *testing.T) {
	now := time.Date(2026, 5, 25, 1, 2, 3, 0, time.UTC)
	store := humanidentity.NewHumanIdentityDirectoryStore()
	for _, user := range []model.HumanIdentity{
		{ID: "human_keep_001", TenantID: "tenant_lab_001", Subject: "sub_keep_001", Source: "scim", Status: "active"},
		{ID: "human_missing_001", TenantID: "tenant_lab_001", Subject: "sub_missing_001", Source: "scim", Status: "active"},
		{ID: "human_other_source_001", TenantID: "tenant_lab_001", Subject: "sub_other_001", Source: "hris", Status: "active"},
	} {
		if _, err := store.Upsert(context.Background(), user, user.TenantID, now); err != nil {
			t.Fatalf("seed %s returned error: %v", user.ID, err)
		}
	}
	result, err := humanidentity.HumanIdentityDirectoryImport(context.Background(), store, humanidentity.HumanIdentityDirectoryImportRequest{
		Source:           "scim",
		ImportRunID:      "human_import_run_reconcile_001",
		Checkpoint:       "cursor_reconcile_001",
		ReconcileMissing: boolPtr(true),
		Identities: []model.HumanIdentity{
			{ID: "human_keep_001", Subject: "sub_keep_001", Status: "active"},
		},
	}, "tenant_lab_001", now)
	if err != nil {
		t.Fatalf("humanidentity.HumanIdentityDirectoryImport returned error: %v", err)
	}
	if result.Upserted != 1 || result.Deactivated != 1 || len(result.DeactivatedIdentities) != 1 {
		t.Fatalf("import result = %#v, want one upsert and one deactivate", result)
	}
	if result.DeactivatedIdentities[0].Metadata["deactivated_by_import_run_id"] != "human_import_run_reconcile_001" {
		t.Fatalf("deactivation metadata = %#v, want import run marker", result.DeactivatedIdentities[0].Metadata)
	}
	if result.DeactivatedIdentities[0].Metadata["deactivated_by_import_checkpoint"] != "cursor_reconcile_001" {
		t.Fatalf("deactivation metadata = %#v, want checkpoint marker", result.DeactivatedIdentities[0].Metadata)
	}
	items, err := store.List(context.Background(), "tenant_lab_001")
	if err != nil {
		t.Fatalf("List returned error: %v", err)
	}
	statuses := map[string]string{}
	for _, item := range items {
		statuses[item.ID] = item.Status
	}
	if statuses["human_keep_001"] != "active" || statuses["human_missing_001"] != "deleted" || statuses["human_other_source_001"] != "active" {
		t.Fatalf("statuses after reconcile = %#v", statuses)
	}
	if _, err := humanidentity.HumanIdentityDirectoryImport(context.Background(), store, humanidentity.HumanIdentityDirectoryImportRequest{
		Source:           "scim",
		ReconcileMissing: boolPtr(true),
		Identities: []model.HumanIdentity{
			{ID: "human_mixed_source_001", Subject: "sub_mixed_source_001", Source: "hris"},
		},
	}, "tenant_lab_001", now); err == nil {
		t.Fatal("mixed source reconcile import accepted")
	}
}

func TestHumanIdentityDirectoryImportUsesSourcePolicyReconcileDefault(t *testing.T) {
	now := time.Date(2026, 5, 25, 1, 2, 3, 0, time.UTC)
	store := humanidentity.NewHumanIdentityDirectoryStore()
	if _, err := humanidentity.HumanIdentityDirectoryUpsertSourcePolicy(context.Background(), store, "tenant_lab_001", humanidentity.HumanIdentitySourcePolicy{
		Source:           "scim",
		ConnectorType:    "scim",
		Enabled:          true,
		ReconcileMissing: true,
	}, now); err != nil {
		t.Fatalf("upsert source policy returned error: %v", err)
	}
	for _, user := range []model.HumanIdentity{
		{ID: "human_policy_keep_001", TenantID: "tenant_lab_001", Subject: "sub_policy_keep_001", Source: "scim", Status: "active"},
		{ID: "human_policy_missing_001", TenantID: "tenant_lab_001", Subject: "sub_policy_missing_001", Source: "scim", Status: "active"},
	} {
		if _, err := store.Upsert(context.Background(), user, user.TenantID, now); err != nil {
			t.Fatalf("seed %s returned error: %v", user.ID, err)
		}
	}
	result, err := humanidentity.HumanIdentityDirectoryImport(context.Background(), store, humanidentity.HumanIdentityDirectoryImportRequest{
		Source: "scim",
		Identities: []model.HumanIdentity{
			{ID: "human_policy_keep_001", Subject: "sub_policy_keep_001", Status: "active"},
		},
	}, "tenant_lab_001", now)
	if err != nil {
		t.Fatalf("source policy default import returned error: %v", err)
	}
	if !result.ReconcileMissing || result.Deactivated != 1 {
		t.Fatalf("source policy default import = %#v, want reconcile default with one deactivation", result)
	}
	if _, err := store.Upsert(context.Background(), model.HumanIdentity{ID: "human_policy_missing_002", TenantID: "tenant_lab_001", Subject: "sub_policy_missing_002", Source: "scim", Status: "active"}, "tenant_lab_001", now); err != nil {
		t.Fatalf("seed explicit override identity returned error: %v", err)
	}
	result, err = humanidentity.HumanIdentityDirectoryImport(context.Background(), store, humanidentity.HumanIdentityDirectoryImportRequest{
		Source:           "scim",
		ReconcileMissing: boolPtr(false),
		Identities: []model.HumanIdentity{
			{ID: "human_policy_keep_001", Subject: "sub_policy_keep_001", Status: "active"},
		},
	}, "tenant_lab_001", now)
	if err != nil {
		t.Fatalf("explicit non-reconcile import returned error: %v", err)
	}
	if result.ReconcileMissing || result.Deactivated != 0 {
		t.Fatalf("explicit non-reconcile import = %#v, want policy override false", result)
	}
}

func TestHumanIdentityDirectoryImportDryRunDoesNotMutate(t *testing.T) {
	now := time.Date(2026, 5, 25, 1, 2, 3, 0, time.UTC)
	store := humanidentity.NewHumanIdentityDirectoryStore()
	if _, err := store.Upsert(context.Background(), model.HumanIdentity{
		ID:       "human_dry_missing_001",
		TenantID: "tenant_lab_001",
		Subject:  "sub_dry_missing_001",
		Source:   "scim",
		Status:   "active",
	}, "tenant_lab_001", now); err != nil {
		t.Fatalf("seed returned error: %v", err)
	}
	result, err := humanidentity.HumanIdentityDirectoryImport(context.Background(), store, humanidentity.HumanIdentityDirectoryImportRequest{
		Source:           "scim",
		ImportRunID:      "human_import_run_dry_001",
		Checkpoint:       "cursor_dry_001",
		DryRun:           true,
		ReconcileMissing: boolPtr(true),
		Identities: []model.HumanIdentity{
			{ID: "human_dry_new_001", Subject: "sub_dry_new_001", Status: "active"},
		},
	}, "tenant_lab_001", now)
	if err != nil {
		t.Fatalf("humanidentity.HumanIdentityDirectoryImport returned error: %v", err)
	}
	if !result.DryRun || result.Upserted != 1 || result.Deactivated != 1 {
		t.Fatalf("dry-run import result = %#v, want dry-run one upsert and one deactivate", result)
	}
	if result.ImportRunID != "human_import_run_dry_001" || result.Identities[0].Metadata["import_run_id"] != "human_import_run_dry_001" {
		t.Fatalf("dry-run import run metadata = %#v / %#v", result.ImportRunID, result.Identities[0].Metadata)
	}
	if result.Checkpoint != "cursor_dry_001" || result.Identities[0].Metadata["import_checkpoint"] != "cursor_dry_001" {
		t.Fatalf("dry-run checkpoint metadata = %#v / %#v", result.Checkpoint, result.Identities[0].Metadata)
	}
	items, err := store.List(context.Background(), "tenant_lab_001")
	if err != nil {
		t.Fatalf("List returned error: %v", err)
	}
	if len(items) != 1 || items[0].ID != "human_dry_missing_001" || items[0].Status != "active" {
		t.Fatalf("dry-run mutated store: %#v", items)
	}
	states, err := store.ListSourceStates(context.Background(), "tenant_lab_001")
	if err != nil {
		t.Fatalf("ListSourceStates returned error: %v", err)
	}
	if len(states) != 0 {
		t.Fatalf("dry-run recorded source state: %#v", states)
	}
}

func TestHumanIdentityDirectoryImportRespectsDisabledSourcePolicy(t *testing.T) {
	now := time.Date(2026, 5, 25, 1, 2, 3, 0, time.UTC)
	store := humanidentity.NewHumanIdentityDirectoryStore()
	if _, err := humanidentity.HumanIdentityDirectoryUpsertSourcePolicy(context.Background(), store, "tenant_lab_001", humanidentity.HumanIdentitySourcePolicy{
		Source:        "scim",
		ConnectorType: "scim",
		Enabled:       false,
	}, now); err != nil {
		t.Fatalf("upsert disabled source policy returned error: %v", err)
	}
	_, err := humanidentity.HumanIdentityDirectoryImport(context.Background(), store, humanidentity.HumanIdentityDirectoryImportRequest{
		Source: "scim",
		Identities: []model.HumanIdentity{
			{ID: "human_disabled_policy_001", Subject: "sub_disabled_policy_001", Status: "active"},
		},
	}, "tenant_lab_001", now)
	if err == nil || !strings.Contains(err.Error(), "disabled by source policy") {
		t.Fatalf("disabled source policy import error = %v, want disabled policy rejection", err)
	}
	result, err := humanidentity.HumanIdentityDirectoryImport(context.Background(), store, humanidentity.HumanIdentityDirectoryImportRequest{
		Source: "scim",
		DryRun: true,
		Identities: []model.HumanIdentity{
			{ID: "human_disabled_policy_dry_001", Subject: "sub_disabled_policy_dry_001", Status: "active"},
		},
	}, "tenant_lab_001", now)
	if err != nil {
		t.Fatalf("dry-run disabled source policy import returned error: %v", err)
	}
	if !result.DryRun || result.Upserted != 1 {
		t.Fatalf("dry-run disabled source policy result = %#v", result)
	}
	items, err := store.List(context.Background(), "tenant_lab_001")
	if err != nil {
		t.Fatalf("List returned error: %v", err)
	}
	if len(items) != 0 {
		t.Fatalf("disabled policy imports mutated store: %#v", items)
	}
}

func TestHumanIdentityDirectoryImportValidationFailureDoesNotMutate(t *testing.T) {
	now := time.Date(2026, 5, 25, 1, 2, 3, 0, time.UTC)
	store := humanidentity.NewHumanIdentityDirectoryStore()
	_, err := humanidentity.HumanIdentityDirectoryImport(context.Background(), store, humanidentity.HumanIdentityDirectoryImportRequest{
		Source: "scim",
		Identities: []model.HumanIdentity{
			{ID: "human_valid_before_error_001", Subject: "sub_valid_before_error_001", Status: "active"},
			{ID: "human_invalid_after_valid_001", Subject: "sub_invalid_after_valid_001", Status: "blocked"},
		},
	}, "tenant_lab_001", now)
	if err == nil {
		t.Fatal("invalid import accepted")
	}
	items, listErr := store.List(context.Background(), "tenant_lab_001")
	if listErr != nil {
		t.Fatalf("List returned error: %v", listErr)
	}
	if len(items) != 0 {
		t.Fatalf("validation failure partially mutated store: %#v", items)
	}
}
