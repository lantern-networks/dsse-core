package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/lantern-networks/dsse-core/enrolledinventory"
	"github.com/lantern-networks/dsse-core/revocation"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	humanidentity "github.com/lantern-networks/dsse-core/humanidentity"

	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"

	_ "github.com/lib/pq"
)

func TestSetupEdgeHumanIdentityDirectoryPostgresE2E(t *testing.T) {
	dsn := os.Getenv("POSTGRES_QUEUE_E2E_DSN")
	if dsn == "" {
		t.Skip("POSTGRES_QUEUE_E2E_DSN is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("sql.Open returned error: %v", err)
	}
	if err := db.PingContext(ctx); err != nil {
		t.Fatalf("PingContext returned error: %v", err)
	}
	resetPostgresExportTaskQueueTables(t, ctx, db)
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanupCancel()
		resetPostgresExportTaskQueueTables(t, cleanupCtx, db)
		_ = db.Close()
	})

	store, closeFn, err := setupEdgeHumanIdentityDirectory(ctx, edgeHumanIdentityDirectoryConfig{
		Mode:          "postgres",
		DSN:           dsn,
		MigrationDir:  filepath.Join("..", "..", "migrations"),
		RunMigrations: true,
	})
	if err != nil {
		t.Fatalf("setupEdgeHumanIdentityDirectory returned error: %v", err)
	}
	t.Cleanup(func() {
		if err := closeFn(); err != nil {
			t.Fatalf("close human identity directory: %v", err)
		}
	})

	now := time.Date(2026, 5, 25, 1, 2, 3, 0, time.UTC)
	expiresAt := now.Add(time.Hour).Format(time.RFC3339)
	if _, err := store.Upsert(ctx, model.HumanIdentity{
		ID:        "human_pg_active_001",
		Subject:   "sub_human_pg_active_001",
		Email:     stringPtr("human-active@example.jp"),
		Source:    "idp",
		Status:    "active",
		ExpiresAt: &expiresAt,
	}, "tenant_lab_001", now); err != nil {
		t.Fatalf("upsert active human returned error: %v", err)
	}
	if _, err := store.Upsert(ctx, model.HumanIdentity{
		ID:      "human_pg_suspended_001",
		Subject: "sub_human_pg_suspended_001",
		Source:  "idp",
		Status:  "suspended",
	}, "tenant_lab_001", now); err != nil {
		t.Fatalf("upsert suspended human returned error: %v", err)
	}

	items, err := store.List(ctx, "tenant_lab_001")
	if err != nil {
		t.Fatalf("list human identities returned error: %v", err)
	}
	if got, want := len(items), 2; got != want {
		t.Fatalf("listed human identities = %d, want %d", got, want)
	}
	stats, err := store.Stats(ctx, "tenant_lab_001", now)
	if err != nil {
		t.Fatalf("human identity stats returned error: %v", err)
	}
	if stats.Total != 2 || stats.Active != 1 {
		t.Fatalf("human identity stats = %#v, want total=2 active=1", stats)
	}

	var rows int
	if err := db.QueryRowContext(ctx, "SELECT count(*) FROM human_identities WHERE tenant_id = $1", "tenant_lab_001").Scan(&rows); err != nil {
		t.Fatalf("query human_identities count: %v", err)
	}
	if rows != 2 {
		t.Fatalf("human_identities rows = %d, want 2", rows)
	}
}

func TestPostgresHumanIdentityDirectoryImportRollsBackOnWriteFailureE2E(t *testing.T) {
	dsn := os.Getenv("POSTGRES_QUEUE_E2E_DSN")
	if dsn == "" {
		t.Skip("POSTGRES_QUEUE_E2E_DSN is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("sql.Open returned error: %v", err)
	}
	if err := db.PingContext(ctx); err != nil {
		t.Fatalf("PingContext returned error: %v", err)
	}
	resetPostgresExportTaskQueueTables(t, ctx, db)
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanupCancel()
		resetPostgresExportTaskQueueTables(t, cleanupCtx, db)
		_ = db.Close()
	})

	store, closeFn, err := setupEdgeHumanIdentityDirectory(ctx, edgeHumanIdentityDirectoryConfig{
		Mode:          "postgres",
		DSN:           dsn,
		MigrationDir:  filepath.Join("..", "..", "migrations"),
		RunMigrations: true,
	})
	if err != nil {
		t.Fatalf("setupEdgeHumanIdentityDirectory returned error: %v", err)
	}
	t.Cleanup(func() {
		if err := closeFn(); err != nil {
			t.Fatalf("close human identity directory: %v", err)
		}
	})
	if _, err := db.ExecContext(ctx, `
CREATE OR REPLACE FUNCTION human_identity_import_fail_for_test() RETURNS trigger AS $$
BEGIN
	IF NEW.human_identity_id = 'human_tx_fail_002' THEN
		RAISE EXCEPTION 'forced human identity import failure';
	END IF;
	RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER human_identity_import_fail_for_test
BEFORE INSERT OR UPDATE ON human_identities
FOR EACH ROW EXECUTE FUNCTION human_identity_import_fail_for_test();
`); err != nil {
		t.Fatalf("create failure trigger: %v", err)
	}

	_, err = humanidentity.HumanIdentityDirectoryImport(ctx, store, humanidentity.HumanIdentityDirectoryImportRequest{
		Source:      "scim",
		ImportRunID: "human_import_run_tx_001",
		Identities: []model.HumanIdentity{
			{ID: "human_tx_ok_001", Subject: "sub_human_tx_ok_001", Status: "active"},
			{ID: "human_tx_fail_002", Subject: "sub_human_tx_fail_002", Status: "active"},
		},
	}, "tenant_lab_001", time.Date(2026, 5, 25, 1, 2, 3, 0, time.UTC))
	if err == nil {
		t.Fatal("import with forced database failure succeeded")
	}
	var rows int
	if err := db.QueryRowContext(ctx, "SELECT count(*) FROM human_identities WHERE tenant_id = $1", "tenant_lab_001").Scan(&rows); err != nil {
		t.Fatalf("query human identities count: %v", err)
	}
	if rows != 0 {
		t.Fatalf("human identity import left %d rows after rollback, want 0", rows)
	}
}

func TestAdminHumanIdentityEndpointPostgresE2E(t *testing.T) {
	dsn := os.Getenv("POSTGRES_QUEUE_E2E_DSN")
	if dsn == "" {
		t.Skip("POSTGRES_QUEUE_E2E_DSN is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("sql.Open returned error: %v", err)
	}
	if err := db.PingContext(ctx); err != nil {
		t.Fatalf("PingContext returned error: %v", err)
	}
	resetPostgresExportTaskQueueTables(t, ctx, db)
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanupCancel()
		resetPostgresExportTaskQueueTables(t, cleanupCtx, db)
		_ = db.Close()
	})

	store, closeFn, err := setupEdgeHumanIdentityDirectory(ctx, edgeHumanIdentityDirectoryConfig{
		Mode:          "postgres",
		DSN:           dsn,
		MigrationDir:  filepath.Join("..", "..", "migrations"),
		RunMigrations: true,
	})
	if err != nil {
		t.Fatalf("setupEdgeHumanIdentityDirectory returned error: %v", err)
	}
	t.Cleanup(func() {
		if err := closeFn(); err != nil {
			t.Fatalf("close human identity directory: %v", err)
		}
	})

	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	handler := newServerWithConfig(serverConfig{
		Evaluator:       testEvaluator(),
		Writer:          writer,
		HumanIdentities: store,
		LabMode:         boolPtr(true),
	})

	body := []byte(`{
		"id":"human_endpoint_pg_001",
		"subject":"sub_human_endpoint_pg_001",
		"email":"human-endpoint@example.jp",
		"display_name":"Human Endpoint",
		"source":"idp",
		"status":"active"
	}`)
	req := httptest.NewRequest(http.MethodPost, "/admin/human-identities", bytes.NewReader(body))
	req.Header.Set("content-type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST status = %d, want %d, body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/admin/human-identities", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET status = %d, want %d, body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var list humanidentity.HumanIdentityDirectoryListResponse
	if err := json.NewDecoder(rec.Body).Decode(&list); err != nil {
		t.Fatalf("decode human identity list response: %v", err)
	}
	if list.Count != 1 || list.ActiveCount != 1 || len(list.Identities) != 1 {
		t.Fatalf("list response = %#v, want one active human identity", list)
	}
	if list.Identities[0].ID != "human_endpoint_pg_001" {
		t.Fatalf("listed identity ID = %q", list.Identities[0].ID)
	}

	req = httptest.NewRequest(http.MethodGet, "/admin/human-identities?subject=sub_human_endpoint_pg_001&email=human-endpoint%40example.jp", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("subject/email filtered GET status = %d, want %d, body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	list = humanidentity.HumanIdentityDirectoryListResponse{}
	if err := json.NewDecoder(rec.Body).Decode(&list); err != nil {
		t.Fatalf("decode subject/email filtered human identity list response: %v", err)
	}
	if list.Subject != "sub_human_endpoint_pg_001" || list.Email != "human-endpoint@example.jp" || list.Count != 1 || list.Identities[0].ID != "human_endpoint_pg_001" {
		t.Fatalf("subject/email filtered list = %#v, want initial identity", list)
	}

	importBody := []byte(`{
		"source":"scim",
		"import_run_id":"human_import_run_pg_001",
		"checkpoint":"cursor_pg_endpoint_001",
		"identities":[
			{"id":"human_endpoint_pg_import_001","subject":"sub_human_endpoint_pg_import_001","status":"active"},
			{"id":"human_endpoint_pg_import_002","subject":"sub_human_endpoint_pg_import_002","status":"deleted"}
		]
	}`)
	req = httptest.NewRequest(http.MethodPost, "/admin/human-identities/import", bytes.NewReader(importBody))
	req.Header.Set("content-type", "application/json")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("import status = %d, want %d, body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var importResult humanidentity.HumanIdentityDirectoryImportResponse
	if err := json.NewDecoder(rec.Body).Decode(&importResult); err != nil {
		t.Fatalf("decode human identity import response: %v", err)
	}
	if importResult.Upserted != 2 || importResult.ActiveCount != 1 {
		t.Fatalf("import result = %#v, want two upserted and one active", importResult)
	}
	if importResult.ImportRunID != "human_import_run_pg_001" {
		t.Fatalf("import_run_id = %q, want postgres endpoint run ID", importResult.ImportRunID)
	}
	if importResult.Checkpoint != "cursor_pg_endpoint_001" {
		t.Fatalf("checkpoint = %q, want postgres endpoint cursor", importResult.Checkpoint)
	}

	req = httptest.NewRequest(http.MethodGet, "/admin/human-identities", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET after import status = %d, want %d, body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	list = humanidentity.HumanIdentityDirectoryListResponse{}
	if err := json.NewDecoder(rec.Body).Decode(&list); err != nil {
		t.Fatalf("decode human identity list response after import: %v", err)
	}
	if list.Count != 3 || list.ActiveCount != 2 {
		t.Fatalf("list after import = %#v, want count=3 active=2", list)
	}

	req = httptest.NewRequest(http.MethodGet, "/admin/human-identities?import_run_id=human_import_run_pg_001", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("import run filtered GET status = %d, want %d, body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	list = humanidentity.HumanIdentityDirectoryListResponse{}
	if err := json.NewDecoder(rec.Body).Decode(&list); err != nil {
		t.Fatalf("decode import run filtered human identity list response: %v", err)
	}
	if list.ImportRunID != "human_import_run_pg_001" || list.Count != 2 || list.ActiveCount != 1 {
		t.Fatalf("import run filtered list = %#v, want imported identities", list)
	}

	req = httptest.NewRequest(http.MethodGet, "/admin/human-identities/import-runs?source=scim&limit=10", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("import run summary GET status = %d, want %d, body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var importRuns humanidentity.HumanIdentityImportRunListResponse
	if err := json.NewDecoder(rec.Body).Decode(&importRuns); err != nil {
		t.Fatalf("decode import run summary response: %v", err)
	}
	foundImportRun := false
	for _, run := range importRuns.Runs {
		if run.ImportRunID == "human_import_run_pg_001" {
			foundImportRun = true
			if run.Source != "scim" || run.Checkpoint != "cursor_pg_endpoint_001" || run.Upserted != 2 || run.Active != 1 || run.Deleted != 1 {
				t.Fatalf("postgres import run summary = %#v, want upserted=2 active=1 deleted=1", run)
			}
		}
	}
	if importRuns.Source != "scim" {
		t.Fatalf("postgres import run source filter = %q, want scim", importRuns.Source)
	}
	if !foundImportRun {
		t.Fatalf("postgres import run summary missing run: %#v", importRuns)
	}

	req = httptest.NewRequest(http.MethodGet, "/admin/human-identities/sources", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("source summary GET status = %d, want %d, body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var sources humanidentity.HumanIdentitySourceListResponse
	if err := json.NewDecoder(rec.Body).Decode(&sources); err != nil {
		t.Fatalf("decode source summary response: %v", err)
	}
	if sources.TenantID != "tenant_lab_001" || sources.Count != 2 || len(sources.Sources) != 2 {
		t.Fatalf("source summaries = %#v", sources)
	}
	if sources.Sources[0].Source != "idp" || sources.Sources[0].Total != 1 || sources.Sources[0].Active != 1 {
		t.Fatalf("idp source summary = %#v", sources.Sources[0])
	}
	if sources.Sources[1].Source != "scim" || sources.Sources[1].Total != 2 || sources.Sources[1].Active != 1 || sources.Sources[1].Deleted != 1 {
		t.Fatalf("scim source summary = %#v, want total=2 active=1 deleted=1", sources.Sources[1])
	}
	if sources.Sources[1].ObservedAt == "" || sources.Sources[1].LatestImportRunID != "human_import_run_pg_001" {
		t.Fatalf("scim source observation = %#v, want latest import run", sources.Sources[1])
	}
	policyBody := []byte(`{
		"source":"scim",
		"connector_type":"scim",
		"enabled":true,
		"reconcile_missing":true,
		"expected_interval_seconds":3600,
		"stale_after_seconds":7200,
		"metadata":{"connector_id":"postgres_scim"}
	}`)
	req = httptest.NewRequest(http.MethodPost, "/admin/human-identities/sources/policies", bytes.NewReader(policyBody))
	req.Header.Set("content-type", "application/json")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("source policy POST status = %d, want %d, body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var sourcePolicy humanidentity.HumanIdentitySourcePolicy
	if err := json.NewDecoder(rec.Body).Decode(&sourcePolicy); err != nil {
		t.Fatalf("decode source policy response: %v", err)
	}
	if sourcePolicy.TenantID != "tenant_lab_001" || sourcePolicy.Source != "scim" || sourcePolicy.ConnectorType != "scim" || !sourcePolicy.Enabled || !sourcePolicy.ReconcileMissing || sourcePolicy.StaleAfterSeconds != 7200 {
		t.Fatalf("source policy = %#v", sourcePolicy)
	}
	req = httptest.NewRequest(http.MethodGet, "/admin/human-identities/sources/policies", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("source policy GET status = %d, want %d, body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var sourcePolicies humanidentity.HumanIdentitySourcePolicyListResponse
	if err := json.NewDecoder(rec.Body).Decode(&sourcePolicies); err != nil {
		t.Fatalf("decode source policy list response: %v", err)
	}
	if sourcePolicies.TenantID != "tenant_lab_001" || sourcePolicies.Count != 1 || len(sourcePolicies.Policies) != 1 || sourcePolicies.Policies[0].Source != "scim" {
		t.Fatalf("source policies = %#v, want scim policy", sourcePolicies)
	}
	req = httptest.NewRequest(http.MethodGet, "/admin/human-identities/sources/due", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("source due GET status = %d, want %d, body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var sourceDue humanidentity.HumanIdentitySourceDueListResponse
	if err := json.NewDecoder(rec.Body).Decode(&sourceDue); err != nil {
		t.Fatalf("decode source due response: %v", err)
	}
	if sourceDue.TenantID != "tenant_lab_001" || sourceDue.Count != 0 || len(sourceDue.Sources) != 0 {
		t.Fatalf("source due = %#v, want no due sources immediately after import", sourceDue)
	}
	req = httptest.NewRequest(http.MethodGet, "/admin/human-identities/sources/health", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("source health GET status = %d, want %d, body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var sourceHealth humanidentity.HumanIdentitySourceHealthResponse
	if err := json.NewDecoder(rec.Body).Decode(&sourceHealth); err != nil {
		t.Fatalf("decode source health response: %v", err)
	}
	if sourceHealth.TenantID != "tenant_lab_001" || sourceHealth.SourceCount != 2 || len(sourceHealth.Sources) != 2 {
		t.Fatalf("source health = %#v, want two sources", sourceHealth)
	}
	if sourceHealth.Sources[1].Source != "scim" || !sourceHealth.Sources[1].Configured || sourceHealth.Sources[1].ConnectorType != "scim" || sourceHealth.Sources[1].StaleAfterSeconds != 7200 {
		t.Fatalf("scim source health policy fields = %#v", sourceHealth.Sources[1])
	}
	req = httptest.NewRequest(http.MethodGet, "/admin/human-identities/sources/state", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("source state GET status = %d, want %d, body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var sourceState humanidentity.HumanIdentitySourceStateListResponse
	if err := json.NewDecoder(rec.Body).Decode(&sourceState); err != nil {
		t.Fatalf("decode source state response: %v", err)
	}
	if sourceState.TenantID != "tenant_lab_001" || sourceState.Count != 1 || len(sourceState.States) != 1 || sourceState.States[0].Source != "scim" || sourceState.States[0].LastImportRunID != "human_import_run_pg_001" || sourceState.States[0].Checkpoint != "cursor_pg_endpoint_001" {
		t.Fatalf("source state = %#v, want scim checkpoint", sourceState)
	}

	req = httptest.NewRequest(http.MethodGet, "/admin/human-identities/import-runs/human_import_run_pg_001", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("import run detail GET status = %d, want %d, body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var importRunDetail humanidentity.HumanIdentityImportRunDetailResponse
	if err := json.NewDecoder(rec.Body).Decode(&importRunDetail); err != nil {
		t.Fatalf("decode import run detail response: %v", err)
	}
	if importRunDetail.ImportRunID != "human_import_run_pg_001" || importRunDetail.Summary.Checkpoint != "cursor_pg_endpoint_001" || importRunDetail.Summary.Upserted != 2 || len(importRunDetail.UpsertedIdentities) != 2 {
		t.Fatalf("postgres import run detail = %#v, want two upserted identities", importRunDetail)
	}

	req = httptest.NewRequest(http.MethodGet, "/admin/human-identities?limit=2", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("paged GET status = %d, want %d, body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	list = humanidentity.HumanIdentityDirectoryListResponse{}
	if err := json.NewDecoder(rec.Body).Decode(&list); err != nil {
		t.Fatalf("decode paged human identity list response: %v", err)
	}
	if list.Count != 2 || list.NextCursor == "" {
		t.Fatalf("paged list = %#v, want two rows and next cursor", list)
	}
	req = httptest.NewRequest(http.MethodGet, "/admin/human-identities?limit=2&cursor="+url.QueryEscape(list.NextCursor), nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("next page GET status = %d, want %d, body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	list = humanidentity.HumanIdentityDirectoryListResponse{}
	if err := json.NewDecoder(rec.Body).Decode(&list); err != nil {
		t.Fatalf("decode next page human identity list response: %v", err)
	}
	if list.Count != 1 || list.NextCursor != "" {
		t.Fatalf("next page list = %#v, want final one row", list)
	}

	req = httptest.NewRequest(http.MethodGet, "/admin/human-identities?source=scim&status=active&limit=1", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("filtered GET status = %d, want %d, body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	list = humanidentity.HumanIdentityDirectoryListResponse{}
	if err := json.NewDecoder(rec.Body).Decode(&list); err != nil {
		t.Fatalf("decode filtered human identity list response: %v", err)
	}
	if list.Source != "scim" || list.Status != "active" || list.Limit != 1 || list.Count != 1 || list.ActiveCount != 1 || list.Identities[0].ID != "human_endpoint_pg_import_001" {
		t.Fatalf("filtered list after import = %#v, want one active scim identity", list)
	}

	failedImportBody := []byte(`{
		"source":"scim",
		"import_run_id":"human_import_run_pg_failure_001",
		"checkpoint":"cursor_pg_failure_001",
		"identities":[
			{"id":"human_endpoint_pg_failure_001","subject":"sub_human_endpoint_pg_failure_001","status":"blocked"}
		]
	}`)
	req = httptest.NewRequest(http.MethodPost, "/admin/human-identities/import", bytes.NewReader(failedImportBody))
	req.Header.Set("content-type", "application/json")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("failed import status = %d, want %d, body=%s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
	req = httptest.NewRequest(http.MethodGet, "/admin/human-identities/sources/state", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("source state after failed import status = %d, want %d, body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	sourceState = humanidentity.HumanIdentitySourceStateListResponse{}
	if err := json.NewDecoder(rec.Body).Decode(&sourceState); err != nil {
		t.Fatalf("decode source state after failed import: %v", err)
	}
	if sourceState.Count != 1 || len(sourceState.States) != 1 || sourceState.States[0].Source != "scim" || sourceState.States[0].Status != "error" || sourceState.States[0].LastImportRunID != "human_import_run_pg_failure_001" || sourceState.States[0].Checkpoint != "cursor_pg_failure_001" || sourceState.States[0].LastError == "" {
		t.Fatalf("source state after failed import = %#v, want error checkpoint", sourceState)
	}
}

// The risk upgrade must see every tenant and all rows, rather than a Console page.
func TestUserRiskMigrationPostgresDirectorySnapshot(t *testing.T) {
	dsn := os.Getenv("POSTGRES_QUEUE_E2E_DSN")
	if dsn == "" {
		t.Skip("POSTGRES_QUEUE_E2E_DSN is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	store, closeFn, err := setupEdgeHumanIdentityDirectory(ctx, edgeHumanIdentityDirectoryConfig{Mode: "postgres", DSN: dsn, MigrationDir: filepath.Join("..", "..", "migrations"), RunMigrations: true})
	if err != nil {
		t.Fatal(err)
	}
	defer closeFn()
	const tenantA = "risk-migration-a"
	const tenantB = "risk-migration-b"
	defer func() {
		_, err := store.(postgresHumanIdentityDirectoryStore).DB.ExecContext(context.Background(), "DELETE FROM human_identities WHERE tenant_id IN ($1, $2)", tenantA, tenantB)
		if err != nil {
			t.Errorf("clean risk directory fixture: %v", err)
		}
	}()
	for i := 0; i < 205; i++ {
		id := fmt.Sprintf("risk-%03d", i)
		if _, err := store.Upsert(ctx, model.HumanIdentity{ID: id, Subject: id}, tenantA, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.Upsert(ctx, model.HumanIdentity{ID: "risk-204", Subject: "risk-204"}, tenantB, time.Now()); err != nil {
		t.Fatal(err)
	}
	if person, _, err := resolveRiskPerson(ctx, store, tenantA, "risk-204"); err != nil || person.ID != "risk-204" {
		t.Fatalf("risk lookup after first Console page: %#v %v", person, err)
	}
	snapshot := store.(interface {
		RiskIdentitySnapshot(context.Context) ([]model.HumanIdentity, error)
	})
	people, err := snapshot.RiskIdentitySnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, p := range people {
		if p.TenantID == tenantA || p.TenantID == tenantB {
			count++
		}
	}
	if count != 206 {
		t.Fatalf("incomplete snapshot: %d", count)
	}
	path := filepath.Join(t.TempDir(), "risk.json")
	raw := `{"schema_version":"high_risk_overlay_state.v1","devices":{"risk-204":"high"}}`
	if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	overlay := revocation.NewHighRiskOverlay()
	overlay.SetStatePath(path)
	if err := prepareUserRiskState(ctx, overlay, enrolledinventory.NewLedger(), store); err == nil {
		t.Fatal("cross-tenant collision outside the first Console page was not detected")
	}
	saved, _ := os.ReadFile(path)
	if string(saved) != raw {
		t.Fatal("rejected migration changed durable state")
	}
}
