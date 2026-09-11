package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var _ adminExportJobRuntimeStore = postgresAdminExportJobStore{}

func TestBuildPostgresAdminExportJobUpsertStatementSerializesPayload(t *testing.T) {
	now := time.Date(2026, 5, 23, 2, 0, 0, 0, time.UTC)
	req := adminExportJobRequest{Stream: "access", Format: "ndjson", From: "2026-05-23T00:00:00Z", To: "2026-05-23T01:00:00Z"}
	job := newAdminExportJobStore().Create(req, "tenant_lab_001", "admin_lab_001", now)

	statement, err := buildPostgresAdminExportJobUpsertStatement(job, now.Add(time.Minute))
	if err != nil {
		t.Fatalf("buildPostgresAdminExportJobUpsertStatement returned error: %v", err)
	}
	for _, want := range []string{
		"INSERT INTO admin_export_jobs",
		"ON CONFLICT (tenant_id, export_job_id) DO UPDATE",
		"payload = EXCLUDED.payload",
		"$6::jsonb",
	} {
		if !strings.Contains(statement.SQL, want) {
			t.Fatalf("SQL = %s, want %s", statement.SQL, want)
		}
	}
	if len(statement.Args) != 6 || statement.Args[0] != "tenant_lab_001" || statement.Args[1] != job.ID || statement.Args[2] != "queued" {
		t.Fatalf("args = %#v", statement.Args)
	}
	var payload adminExportJob
	if err := json.Unmarshal([]byte(statement.Args[5].(string)), &payload); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	if payload.ID != job.ID || payload.TenantID != job.TenantID || payload.Status != "queued" {
		t.Fatalf("payload = %#v", payload)
	}
}

func TestBuildPostgresAdminExportJobGetAndListStatementsScopeTenant(t *testing.T) {
	getStatement, err := buildPostgresAdminExportJobGetStatement("tenant_lab_001", "export_001")
	if err != nil {
		t.Fatalf("build get statement returned error: %v", err)
	}
	if !strings.Contains(getStatement.SQL, "tenant_id = $1") || !strings.Contains(getStatement.SQL, "export_job_id = $2") {
		t.Fatalf("get SQL = %s", getStatement.SQL)
	}
	if getStatement.Args[0] != "tenant_lab_001" || getStatement.Args[1] != "export_001" {
		t.Fatalf("get args = %#v", getStatement.Args)
	}
	getByIDStatement, err := buildPostgresAdminExportJobGetByIDStatement("export_001")
	if err != nil {
		t.Fatalf("build get by id statement returned error: %v", err)
	}
	if !strings.Contains(getByIDStatement.SQL, "WHERE export_job_id = $1") || !strings.Contains(getByIDStatement.SQL, "LIMIT 1") {
		t.Fatalf("get by id SQL = %s", getByIDStatement.SQL)
	}
	if getByIDStatement.Args[0] != "export_001" {
		t.Fatalf("get by id args = %#v", getByIDStatement.Args)
	}
	getByIDForUpdateStatement, err := buildPostgresAdminExportJobGetByIDForUpdateStatement("export_001")
	if err != nil {
		t.Fatalf("build get by id for update statement returned error: %v", err)
	}
	if !strings.Contains(getByIDForUpdateStatement.SQL, "FOR UPDATE") || !strings.Contains(getByIDForUpdateStatement.SQL, "LIMIT 1 FOR UPDATE") {
		t.Fatalf("get by id for update SQL = %s", getByIDForUpdateStatement.SQL)
	}
	schemaSQL := strings.Join(postgresAdminExportJobSchemaSQL(), "\n")
	if !strings.Contains(schemaSQL, "CREATE UNIQUE INDEX IF NOT EXISTS admin_export_jobs_export_job_id_unique_idx") {
		t.Fatalf("schema SQL does not enforce globally unique export_job_id: %s", schemaSQL)
	}

	listStatement, err := buildPostgresAdminExportJobListStatement("tenant_lab_001", 50)
	if err != nil {
		t.Fatalf("build list statement returned error: %v", err)
	}
	if !strings.Contains(listStatement.SQL, "WHERE tenant_id = $1") || !strings.Contains(listStatement.SQL, "ORDER BY created_at DESC") {
		t.Fatalf("list SQL = %s", listStatement.SQL)
	}
	if listStatement.Args[0] != "tenant_lab_001" || listStatement.Args[1] != 50 {
		t.Fatalf("list args = %#v", listStatement.Args)
	}
}

func TestBuildPostgresAdminExportJobStatementsRejectInvalidInputs(t *testing.T) {
	now := time.Date(2026, 5, 23, 2, 0, 0, 0, time.UTC)
	if _, err := buildPostgresAdminExportJobUpsertStatement(adminExportJob{}, now); err == nil {
		t.Fatalf("upsert accepted empty job")
	}
	if _, err := buildPostgresAdminExportJobGetStatement("", "export_001"); err == nil {
		t.Fatalf("get accepted empty tenant")
	}
	if _, err := buildPostgresAdminExportJobGetByIDStatement(""); err == nil {
		t.Fatalf("get by id accepted empty job id")
	}
	if _, err := buildPostgresAdminExportJobListStatement("", 10); err == nil {
		t.Fatalf("list accepted empty tenant")
	}
}

func TestDecodePostgresAdminExportJobPayloadRejectsInvalidPayload(t *testing.T) {
	if _, err := decodePostgresAdminExportJobPayload(nil); err == nil {
		t.Fatalf("decode accepted empty payload")
	}
	if _, err := decodePostgresAdminExportJobPayload([]byte(`{"id":"","tenant_id":"tenant_lab_001"}`)); err == nil {
		t.Fatalf("decode accepted missing id")
	}
}

func TestPostgresAdminExportJobMigrationMatchesSchemaSQL(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "migrations", "002_admin_export_jobs.sql"))
	if err != nil {
		t.Fatalf("read migration: %v", err)
	}
	want := normalizePostgresExportTaskSQLContract(strings.Join(postgresAdminExportJobSchemaSQL(), "\n"))
	got := normalizePostgresExportTaskSQLContract(string(data))
	if got != want {
		t.Fatalf("admin export job migration SQL does not match schema helper\nmigration: %s\nhelper:    %s", got, want)
	}
}
