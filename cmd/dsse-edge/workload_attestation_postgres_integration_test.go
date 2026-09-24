package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	nhi "github.com/lantern-networks/dsse-core/nhi"

	"github.com/lantern-networks/dsse-core/logs"
	migrationstore "github.com/lantern-networks/dsse-core/migrations"
	"github.com/lantern-networks/dsse-core/model"

	_ "github.com/lib/pq"
)

func TestPostgresWorkloadAttestationNonceStoreE2E(t *testing.T) {
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
	if err := migrationstoreApplyForWorkloadAttestationTest(ctx, db); err != nil {
		t.Fatalf("apply workload attestation nonce migration: %v", err)
	}

	now := time.Date(2026, 5, 25, 1, 2, 3, 0, time.UTC)
	first := &postgresWorkloadAttestationNonceStore{DB: db}
	second := &postgresWorkloadAttestationNonceStore{DB: db}
	if err := first.Remember("tenant_lab_001", "nonce_distributed_001", now, now.Add(5*time.Minute)); err != nil {
		t.Fatalf("first Remember returned error: %v", err)
	}
	if err := second.Remember("tenant_lab_001", "nonce_distributed_001", now.Add(time.Second), now.Add(5*time.Minute)); err == nil || !strings.Contains(err.Error(), "already used") {
		t.Fatalf("second Remember error = %v, want replay rejection", err)
	}
	if err := second.Remember("tenant_other", "nonce_distributed_001", now.Add(time.Second), now.Add(5*time.Minute)); err != nil {
		t.Fatalf("other tenant Remember returned error: %v", err)
	}
	if err := first.Remember("tenant_lab_001", "nonce_expired_001", now, now.Add(time.Second)); err != nil {
		t.Fatalf("expired setup Remember returned error: %v", err)
	}
	if err := second.Remember("tenant_lab_001", "nonce_expired_001", now.Add(2*time.Second), now.Add(5*time.Minute)); err != nil {
		t.Fatalf("Remember after expiry returned error: %v", err)
	}
}

func TestPostgresWorkloadAttestationNonceStoreDecisionEvaluateE2E(t *testing.T) {
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
	if err := migrationstoreApplyForWorkloadAttestationTest(ctx, db); err != nil {
		t.Fatalf("apply workload attestation nonce migration: %v", err)
	}

	now := time.Now().UTC()
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	delegatedGrants := newDelegatedAccessGrantStore()
	if _, err := delegatedGrants.Upsert(model.DelegatedAccessGrant{
		ID:            "dag_lab_001",
		TenantID:      "tenant_lab_001",
		SubjectUserID: "user_lab_001",
		ActorNHIID:    "nhi_soc_agent_001",
		ToolIDs:       []string{"tool_ticket_create_001"},
		ApplicationID: stringPtr("app_dummy_https"),
		ExpiresAt:     now.Add(time.Hour).Format(time.RFC3339),
		Status:        "active",
		Metadata:      map[string]any{},
	}); err != nil {
		t.Fatalf("upsert delegated grant: %v", err)
	}
	nhiRegistry := nhi.NewStore()
	if _, err := nhiRegistry.Upsert(context.Background(), model.NonHumanIdentity{
		ID:                    "nhi_soc_agent_001",
		Name:                  "SOC Agent",
		NHIType:               "ai_agent",
		OwnerUserID:           "user_owner_001",
		Status:                "active",
		AllowedApplicationIDs: []string{"app_dummy_https"},
		AllowedScopes:         []string{"ticket:create"},
		AllowlistEnforced:     true,
	}, "tenant_lab_001", now); err != nil {
		t.Fatalf("upsert NHI: %v", err)
	}
	devMode := false
	attestationSecret := "runtime-attestation-secret"
	tenantCAs, connectorTLS := postgresTestConnectorIdentity(t, "tenant_lab_001", "conn_attestation")
	handler := newServerWithConfig(serverConfig{
		Evaluator: testEvaluatorWithPolicies([]model.Policy{{
			ID:       "pol_lab_nhi_tool_attested_allow_001",
			TenantID: "tenant_lab_001",
			Priority: 90,
			Conditions: map[string]any{
				"actor_type":                "delegated_agent",
				"actor_nhi_id":              "nhi_soc_agent_001",
				"delegated_access_grant_id": "dag_lab_001",
				"tool_id":                   "tool_ticket_create_001",
				"application_id":            "app_dummy_https",
			},
			Action:                      model.PolicyAction{Decision: "allow"},
			RequiredWorkloadAttestation: true,
			Status:                      "active",
		}}),
		TenantCARegistry:          tenantCAs,
		Writer:                    writer,
		ConnectorSecret:           defaultConnectorSecret,
		WorkloadAttestationSecret: attestationSecret,
		WorkloadAttestations:      &postgresWorkloadAttestationNonceStore{DB: db},
		LabMode:                   &devMode,
		DelegatedGrants:           delegatedGrants,
		NonHumanIdentities:        nhiRegistry,
	})
	body := []byte(`{
		"tenant_id":"tenant_lab_001",
		"subject_user_id":"user_lab_001",
		"actor_type":"human",
		"actor_nhi_id":"nhi_soc_agent_001",
		"delegated_access_grant_id":"dag_lab_001",
		"agent_task_session_id":"ats_lab_001",
		"tool_id":"tool_ticket_create_001",
		"tool_action_type":"ticket:create",
		"application_id":"app_dummy_https",
		"service_family":"https",
		"workload_attestation_state":"verified"
	}`)
	signedReq := model.DecisionRequest{
		TenantID:               "tenant_lab_001",
		ActorType:              "delegated_agent",
		ActorNHIID:             "nhi_soc_agent_001",
		DelegatedAccessGrantID: "dag_lab_001",
		AgentTaskSessionID:     "ats_lab_001",
		ToolID:                 "tool_ticket_create_001",
		ToolActionType:         "ticket:create",
		ApplicationID:          "app_dummy_https",
	}
	timestamp := now.Format(time.RFC3339)
	nonce := "nonce-postgres-runtime-decision-e2e"
	signature := runtimeWorkloadAttestationSignature(attestationSecret, signedReq, "verified", timestamp, nonce)

	req := httptest.NewRequest(http.MethodPost, "/decisions/evaluate", bytes.NewReader(body))
	req.TLS = connectorTLS
	req.Header.Set(connectorIDHeader, "conn_attestation")
	req.Header.Set("content-type", "application/json")
	req.Header.Set(connectorSecretHeader, defaultConnectorSecret)
	req.Header.Set(workloadAttestationStateHeader, "verified")
	req.Header.Set(workloadAttestationTimestampHeader, timestamp)
	req.Header.Set(workloadAttestationNonceHeader, nonce)
	req.Header.Set(workloadAttestationSignatureHeader, signature)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("first status = %d, body=%s", rec.Code, rec.Body.String())
	}
	var dec model.AccessDecision
	if err := json.NewDecoder(rec.Body).Decode(&dec); err != nil {
		t.Fatalf("decode first decision: %v", err)
	}
	if dec.Decision != "allow" || dec.Metadata["workload_attestation_nonce_hash"] != runtimeWorkloadAttestationNonceHash("tenant_lab_001", nonce) {
		t.Fatalf("first decision = %#v, want allow with nonce hash", dec)
	}

	req = httptest.NewRequest(http.MethodPost, "/decisions/evaluate", bytes.NewReader(body))
	req.TLS = connectorTLS
	req.Header.Set(connectorIDHeader, "conn_attestation")
	req.Header.Set("content-type", "application/json")
	req.Header.Set(connectorSecretHeader, defaultConnectorSecret)
	req.Header.Set(workloadAttestationStateHeader, "verified")
	req.Header.Set(workloadAttestationTimestampHeader, timestamp)
	req.Header.Set(workloadAttestationNonceHeader, nonce)
	req.Header.Set(workloadAttestationSignatureHeader, signature)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("replay status = %d, want %d, body=%s", rec.Code, http.StatusUnauthorized, rec.Body.String())
	}

	var count int
	if err := db.QueryRowContext(ctx, "SELECT count(*) FROM workload_attestation_nonces WHERE tenant_id = $1", "tenant_lab_001").Scan(&count); err != nil {
		t.Fatalf("query workload nonce count: %v", err)
	}
	if count != 1 {
		t.Fatalf("workload nonce rows = %d, want 1", count)
	}
}

func migrationstoreApplyForWorkloadAttestationTest(ctx context.Context, db *sql.DB) error {
	migrations, err := migrationstore.LoadDir(filepath.Join("..", "..", "migrations"))
	if err != nil {
		return err
	}
	migrations, err = selectPostgresComponentMigrations(migrations, "workload attestation nonce", postgresWorkloadAttestationNonceMigrationVersions()...)
	if err != nil {
		return err
	}
	return migrationstore.Apply(ctx, db, migrations)
}
