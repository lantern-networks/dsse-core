package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/model"
)

func TestBuildPostgresAdminAuditOutboxInsertStatement(t *testing.T) {
	now := time.Date(2026, 5, 23, 2, 0, 0, 0, time.UTC)
	audit := model.AuditLog{
		ID:        "audit_admin_export_requested_001",
		TenantID:  "tenant_lab_001",
		EventType: "admin_export_requested",
		Timestamp: now.Add(-time.Minute).Format(time.RFC3339),
		Metadata:  map[string]any{"export_job_id": "exp_lab_001"},
	}
	statement, err := buildPostgresAdminAuditOutboxInsertStatement(audit, now)
	if err != nil {
		t.Fatalf("buildPostgresAdminAuditOutboxInsertStatement returned error: %v", err)
	}
	for _, want := range []string{
		"INSERT INTO admin_audit_outbox",
		"ON CONFLICT (tenant_id, outbox_id) DO NOTHING",
		"$5::jsonb",
	} {
		if !strings.Contains(statement.SQL, want) {
			t.Fatalf("statement SQL missing %q: %s", want, statement.SQL)
		}
	}
	if got, want := len(statement.Args), 6; got != want {
		t.Fatalf("arg count = %d, want %d", got, want)
	}
	if statement.Args[0] != "tenant_lab_001" || statement.Args[1] != "audit_admin_export_requested_001" || statement.Args[2] != "admin_export_requested" {
		t.Fatalf("statement args = %#v", statement.Args)
	}
	payload, ok := statement.Args[4].(string)
	if !ok || !strings.Contains(payload, `"event_type":"admin_export_requested"`) || !strings.Contains(payload, `"export_job_id":"exp_lab_001"`) {
		t.Fatalf("payload arg = %#v", statement.Args[4])
	}
}

func TestHTTPAdminAuditOutboxDeliveryPostsJSON(t *testing.T) {
	audit := model.AuditLog{
		ID:        "audit_webhook_001",
		TenantID:  "tenant_lab_001",
		EventType: "admin_export_requested",
		Timestamp: "2026-05-23T03:10:00Z",
	}
	var gotAuth string
	var gotSignature string
	var gotSignatureKeyID string
	var gotTimestamp string
	var gotNonce string
	var gotAudit model.AuditLog
	var gotPayload []byte
	client := &http.Client{Transport: auditOutboxRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		gotAuth = r.Header.Get("authorization")
		gotSignature = r.Header.Get("x-admin-audit-signature")
		gotSignatureKeyID = r.Header.Get("x-admin-audit-signature-key-id")
		gotTimestamp = r.Header.Get("x-admin-audit-timestamp")
		gotNonce = r.Header.Get("x-admin-audit-nonce")
		if r.Header.Get("content-type") != "application/json" {
			t.Fatalf("content-type = %q, want application/json", r.Header.Get("content-type"))
		}
		var err error
		gotPayload, err = io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read webhook body: %v", err)
		}
		if err := json.NewDecoder(bytes.NewReader(gotPayload)).Decode(&gotAudit); err != nil {
			t.Fatalf("decode webhook body: %v", err)
		}
		return &http.Response{StatusCode: http.StatusAccepted, Body: io.NopCloser(strings.NewReader(""))}, nil
	})}

	delivery := httpAdminAuditOutboxDelivery{
		Endpoint:      "https://siem.example.test/audit",
		BearerToken:   "secret-token",
		SigningSecret: "signing-secret",
		SigningKeyID:  "kid-001",
		Timeout:       time.Second,
		Client:        client,
		Now: func() time.Time {
			return time.Date(2026, 5, 23, 3, 11, 0, 0, time.UTC)
		},
		Nonce: func() (string, error) {
			return "nonce-001", nil
		},
	}
	if err := delivery.DeliverAdminAudit(context.Background(), audit); err != nil {
		t.Fatalf("DeliverAdminAudit returned error: %v", err)
	}
	if gotAuth != "Bearer secret-token" {
		t.Fatalf("authorization = %q, want bearer token", gotAuth)
	}
	if gotSignatureKeyID != "kid-001" {
		t.Fatalf("x-admin-audit-signature-key-id = %q, want kid-001", gotSignatureKeyID)
	}
	if gotTimestamp != "2026-05-23T03:11:00Z" {
		t.Fatalf("x-admin-audit-timestamp = %q, want 2026-05-23T03:11:00Z", gotTimestamp)
	}
	if gotNonce != "nonce-001" {
		t.Fatalf("x-admin-audit-nonce = %q, want nonce-001", gotNonce)
	}
	if want := adminAuditWebhookSignature("signing-secret", gotTimestamp, gotNonce, gotPayload); gotSignature != want {
		t.Fatalf("x-admin-audit-signature = %q, want %q", gotSignature, want)
	}
	if gotAudit.ID != audit.ID || gotAudit.EventType != audit.EventType || gotAudit.TenantID != audit.TenantID {
		t.Fatalf("got audit = %#v", gotAudit)
	}
}

func TestHTTPAdminAuditOutboxDeliveryRejectsNon2xx(t *testing.T) {
	client := &http.Client{Transport: auditOutboxRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusServiceUnavailable, Body: io.NopCloser(strings.NewReader(""))}, nil
	})}

	delivery := httpAdminAuditOutboxDelivery{Endpoint: "https://siem.example.test/audit", Timeout: time.Second, Client: client}
	err := delivery.DeliverAdminAudit(context.Background(), model.AuditLog{ID: "audit_webhook_503", TenantID: "tenant_lab_001", EventType: "admin_export_requested"})
	if err == nil || !strings.Contains(err.Error(), "status 503") {
		t.Fatalf("DeliverAdminAudit error = %v, want status 503", err)
	}
	if got, want := adminAuditOutboxDeliveryFailureReason(err), "audit_delivery_http_5xx"; got != want {
		t.Fatalf("delivery failure reason = %q, want %q", got, want)
	}
}

func TestAdminAuditOutboxDeliveryFailureReason(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want string
	}{
		{
			name: "transport",
			err:  adminAuditOutboxDeliveryFailure{Code: "audit_delivery_transport_failed", Err: io.ErrUnexpectedEOF},
			want: "audit_delivery_transport_failed",
		},
		{
			name: "fallback",
			err:  io.ErrClosedPipe,
			want: "audit_delivery_failed",
		},
		{
			name: "blank typed code",
			err:  adminAuditOutboxDeliveryFailure{Err: io.ErrUnexpectedEOF},
			want: "audit_delivery_failed",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := adminAuditOutboxDeliveryFailureReason(tc.err); got != tc.want {
				t.Fatalf("reason = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestAdminAuditOutboxHTTPStatusFailureCode(t *testing.T) {
	for _, tc := range []struct {
		status int
		want   string
	}{
		{status: http.StatusMultipleChoices, want: "audit_delivery_http_3xx"},
		{status: http.StatusUnauthorized, want: "audit_delivery_http_4xx"},
		{status: http.StatusServiceUnavailable, want: "audit_delivery_http_5xx"},
		{status: http.StatusSwitchingProtocols, want: "audit_delivery_http_status"},
	} {
		if got := adminAuditOutboxHTTPStatusFailureCode(tc.status); got != tc.want {
			t.Fatalf("status %d code = %q, want %q", tc.status, got, tc.want)
		}
	}
}

func TestVerifyAdminAuditWebhookSignature(t *testing.T) {
	payload := []byte(`{"id":"audit_webhook_verify_001"}`)
	timestamp := "2026-05-23T03:11:00Z"
	nonce := "nonce-001"
	signature := adminAuditWebhookSignature("signing-secret", timestamp, nonce, payload)
	now := time.Date(2026, 5, 23, 3, 12, 0, 0, time.UTC)
	if err := verifyAdminAuditWebhookSignature("signing-secret", timestamp, nonce, signature, payload, now, 5*time.Minute); err != nil {
		t.Fatalf("verifyAdminAuditWebhookSignature returned error: %v", err)
	}
	if err := verifyAdminAuditWebhookSignature("signing-secret", timestamp, nonce, "sha256=bad", payload, now, 5*time.Minute); err == nil || !strings.Contains(err.Error(), "invalid") {
		t.Fatalf("bad signature error = %v, want invalid", err)
	}
	oldNow := time.Date(2026, 5, 23, 3, 30, 0, 0, time.UTC)
	if err := verifyAdminAuditWebhookSignature("signing-secret", timestamp, nonce, signature, payload, oldNow, 5*time.Minute); err == nil || !strings.Contains(err.Error(), "outside allowed skew") {
		t.Fatalf("old timestamp error = %v, want outside allowed skew", err)
	}
}

type auditOutboxRoundTripFunc func(*http.Request) (*http.Response, error)

func (fn auditOutboxRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return fn(request)
}

func TestPostgresAdminAuditOutboxMigrationMatchesSchemaSQL(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "migrations", "004_admin_audit_outbox.sql"))
	if err != nil {
		t.Fatalf("read migration: %v", err)
	}
	want := normalizePostgresExportTaskSQLContract(strings.Join(postgresAdminAuditOutboxSchemaSQL(), "\n"))
	got := normalizePostgresExportTaskSQLContract(string(data))
	if got != want {
		t.Fatalf("migration drift:\nwant: %s\n got: %s", want, got)
	}
}

func TestBuildPostgresAdminAuditOutboxPublisherStatements(t *testing.T) {
	now := time.Date(2026, 5, 23, 2, 10, 0, 0, time.UTC)
	lockedUntil := now.Add(time.Minute)
	claim, err := buildPostgresAdminAuditOutboxClaimStatement("tenant_lab_001", "publisher_001", 25, 5, now, lockedUntil)
	if err != nil {
		t.Fatalf("build claim statement returned error: %v", err)
	}
	for _, want := range []string{
		"FOR UPDATE SKIP LOCKED",
		"status = 'publishing'",
		"publish_attempt = outbox.publish_attempt + 1",
		"publish_attempt < $6",
		"RETURNING outbox.tenant_id, outbox.outbox_id, outbox.publish_attempt, outbox.payload",
	} {
		if !strings.Contains(claim.SQL, want) {
			t.Fatalf("claim SQL missing %q: %s", want, claim.SQL)
		}
	}
	if got, want := len(claim.Args), 6; got != want {
		t.Fatalf("claim arg count = %d, want %d", got, want)
	}

	publish, err := buildPostgresAdminAuditOutboxMarkPublishedStatement("tenant_lab_001", "audit_001", "publisher_001", now)
	if err != nil {
		t.Fatalf("build publish statement returned error: %v", err)
	}
	for _, want := range []string{"status = 'published'", "locked_by = NULL", "status = 'publishing'"} {
		if !strings.Contains(publish.SQL, want) {
			t.Fatalf("publish SQL missing %q: %s", want, publish.SQL)
		}
	}

	release, err := buildPostgresAdminAuditOutboxReleaseStatement("tenant_lab_001", "audit_001", "publisher_001", "siem unavailable", now.Add(30*time.Second), now)
	if err != nil {
		t.Fatalf("build release statement returned error: %v", err)
	}
	for _, want := range []string{"status = 'pending'", "last_error = $4", "next_attempt_at = $5::timestamptz", "status = 'publishing'"} {
		if !strings.Contains(release.SQL, want) {
			t.Fatalf("release SQL missing %q: %s", want, release.SQL)
		}
	}

	listDead, err := buildPostgresAdminAuditOutboxListDeadStatement("tenant_lab_001", 25)
	if err != nil {
		t.Fatalf("build list dead statement returned error: %v", err)
	}
	for _, want := range []string{"WHERE tenant_id = $1 AND status = 'dead'", "ORDER BY COALESCE(dead_at, updated_at) DESC", "LIMIT $2"} {
		if !strings.Contains(listDead.SQL, want) {
			t.Fatalf("list dead SQL missing %q: %s", want, listDead.SQL)
		}
	}
	if got, want := listDead.Args[1], 25; got != want {
		t.Fatalf("list dead limit arg = %v, want %d", got, want)
	}

	getDead, err := buildPostgresAdminAuditOutboxGetDeadStatement("tenant_lab_001", "audit_001")
	if err != nil {
		t.Fatalf("build get dead statement returned error: %v", err)
	}
	for _, want := range []string{"WHERE tenant_id = $1 AND outbox_id = $2 AND status = 'dead'", "LIMIT 1"} {
		if !strings.Contains(getDead.SQL, want) {
			t.Fatalf("get dead SQL missing %q: %s", want, getDead.SQL)
		}
	}
	if getDead.Args[0] != "tenant_lab_001" || getDead.Args[1] != "audit_001" {
		t.Fatalf("get dead args = %#v", getDead.Args)
	}

	stats, err := buildPostgresAdminAuditOutboxStatsStatement("tenant_lab_001")
	if err != nil {
		t.Fatalf("build stats statement returned error: %v", err)
	}
	for _, want := range []string{"MIN(CASE WHEN status = 'dead' THEN COALESCE(dead_at, updated_at) ELSE occurred_at END)", "WHERE tenant_id = $1", "GROUP BY status"} {
		if !strings.Contains(stats.SQL, want) {
			t.Fatalf("stats SQL missing %q: %s", want, stats.SQL)
		}
	}

	replayDead, err := buildPostgresAdminAuditOutboxReplayDeadStatement("tenant_lab_001", "audit_001", now)
	if err != nil {
		t.Fatalf("build replay dead statement returned error: %v", err)
	}
	for _, want := range []string{"WITH picked AS", "previous_last_error", "status = 'pending'", "publish_attempt = 0", "last_error = NULL", "dead_at = NULL", "WHERE tenant_id = $1 AND outbox_id = $2 AND status = 'dead'"} {
		if !strings.Contains(replayDead.SQL, want) {
			t.Fatalf("replay dead SQL missing %q: %s", want, replayDead.SQL)
		}
	}

	markDead, err := buildPostgresAdminAuditOutboxMarkDeadStatement("tenant_lab_001", "audit_001", "publisher_001", "max attempts exceeded", now)
	if err != nil {
		t.Fatalf("build mark dead statement returned error: %v", err)
	}
	for _, want := range []string{"status = 'dead'", "dead_at = $5::timestamptz", "last_error = $4", "next_attempt_at = NULL", "status = 'publishing'"} {
		if !strings.Contains(markDead.SQL, want) {
			t.Fatalf("mark dead SQL missing %q: %s", want, markDead.SQL)
		}
	}
}
