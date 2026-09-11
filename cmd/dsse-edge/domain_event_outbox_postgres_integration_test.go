package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/objectstore"

	_ "github.com/lib/pq"
)

func TestPostgresDomainEventOutboxStoreE2E(t *testing.T) {
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
	applyPostgresExportTaskQueueMigration(t, ctx, db)

	now := time.Date(2026, 5, 24, 5, 0, 0, 0, time.UTC)
	payload := map[string]any{"id": "tce_domain_e2e_001", "tool_id": "tool_ticket_create_001"}
	_, checksum, err := domainEventOutboxPayloadAndChecksum(payload)
	if err != nil {
		t.Fatalf("domainEventOutboxPayloadAndChecksum returned error: %v", err)
	}
	store := postgresDomainEventOutboxStore{DB: db}
	event := domainEventOutboxEnvelope{
		ID:              "domain_outbox_e2e_001",
		TenantID:        "tenant_lab_001",
		SchemaVersion:   "2026-05-24.1",
		EventPlane:      "domain",
		Stream:          "tool_call_events",
		EventType:       "tool_call_event_recorded",
		Status:          "pending",
		OccurredAt:      now.Add(-time.Second),
		ReceivedAt:      now,
		Payload:         payload,
		PayloadChecksum: checksum,
		PublishAttempt:  0,
		Metadata:        map[string]any{"dedup_key": "tenant_lab_001:tool_call_events:tce_domain_e2e_001"},
	}
	if err := store.InsertEvent(ctx, event, now); err != nil {
		t.Fatalf("InsertEvent returned error: %v", err)
	}
	claimed, err := store.Claim(ctx, "tenant_lab_001", "domain", "publisher_tokyo_001", 10, 5, now, time.Minute)
	if err != nil {
		t.Fatalf("Claim returned error: %v", err)
	}
	if len(claimed) != 1 || claimed[0].ID != event.ID || claimed[0].Status != "publishing" {
		t.Fatalf("claimed = %#v", claimed)
	}
	if err := store.MarkPublished(ctx, "tenant_lab_001", event.ID, "publisher_tokyo_001", now.Add(time.Second)); err != nil {
		t.Fatalf("MarkPublished returned error: %v", err)
	}
	var status string
	if err := db.QueryRowContext(ctx, "SELECT status FROM domain_event_outbox WHERE tenant_id = $1 AND outbox_id = $2", "tenant_lab_001", event.ID).Scan(&status); err != nil {
		t.Fatalf("query status: %v", err)
	}
	if status != "published" {
		t.Fatalf("status = %q, want published", status)
	}
}

func TestPostgresDomainEventOutboxClaimReclaimsStalePublishingE2E(t *testing.T) {
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
	applyPostgresExportTaskQueueMigration(t, ctx, db)

	now := time.Date(2026, 5, 24, 5, 20, 0, 0, time.UTC)
	event := mustDomainEventOutboxEnvelope(t)
	event.ID = "domain_outbox_stale_reclaim_e2e_001"
	event.OccurredAt = now.Add(-time.Minute)
	event.ReceivedAt = now
	store := postgresDomainEventOutboxStore{DB: db}
	if err := store.InsertEvent(ctx, event, now); err != nil {
		t.Fatalf("InsertEvent returned error: %v", err)
	}

	claimedA, err := store.Claim(ctx, "tenant_lab_001", "domain", "publisher_stale_a", 10, 5, now, 10*time.Millisecond)
	if err != nil {
		t.Fatalf("first Claim returned error: %v", err)
	}
	if len(claimedA) != 1 || claimedA[0].ID != event.ID || claimedA[0].PublishAttempt != 1 {
		t.Fatalf("claimedA = %#v, want first attempt", claimedA)
	}
	// Claim compares the stored locked_until against the explicit now argument
	// passed to SQL, so this test does not depend on the database wall clock.
	claimedB, err := store.Claim(ctx, "tenant_lab_001", "domain", "publisher_stale_b", 10, 5, now.Add(20*time.Millisecond), time.Minute)
	if err != nil {
		t.Fatalf("second Claim returned error: %v", err)
	}
	if len(claimedB) != 1 || claimedB[0].ID != event.ID || claimedB[0].PublishAttempt != 2 {
		t.Fatalf("claimedB = %#v, want reclaimed second attempt", claimedB)
	}
	err = store.MarkPublished(ctx, "tenant_lab_001", event.ID, "publisher_stale_a", now.Add(30*time.Millisecond))
	if err == nil || !strings.Contains(err.Error(), "lock was stolen") {
		t.Fatalf("stale publisher MarkPublished error = %v, want stolen lock", err)
	}
	if err := store.MarkPublished(ctx, "tenant_lab_001", event.ID, "publisher_stale_b", now.Add(40*time.Millisecond)); err != nil {
		t.Fatalf("current publisher MarkPublished returned error: %v", err)
	}
	var status string
	var publishAttempt int
	var lockedBy sql.NullString
	if err := db.QueryRowContext(ctx, "SELECT status, publish_attempt, locked_by FROM domain_event_outbox WHERE tenant_id = $1 AND outbox_id = $2", "tenant_lab_001", event.ID).Scan(&status, &publishAttempt, &lockedBy); err != nil {
		t.Fatalf("query reclaimed row returned error: %v", err)
	}
	if status != "published" || publishAttempt != 2 || lockedBy.Valid {
		t.Fatalf("status=%s publish_attempt=%d locked_by=%v, want published/2/null", status, publishAttempt, lockedBy)
	}
}

func TestPostgresDomainEventOutboxPublisherE2E(t *testing.T) {
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
	applyPostgresExportTaskQueueMigration(t, ctx, db)

	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	now := time.Date(2026, 5, 24, 6, 0, 0, 0, time.UTC)
	event := mustDomainEventOutboxEnvelope(t)
	event.ID = "domain_outbox_publisher_e2e_001"
	event.OccurredAt = now.Add(-time.Minute)
	event.ReceivedAt = now
	store := postgresDomainEventOutboxStore{DB: db}
	if err := store.InsertEvent(ctx, event, now); err != nil {
		t.Fatalf("InsertEvent returned error: %v", err)
	}
	publisher := postgresDomainEventOutboxPublisher{
		Store:       store,
		TenantID:    "tenant_lab_001",
		EventPlane:  "domain",
		PublisherID: "publisher_tokyo_001",
		Writer:      writer,
		MaxAttempts: 5,
	}
	published, err := publisher.PublishOnce(ctx, now.Add(time.Second))
	if err != nil {
		t.Fatalf("PublishOnce returned error: %v", err)
	}
	if published != 1 {
		t.Fatalf("published = %d, want 1", published)
	}
	rows, err := writer.ReadJSONL("domain_events.log.jsonl")
	if err != nil {
		t.Fatalf("ReadJSONL returned error: %v", err)
	}
	if len(rows) != 1 || rows[0]["id"] != event.ID {
		t.Fatalf("rows = %#v", rows)
	}
	var status string
	if err := db.QueryRowContext(ctx, "SELECT status FROM domain_event_outbox WHERE tenant_id = $1 AND outbox_id = $2", "tenant_lab_001", event.ID).Scan(&status); err != nil {
		t.Fatalf("query status: %v", err)
	}
	if status != "published" {
		t.Fatalf("status = %q, want published", status)
	}
}

func TestPostgresDomainEventOutboxPublisherAccessPlaneE2E(t *testing.T) {
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
	applyPostgresExportTaskQueueMigration(t, ctx, db)

	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	now := time.Date(2026, 5, 24, 9, 0, 0, 0, time.UTC)
	domainEvent := mustDomainEventOutboxEnvelope(t)
	domainEvent.ID = "domain_outbox_domain_plane_pending_001"
	domainEvent.OccurredAt = now.Add(-2 * time.Minute)
	domainEvent.ReceivedAt = now
	accessEvent, err := domainEventOutboxEnvelopeFromAccessLog(model.AccessLog{
		ID:               "alog_access_plane_e2e_001",
		TenantID:         "tenant_lab_001",
		AccessDecisionID: "dec_access_plane_e2e_001",
		Decision:         "allow",
		Timestamp:        now.Add(-time.Minute).Format(time.RFC3339),
		Metadata:         map[string]any{},
	}, now)
	if err != nil {
		t.Fatalf("domainEventOutboxEnvelopeFromAccessLog returned error: %v", err)
	}
	accessEvent.ID = "domain_outbox_access_plane_e2e_001"
	store := postgresDomainEventOutboxStore{DB: db}
	if err := store.InsertEvent(ctx, domainEvent, now); err != nil {
		t.Fatalf("InsertEvent domain returned error: %v", err)
	}
	if err := store.InsertEvent(ctx, accessEvent, now); err != nil {
		t.Fatalf("InsertEvent access returned error: %v", err)
	}
	publisher := postgresDomainEventOutboxPublisher{
		Store:       store,
		TenantID:    "tenant_lab_001",
		EventPlane:  "access",
		PublisherID: "publisher_access_tokyo_001",
		Writer:      writer,
		MaxAttempts: 5,
	}
	published, err := publisher.PublishOnce(ctx, now.Add(time.Second))
	if err != nil {
		t.Fatalf("PublishOnce returned error: %v", err)
	}
	if published != 1 {
		t.Fatalf("published = %d, want 1", published)
	}
	rows, err := writer.ReadJSONL("access_events.log.jsonl")
	if err != nil {
		t.Fatalf("ReadJSONL access_events returned error: %v", err)
	}
	if len(rows) != 1 || rows[0]["id"] != accessEvent.ID || rows[0]["event_plane"] != "access" {
		t.Fatalf("access rows = %#v", rows)
	}
	domainRows, err := writer.ReadJSONL("domain_events.log.jsonl")
	if err != nil {
		t.Fatalf("ReadJSONL domain_events returned error: %v", err)
	}
	if len(domainRows) != 0 {
		t.Fatalf("domain rows = %#v; access-plane publisher should not deliver domain-plane rows", domainRows)
	}
	statusByID := map[string]string{}
	for _, id := range []string{domainEvent.ID, accessEvent.ID} {
		var status string
		if err := db.QueryRowContext(ctx, "SELECT status FROM domain_event_outbox WHERE tenant_id = $1 AND outbox_id = $2", "tenant_lab_001", id).Scan(&status); err != nil {
			t.Fatalf("query status for %s: %v", id, err)
		}
		statusByID[id] = status
	}
	if statusByID[accessEvent.ID] != "published" || statusByID[domainEvent.ID] != "pending" {
		t.Fatalf("statusByID = %#v, want access published and domain pending", statusByID)
	}
}

func TestRunPostgresDomainEventOutboxPublisherModeE2E(t *testing.T) {
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
	applyPostgresExportTaskQueueMigration(t, ctx, db)

	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	now := time.Date(2026, 5, 24, 12, 0, 0, 0, time.UTC)
	event := mustDomainEventOutboxEnvelope(t)
	event.ID = "domain_outbox_publisher_mode_e2e_001"
	event.OccurredAt = now.Add(-time.Minute)
	event.ReceivedAt = now
	store := postgresDomainEventOutboxStore{DB: db}
	if err := store.InsertEvent(ctx, event, now); err != nil {
		t.Fatalf("InsertEvent returned error: %v", err)
	}

	runCtx, stop := context.WithCancel(context.Background())
	go func() {
		time.Sleep(500 * time.Millisecond)
		stop()
	}()
	err = runPostgresDomainEventOutboxPublisher(runCtx, postgresDomainEventOutboxPublisherConfig{
		DSN:           dsn,
		MigrationDir:  filepath.Join("..", "..", "migrations"),
		RunMigrations: true,
		TenantID:      "tenant_lab_001",
		EventPlane:    "domain",
		PublisherID:   "domain_publisher_mode_e2e_001",
		PollInterval:  10 * time.Millisecond,
		Writer:        writer,
	})
	if err != nil {
		t.Fatalf("runPostgresDomainEventOutboxPublisher returned error: %v", err)
	}
	rows, err := writer.ReadJSONL("domain_events.log.jsonl")
	if err != nil {
		t.Fatalf("ReadJSONL returned error: %v", err)
	}
	if len(rows) != 1 || rows[0]["id"] != event.ID {
		t.Fatalf("domain event rows = %#v", rows)
	}
	var status string
	if err := db.QueryRowContext(ctx, "SELECT status FROM domain_event_outbox WHERE tenant_id = $1 AND outbox_id = $2", "tenant_lab_001", event.ID).Scan(&status); err != nil {
		t.Fatalf("query domain event status returned error: %v", err)
	}
	if status != "published" {
		t.Fatalf("domain event status = %s, want published", status)
	}
}

func TestRunPostgresDomainEventOutboxPublisherObjectStoreModeE2E(t *testing.T) {
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
	applyPostgresExportTaskQueueMigration(t, ctx, db)

	objectStore, err := objectstore.NewLocalStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalStore returned error: %v", err)
	}
	now := time.Date(2026, 5, 24, 13, 0, 0, 0, time.UTC)
	event := mustDomainEventOutboxEnvelope(t)
	event.ID = "domain_outbox_publisher_objectstore_mode_e2e_001"
	event.EventPlane = "evidence"
	event.OccurredAt = now.Add(-time.Minute)
	event.ReceivedAt = now
	store := postgresDomainEventOutboxStore{DB: db}
	if err := store.InsertEvent(ctx, event, now); err != nil {
		t.Fatalf("InsertEvent returned error: %v", err)
	}

	runCtx, stop := context.WithCancel(context.Background())
	go func() {
		time.Sleep(500 * time.Millisecond)
		stop()
	}()
	err = runPostgresDomainEventOutboxPublisher(runCtx, postgresDomainEventOutboxPublisherConfig{
		DSN:          dsn,
		MigrationDir: filepath.Join("..", "..", "migrations"),
		TenantID:     "tenant_lab_001",
		EventPlane:   "evidence",
		PublisherID:  "domain_publisher_objectstore_mode_e2e_001",
		PollInterval: 10 * time.Millisecond,
		DeliveryMode: "objectstore",
		ObjectStore:  objectStore,
	})
	if err != nil {
		t.Fatalf("runPostgresDomainEventOutboxPublisher objectstore returned error: %v", err)
	}
	manifestRef := domainEventOutboxManifestFilename(domainEventOutboxObjectFilename(event))
	verification, err := verifyDomainEventOutboxObjectManifest(objectStore, manifestRef)
	if err != nil {
		t.Fatalf("verifyDomainEventOutboxObjectManifest returned error: %v", err)
	}
	if verification.ObjectRef != domainEventOutboxObjectFilename(event) || verification.PayloadChecksum != event.PayloadChecksum || verification.RowCount != 1 {
		t.Fatalf("verification = %#v", verification)
	}
	var status string
	if err := db.QueryRowContext(ctx, "SELECT status FROM domain_event_outbox WHERE tenant_id = $1 AND outbox_id = $2", "tenant_lab_001", event.ID).Scan(&status); err != nil {
		t.Fatalf("query objectstore domain event status returned error: %v", err)
	}
	if status != "published" {
		t.Fatalf("domain event status = %s, want published", status)
	}
}

func TestRunPostgresDomainEventOutboxPublisherWebhookModeE2E(t *testing.T) {
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
	applyPostgresExportTaskQueueMigration(t, ctx, db)

	now := time.Date(2026, 5, 24, 14, 0, 0, 0, time.UTC)
	event := mustDomainEventOutboxEnvelope(t)
	event.ID = "domain_outbox_publisher_webhook_mode_e2e_001"
	event.OccurredAt = now.Add(-time.Minute)
	event.ReceivedAt = now
	store := postgresDomainEventOutboxStore{DB: db}
	if err := store.InsertEvent(ctx, event, now); err != nil {
		t.Fatalf("InsertEvent returned error: %v", err)
	}

	type webhookCapture struct {
		auth      string
		keyID     string
		timestamp string
		nonce     string
		signature string
		payload   []byte
		event     domainEventOutboxEnvelope
	}
	received := make(chan webhookCapture, 1)
	webhook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		payload, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read body", http.StatusInternalServerError)
			return
		}
		var gotEvent domainEventOutboxEnvelope
		if err := json.Unmarshal(payload, &gotEvent); err != nil {
			http.Error(w, "decode body", http.StatusBadRequest)
			return
		}
		received <- webhookCapture{
			auth:      r.Header.Get("authorization"),
			keyID:     r.Header.Get("x-domain-event-signature-key-id"),
			timestamp: r.Header.Get("x-domain-event-timestamp"),
			nonce:     r.Header.Get("x-domain-event-nonce"),
			signature: r.Header.Get("x-domain-event-signature"),
			payload:   payload,
			event:     gotEvent,
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer webhook.Close()

	runCtx, stop := context.WithCancel(context.Background())
	go func() {
		time.Sleep(500 * time.Millisecond)
		stop()
	}()
	err = runPostgresDomainEventOutboxPublisher(runCtx, postgresDomainEventOutboxPublisherConfig{
		DSN:            dsn,
		MigrationDir:   filepath.Join("..", "..", "migrations"),
		TenantID:       "tenant_lab_001",
		EventPlane:     "domain",
		PublisherID:    "domain_publisher_webhook_mode_e2e_001",
		PollInterval:   10 * time.Millisecond,
		DeliveryMode:   "webhook",
		WebhookURL:     webhook.URL,
		WebhookToken:   "domain-webhook-token",
		WebhookSecret:  "domain-webhook-secret",
		WebhookKeyID:   "kid-domain-webhook-e2e",
		WebhookTimeout: time.Second,
	})
	if err != nil {
		t.Fatalf("runPostgresDomainEventOutboxPublisher webhook returned error: %v", err)
	}

	var got webhookCapture
	select {
	case got = <-received:
	default:
		t.Fatalf("webhook did not receive a domain event")
	}
	if got.auth != "Bearer domain-webhook-token" || got.keyID != "kid-domain-webhook-e2e" || got.event.ID != event.ID {
		t.Fatalf("webhook capture = %#v", got)
	}
	if want := domainEventWebhookSignature("domain-webhook-secret", got.timestamp, got.nonce, got.payload); got.signature != want {
		t.Fatalf("webhook signature = %q, want %q", got.signature, want)
	}
	if err := verifyDomainEventWebhookSignature("domain-webhook-secret", got.timestamp, got.nonce, got.signature, got.payload, time.Now().UTC(), 5*time.Minute); err != nil {
		t.Fatalf("verifyDomainEventWebhookSignature returned error: %v", err)
	}
	var status string
	if err := db.QueryRowContext(ctx, "SELECT status FROM domain_event_outbox WHERE tenant_id = $1 AND outbox_id = $2", "tenant_lab_001", event.ID).Scan(&status); err != nil {
		t.Fatalf("query webhook domain event status returned error: %v", err)
	}
	if status != "published" {
		t.Fatalf("domain event status = %s, want published", status)
	}
}

func TestRunPostgresDomainEventOutboxPublisherWebhookFailureDeadLettersModeE2E(t *testing.T) {
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
	applyPostgresExportTaskQueueMigration(t, ctx, db)

	now := time.Date(2026, 5, 24, 14, 30, 0, 0, time.UTC)
	event := mustDomainEventOutboxEnvelope(t)
	event.ID = "domain_outbox_publisher_webhook_dead_mode_e2e_001"
	event.OccurredAt = now.Add(-time.Minute)
	event.ReceivedAt = now
	store := postgresDomainEventOutboxStore{DB: db}
	if err := store.InsertEvent(ctx, event, now); err != nil {
		t.Fatalf("InsertEvent returned error: %v", err)
	}

	received := make(chan struct{}, 1)
	webhook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case received <- struct{}{}:
		default:
		}
		http.Error(w, "temporary unavailable", http.StatusServiceUnavailable)
	}))
	defer webhook.Close()

	runCtx, stop := context.WithCancel(context.Background())
	defer stop()
	err = runPostgresDomainEventOutboxPublisher(runCtx, postgresDomainEventOutboxPublisherConfig{
		DSN:            dsn,
		MigrationDir:   filepath.Join("..", "..", "migrations"),
		TenantID:       "tenant_lab_001",
		EventPlane:     "domain",
		PublisherID:    "domain_publisher_webhook_dead_mode_e2e_001",
		PollInterval:   10 * time.Millisecond,
		DeliveryMode:   "webhook",
		WebhookURL:     webhook.URL,
		WebhookSecret:  "domain-webhook-secret",
		WebhookKeyID:   "kid-domain-webhook-dead-e2e",
		WebhookTimeout: time.Second,
		MaxAttempts:    1,
	})
	if err == nil || !strings.Contains(err.Error(), "domain_event_delivery_http_5xx") {
		t.Fatalf("runPostgresDomainEventOutboxPublisher error = %v, want domain_event_delivery_http_5xx", err)
	}
	select {
	case <-received:
	default:
		t.Fatalf("webhook did not receive the failed domain event")
	}
	var status, lastError string
	var deadAtPresent bool
	if err := db.QueryRowContext(ctx, "SELECT status, last_error, dead_at IS NOT NULL FROM domain_event_outbox WHERE tenant_id = $1 AND outbox_id = $2", "tenant_lab_001", event.ID).Scan(&status, &lastError, &deadAtPresent); err != nil {
		t.Fatalf("query webhook failure domain event status returned error: %v", err)
	}
	if status != "dead" || lastError != "domain_event_delivery_http_5xx" || !deadAtPresent {
		t.Fatalf("status=%s last_error=%s dead_at=%v, want dead/domain_event_delivery_http_5xx/dead_at", status, lastError, deadAtPresent)
	}
	deadRows, err := store.ListDead(ctx, "tenant_lab_001", "domain", 10)
	if err != nil {
		t.Fatalf("ListDead returned error: %v", err)
	}
	if len(deadRows) != 1 || deadRows[0].OutboxID != event.ID || deadRows[0].LastError != "domain_event_delivery_http_5xx" {
		t.Fatalf("deadRows = %#v, want one classified dead domain event", deadRows)
	}
	replayed, found, err := store.ReplayDead(ctx, "tenant_lab_001", "domain", event.ID, now.Add(2*time.Second))
	if err != nil {
		t.Fatalf("ReplayDead returned error: %v", err)
	}
	if !found || replayed.Status != "pending" || replayed.PublishAttempt != 0 || replayed.EventPlane != "domain" {
		t.Fatalf("replayed = %#v found=%v, want pending domain attempt 0", replayed, found)
	}
	if replayed.PreviousPublishAttempt != 1 || replayed.PreviousLastError != "domain_event_delivery_http_5xx" || replayed.PreviousDeadAt == nil {
		t.Fatalf("replayed previous failure = %#v, want attempt 1/domain_event_delivery_http_5xx/dead_at", replayed)
	}
	stats, err := store.Stats(ctx, "tenant_lab_001", "domain")
	if err != nil {
		t.Fatalf("Stats after replay returned error: %v", err)
	}
	if stats.Pending != 1 || stats.Dead != 0 || stats.Total != 1 || stats.OldestPendingAt == nil || !stats.OldestPendingAt.Equal(event.OccurredAt.UTC()) {
		t.Fatalf("stats after replay = %#v, want one pending row", stats)
	}
	claimedAfterReplay, err := store.Claim(ctx, "tenant_lab_001", "domain", "domain_publisher_replay_e2e_001", 10, 5, now.Add(3*time.Second), time.Minute)
	if err != nil {
		t.Fatalf("Claim after replay returned error: %v", err)
	}
	if len(claimedAfterReplay) != 1 || claimedAfterReplay[0].ID != event.ID || claimedAfterReplay[0].PublishAttempt != 1 {
		t.Fatalf("claimed after replay = %#v, want replayed event attempt 1", claimedAfterReplay)
	}
}
