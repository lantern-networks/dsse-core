package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	usagemeter "github.com/lantern-networks/dsse-core/usagemeter"

	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/objectstore"
)

type recordingAdminAuditOutboxDeadReader struct {
	mu       sync.Mutex
	tenantID string
	limit    int
	rows     []postgresAdminAuditOutboxDeadRow
	err      error

	getTenantID string
	getOutboxID string
	getRow      postgresAdminAuditOutboxDeadRow
	getFound    bool
	getErr      error

	replayTenantID string
	replayOutboxID string
	replayResult   postgresAdminAuditOutboxReplayResult
	replayFound    bool
	replayErr      error

	statsTenantID string
	stats         postgresAdminAuditOutboxStats
	statsErr      error

	insertedAudits []model.AuditLog
	wrapperAudits  []model.AuditLog // admin_config_change rows from the adminEndpoint wrapper (b), kept separately
	insertErr      error
}

type recordingDomainEventOutbox struct {
	mu sync.Mutex

	events []domainEventOutboxEnvelope
	err    error

	listTenantID   string
	listEventPlane string
	listLimit      int
	deadRows       []postgresDomainEventOutboxDeadRow
	listErr        error

	statsTenantID   string
	statsEventPlane string
	stats           postgresDomainEventOutboxStats
	statsErr        error

	replayTenantID   string
	replayEventPlane string
	replayOutboxID   string
	replayResult     postgresDomainEventOutboxReplayResult
	replayFound      bool
	replayErr        error
}

func (outbox *recordingDomainEventOutbox) InsertEvent(_ context.Context, event domainEventOutboxEnvelope, _ time.Time) error {
	outbox.mu.Lock()
	defer outbox.mu.Unlock()
	outbox.events = append(outbox.events, event)
	return outbox.err
}

func (outbox *recordingDomainEventOutbox) insertedEvents() []domainEventOutboxEnvelope {
	outbox.mu.Lock()
	defer outbox.mu.Unlock()
	return append([]domainEventOutboxEnvelope(nil), outbox.events...)
}

func (outbox *recordingDomainEventOutbox) ListDead(_ context.Context, tenantID, eventPlane string, limit int) ([]postgresDomainEventOutboxDeadRow, error) {
	outbox.mu.Lock()
	defer outbox.mu.Unlock()
	outbox.listTenantID = tenantID
	outbox.listEventPlane = eventPlane
	outbox.listLimit = limit
	return outbox.deadRows, outbox.listErr
}

func (outbox *recordingDomainEventOutbox) Stats(_ context.Context, tenantID, eventPlane string) (postgresDomainEventOutboxStats, error) {
	outbox.mu.Lock()
	defer outbox.mu.Unlock()
	outbox.statsTenantID = tenantID
	outbox.statsEventPlane = eventPlane
	return outbox.stats, outbox.statsErr
}

func (outbox *recordingDomainEventOutbox) ReplayDead(_ context.Context, tenantID, eventPlane, outboxID string, _ time.Time) (postgresDomainEventOutboxReplayResult, bool, error) {
	outbox.mu.Lock()
	defer outbox.mu.Unlock()
	outbox.replayTenantID = tenantID
	outbox.replayEventPlane = eventPlane
	outbox.replayOutboxID = outboxID
	return outbox.replayResult, outbox.replayFound, outbox.replayErr
}

func (reader *recordingAdminAuditOutboxDeadReader) ListDead(_ context.Context, tenantID string, limit int) ([]postgresAdminAuditOutboxDeadRow, error) {
	reader.tenantID = tenantID
	reader.limit = limit
	return reader.rows, reader.err
}

func (reader *recordingAdminAuditOutboxDeadReader) GetDead(_ context.Context, tenantID, outboxID string) (postgresAdminAuditOutboxDeadRow, bool, error) {
	reader.getTenantID = tenantID
	reader.getOutboxID = outboxID
	return reader.getRow, reader.getFound, reader.getErr
}

func (reader *recordingAdminAuditOutboxDeadReader) ReplayDead(_ context.Context, tenantID, outboxID string, _ time.Time) (postgresAdminAuditOutboxReplayResult, bool, error) {
	reader.replayTenantID = tenantID
	reader.replayOutboxID = outboxID
	return reader.replayResult, reader.replayFound, reader.replayErr
}

func (reader *recordingAdminAuditOutboxDeadReader) Stats(_ context.Context, tenantID string) (postgresAdminAuditOutboxStats, error) {
	reader.statsTenantID = tenantID
	return reader.stats, reader.statsErr
}

func (reader *recordingAdminAuditOutboxDeadReader) InsertAudit(_ context.Context, audit model.AuditLog, _ time.Time) error {
	reader.mu.Lock()
	defer reader.mu.Unlock()
	// The adminEndpoint wrapper emits a uniform `admin_config_change` audit per mutation (b), which lands in
	// this recording outbox alongside each handler's domain audit. Domain-audit contract tests assert on their
	// specific event via insertedAudits, so drop the wrapper row here (its own coverage is tested separately via
	// the audit stream file). This keeps the ~17 domain contract tests asserting exactly their event.
	if audit.EventType == "admin_config_change" {
		reader.wrapperAudits = append(reader.wrapperAudits, audit)
		return reader.insertErr
	}
	reader.insertedAudits = append(reader.insertedAudits, audit)
	return reader.insertErr
}

func (reader *recordingAdminAuditOutboxDeadReader) insertedAuditEventTypes() map[string]bool {
	reader.mu.Lock()
	defer reader.mu.Unlock()
	return auditLogEventTypes(append([]model.AuditLog(nil), reader.insertedAudits...))
}

func TestAdminAuditOutboxDeadRowsEndpointScopesTenant(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	reader := &recordingAdminAuditOutboxDeadReader{
		rows: []postgresAdminAuditOutboxDeadRow{
			{
				TenantID:       "tenant_lab_001",
				OutboxID:       "audit_dead_001",
				EventType:      "admin_export_requested",
				PublishAttempt: 3,
				LastError:      "audit_delivery_failed",
				OccurredAt:     time.Date(2026, 5, 24, 1, 0, 0, 0, time.UTC),
				DeadAt:         time.Date(2026, 5, 24, 1, 5, 0, 0, time.UTC),
				Audit: model.AuditLog{
					ID:        "audit_dead_001",
					TenantID:  "tenant_lab_001",
					EventType: "admin_export_requested",
					Timestamp: "2026-05-24T01:00:00Z",
				},
			},
		},
	}
	handler := newServerWithConfig(serverConfig{
		Evaluator:        testEvaluator(),
		Writer:           writer,
		Registry:         connector.NewRegistry(),
		AdminAuditOutbox: reader,
	})
	req := httptest.NewRequest(http.MethodGet, "/admin/audit-outbox/dead?tenant_id=tenant_other_001&limit=7", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if reader.tenantID != "tenant_lab_001" || reader.limit != 7 {
		t.Fatalf("reader got tenant=%q limit=%d, want tenant_lab_001 limit=7", reader.tenantID, reader.limit)
	}
	var result map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&result); err != nil {
		t.Fatalf("decode dead rows response: %v", err)
	}
	if result["limit"] != float64(7) || result["returned"] != float64(1) {
		t.Fatalf("result summary = %#v", result)
	}
	rows, ok := result["rows"].([]any)
	if !ok || len(rows) != 1 {
		t.Fatalf("rows = %#v", result["rows"])
	}
	row, ok := rows[0].(map[string]any)
	if !ok || row["tenant_id"] != "tenant_lab_001" || row["outbox_id"] != "audit_dead_001" || row["last_error"] != "audit_delivery_failed" {
		t.Fatalf("row = %#v", rows[0])
	}
}

func TestAdminAuditOutboxDeadRowDetailEndpointScopesTenant(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	reader := &recordingAdminAuditOutboxDeadReader{
		getFound: true,
		getRow: postgresAdminAuditOutboxDeadRow{
			TenantID:       "tenant_lab_001",
			OutboxID:       "audit_dead_001",
			EventType:      "admin_export_requested",
			PublishAttempt: 5,
			LastError:      "audit_delivery_http_5xx",
			OccurredAt:     time.Date(2026, 5, 23, 1, 0, 0, 0, time.UTC),
			DeadAt:         time.Date(2026, 5, 23, 1, 5, 0, 0, time.UTC),
			Audit:          model.AuditLog{ID: "audit_dead_001", TenantID: "tenant_lab_001", EventType: "admin_export_requested"},
		},
	}
	handler := newServerWithConfig(serverConfig{
		Evaluator:        testEvaluator(),
		Writer:           writer,
		Registry:         connector.NewRegistry(),
		AdminAuditOutbox: reader,
	})
	req := httptest.NewRequest(http.MethodGet, "/admin/audit-outbox/dead/audit_dead_001?tenant_id=tenant_other_001", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if reader.getTenantID != "tenant_lab_001" || reader.getOutboxID != "audit_dead_001" {
		t.Fatalf("get dead got tenant=%q outbox=%q", reader.getTenantID, reader.getOutboxID)
	}
	var result postgresAdminAuditOutboxDeadRow
	if err := json.NewDecoder(rec.Body).Decode(&result); err != nil {
		t.Fatalf("decode dead row detail: %v", err)
	}
	if result.OutboxID != "audit_dead_001" || result.LastError != "audit_delivery_http_5xx" || result.Audit.ID != "audit_dead_001" {
		t.Fatalf("result = %#v", result)
	}
}

func TestAdminAuditOutboxStatsEndpointScopesTenant(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	reader := &recordingAdminAuditOutboxDeadReader{
		stats: postgresAdminAuditOutboxStats{
			TenantID:   "tenant_lab_001",
			Pending:    2,
			Publishing: 1,
			Published:  4,
			Dead:       3,
			Total:      10,
		},
	}
	handler := newServerWithConfig(serverConfig{
		Evaluator:        testEvaluator(),
		Writer:           writer,
		Registry:         connector.NewRegistry(),
		AdminAuditOutbox: reader,
	})
	req := httptest.NewRequest(http.MethodGet, "/admin/audit-outbox/stats?tenant_id=tenant_other_001", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if reader.statsTenantID != "tenant_lab_001" {
		t.Fatalf("stats tenant = %q, want tenant_lab_001", reader.statsTenantID)
	}
	var result postgresAdminAuditOutboxStats
	if err := json.NewDecoder(rec.Body).Decode(&result); err != nil {
		t.Fatalf("decode stats response: %v", err)
	}
	if result.Dead != 3 || result.Total != 10 {
		t.Fatalf("stats = %#v", result)
	}
}

func TestAdminAuditOutboxHealthEndpointScopesTenant(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	oldestPending := time.Now().UTC().Add(-adminAuditOutboxPendingStaleAfter - time.Minute)
	reader := &recordingAdminAuditOutboxDeadReader{
		stats: postgresAdminAuditOutboxStats{
			TenantID:        "tenant_lab_001",
			Pending:         1,
			Dead:            1,
			Total:           2,
			OldestPendingAt: &oldestPending,
		},
	}
	handler := newServerWithConfig(serverConfig{
		Evaluator:        testEvaluator(),
		Writer:           writer,
		Registry:         connector.NewRegistry(),
		AdminAuditOutbox: reader,
	})
	req := httptest.NewRequest(http.MethodGet, "/admin/audit-outbox/health?tenant_id=tenant_other_001", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if reader.statsTenantID != "tenant_lab_001" {
		t.Fatalf("health tenant = %q, want tenant_lab_001", reader.statsTenantID)
	}
	var result adminAuditOutboxHealth
	if err := json.NewDecoder(rec.Body).Decode(&result); err != nil {
		t.Fatalf("decode health response: %v", err)
	}
	reasons := strings.Join(result.Reasons, ",")
	if result.Status != "degraded" || result.Stats.Dead != 1 || !strings.Contains(reasons, "dead_rows_present") || !strings.Contains(reasons, "pending_backlog_stale") {
		t.Fatalf("health = %#v", result)
	}
}

func TestAdminAuditOutboxHealthFromStatsOK(t *testing.T) {
	now := time.Date(2026, 5, 23, 4, 0, 0, 0, time.UTC)
	oldestPending := now.Add(-time.Minute)
	health := adminAuditOutboxHealthFromStats(postgresAdminAuditOutboxStats{
		TenantID:        "tenant_lab_001",
		Pending:         1,
		Total:           1,
		OldestPendingAt: &oldestPending,
	}, now)
	if health.Status != "ok" || len(health.Reasons) != 0 || health.CheckedAt != now.Format(time.RFC3339) {
		t.Fatalf("health = %#v, want ok", health)
	}
}

func TestDomainEventOutboxDeadRowsEndpointScopesTenantAndPlane(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	outbox := &recordingDomainEventOutbox{
		deadRows: []postgresDomainEventOutboxDeadRow{
			{
				TenantID:        "tenant_lab_001",
				OutboxID:        "domain_dead_001",
				EventPlane:      "access",
				Stream:          "tool_call_events",
				EventType:       "tool_call_recorded",
				PublishAttempt:  5,
				LastError:       "domain_event_delivery_http_5xx",
				OccurredAt:      time.Date(2026, 5, 24, 1, 0, 0, 0, time.UTC),
				DeadAt:          time.Date(2026, 5, 24, 1, 5, 0, 0, time.UTC),
				PayloadChecksum: "sha256:abc",
				Payload:         map[string]any{"tool_call_event_id": "tool_call_001"},
				Metadata:        map[string]any{"source_event_id": "tool_call_001"},
			},
		},
	}
	handler := newServerWithConfig(serverConfig{
		Evaluator:         testEvaluator(),
		Writer:            writer,
		Registry:          connector.NewRegistry(),
		DomainEventOutbox: outbox,
		AdminAuditOutbox:  &recordingAdminAuditOutboxDeadReader{},
	})
	req := httptest.NewRequest(http.MethodGet, "/admin/domain-event-outbox/dead?tenant_id=tenant_other_001&event_plane=access&limit=7", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if outbox.listTenantID != "tenant_lab_001" || outbox.listEventPlane != "access" || outbox.listLimit != 7 {
		t.Fatalf("list got tenant=%q plane=%q limit=%d", outbox.listTenantID, outbox.listEventPlane, outbox.listLimit)
	}
	var result map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&result); err != nil {
		t.Fatalf("decode dead rows response: %v", err)
	}
	if result["event_plane"] != "access" || result["limit"] != float64(7) || result["returned"] != float64(1) {
		t.Fatalf("result summary = %#v", result)
	}
	rows, ok := result["rows"].([]any)
	if !ok || len(rows) != 1 {
		t.Fatalf("rows = %#v", result["rows"])
	}
	row, ok := rows[0].(map[string]any)
	if !ok || row["tenant_id"] != "tenant_lab_001" || row["event_plane"] != "access" || row["outbox_id"] != "domain_dead_001" {
		t.Fatalf("row = %#v", rows[0])
	}
}

func TestDomainEventOutboxStatsEndpointScopesTenantAndPlane(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	outbox := &recordingDomainEventOutbox{
		stats: postgresDomainEventOutboxStats{
			TenantID:   "tenant_lab_001",
			EventPlane: "evidence",
			Pending:    2,
			Publishing: 1,
			Published:  4,
			Dead:       3,
			Total:      10,
		},
	}
	handler := newServerWithConfig(serverConfig{
		Evaluator:         testEvaluator(),
		Writer:            writer,
		Registry:          connector.NewRegistry(),
		DomainEventOutbox: outbox,
	})
	req := httptest.NewRequest(http.MethodGet, "/admin/domain-event-outbox/stats?tenant_id=tenant_other_001&event_plane=evidence", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if outbox.statsTenantID != "tenant_lab_001" || outbox.statsEventPlane != "evidence" {
		t.Fatalf("stats got tenant=%q plane=%q", outbox.statsTenantID, outbox.statsEventPlane)
	}
	var result postgresDomainEventOutboxStats
	if err := json.NewDecoder(rec.Body).Decode(&result); err != nil {
		t.Fatalf("decode stats response: %v", err)
	}
	if result.EventPlane != "evidence" || result.Dead != 3 || result.Total != 10 {
		t.Fatalf("stats = %#v", result)
	}
}

func TestDomainEventOutboxHealthEndpointScopesTenantAndPlane(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	oldestPublishing := time.Now().UTC().Add(-domainEventOutboxPublishingStaleAfter - time.Minute)
	outbox := &recordingDomainEventOutbox{
		stats: postgresDomainEventOutboxStats{
			TenantID:           "tenant_lab_001",
			EventPlane:         "domain",
			Publishing:         1,
			Total:              1,
			OldestPublishingAt: &oldestPublishing,
		},
	}
	handler := newServerWithConfig(serverConfig{
		Evaluator:         testEvaluator(),
		Writer:            writer,
		Registry:          connector.NewRegistry(),
		DomainEventOutbox: outbox,
	})
	req := httptest.NewRequest(http.MethodGet, "/admin/domain-event-outbox/health?tenant_id=tenant_other_001", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if outbox.statsTenantID != "tenant_lab_001" || outbox.statsEventPlane != "domain" {
		t.Fatalf("health got tenant=%q plane=%q", outbox.statsTenantID, outbox.statsEventPlane)
	}
	var result domainEventOutboxHealth
	if err := json.NewDecoder(rec.Body).Decode(&result); err != nil {
		t.Fatalf("decode health response: %v", err)
	}
	if result.Status != "degraded" || result.EventPlane != "domain" || !strings.Contains(strings.Join(result.Reasons, ","), "publishing_lock_stale") {
		t.Fatalf("health = %#v", result)
	}
}

func TestDomainEventOutboxObjectManifestVerifyEndpoint(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	objectStore, err := objectstore.NewLocalStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalStore returned error: %v", err)
	}
	event := mustDomainEventOutboxEnvelope(t)
	event.EventPlane = "evidence"
	if err := (objectStoreDomainEventOutboxDelivery{ObjectStore: objectStore}).DeliverDomainEvent(context.Background(), event); err != nil {
		t.Fatalf("DeliverDomainEvent returned error: %v", err)
	}
	manifestRef := domainEventOutboxManifestFilename(domainEventOutboxObjectFilename(event))
	handler := newServerWithConfig(serverConfig{
		Evaluator:         testEvaluator(),
		Writer:            writer,
		Registry:          connector.NewRegistry(),
		ExportObjectStore: objectStore,
	})
	req := httptest.NewRequest(http.MethodGet, "/admin/domain-event-outbox/object-manifests/verify?manifest_ref="+url.QueryEscape(manifestRef), nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var result domainEventOutboxObjectVerification
	if err := json.NewDecoder(rec.Body).Decode(&result); err != nil {
		t.Fatalf("decode verification response: %v", err)
	}
	if result.ManifestRef != manifestRef || result.ObjectRef != domainEventOutboxObjectFilename(event) || result.PayloadChecksum != event.PayloadChecksum || result.RowCount != 1 {
		t.Fatalf("verification = %#v", result)
	}
}

func TestDomainEventOutboxObjectManifestVerifyEndpointReturnsNotFoundForMissingManifest(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	objectStoreDir := t.TempDir()
	objectStore, err := objectstore.NewLocalStore(objectStoreDir)
	if err != nil {
		t.Fatalf("NewLocalStore returned error: %v", err)
	}
	handler := newServerWithConfig(serverConfig{
		Evaluator:         testEvaluator(),
		Writer:            writer,
		Registry:          connector.NewRegistry(),
		ExportObjectStore: objectStore,
	})
	manifestRef := "domain-events/tenant_lab_001/domain/2026/05/24/missing.manifest.ndjson.gz"
	req := httptest.NewRequest(http.MethodGet, "/admin/domain-event-outbox/object-manifests/verify?manifest_ref="+url.QueryEscape(manifestRef), nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusNotFound, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "domain event object manifest not found") {
		t.Fatalf("body = %s, want generic not found error", rec.Body.String())
	}
	for _, leaked := range []string{objectStoreDir, "no such file", "read generated object"} {
		if strings.Contains(rec.Body.String(), leaked) {
			t.Fatalf("body leaked %q: %s", leaked, rec.Body.String())
		}
	}
}

func TestDomainEventOutboxObjectManifestVerifyEndpointReturnsUnprocessableForChecksumMismatch(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	objectStoreDir := t.TempDir()
	objectStore, err := objectstore.NewLocalStore(objectStoreDir)
	if err != nil {
		t.Fatalf("NewLocalStore returned error: %v", err)
	}
	event := mustDomainEventOutboxEnvelope(t)
	event.EventPlane = "evidence"
	value, err := domainEventOutboxEnvelopeMap(event)
	if err != nil {
		t.Fatalf("domainEventOutboxEnvelopeMap returned error: %v", err)
	}
	objectRef := domainEventOutboxObjectFilename(event)
	if _, err := objectStore.WriteGzipJSONL(objectRef, []map[string]any{value}); err != nil {
		t.Fatalf("WriteGzipJSONL object returned error: %v", err)
	}
	manifestRef := domainEventOutboxManifestFilename(objectRef)
	manifest := map[string]any{
		"schema_version":   event.SchemaVersion,
		"tenant_id":        event.TenantID,
		"event_plane":      event.EventPlane,
		"stream":           event.Stream,
		"event_type":       event.EventType,
		"outbox_id":        event.ID,
		"object_ref":       objectRef,
		"object_checksum":  "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		"payload_checksum": event.PayloadChecksum,
		"format":           "ndjson",
		"compression":      "gzip",
		"row_count":        1,
		"occurred_at":      event.OccurredAt.Format(time.RFC3339),
		"received_at":      event.ReceivedAt.Format(time.RFC3339),
		"created_at":       time.Date(2026, 5, 24, 7, 0, 0, 0, time.UTC).Format(time.RFC3339),
	}
	if _, err := objectStore.WriteGzipJSONL(manifestRef, []map[string]any{manifest}); err != nil {
		t.Fatalf("WriteGzipJSONL manifest returned error: %v", err)
	}
	handler := newServerWithConfig(serverConfig{
		Evaluator:         testEvaluator(),
		Writer:            writer,
		Registry:          connector.NewRegistry(),
		ExportObjectStore: objectStore,
	})
	req := httptest.NewRequest(http.MethodGet, "/admin/domain-event-outbox/object-manifests/verify?manifest_ref="+url.QueryEscape(manifestRef), nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusUnprocessableEntity, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "domain event object manifest verification failed") {
		t.Fatalf("body = %s, want generic verification error", rec.Body.String())
	}
	for _, leaked := range []string{objectStoreDir, "checksum mismatch", "bbbbbbbb"} {
		if strings.Contains(rec.Body.String(), leaked) {
			t.Fatalf("body leaked %q: %s", leaked, rec.Body.String())
		}
	}
}

func TestDomainEventOutboxObjectManifestVerifyEndpointReturnsInternalForStoreFailure(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	handler := newServerWithConfig(serverConfig{
		Evaluator:         testEvaluator(),
		Writer:            writer,
		Registry:          connector.NewRegistry(),
		ExportObjectStore: failingGeneratedObjectStore{readErr: fmt.Errorf("backend path /secret/domain-events unavailable")},
	})
	manifestRef := "domain-events/tenant_lab_001/domain/2026/05/24/internal.manifest.ndjson.gz"
	req := httptest.NewRequest(http.MethodGet, "/admin/domain-event-outbox/object-manifests/verify?manifest_ref="+url.QueryEscape(manifestRef), nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusInternalServerError, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "domain event object manifest verification internal error") {
		t.Fatalf("body = %s, want generic internal verification error", rec.Body.String())
	}
	for _, leaked := range []string{"/secret", "backend path", "unavailable"} {
		if strings.Contains(rec.Body.String(), leaked) {
			t.Fatalf("body leaked %q: %s", leaked, rec.Body.String())
		}
	}
}

func TestDomainEventOutboxObjectManifestListEndpoint(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	objectStore, err := objectstore.NewLocalStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalStore returned error: %v", err)
	}
	event := mustDomainEventOutboxEnvelope(t)
	event.EventPlane = "evidence"
	if err := (objectStoreDomainEventOutboxDelivery{ObjectStore: objectStore}).DeliverDomainEvent(context.Background(), event); err != nil {
		t.Fatalf("DeliverDomainEvent returned error: %v", err)
	}
	manifestRef := domainEventOutboxManifestFilename(domainEventOutboxObjectFilename(event))
	handler := newServerWithConfig(serverConfig{
		Evaluator:         testEvaluator(),
		Writer:            writer,
		Registry:          connector.NewRegistry(),
		ExportObjectStore: objectStore,
	})
	req := httptest.NewRequest(http.MethodGet, "/admin/domain-event-outbox/object-manifests?event_plane=evidence&limit=10", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var result domainEventOutboxObjectManifestListResponse
	if err := json.NewDecoder(rec.Body).Decode(&result); err != nil {
		t.Fatalf("decode manifest list response: %v", err)
	}
	if result.EventPlane != "evidence" || result.Prefix != "domain-events/tenant_lab_001/evidence/" || result.Returned != 1 || len(result.Rows) != 1 || result.Rows[0].ManifestRef != manifestRef {
		t.Fatalf("manifest list = %#v", result)
	}
}

func TestDomainEventOutboxObjectManifestListEndpointRejectsInvalidPlane(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	objectStore, err := objectstore.NewLocalStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalStore returned error: %v", err)
	}
	handler := newServerWithConfig(serverConfig{
		Evaluator:         testEvaluator(),
		Writer:            writer,
		Registry:          connector.NewRegistry(),
		ExportObjectStore: objectStore,
	})
	req := httptest.NewRequest(http.MethodGet, "/admin/domain-event-outbox/object-manifests?event_plane=admin", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

func TestDomainEventOutboxObjectManifestListEndpointRejectsUnsafePrefix(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	objectStore, err := objectstore.NewLocalStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalStore returned error: %v", err)
	}
	handler := newServerWithConfig(serverConfig{
		Evaluator:         testEvaluator(),
		Writer:            writer,
		Registry:          connector.NewRegistry(),
		ExportObjectStore: objectStore,
	})
	req := httptest.NewRequest(http.MethodGet, "/admin/domain-event-outbox/object-manifests?prefix=../domain-events/", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

func TestDomainEventOutboxObjectManifestListEndpointRejectsCrossTenantPrefix(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	objectStore, err := objectstore.NewLocalStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalStore returned error: %v", err)
	}
	handler := newServerWithConfig(serverConfig{
		Evaluator:         testEvaluator(),
		Writer:            writer,
		Registry:          connector.NewRegistry(),
		ExportObjectStore: objectStore,
	})
	req := httptest.NewRequest(http.MethodGet, "/admin/domain-event-outbox/object-manifests?prefix=domain-events/tenant_other_001/", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

func TestDomainEventOutboxObjectManifestVerifyEndpointRejectsUnsafeRef(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	domainOutbox := &recordingDomainEventOutbox{}
	usageMeters := usagemeter.NewUsageMeterStore()
	handler := newServerWithConfig(serverConfig{
		Evaluator:         testEvaluator(),
		Writer:            writer,
		Registry:          connector.NewRegistry(),
		DomainEventOutbox: domainOutbox,
		UsageMeters:       usageMeters,
	})
	req := httptest.NewRequest(http.MethodGet, "/admin/domain-event-outbox/object-manifests/verify?manifest_ref=../domain-events/tenant/evidence/2026/05/24/bad.manifest.ndjson.gz", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

func TestDomainEventOutboxObjectManifestVerifyEndpointRejectsCrossTenantRef(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	handler := newServerWithConfig(serverConfig{
		Evaluator: testEvaluator(),
		Writer:    writer,
		Registry:  connector.NewRegistry(),
	})
	req := httptest.NewRequest(http.MethodGet, "/admin/domain-event-outbox/object-manifests/verify?manifest_ref=domain-events/tenant_other_001/domain/2026/05/24/bad.manifest.ndjson.gz", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

func TestDomainEventOutboxEndpointRejectsInvalidPlane(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	handler := newServerWithConfig(serverConfig{
		Evaluator:         testEvaluator(),
		Writer:            writer,
		Registry:          connector.NewRegistry(),
		DomainEventOutbox: &recordingDomainEventOutbox{},
	})
	req := httptest.NewRequest(http.MethodGet, "/admin/domain-event-outbox/stats?event_plane=admin", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

func TestDomainEventOutboxReplayEndpointScopesTenantPlaneAndAudits(t *testing.T) {
	if !adminPermissionAllowed([]string{"admin"}, "admin.domain_events.delivery.replay") {
		t.Fatalf("admin role should have admin.domain_events.delivery.replay")
	}
	if adminPermissionAllowed([]string{"auditor"}, "admin.domain_events.delivery.replay") {
		t.Fatalf("auditor role should not have admin.domain_events.delivery.replay")
	}
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	domainOutbox := &recordingDomainEventOutbox{
		replayFound: true,
		replayResult: postgresDomainEventOutboxReplayResult{
			TenantID:               "tenant_lab_001",
			OutboxID:               "domain_dead_001",
			EventPlane:             "access",
			Status:                 "pending",
			PublishAttempt:         0,
			UpdatedAt:              time.Date(2026, 5, 24, 2, 0, 0, 0, time.UTC),
			PreviousPublishAttempt: 5,
			PreviousLastError:      "domain_event_delivery_http_5xx",
		},
	}
	auditOutbox := &recordingAdminAuditOutboxDeadReader{}
	handler := newServerWithConfig(serverConfig{
		Evaluator:         testEvaluator(),
		Writer:            writer,
		Registry:          connector.NewRegistry(),
		DomainEventOutbox: domainOutbox,
		AdminAuditOutbox:  auditOutbox,
	})
	req := httptest.NewRequest(http.MethodPost, "/admin/domain-event-outbox/dead/domain_dead_001/replay?tenant_id=tenant_other_001&event_plane=access", strings.NewReader(`{"reason":"operator retry"}`))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if domainOutbox.replayTenantID != "tenant_lab_001" || domainOutbox.replayEventPlane != "access" || domainOutbox.replayOutboxID != "domain_dead_001" {
		t.Fatalf("replay got tenant=%q plane=%q outbox=%q", domainOutbox.replayTenantID, domainOutbox.replayEventPlane, domainOutbox.replayOutboxID)
	}
	var result postgresDomainEventOutboxReplayResult
	if err := json.NewDecoder(rec.Body).Decode(&result); err != nil {
		t.Fatalf("decode replay response: %v", err)
	}
	if result.Status != "pending" || result.EventPlane != "access" || result.PublishAttempt != 0 {
		t.Fatalf("result = %#v, want access pending attempt 0", result)
	}
	auditRows, err := readAuditRowsExcludingWrapper(writer)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	if len(auditRows) != 1 || auditRows[0]["event_type"] != "admin_domain_event_outbox_replayed" {
		t.Fatalf("audit rows = %#v", auditRows)
	}
	metadata := auditRows[0]["metadata"].(map[string]any)
	if metadata["outbox_id"] != "domain_dead_001" || metadata["event_plane"] != "access" || metadata["reason"] != "operator retry" || metadata["previous_last_error"] != "domain_event_delivery_http_5xx" {
		t.Fatalf("metadata = %#v", metadata)
	}
	if len(auditOutbox.insertedAudits) != 1 || auditOutbox.insertedAudits[0].EventType != "admin_domain_event_outbox_replayed" {
		t.Fatalf("outbox audits = %#v", auditOutbox.insertedAudits)
	}
}

func TestDomainEventOutboxMirrorHealthEndpoint(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	monitor := newDomainEventOutboxMirrorMonitor()
	monitor.RecordInsertFailure(domainEventOutboxEnvelope{
		ID:         "domain_outbox_access_logs_alog_001",
		EventPlane: "access",
		Stream:     "access_logs",
	}, fmt.Errorf("postgres unavailable"), time.Date(2026, 5, 24, 8, 30, 0, 0, time.UTC))
	handler := newServerWithConfig(serverConfig{
		Evaluator:         testEvaluator(),
		Writer:            writer,
		DomainEventMirror: monitor,
	})

	req := httptest.NewRequest(http.MethodGet, "/admin/domain-event-outbox/mirror-health", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("domain event mirror health status = %d, want %d, body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var health domainEventOutboxMirrorHealth
	if err := json.Unmarshal(rec.Body.Bytes(), &health); err != nil {
		t.Fatalf("decode domain event mirror health: %v", err)
	}
	if health.Status != "degraded" || health.Stats["insert_failures"] != 1 || health.LastEventPlane != "access" || health.LastStream != "access_logs" {
		t.Fatalf("health = %#v, want degraded access insert failure", health)
	}
}

func TestAdminAuditOutboxReplayEndpointScopesTenantAndAudits(t *testing.T) {
	if !adminPermissionAllowed([]string{"admin"}, "admin.audit.delivery.replay") {
		t.Fatalf("admin role should have admin.audit.delivery.replay")
	}
	if adminPermissionAllowed([]string{"auditor"}, "admin.audit.delivery.replay") {
		t.Fatalf("auditor role should not have admin.audit.delivery.replay")
	}
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	reader := &recordingAdminAuditOutboxDeadReader{
		replayFound: true,
		replayResult: postgresAdminAuditOutboxReplayResult{
			TenantID:               "tenant_lab_001",
			OutboxID:               "audit_dead_001",
			Status:                 "pending",
			PublishAttempt:         0,
			UpdatedAt:              time.Date(2026, 5, 24, 2, 0, 0, 0, time.UTC),
			PreviousPublishAttempt: 5,
			PreviousLastError:      "audit_delivery_http_5xx",
		},
	}
	handler := newServerWithConfig(serverConfig{
		Evaluator:        testEvaluator(),
		Writer:           writer,
		Registry:         connector.NewRegistry(),
		AdminAuditOutbox: reader,
	})
	req := httptest.NewRequest(http.MethodPost, "/admin/audit-outbox/dead/audit_dead_001/replay?tenant_id=tenant_other_001", strings.NewReader(`{"reason":"operator retry"}`))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if reader.replayTenantID != "tenant_lab_001" || reader.replayOutboxID != "audit_dead_001" {
		t.Fatalf("replay got tenant=%q outbox=%q", reader.replayTenantID, reader.replayOutboxID)
	}
	var result postgresAdminAuditOutboxReplayResult
	if err := json.NewDecoder(rec.Body).Decode(&result); err != nil {
		t.Fatalf("decode replay response: %v", err)
	}
	if result.Status != "pending" || result.PublishAttempt != 0 {
		t.Fatalf("result = %#v, want pending attempt 0", result)
	}
	auditRows, err := readAuditRowsExcludingWrapper(writer)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	if len(auditRows) != 1 || auditRows[0]["event_type"] != "admin_audit_outbox_replayed" {
		t.Fatalf("audit rows = %#v", auditRows)
	}
	metadata := auditRows[0]["metadata"].(map[string]any)
	if metadata["outbox_id"] != "audit_dead_001" || metadata["status"] != "pending" || metadata["reason"] != "operator retry" || metadata["previous_last_error"] != "audit_delivery_http_5xx" {
		t.Fatalf("metadata = %#v", metadata)
	}
	if len(reader.insertedAudits) != 1 || reader.insertedAudits[0].EventType != "admin_audit_outbox_replayed" {
		t.Fatalf("outbox inserted audits = %#v, want replay audit", reader.insertedAudits)
	}
}
