package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/lantern-networks/dsse-core/model"
)

const domainEventOutboxSchemaVersion = "2026-05-24.1"

var domainEventOutboxAllowedStreamList = []string{
	"authentication_events",
	"break_glass_events",
	"device_events",
	"agent_update_events",
	"human_approval_events",
	"delegated_access_grants",
	"tool_call_events",
	"inspection_events",
	"access_logs",
	"decision_traces",
	"connector_logs",
}

var domainEventOutboxAllowedStreams = domainEventOutboxAllowedStreamSet(domainEventOutboxAllowedStreamList)

type domainEventOutboxEnvelope struct {
	ID              string         `json:"id"`
	TenantID        string         `json:"tenant_id"`
	SchemaVersion   string         `json:"schema_version"`
	EventPlane      string         `json:"event_plane"`
	Stream          string         `json:"stream"`
	EventType       string         `json:"event_type"`
	Status          string         `json:"status"`
	OccurredAt      time.Time      `json:"occurred_at"`
	ReceivedAt      time.Time      `json:"received_at"`
	Payload         map[string]any `json:"payload"`
	PayloadChecksum string         `json:"payload_checksum"`
	PublishAttempt  int            `json:"publish_attempt"`
	NextAttemptAt   *time.Time     `json:"next_attempt_at,omitempty"`
	LockedBy        *string        `json:"locked_by,omitempty"`
	LockedUntil     *time.Time     `json:"locked_until,omitempty"`
	LastError       *string        `json:"last_error,omitempty"`
	DeadAt          *time.Time     `json:"dead_at,omitempty"`
	Metadata        map[string]any `json:"metadata"`
}

func domainEventOutboxEnvelopeFromToolCallEvent(event model.ToolCallEvent, now time.Time) (domainEventOutboxEnvelope, error) {
	return domainEventOutboxEnvelopeFromModel("tool_call_events", "tool_call_event_recorded", event.ID, event.TenantID, event.Timestamp, event, now)
}

func domainEventOutboxEnvelopeFromHumanApprovalEvent(event model.HumanApprovalEvent, now time.Time) (domainEventOutboxEnvelope, error) {
	return domainEventOutboxEnvelopeFromModel("human_approval_events", "human_approval_event_recorded", event.ID, event.TenantID, event.CreatedAt, event, now)
}

func domainEventOutboxEnvelopeFromInspectionEvent(event model.InspectionEvent, now time.Time) (domainEventOutboxEnvelope, error) {
	return domainEventOutboxEnvelopeFromModel("inspection_events", "inspection_event_recorded", event.ID, event.TenantID, event.Timestamp, event, now)
}

func domainEventOutboxEnvelopeFromAuthenticationEvent(event model.AuthenticationEvent, now time.Time) (domainEventOutboxEnvelope, error) {
	return domainEventOutboxEnvelopeFromModel("authentication_events", "authentication_event_recorded", event.ID, event.TenantID, event.Timestamp, event, now)
}

func domainEventOutboxEnvelopeFromDelegatedAccessGrant(event model.DelegatedAccessGrant, eventType, occurredAtValue string, now time.Time) (domainEventOutboxEnvelope, error) {
	return domainEventOutboxEnvelopeFromModel("delegated_access_grants", eventType, event.ID, event.TenantID, occurredAtValue, event, now)
}

func domainEventOutboxEnvelopeFromBreakGlassAccessRequest(event breakGlassAccessRequest, eventType, occurredAtValue string, now time.Time) (domainEventOutboxEnvelope, error) {
	return domainEventOutboxEnvelopeFromModel("break_glass_events", eventType, event.ID, event.TenantID, occurredAtValue, event, now)
}

func domainEventOutboxEnvelopeFromDevice(event model.Device, eventType, occurredAtValue string, now time.Time) (domainEventOutboxEnvelope, error) {
	return domainEventOutboxEnvelopeFromModel("device_events", eventType, event.ID, event.TenantID, occurredAtValue, event, now)
}

// ★ THE AGGREGATE ID CARRIES THE DEVICE (2026-08-12, ninth review). The outbox key is derived from the
// aggregate id and the tenant, and the id in an agent update event is chosen by the ENDPOINT — so two devices
// in one tenant picking the same string collided: the second INSERT hit ON CONFLICT DO NOTHING, the request
// was answered 202, and only the downstream event disappeared. The database table and the in-process
// reservation were both re-keyed to (tenant, device, event) and this was the third place holding the same
// assumption.
//
// Composed rather than adding a parameter to the shared helper: every other producer here has an aggregate id
// the SERVER assigns, and this is the one that does not.
func domainEventOutboxEnvelopeFromAgentUpdateEvent(event model.AgentUpdateEvent, now time.Time) (domainEventOutboxEnvelope, error) {
	aggregateID := strings.TrimSpace(event.DeviceID) + ":" + strings.TrimSpace(event.ID)
	return domainEventOutboxEnvelopeFromModel("agent_update_events", "agent_update_event_recorded", aggregateID, event.TenantID, event.Timestamp, event, now)
}

func domainEventOutboxEnvelopeFromAccessLog(event model.AccessLog, now time.Time) (domainEventOutboxEnvelope, error) {
	return domainEventOutboxEnvelopeFromModelForPlane("access", "access_logs", "access_log_recorded", event.ID, event.TenantID, event.Timestamp, event, now)
}

func domainEventOutboxEnvelopeFromDecisionTrace(event model.DecisionTrace, tenantID string, now time.Time) (domainEventOutboxEnvelope, error) {
	return domainEventOutboxEnvelopeFromModelForPlane("access", "decision_traces", "decision_trace_recorded", event.ID, tenantID, event.Timestamp, event, now)
}

func domainEventOutboxEnvelopeFromConnectorLog(event map[string]any, now time.Time) (domainEventOutboxEnvelope, error) {
	return domainEventOutboxEnvelopeFromModelForPlane(
		"access",
		"connector_logs",
		"connector_log_recorded",
		domainEventOutboxMapString(event, "id"),
		domainEventOutboxMapString(event, "tenant_id"),
		domainEventOutboxMapString(event, "timestamp"),
		event,
		now,
	)
}

func domainEventOutboxMapString(value map[string]any, key string) string {
	if value == nil {
		return ""
	}
	if text, ok := value[key].(string); ok {
		return strings.TrimSpace(text)
	}
	return ""
}

func domainEventOutboxEnvelopeFromModel(stream, eventType, eventID, tenantID, occurredAtValue string, event any, now time.Time) (domainEventOutboxEnvelope, error) {
	return domainEventOutboxEnvelopeFromModelForPlane("domain", stream, eventType, eventID, tenantID, occurredAtValue, event, now)
}

func domainEventOutboxEnvelopeFromModelForPlane(eventPlane, stream, eventType, eventID, tenantID, occurredAtValue string, event any, now time.Time) (domainEventOutboxEnvelope, error) {
	eventPlane = strings.TrimSpace(eventPlane)
	stream = strings.TrimSpace(stream)
	eventType = strings.TrimSpace(eventType)
	eventID = strings.TrimSpace(eventID)
	tenantID = strings.TrimSpace(tenantID)
	if eventPlane == "" || stream == "" || eventType == "" || eventID == "" || tenantID == "" {
		return domainEventOutboxEnvelope{}, fmt.Errorf("event_plane, stream, event_type, event id, and tenant_id are required")
	}
	if !domainEventOutboxPlaneAllowed(eventPlane) {
		return domainEventOutboxEnvelope{}, fmt.Errorf("domain event outbox event_plane is invalid: %s", eventPlane)
	}
	if !domainEventOutboxStreamAllowed(stream) {
		return domainEventOutboxEnvelope{}, fmt.Errorf("domain event stream is invalid: %s", stream)
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	occurredAt := now.UTC()
	if strings.TrimSpace(occurredAtValue) != "" {
		parsed, err := time.Parse(time.RFC3339, strings.TrimSpace(occurredAtValue))
		if err != nil {
			return domainEventOutboxEnvelope{}, fmt.Errorf("domain event occurred_at: %w", err)
		}
		occurredAt = parsed.UTC()
	}
	payloadBytes, err := json.Marshal(event)
	if err != nil {
		return domainEventOutboxEnvelope{}, fmt.Errorf("marshal domain event payload: %w", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return domainEventOutboxEnvelope{}, fmt.Errorf("decode domain event payload: %w", err)
	}
	_, checksum, err := domainEventOutboxPayloadAndChecksum(payload)
	if err != nil {
		return domainEventOutboxEnvelope{}, err
	}
	return domainEventOutboxEnvelope{
		ID:              domainEventOutboxID(stream, eventID),
		TenantID:        tenantID,
		SchemaVersion:   domainEventOutboxSchemaVersion,
		EventPlane:      eventPlane,
		Stream:          stream,
		EventType:       eventType,
		Status:          "pending",
		OccurredAt:      occurredAt,
		ReceivedAt:      now.UTC(),
		Payload:         payload,
		PayloadChecksum: checksum,
		PublishAttempt:  0,
		Metadata: map[string]any{
			"source_event_id": eventID,
			"dedup_key":       tenantID + ":" + stream + ":" + eventID,
		},
	}, nil
}

func domainEventOutboxID(stream, eventID string) string {
	return "domain_outbox_" + strings.ReplaceAll(strings.TrimSpace(stream), "/", "_") + "_" + strings.TrimSpace(eventID)
}

type postgresDomainEventOutboxClaimedRow struct {
	TenantID        string
	OutboxID        string
	SchemaVersion   string
	EventPlane      string
	Stream          string
	EventType       string
	PublishAttempt  int
	OccurredAt      time.Time
	ReceivedAt      time.Time
	PayloadChecksum string
	Payload         []byte
	Metadata        []byte
}

type postgresDomainEventOutboxDeadRow struct {
	TenantID        string         `json:"tenant_id"`
	OutboxID        string         `json:"outbox_id"`
	EventPlane      string         `json:"event_plane"`
	Stream          string         `json:"stream"`
	EventType       string         `json:"event_type"`
	PublishAttempt  int            `json:"publish_attempt"`
	LastError       string         `json:"last_error"`
	OccurredAt      time.Time      `json:"occurred_at"`
	DeadAt          time.Time      `json:"dead_at"`
	PayloadChecksum string         `json:"payload_checksum"`
	Payload         map[string]any `json:"payload"`
	Metadata        map[string]any `json:"metadata"`
}

type postgresDomainEventOutboxReplayResult struct {
	TenantID               string     `json:"tenant_id"`
	OutboxID               string     `json:"outbox_id"`
	EventPlane             string     `json:"event_plane"`
	Status                 string     `json:"status"`
	PublishAttempt         int        `json:"publish_attempt"`
	UpdatedAt              time.Time  `json:"updated_at"`
	PreviousPublishAttempt int        `json:"previous_publish_attempt"`
	PreviousLastError      string     `json:"previous_last_error"`
	PreviousDeadAt         *time.Time `json:"previous_dead_at,omitempty"`
}

type postgresDomainEventOutboxStats struct {
	TenantID           string     `json:"tenant_id"`
	EventPlane         string     `json:"event_plane"`
	Pending            int        `json:"pending"`
	Publishing         int        `json:"publishing"`
	Published          int        `json:"published"`
	Dead               int        `json:"dead"`
	Total              int        `json:"total"`
	OldestPendingAt    *time.Time `json:"oldest_pending_at,omitempty"`
	OldestPublishingAt *time.Time `json:"oldest_publishing_at,omitempty"`
	OldestDeadAt       *time.Time `json:"oldest_dead_at,omitempty"`
}

type domainEventOutboxDeadReader interface {
	ListDead(ctx context.Context, tenantID, eventPlane string, limit int) ([]postgresDomainEventOutboxDeadRow, error)
}

type domainEventOutboxStatsReader interface {
	Stats(ctx context.Context, tenantID, eventPlane string) (postgresDomainEventOutboxStats, error)
}

type domainEventOutboxDeadReplayer interface {
	ReplayDead(ctx context.Context, tenantID, eventPlane, outboxID string, now time.Time) (postgresDomainEventOutboxReplayResult, bool, error)
}

type postgresDomainEventOutboxStore struct {
	DB *sql.DB
}

var _ domainEventOutboxWriter = postgresDomainEventOutboxStore{}
var _ domainEventOutboxDeadReader = postgresDomainEventOutboxStore{}
var _ domainEventOutboxStatsReader = postgresDomainEventOutboxStore{}

type domainEventOutboxWriter interface {
	InsertEvent(context.Context, domainEventOutboxEnvelope, time.Time) error
}

func appendDomainEventOutbox(ctx context.Context, writer domainEventOutboxWriter, event domainEventOutboxEnvelope, now time.Time) {
	if writer == nil {
		return
	}
	if err := writer.InsertEvent(ctx, event, now); err != nil {
		log.Printf("domain event outbox insert failed: %v", err)
	}
}

type domainEventOutboxMirrorHealth struct {
	Status         string           `json:"status"`
	Reasons        []string         `json:"reasons"`
	CheckedAt      string           `json:"checked_at"`
	Stats          map[string]int64 `json:"stats"`
	LastSuccessAt  string           `json:"last_success_at,omitempty"`
	LastFailureAt  string           `json:"last_failure_at,omitempty"`
	LastError      string           `json:"last_error,omitempty"`
	LastEventPlane string           `json:"last_event_plane,omitempty"`
	LastStream     string           `json:"last_stream,omitempty"`
	LastOutboxID   string           `json:"last_outbox_id,omitempty"`
}

type domainEventOutboxMirrorMonitor struct {
	mu             sync.RWMutex
	mirrored       int64
	insertFailures int64
	lastSuccessAt  time.Time
	lastFailureAt  time.Time
	lastError      string
	lastEventPlane string
	lastStream     string
	lastOutboxID   string
}

func newDomainEventOutboxMirrorMonitor() *domainEventOutboxMirrorMonitor {
	return &domainEventOutboxMirrorMonitor{}
}

func (monitor *domainEventOutboxMirrorMonitor) RecordSuccess(event domainEventOutboxEnvelope, now time.Time) {
	if monitor == nil {
		return
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	monitor.mu.Lock()
	defer monitor.mu.Unlock()
	monitor.mirrored++
	monitor.lastSuccessAt = now.UTC()
	monitor.lastEventPlane = strings.TrimSpace(event.EventPlane)
	monitor.lastStream = strings.TrimSpace(event.Stream)
	monitor.lastOutboxID = strings.TrimSpace(event.ID)
}

func (monitor *domainEventOutboxMirrorMonitor) RecordInsertFailure(event domainEventOutboxEnvelope, err error, now time.Time) {
	if monitor == nil {
		return
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	message := "insert_failed"
	if err != nil {
		message += ": " + strings.TrimSpace(err.Error())
	}
	monitor.mu.Lock()
	defer monitor.mu.Unlock()
	monitor.insertFailures++
	monitor.lastFailureAt = now.UTC()
	monitor.lastError = message
	monitor.lastEventPlane = strings.TrimSpace(event.EventPlane)
	monitor.lastStream = strings.TrimSpace(event.Stream)
	monitor.lastOutboxID = strings.TrimSpace(event.ID)
}

func (monitor *domainEventOutboxMirrorMonitor) Health(now time.Time) domainEventOutboxMirrorHealth {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	health := domainEventOutboxMirrorHealth{
		Status:    "unconfigured",
		Reasons:   []string{"domain_event_outbox_mirror_unconfigured"},
		CheckedAt: now.UTC().Format(time.RFC3339),
		Stats: map[string]int64{
			"mirrored":        0,
			"insert_failures": 0,
		},
	}
	if monitor == nil {
		return health
	}
	monitor.mu.RLock()
	defer monitor.mu.RUnlock()
	health.Status = "ok"
	health.Reasons = []string{}
	health.Stats["mirrored"] = monitor.mirrored
	health.Stats["insert_failures"] = monitor.insertFailures
	if !monitor.lastSuccessAt.IsZero() {
		health.LastSuccessAt = monitor.lastSuccessAt.UTC().Format(time.RFC3339)
	}
	if !monitor.lastFailureAt.IsZero() {
		health.LastFailureAt = monitor.lastFailureAt.UTC().Format(time.RFC3339)
		health.LastError = monitor.lastError
		if monitor.lastSuccessAt.IsZero() || monitor.lastFailureAt.After(monitor.lastSuccessAt) {
			health.Status = "degraded"
			health.Reasons = append(health.Reasons, "latest_mirror_attempt_failed")
		}
	}
	health.LastEventPlane = monitor.lastEventPlane
	health.LastStream = monitor.lastStream
	health.LastOutboxID = monitor.lastOutboxID
	return health
}

type monitoredDomainEventOutbox struct {
	Writer  domainEventOutboxWriter
	Monitor *domainEventOutboxMirrorMonitor
}

func (outbox monitoredDomainEventOutbox) InsertEvent(ctx context.Context, event domainEventOutboxEnvelope, now time.Time) error {
	if outbox.Writer == nil {
		err := fmt.Errorf("domain event outbox writer is not configured")
		outbox.Monitor.RecordInsertFailure(event, err, now)
		return err
	}
	if err := outbox.Writer.InsertEvent(ctx, event, now); err != nil {
		outbox.Monitor.RecordInsertFailure(event, err, now)
		return err
	}
	outbox.Monitor.RecordSuccess(event, now)
	return nil
}

func (outbox monitoredDomainEventOutbox) ListDead(ctx context.Context, tenantID, eventPlane string, limit int) ([]postgresDomainEventOutboxDeadRow, error) {
	reader, ok := outbox.Writer.(domainEventOutboxDeadReader)
	if !ok {
		return nil, fmt.Errorf("domain event outbox dead row reader is not configured")
	}
	return reader.ListDead(ctx, tenantID, eventPlane, limit)
}

func (outbox monitoredDomainEventOutbox) Stats(ctx context.Context, tenantID, eventPlane string) (postgresDomainEventOutboxStats, error) {
	reader, ok := outbox.Writer.(domainEventOutboxStatsReader)
	if !ok {
		return postgresDomainEventOutboxStats{}, fmt.Errorf("domain event outbox stats reader is not configured")
	}
	return reader.Stats(ctx, tenantID, eventPlane)
}

func (outbox monitoredDomainEventOutbox) ReplayDead(ctx context.Context, tenantID, eventPlane, outboxID string, now time.Time) (postgresDomainEventOutboxReplayResult, bool, error) {
	replayer, ok := outbox.Writer.(domainEventOutboxDeadReplayer)
	if !ok {
		return postgresDomainEventOutboxReplayResult{}, false, fmt.Errorf("domain event outbox replay is not configured")
	}
	return replayer.ReplayDead(ctx, tenantID, eventPlane, outboxID, now)
}

func postgresDomainEventOutboxSchemaSQL() []string {
	return []string{
		strings.Join([]string{
			"CREATE TABLE IF NOT EXISTS domain_event_outbox (",
			"tenant_id text NOT NULL,",
			"outbox_id text NOT NULL,",
			"schema_version text NOT NULL,",
			"event_plane text NOT NULL CHECK (event_plane IN ('domain', 'access', 'evidence')),",
			"stream text NOT NULL CONSTRAINT domain_event_outbox_stream_check CHECK (" + domainEventOutboxStreamCheckExpression() + "),",
			"event_type text NOT NULL,",
			"status text NOT NULL CHECK (status IN ('pending', 'publishing', 'published', 'dead')),",
			"occurred_at timestamptz NOT NULL,",
			"received_at timestamptz NOT NULL,",
			"published_at timestamptz,",
			"dead_at timestamptz,",
			"publish_attempt integer NOT NULL DEFAULT 0 CHECK (publish_attempt >= 0),",
			"locked_by text,",
			"locked_until timestamptz,",
			"next_attempt_at timestamptz,",
			"last_error text,",
			"payload_checksum text NOT NULL CHECK (payload_checksum ~ '^sha256:[a-f0-9]{64}$'),",
			"payload jsonb NOT NULL,",
			"metadata jsonb NOT NULL DEFAULT '{}'::jsonb,",
			"created_at timestamptz NOT NULL DEFAULT now(),",
			"updated_at timestamptz NOT NULL DEFAULT now(),",
			"PRIMARY KEY (tenant_id, outbox_id)",
			")",
		}, " "),
		"CREATE INDEX IF NOT EXISTS domain_event_outbox_pending_idx ON domain_event_outbox (tenant_id, event_plane, status, next_attempt_at, occurred_at, outbox_id)",
		"CREATE INDEX IF NOT EXISTS domain_event_outbox_stream_idx ON domain_event_outbox (tenant_id, stream, occurred_at DESC)",
		"CREATE INDEX IF NOT EXISTS domain_event_outbox_event_idx ON domain_event_outbox (tenant_id, event_type, occurred_at DESC)",
	}
}

func postgresDomainEventOutboxStreamCheckMigrationSQL() []string {
	return []string{
		strings.Join([]string{
			"DO $$",
			"BEGIN",
			"IF NOT EXISTS (",
			"SELECT 1 FROM pg_constraint",
			"WHERE conname = 'domain_event_outbox_stream_check'",
			"AND conrelid = 'domain_event_outbox'::regclass",
			") THEN",
			"ALTER TABLE domain_event_outbox",
			"ADD CONSTRAINT domain_event_outbox_stream_check CHECK (" + domainEventOutboxStreamCheckExpression() + ")",
			";",
			"END IF",
			";",
			"END",
			"$$",
		}, " "),
	}
}

func (store postgresDomainEventOutboxStore) InsertEvent(ctx context.Context, event domainEventOutboxEnvelope, now time.Time) error {
	if store.DB == nil {
		return fmt.Errorf("postgres domain event outbox db is not configured")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	statement, err := buildPostgresDomainEventOutboxInsertStatement(event, now)
	if err != nil {
		return err
	}
	_, err = store.DB.ExecContext(ctx, statement.SQL, statement.Args...)
	return err
}

func (store postgresDomainEventOutboxStore) Claim(ctx context.Context, tenantID, eventPlane, publisherID string, limit, maxAttempts int, now time.Time, lockDuration time.Duration) ([]domainEventOutboxEnvelope, error) {
	if store.DB == nil {
		return nil, fmt.Errorf("postgres domain event outbox db is not configured")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if lockDuration <= 0 {
		lockDuration = time.Minute
	}
	statement, err := buildPostgresDomainEventOutboxClaimStatement(tenantID, eventPlane, publisherID, limit, maxAttempts, now, now.Add(lockDuration))
	if err != nil {
		return nil, err
	}
	rows, err := store.DB.QueryContext(ctx, statement.SQL, statement.Args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var envelopes []domainEventOutboxEnvelope
	for rows.Next() {
		var row postgresDomainEventOutboxClaimedRow
		if err := rows.Scan(&row.TenantID, &row.OutboxID, &row.SchemaVersion, &row.EventPlane, &row.Stream, &row.EventType, &row.PublishAttempt, &row.OccurredAt, &row.ReceivedAt, &row.PayloadChecksum, &row.Payload, &row.Metadata); err != nil {
			return nil, err
		}
		envelope, err := hydratePostgresDomainEventOutboxClaimedRow(row)
		if err != nil {
			return nil, err
		}
		envelopes = append(envelopes, envelope)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return envelopes, nil
}

func (store postgresDomainEventOutboxStore) MarkPublished(ctx context.Context, tenantID, outboxID, publisherID string, now time.Time) error {
	statement, err := buildPostgresDomainEventOutboxMarkPublishedStatement(tenantID, outboxID, publisherID, now)
	if err != nil {
		return err
	}
	return store.execLifecycleStatement(ctx, statement, "domain event outbox mark published")
}

func (store postgresDomainEventOutboxStore) Release(ctx context.Context, tenantID, outboxID, publisherID, reason string, nextAttemptAt, now time.Time) error {
	statement, err := buildPostgresDomainEventOutboxReleaseStatement(tenantID, outboxID, publisherID, reason, nextAttemptAt, now)
	if err != nil {
		return err
	}
	return store.execLifecycleStatement(ctx, statement, "domain event outbox release")
}

func (store postgresDomainEventOutboxStore) MarkDead(ctx context.Context, tenantID, outboxID, publisherID, reason string, now time.Time) error {
	statement, err := buildPostgresDomainEventOutboxMarkDeadStatement(tenantID, outboxID, publisherID, reason, now)
	if err != nil {
		return err
	}
	return store.execLifecycleStatement(ctx, statement, "domain event outbox mark dead")
}

func (store postgresDomainEventOutboxStore) ListDead(ctx context.Context, tenantID, eventPlane string, limit int) ([]postgresDomainEventOutboxDeadRow, error) {
	if store.DB == nil {
		return nil, fmt.Errorf("postgres domain event outbox db is not configured")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	statement, err := buildPostgresDomainEventOutboxListDeadStatement(tenantID, eventPlane, limit)
	if err != nil {
		return nil, err
	}
	rows, err := store.DB.QueryContext(ctx, statement.SQL, statement.Args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var deadRows []postgresDomainEventOutboxDeadRow
	for rows.Next() {
		row, err := scanPostgresDomainEventOutboxDeadRow(rows)
		if err != nil {
			return nil, err
		}
		deadRows = append(deadRows, row)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return deadRows, nil
}

func (store postgresDomainEventOutboxStore) Stats(ctx context.Context, tenantID, eventPlane string) (postgresDomainEventOutboxStats, error) {
	if store.DB == nil {
		return postgresDomainEventOutboxStats{}, fmt.Errorf("postgres domain event outbox db is not configured")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	statement, err := buildPostgresDomainEventOutboxStatsStatement(tenantID, eventPlane)
	if err != nil {
		return postgresDomainEventOutboxStats{}, err
	}
	stats := postgresDomainEventOutboxStats{TenantID: strings.TrimSpace(tenantID), EventPlane: strings.TrimSpace(eventPlane)}
	rows, err := store.DB.QueryContext(ctx, statement.SQL, statement.Args...)
	if err != nil {
		return postgresDomainEventOutboxStats{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var status string
		var count int
		var oldest sql.NullTime
		if err := rows.Scan(&status, &count, &oldest); err != nil {
			return postgresDomainEventOutboxStats{}, err
		}
		stats.Total += count
		var oldestAt *time.Time
		if oldest.Valid {
			normalized := oldest.Time.UTC()
			oldestAt = &normalized
		}
		switch status {
		case "pending":
			stats.Pending = count
			stats.OldestPendingAt = oldestAt
		case "publishing":
			stats.Publishing = count
			stats.OldestPublishingAt = oldestAt
		case "published":
			stats.Published = count
		case "dead":
			stats.Dead = count
			stats.OldestDeadAt = oldestAt
		}
	}
	if err := rows.Err(); err != nil {
		return postgresDomainEventOutboxStats{}, err
	}
	return stats, nil
}

func (store postgresDomainEventOutboxStore) ReplayDead(ctx context.Context, tenantID, eventPlane, outboxID string, now time.Time) (postgresDomainEventOutboxReplayResult, bool, error) {
	return replayPostgresDomainEventOutboxDeadRow(ctx, store.DB, tenantID, eventPlane, outboxID, now)
}

func (store postgresDomainEventOutboxStore) execLifecycleStatement(ctx context.Context, statement postgresExportTaskQueueStatement, operation string) error {
	if store.DB == nil {
		return fmt.Errorf("postgres domain event outbox db is not configured")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	result, err := store.DB.ExecContext(ctx, statement.SQL, statement.Args...)
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err == nil && affected == 0 {
		return fmt.Errorf("%s: lock was stolen or row is not publishing", operation)
	}
	return nil
}

func buildPostgresDomainEventOutboxListDeadStatement(tenantID, eventPlane string, limit int) (postgresExportTaskQueueStatement, error) {
	tenantID = strings.TrimSpace(tenantID)
	eventPlane = strings.TrimSpace(eventPlane)
	if tenantID == "" || eventPlane == "" {
		return postgresExportTaskQueueStatement{}, fmt.Errorf("tenant_id and event_plane are required")
	}
	if !domainEventOutboxPlaneAllowed(eventPlane) {
		return postgresExportTaskQueueStatement{}, fmt.Errorf("domain event outbox event_plane is invalid: %s", eventPlane)
	}
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}
	return postgresExportTaskQueueStatement{
		SQL: strings.Join([]string{
			"SELECT tenant_id, outbox_id, event_plane, stream, event_type, publish_attempt, COALESCE(last_error, ''), occurred_at, COALESCE(dead_at, updated_at), payload_checksum, payload, metadata",
			"FROM domain_event_outbox",
			"WHERE tenant_id = $1 AND event_plane = $2 AND status = 'dead'",
			"ORDER BY COALESCE(dead_at, updated_at) DESC, outbox_id DESC",
			"LIMIT $3",
		}, " "),
		Args: []any{tenantID, eventPlane, limit},
	}, nil
}

func buildPostgresDomainEventOutboxStatsStatement(tenantID, eventPlane string) (postgresExportTaskQueueStatement, error) {
	tenantID = strings.TrimSpace(tenantID)
	eventPlane = strings.TrimSpace(eventPlane)
	if tenantID == "" || eventPlane == "" {
		return postgresExportTaskQueueStatement{}, fmt.Errorf("tenant_id and event_plane are required")
	}
	if !domainEventOutboxPlaneAllowed(eventPlane) {
		return postgresExportTaskQueueStatement{}, fmt.Errorf("domain event outbox event_plane is invalid: %s", eventPlane)
	}
	return postgresExportTaskQueueStatement{
		SQL: strings.Join([]string{
			"SELECT status, count(*), MIN(CASE WHEN status = 'dead' THEN COALESCE(dead_at, updated_at) ELSE occurred_at END)",
			"FROM domain_event_outbox",
			"WHERE tenant_id = $1 AND event_plane = $2",
			"GROUP BY status",
		}, " "),
		Args: []any{tenantID, eventPlane},
	}, nil
}

func buildPostgresDomainEventOutboxReplayDeadStatement(tenantID, eventPlane, outboxID string, now time.Time) (postgresExportTaskQueueStatement, error) {
	tenantID = strings.TrimSpace(tenantID)
	eventPlane = strings.TrimSpace(eventPlane)
	outboxID = strings.TrimSpace(outboxID)
	if tenantID == "" || eventPlane == "" || outboxID == "" {
		return postgresExportTaskQueueStatement{}, fmt.Errorf("tenant_id, event_plane, and outbox_id are required")
	}
	if !domainEventOutboxPlaneAllowed(eventPlane) {
		return postgresExportTaskQueueStatement{}, fmt.Errorf("domain event outbox event_plane is invalid: %s", eventPlane)
	}
	if now.IsZero() {
		return postgresExportTaskQueueStatement{}, fmt.Errorf("now is required")
	}
	return postgresExportTaskQueueStatement{
		SQL: strings.Join([]string{
			"WITH picked AS (",
			"SELECT tenant_id, event_plane, outbox_id, publish_attempt, COALESCE(last_error, '') AS previous_last_error, dead_at AS previous_dead_at",
			"FROM domain_event_outbox",
			"WHERE tenant_id = $1 AND event_plane = $2 AND outbox_id = $3 AND status = 'dead'",
			"FOR UPDATE",
			"), updated AS (",
			"UPDATE domain_event_outbox AS outbox",
			"SET status = 'pending',",
			"publish_attempt = 0,",
			"locked_by = NULL,",
			"locked_until = NULL,",
			"next_attempt_at = NULL,",
			"last_error = NULL,",
			"dead_at = NULL,",
			"updated_at = $4::timestamptz",
			"FROM picked",
			"WHERE outbox.tenant_id = picked.tenant_id AND outbox.event_plane = picked.event_plane AND outbox.outbox_id = picked.outbox_id",
			"RETURNING outbox.tenant_id, outbox.outbox_id, outbox.event_plane, outbox.status, outbox.publish_attempt, outbox.updated_at, picked.publish_attempt AS previous_publish_attempt, picked.previous_last_error, picked.previous_dead_at",
			")",
			"SELECT tenant_id, outbox_id, event_plane, status, publish_attempt, updated_at, previous_publish_attempt, previous_last_error, previous_dead_at FROM updated",
		}, " "),
		Args: []any{tenantID, eventPlane, outboxID, now.UTC()},
	}, nil
}

func buildPostgresDomainEventOutboxInsertStatement(event domainEventOutboxEnvelope, now time.Time) (postgresExportTaskQueueStatement, error) {
	tenantID := strings.TrimSpace(event.TenantID)
	outboxID := strings.TrimSpace(event.ID)
	schemaVersion := strings.TrimSpace(event.SchemaVersion)
	eventPlane := strings.TrimSpace(event.EventPlane)
	stream := strings.TrimSpace(event.Stream)
	eventType := strings.TrimSpace(event.EventType)
	status := strings.TrimSpace(event.Status)
	if tenantID == "" || outboxID == "" || schemaVersion == "" || eventPlane == "" || stream == "" || eventType == "" || status == "" {
		return postgresExportTaskQueueStatement{}, fmt.Errorf("tenant_id, id, schema_version, event_plane, stream, event_type, and status are required")
	}
	if !domainEventOutboxPlaneAllowed(eventPlane) {
		return postgresExportTaskQueueStatement{}, fmt.Errorf("domain event outbox event_plane is invalid: %s", eventPlane)
	}
	if !domainEventOutboxStatusAllowed(status) {
		return postgresExportTaskQueueStatement{}, fmt.Errorf("domain event outbox status is invalid: %s", status)
	}
	if event.OccurredAt.IsZero() || event.ReceivedAt.IsZero() {
		return postgresExportTaskQueueStatement{}, fmt.Errorf("occurred_at and received_at are required")
	}
	if event.PublishAttempt < 0 {
		return postgresExportTaskQueueStatement{}, fmt.Errorf("publish_attempt must be non-negative")
	}
	payloadBytes, checksum, err := domainEventOutboxPayloadAndChecksum(event.Payload)
	if err != nil {
		return postgresExportTaskQueueStatement{}, err
	}
	if got := strings.TrimSpace(event.PayloadChecksum); got != checksum {
		return postgresExportTaskQueueStatement{}, fmt.Errorf("payload_checksum mismatch")
	}
	metadata := event.Metadata
	if metadata == nil {
		metadata = map[string]any{}
	}
	metadataBytes, err := json.Marshal(metadata)
	if err != nil {
		return postgresExportTaskQueueStatement{}, fmt.Errorf("marshal domain event outbox metadata: %w", err)
	}
	return postgresExportTaskQueueStatement{
		SQL: strings.Join([]string{
			"INSERT INTO domain_event_outbox (tenant_id, outbox_id, schema_version, event_plane, stream, event_type, status, occurred_at, received_at, publish_attempt, payload_checksum, payload, metadata, created_at, updated_at)",
			"VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12::jsonb, $13::jsonb, $14, $14)",
			"ON CONFLICT (tenant_id, outbox_id) DO NOTHING",
		}, " "),
		Args: []any{
			tenantID,
			outboxID,
			schemaVersion,
			eventPlane,
			stream,
			eventType,
			status,
			event.OccurredAt.UTC(),
			event.ReceivedAt.UTC(),
			event.PublishAttempt,
			checksum,
			string(payloadBytes),
			string(metadataBytes),
			now.UTC(),
		},
	}, nil
}

func buildPostgresDomainEventOutboxClaimStatement(tenantID, eventPlane, publisherID string, limit, maxAttempts int, now, lockedUntil time.Time) (postgresExportTaskQueueStatement, error) {
	tenantID = strings.TrimSpace(tenantID)
	eventPlane = strings.TrimSpace(eventPlane)
	publisherID = strings.TrimSpace(publisherID)
	if tenantID == "" || eventPlane == "" || publisherID == "" {
		return postgresExportTaskQueueStatement{}, fmt.Errorf("tenant_id, event_plane, and publisher_id are required")
	}
	if !domainEventOutboxPlaneAllowed(eventPlane) {
		return postgresExportTaskQueueStatement{}, fmt.Errorf("domain event outbox event_plane is invalid: %s", eventPlane)
	}
	if limit <= 0 {
		return postgresExportTaskQueueStatement{}, fmt.Errorf("limit must be positive")
	}
	if maxAttempts <= 0 {
		return postgresExportTaskQueueStatement{}, fmt.Errorf("max_attempts must be positive")
	}
	if now.IsZero() || lockedUntil.IsZero() {
		return postgresExportTaskQueueStatement{}, fmt.Errorf("now and locked_until are required")
	}
	return postgresExportTaskQueueStatement{
		SQL: strings.Join([]string{
			"WITH picked AS (",
			"SELECT tenant_id, outbox_id FROM domain_event_outbox",
			"WHERE tenant_id = $1 AND event_plane = $2",
			"AND (status = 'pending' OR (status = 'publishing' AND locked_until < $5::timestamptz))",
			"AND (next_attempt_at IS NULL OR next_attempt_at <= $5::timestamptz)",
			// ★ A STALE LOCK IS RECLAIMABLE WHATEVER THE ATTEMPT COUNT (2026-08-13, twenty-ninth review). This
			// predicate bounded RETRIES and also gated the stale-lock recovery that shares it — so a row
			// claimed at max-1, whose publisher then crashed, sat at publish_attempt = max and could never be
			// picked up again. mark-published, release and mark-dead all require the original locked_by, so
			// nothing could move it either: not published, not dead-lettered, just gone from every view that
			// counts one or the other. The cap belongs to fresh work; an abandoned lock has to be recoverable
			// so it can at least be declared dead.
			"AND (publish_attempt < $6 OR (status = 'publishing' AND locked_until < $5::timestamptz))",
			"ORDER BY occurred_at ASC, outbox_id ASC",
			"FOR UPDATE SKIP LOCKED LIMIT $3",
			"), updated AS (",
			"UPDATE domain_event_outbox AS outbox",
			"SET status = 'publishing', locked_by = $4, locked_until = $7::timestamptz, publish_attempt = outbox.publish_attempt + 1, updated_at = $5::timestamptz",
			"FROM picked",
			"WHERE outbox.tenant_id = picked.tenant_id AND outbox.outbox_id = picked.outbox_id",
			"RETURNING outbox.tenant_id, outbox.outbox_id, outbox.schema_version, outbox.event_plane, outbox.stream, outbox.event_type, outbox.publish_attempt, outbox.occurred_at, outbox.received_at, outbox.payload_checksum, outbox.payload, outbox.metadata",
			")",
			"SELECT tenant_id, outbox_id, schema_version, event_plane, stream, event_type, publish_attempt, occurred_at, received_at, payload_checksum, payload, metadata FROM updated",
		}, " "),
		Args: []any{tenantID, eventPlane, limit, publisherID, now.UTC(), maxAttempts, lockedUntil.UTC()},
	}, nil
}

func buildPostgresDomainEventOutboxMarkPublishedStatement(tenantID, outboxID, publisherID string, now time.Time) (postgresExportTaskQueueStatement, error) {
	tenantID = strings.TrimSpace(tenantID)
	outboxID = strings.TrimSpace(outboxID)
	publisherID = strings.TrimSpace(publisherID)
	if tenantID == "" || outboxID == "" || publisherID == "" {
		return postgresExportTaskQueueStatement{}, fmt.Errorf("tenant_id, outbox_id, and publisher_id are required")
	}
	if now.IsZero() {
		return postgresExportTaskQueueStatement{}, fmt.Errorf("now is required")
	}
	return postgresExportTaskQueueStatement{
		SQL: strings.Join([]string{
			"UPDATE domain_event_outbox",
			"SET status = 'published', published_at = $4::timestamptz, locked_by = NULL, locked_until = NULL, next_attempt_at = NULL, last_error = NULL, updated_at = $4::timestamptz",
			"WHERE tenant_id = $1 AND outbox_id = $2 AND locked_by = $3 AND status = 'publishing'",
		}, " "),
		Args: []any{tenantID, outboxID, publisherID, now.UTC()},
	}, nil
}

func buildPostgresDomainEventOutboxReleaseStatement(tenantID, outboxID, publisherID, reason string, nextAttemptAt, now time.Time) (postgresExportTaskQueueStatement, error) {
	tenantID = strings.TrimSpace(tenantID)
	outboxID = strings.TrimSpace(outboxID)
	publisherID = strings.TrimSpace(publisherID)
	if tenantID == "" || outboxID == "" || publisherID == "" {
		return postgresExportTaskQueueStatement{}, fmt.Errorf("tenant_id, outbox_id, and publisher_id are required")
	}
	if strings.TrimSpace(reason) == "" {
		reason = "domain_event_delivery_failed"
	}
	if nextAttemptAt.IsZero() || now.IsZero() {
		return postgresExportTaskQueueStatement{}, fmt.Errorf("next_attempt_at and now are required")
	}
	return postgresExportTaskQueueStatement{
		SQL: strings.Join([]string{
			"UPDATE domain_event_outbox",
			"SET status = 'pending', locked_by = NULL, locked_until = NULL, next_attempt_at = $5::timestamptz, last_error = $4, updated_at = $6::timestamptz",
			"WHERE tenant_id = $1 AND outbox_id = $2 AND locked_by = $3 AND status = 'publishing'",
		}, " "),
		Args: []any{tenantID, outboxID, publisherID, reason, nextAttemptAt.UTC(), now.UTC()},
	}, nil
}

func buildPostgresDomainEventOutboxMarkDeadStatement(tenantID, outboxID, publisherID, reason string, now time.Time) (postgresExportTaskQueueStatement, error) {
	tenantID = strings.TrimSpace(tenantID)
	outboxID = strings.TrimSpace(outboxID)
	publisherID = strings.TrimSpace(publisherID)
	if tenantID == "" || outboxID == "" || publisherID == "" {
		return postgresExportTaskQueueStatement{}, fmt.Errorf("tenant_id, outbox_id, and publisher_id are required")
	}
	if strings.TrimSpace(reason) == "" {
		reason = "domain_event_delivery_failed"
	}
	if now.IsZero() {
		return postgresExportTaskQueueStatement{}, fmt.Errorf("now is required")
	}
	return postgresExportTaskQueueStatement{
		SQL: strings.Join([]string{
			"UPDATE domain_event_outbox",
			"SET status = 'dead', dead_at = $5::timestamptz, locked_by = NULL, locked_until = NULL, next_attempt_at = NULL, last_error = $4, updated_at = $5::timestamptz",
			"WHERE tenant_id = $1 AND outbox_id = $2 AND locked_by = $3 AND status = 'publishing'",
		}, " "),
		Args: []any{tenantID, outboxID, publisherID, reason, now.UTC()},
	}, nil
}

func hydratePostgresDomainEventOutboxClaimedRow(row postgresDomainEventOutboxClaimedRow) (domainEventOutboxEnvelope, error) {
	var payload map[string]any
	if len(row.Payload) == 0 {
		return domainEventOutboxEnvelope{}, fmt.Errorf("domain event outbox claimed payload is required")
	}
	if err := json.Unmarshal(row.Payload, &payload); err != nil {
		return domainEventOutboxEnvelope{}, fmt.Errorf("decode domain event outbox claimed payload: %w", err)
	}
	_, checksum, err := domainEventOutboxPayloadAndChecksum(payload)
	if err != nil {
		return domainEventOutboxEnvelope{}, err
	}
	if strings.TrimSpace(row.PayloadChecksum) != checksum {
		return domainEventOutboxEnvelope{}, fmt.Errorf("domain event outbox claimed payload checksum mismatch")
	}
	metadata := map[string]any{}
	if len(row.Metadata) > 0 {
		if err := json.Unmarshal(row.Metadata, &metadata); err != nil {
			return domainEventOutboxEnvelope{}, fmt.Errorf("decode domain event outbox claimed metadata: %w", err)
		}
	}
	envelope := domainEventOutboxEnvelope{
		ID:              strings.TrimSpace(row.OutboxID),
		TenantID:        strings.TrimSpace(row.TenantID),
		SchemaVersion:   strings.TrimSpace(row.SchemaVersion),
		EventPlane:      strings.TrimSpace(row.EventPlane),
		Stream:          strings.TrimSpace(row.Stream),
		EventType:       strings.TrimSpace(row.EventType),
		Status:          "publishing",
		OccurredAt:      row.OccurredAt.UTC(),
		ReceivedAt:      row.ReceivedAt.UTC(),
		Payload:         payload,
		PayloadChecksum: checksum,
		PublishAttempt:  row.PublishAttempt,
		Metadata:        metadata,
	}
	if _, err := buildPostgresDomainEventOutboxInsertStatement(envelope, time.Now().UTC()); err != nil {
		return domainEventOutboxEnvelope{}, fmt.Errorf("hydrate domain event outbox claimed row: %w", err)
	}
	return envelope, nil
}

type domainEventOutboxDeadRowScanner interface {
	Scan(dest ...any) error
}

func scanPostgresDomainEventOutboxDeadRow(scanner domainEventOutboxDeadRowScanner) (postgresDomainEventOutboxDeadRow, error) {
	var row postgresDomainEventOutboxDeadRow
	var payload []byte
	var metadata []byte
	if err := scanner.Scan(&row.TenantID, &row.OutboxID, &row.EventPlane, &row.Stream, &row.EventType, &row.PublishAttempt, &row.LastError, &row.OccurredAt, &row.DeadAt, &row.PayloadChecksum, &payload, &metadata); err != nil {
		return postgresDomainEventOutboxDeadRow{}, err
	}
	if err := json.Unmarshal(payload, &row.Payload); err != nil {
		return postgresDomainEventOutboxDeadRow{}, fmt.Errorf("decode dead domain event outbox payload: %w", err)
	}
	if err := json.Unmarshal(metadata, &row.Metadata); err != nil {
		return postgresDomainEventOutboxDeadRow{}, fmt.Errorf("decode dead domain event outbox metadata: %w", err)
	}
	_, checksum, err := domainEventOutboxPayloadAndChecksum(row.Payload)
	if err != nil {
		return postgresDomainEventOutboxDeadRow{}, err
	}
	if strings.TrimSpace(row.PayloadChecksum) != checksum {
		return postgresDomainEventOutboxDeadRow{}, fmt.Errorf("dead domain event outbox payload checksum mismatch")
	}
	row.OccurredAt = row.OccurredAt.UTC()
	row.DeadAt = row.DeadAt.UTC()
	return row, nil
}

func replayPostgresDomainEventOutboxDeadRow(ctx context.Context, db *sql.DB, tenantID, eventPlane, outboxID string, now time.Time) (postgresDomainEventOutboxReplayResult, bool, error) {
	if db == nil {
		return postgresDomainEventOutboxReplayResult{}, false, fmt.Errorf("postgres domain event outbox db is not configured")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	statement, err := buildPostgresDomainEventOutboxReplayDeadStatement(tenantID, eventPlane, outboxID, now)
	if err != nil {
		return postgresDomainEventOutboxReplayResult{}, false, err
	}
	tx, finish, err := beginCPWriteTransaction(ctx, db)
	if err != nil {
		return postgresDomainEventOutboxReplayResult{}, false, err
	}
	defer finish()
	defer tx.Rollback()
	var result postgresDomainEventOutboxReplayResult
	var previousDeadAt sql.NullTime
	err = tx.QueryRowContext(ctx, statement.SQL, statement.Args...).Scan(&result.TenantID, &result.OutboxID, &result.EventPlane, &result.Status, &result.PublishAttempt, &result.UpdatedAt, &result.PreviousPublishAttempt, &result.PreviousLastError, &previousDeadAt)
	if errors.Is(err, sql.ErrNoRows) {
		return postgresDomainEventOutboxReplayResult{}, false, nil
	}
	if err != nil {
		return postgresDomainEventOutboxReplayResult{}, false, err
	}
	if previousDeadAt.Valid {
		normalized := previousDeadAt.Time.UTC()
		result.PreviousDeadAt = &normalized
	}
	if err := tx.Commit(); err != nil {
		return postgresDomainEventOutboxReplayResult{}, false, err
	}
	return result, true, nil
}

func domainEventOutboxPayloadAndChecksum(payload map[string]any) ([]byte, string, error) {
	if len(payload) == 0 {
		return nil, "", fmt.Errorf("domain event outbox payload is required")
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, "", fmt.Errorf("marshal domain event outbox payload: %w", err)
	}
	sum := sha256.Sum256(data)
	return data, "sha256:" + hex.EncodeToString(sum[:]), nil
}

func domainEventOutboxPlaneAllowed(plane string) bool {
	switch plane {
	case "domain", "access", "evidence":
		return true
	default:
		return false
	}
}

func domainEventOutboxStreamAllowed(stream string) bool {
	_, ok := domainEventOutboxAllowedStreams[strings.TrimSpace(stream)]
	return ok
}

func domainEventOutboxAllowedStreamSet(streams []string) map[string]struct{} {
	allowed := make(map[string]struct{}, len(streams))
	for _, stream := range streams {
		allowed[stream] = struct{}{}
	}
	return allowed
}

func domainEventOutboxStreamCheckExpression() string {
	values := make([]string, 0, len(domainEventOutboxAllowedStreamList))
	for _, stream := range domainEventOutboxAllowedStreamList {
		values = append(values, "'"+stream+"'")
	}
	return "stream IN (" + strings.Join(values, ", ") + ")"
}

func domainEventOutboxStatusAllowed(status string) bool {
	switch status {
	case "pending", "publishing", "published", "dead":
		return true
	default:
		return false
	}
}
