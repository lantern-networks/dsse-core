package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
)

type postgresAdminAuditOutboxPublisher struct {
	DB           *sql.DB
	TenantID     string
	PublisherID  string
	Writer       *logs.Writer
	Delivery     adminAuditOutboxDelivery
	BatchSize    int
	LockDuration time.Duration
	RetryDelay   time.Duration
	MaxAttempts  int
}

type adminAuditOutboxDelivery interface {
	DeliverAdminAudit(ctx context.Context, audit model.AuditLog) error
}

type adminAuditOutboxDeliveryFailure struct {
	Code string
	Err  error
}

func (failure adminAuditOutboxDeliveryFailure) Error() string {
	code := strings.TrimSpace(failure.Code)
	if code == "" {
		code = "audit_delivery_failed"
	}
	if failure.Err == nil {
		return code
	}
	return code + ": " + failure.Err.Error()
}

func (failure adminAuditOutboxDeliveryFailure) Unwrap() error {
	return failure.Err
}

func adminAuditOutboxDeliveryFailureReason(err error) string {
	var failure adminAuditOutboxDeliveryFailure
	if errors.As(err, &failure) && strings.TrimSpace(failure.Code) != "" {
		return strings.TrimSpace(failure.Code)
	}
	return "audit_delivery_failed"
}

type jsonlAdminAuditOutboxDelivery struct {
	Writer *logs.Writer
}

func (delivery jsonlAdminAuditOutboxDelivery) DeliverAdminAudit(_ context.Context, audit model.AuditLog) error {
	if delivery.Writer == nil {
		return fmt.Errorf("admin audit outbox writer is not configured")
	}
	return delivery.Writer.Append("audit.log.jsonl", audit)
}

type httpAdminAuditOutboxDelivery struct {
	Endpoint      string
	BearerToken   string
	SigningSecret string
	SigningKeyID  string
	Timeout       time.Duration
	Client        *http.Client
	Now           func() time.Time
	Nonce         func() (string, error)
}

func (delivery httpAdminAuditOutboxDelivery) DeliverAdminAudit(ctx context.Context, audit model.AuditLog) error {
	endpoint := strings.TrimSpace(delivery.Endpoint)
	if endpoint == "" {
		return fmt.Errorf("admin audit webhook endpoint is required")
	}
	payload, err := json.Marshal(audit)
	if err != nil {
		return fmt.Errorf("marshal admin audit webhook payload: %w", err)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if delivery.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, delivery.Timeout)
		defer cancel()
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("build admin audit webhook request: %w", err)
	}
	request.Header.Set("content-type", "application/json")
	if token := strings.TrimSpace(delivery.BearerToken); token != "" {
		request.Header.Set("authorization", "Bearer "+token)
	}
	if secret := strings.TrimSpace(delivery.SigningSecret); secret != "" {
		timestamp := delivery.now().UTC().Format(time.RFC3339Nano)
		nonce, err := delivery.nonce()
		if err != nil {
			return fmt.Errorf("admin audit webhook nonce: %w", err)
		}
		request.Header.Set("x-admin-audit-timestamp", timestamp)
		request.Header.Set("x-admin-audit-nonce", nonce)
		if keyID := strings.TrimSpace(delivery.SigningKeyID); keyID != "" {
			request.Header.Set("x-admin-audit-signature-key-id", keyID)
		}
		request.Header.Set("x-admin-audit-signature", adminAuditWebhookSignature(secret, timestamp, nonce, payload))
	}
	client := delivery.Client
	if client == nil {
		client = http.DefaultClient
	}
	response, err := client.Do(request)
	if err != nil {
		return adminAuditOutboxDeliveryFailure{Code: "audit_delivery_transport_failed", Err: fmt.Errorf("admin audit webhook delivery: %w", err)}
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return adminAuditOutboxDeliveryFailure{Code: adminAuditOutboxHTTPStatusFailureCode(response.StatusCode), Err: fmt.Errorf("admin audit webhook delivery status %d", response.StatusCode)}
	}
	return nil
}

func adminAuditOutboxHTTPStatusFailureCode(statusCode int) string {
	switch {
	case statusCode >= 500:
		return "audit_delivery_http_5xx"
	case statusCode >= 400:
		return "audit_delivery_http_4xx"
	case statusCode >= 300:
		return "audit_delivery_http_3xx"
	default:
		return "audit_delivery_http_status"
	}
}

func (delivery httpAdminAuditOutboxDelivery) now() time.Time {
	if delivery.Now != nil {
		return delivery.Now()
	}
	return time.Now().UTC()
}

func (delivery httpAdminAuditOutboxDelivery) nonce() (string, error) {
	if delivery.Nonce != nil {
		return delivery.Nonce()
	}
	return adminAuditWebhookNonce()
}

func adminAuditWebhookNonce() (string, error) {
	var data [16]byte
	if _, err := rand.Read(data[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(data[:]), nil
}

func adminAuditWebhookSignature(secret, timestamp, nonce string, payload []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(timestamp))
	_, _ = mac.Write([]byte("."))
	_, _ = mac.Write([]byte(nonce))
	_, _ = mac.Write([]byte("."))
	_, _ = mac.Write(payload)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func verifyAdminAuditWebhookSignature(secret, timestamp, nonce, signature string, payload []byte, now time.Time, maxSkew time.Duration) error {
	secret = strings.TrimSpace(secret)
	timestamp = strings.TrimSpace(timestamp)
	nonce = strings.TrimSpace(nonce)
	signature = strings.TrimSpace(signature)
	if secret == "" || timestamp == "" || nonce == "" || signature == "" {
		return fmt.Errorf("admin audit webhook signature fields are required")
	}
	if maxSkew <= 0 {
		maxSkew = 5 * time.Minute
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	parsed, err := time.Parse(time.RFC3339Nano, timestamp)
	if err != nil {
		return fmt.Errorf("admin audit webhook timestamp: %w", err)
	}
	delta := now.UTC().Sub(parsed.UTC())
	if delta < 0 {
		delta = -delta
	}
	if delta > maxSkew {
		return fmt.Errorf("admin audit webhook timestamp outside allowed skew")
	}
	expected := adminAuditWebhookSignature(secret, timestamp, nonce, payload)
	if !hmac.Equal([]byte(signature), []byte(expected)) {
		return fmt.Errorf("admin audit webhook signature is invalid")
	}
	return nil
}

type postgresAdminAuditOutboxClaimedRow struct {
	TenantID       string
	OutboxID       string
	PublishAttempt int
	Audit          model.AuditLog
}

type postgresAdminAuditOutboxDeadRow struct {
	TenantID       string         `json:"tenant_id"`
	OutboxID       string         `json:"outbox_id"`
	EventType      string         `json:"event_type"`
	PublishAttempt int            `json:"publish_attempt"`
	LastError      string         `json:"last_error"`
	OccurredAt     time.Time      `json:"occurred_at"`
	DeadAt         time.Time      `json:"dead_at"`
	Audit          model.AuditLog `json:"audit"`
}

type postgresAdminAuditOutboxReplayResult struct {
	TenantID               string     `json:"tenant_id"`
	OutboxID               string     `json:"outbox_id"`
	Status                 string     `json:"status"`
	PublishAttempt         int        `json:"publish_attempt"`
	UpdatedAt              time.Time  `json:"updated_at"`
	PreviousPublishAttempt int        `json:"previous_publish_attempt"`
	PreviousLastError      string     `json:"previous_last_error"`
	PreviousDeadAt         *time.Time `json:"previous_dead_at,omitempty"`
}

type postgresAdminAuditOutboxStats struct {
	TenantID           string     `json:"tenant_id"`
	Pending            int        `json:"pending"`
	Publishing         int        `json:"publishing"`
	Published          int        `json:"published"`
	Dead               int        `json:"dead"`
	Total              int        `json:"total"`
	OldestPendingAt    *time.Time `json:"oldest_pending_at,omitempty"`
	OldestPublishingAt *time.Time `json:"oldest_publishing_at,omitempty"`
	OldestDeadAt       *time.Time `json:"oldest_dead_at,omitempty"`
}

type adminAuditOutboxDeadReader interface {
	adminAuditOutboxWriter
	ListDead(ctx context.Context, tenantID string, limit int) ([]postgresAdminAuditOutboxDeadRow, error)
}

type adminAuditOutboxStatsReader interface {
	Stats(ctx context.Context, tenantID string) (postgresAdminAuditOutboxStats, error)
}

type adminAuditOutboxDeadGetter interface {
	GetDead(ctx context.Context, tenantID, outboxID string) (postgresAdminAuditOutboxDeadRow, bool, error)
}

type adminAuditOutboxDeadReplayer interface {
	ReplayDead(ctx context.Context, tenantID, outboxID string, now time.Time) (postgresAdminAuditOutboxReplayResult, bool, error)
}

type adminAuditOutboxWriter interface {
	InsertAudit(ctx context.Context, audit model.AuditLog, now time.Time) error
}

type postgresAdminAuditOutboxReader struct {
	DB *sql.DB
}

var _ adminAuditOutboxWriter = postgresAdminAuditOutboxReader{}

func (reader postgresAdminAuditOutboxReader) ListDead(ctx context.Context, tenantID string, limit int) ([]postgresAdminAuditOutboxDeadRow, error) {
	return listPostgresAdminAuditOutboxDeadRows(ctx, reader.DB, tenantID, limit)
}

func (reader postgresAdminAuditOutboxReader) Stats(ctx context.Context, tenantID string) (postgresAdminAuditOutboxStats, error) {
	return postgresAdminAuditOutboxStatsForTenant(ctx, reader.DB, tenantID)
}

func (reader postgresAdminAuditOutboxReader) GetDead(ctx context.Context, tenantID, outboxID string) (postgresAdminAuditOutboxDeadRow, bool, error) {
	return getPostgresAdminAuditOutboxDeadRow(ctx, reader.DB, tenantID, outboxID)
}

func (reader postgresAdminAuditOutboxReader) ReplayDead(ctx context.Context, tenantID, outboxID string, now time.Time) (postgresAdminAuditOutboxReplayResult, bool, error) {
	return replayPostgresAdminAuditOutboxDeadRow(ctx, reader.DB, tenantID, outboxID, now)
}

func (reader postgresAdminAuditOutboxReader) InsertAudit(ctx context.Context, audit model.AuditLog, now time.Time) error {
	if reader.DB == nil {
		return fmt.Errorf("postgres admin audit outbox db is not configured")
	}
	statement, err := buildPostgresAdminAuditOutboxInsertStatement(audit, now)
	if err != nil {
		return err
	}
	_, err = reader.DB.ExecContext(ctx, statement.SQL, statement.Args...)
	return err
}

func postgresAdminAuditOutboxSchemaSQL() []string {
	return []string{
		strings.Join([]string{
			"CREATE TABLE IF NOT EXISTS admin_audit_outbox (",
			"tenant_id text NOT NULL,",
			"outbox_id text NOT NULL,",
			"event_type text NOT NULL,",
			"status text NOT NULL CHECK (status IN ('pending', 'publishing', 'published', 'dead')),",
			"occurred_at timestamptz NOT NULL,",
			"published_at timestamptz,",
			"dead_at timestamptz,",
			"publish_attempt integer NOT NULL DEFAULT 0 CHECK (publish_attempt >= 0),",
			"locked_by text,",
			"locked_until timestamptz,",
			"next_attempt_at timestamptz,",
			"last_error text,",
			"payload jsonb NOT NULL,",
			"created_at timestamptz NOT NULL DEFAULT now(),",
			"updated_at timestamptz NOT NULL DEFAULT now(),",
			"PRIMARY KEY (tenant_id, outbox_id)",
			")",
		}, " "),
		"CREATE INDEX IF NOT EXISTS admin_audit_outbox_pending_idx ON admin_audit_outbox (tenant_id, status, next_attempt_at, occurred_at, outbox_id)",
		"CREATE INDEX IF NOT EXISTS admin_audit_outbox_event_idx ON admin_audit_outbox (tenant_id, event_type, occurred_at DESC)",
	}
}

func buildPostgresAdminAuditOutboxInsertStatement(audit model.AuditLog, now time.Time) (postgresExportTaskQueueStatement, error) {
	tenantID := strings.TrimSpace(audit.TenantID)
	if tenantID == "" {
		return postgresExportTaskQueueStatement{}, fmt.Errorf("audit tenant_id is required")
	}
	outboxID := strings.TrimSpace(audit.ID)
	if outboxID == "" {
		return postgresExportTaskQueueStatement{}, fmt.Errorf("audit id is required")
	}
	eventType := strings.TrimSpace(audit.EventType)
	if eventType == "" {
		return postgresExportTaskQueueStatement{}, fmt.Errorf("audit event_type is required")
	}
	occurredAt := now.UTC()
	if strings.TrimSpace(audit.Timestamp) != "" {
		parsed, err := time.Parse(time.RFC3339, strings.TrimSpace(audit.Timestamp))
		if err != nil {
			return postgresExportTaskQueueStatement{}, fmt.Errorf("audit timestamp: %w", err)
		}
		occurredAt = parsed.UTC()
	}
	payload, err := json.Marshal(audit)
	if err != nil {
		return postgresExportTaskQueueStatement{}, fmt.Errorf("marshal audit outbox payload: %w", err)
	}
	return postgresExportTaskQueueStatement{
		SQL: strings.Join([]string{
			"INSERT INTO admin_audit_outbox (tenant_id, outbox_id, event_type, status, occurred_at, payload, created_at, updated_at)",
			"VALUES ($1, $2, $3, 'pending', $4, $5::jsonb, $6, $6)",
			"ON CONFLICT (tenant_id, outbox_id) DO NOTHING",
		}, " "),
		Args: []any{
			tenantID,
			outboxID,
			eventType,
			occurredAt,
			string(payload),
			now.UTC(),
		},
	}, nil
}

func buildPostgresAdminAuditOutboxClaimStatement(tenantID, publisherID string, limit, maxAttempts int, now, lockedUntil time.Time) (postgresExportTaskQueueStatement, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return postgresExportTaskQueueStatement{}, fmt.Errorf("tenant_id is required")
	}
	publisherID = strings.TrimSpace(publisherID)
	if publisherID == "" {
		return postgresExportTaskQueueStatement{}, fmt.Errorf("publisher_id is required")
	}
	if limit <= 0 {
		return postgresExportTaskQueueStatement{}, fmt.Errorf("limit must be positive")
	}
	if maxAttempts <= 0 {
		return postgresExportTaskQueueStatement{}, fmt.Errorf("max_attempts must be positive")
	}
	if lockedUntil.IsZero() || !lockedUntil.After(now) {
		return postgresExportTaskQueueStatement{}, fmt.Errorf("locked_until must be after now")
	}
	return postgresExportTaskQueueStatement{
		SQL: strings.Join([]string{
			"WITH picked AS (",
			"SELECT tenant_id, outbox_id FROM admin_audit_outbox",
			"WHERE tenant_id = $1",
			"AND (status = 'pending' OR (status = 'publishing' AND locked_until < $4::timestamptz))",
			"AND (next_attempt_at IS NULL OR next_attempt_at <= $4::timestamptz)",
			// ★ A STALE LOCK IS RECLAIMABLE WHATEVER THE ATTEMPT COUNT (2026-08-13, twenty-ninth review). This
			// predicate bounded RETRIES and also gated the stale-lock recovery that shares it — so a row
			// claimed at max-1, whose publisher then crashed, sat at publish_attempt = max and could never be
			// picked up again. mark-published, release and mark-dead all require the original locked_by, so
			// nothing could move it either: not published, not dead-lettered, just gone from every view that
			// counts one or the other. The cap belongs to fresh work; an abandoned lock has to be recoverable
			// so it can at least be declared dead.
			"AND (publish_attempt < $6 OR (status = 'publishing' AND locked_until < $5::timestamptz))",
			"ORDER BY occurred_at, outbox_id",
			"FOR UPDATE SKIP LOCKED",
			"LIMIT $2",
			")",
			"UPDATE admin_audit_outbox AS outbox",
			"SET status = 'publishing',",
			"publish_attempt = outbox.publish_attempt + 1,",
			"locked_by = $3,",
			"locked_until = $5::timestamptz,",
			"updated_at = $4::timestamptz",
			"FROM picked",
			"WHERE outbox.tenant_id = picked.tenant_id AND outbox.outbox_id = picked.outbox_id",
			"RETURNING outbox.tenant_id, outbox.outbox_id, outbox.publish_attempt, outbox.payload",
		}, " "),
		Args: []any{tenantID, limit, publisherID, now.UTC(), lockedUntil.UTC(), maxAttempts},
	}, nil
}

func buildPostgresAdminAuditOutboxMarkPublishedStatement(tenantID, outboxID, publisherID string, now time.Time) (postgresExportTaskQueueStatement, error) {
	tenantID = strings.TrimSpace(tenantID)
	outboxID = strings.TrimSpace(outboxID)
	publisherID = strings.TrimSpace(publisherID)
	if tenantID == "" || outboxID == "" || publisherID == "" {
		return postgresExportTaskQueueStatement{}, fmt.Errorf("tenant_id, outbox_id, and publisher_id are required")
	}
	return postgresExportTaskQueueStatement{
		SQL: strings.Join([]string{
			"UPDATE admin_audit_outbox",
			"SET status = 'published', published_at = $4::timestamptz, locked_by = NULL, locked_until = NULL, updated_at = $4::timestamptz",
			"WHERE tenant_id = $1 AND outbox_id = $2 AND locked_by = $3 AND status = 'publishing'",
		}, " "),
		Args: []any{tenantID, outboxID, publisherID, now.UTC()},
	}, nil
}

func buildPostgresAdminAuditOutboxListDeadStatement(tenantID string, limit int) (postgresExportTaskQueueStatement, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return postgresExportTaskQueueStatement{}, fmt.Errorf("tenant_id is required")
	}
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}
	return postgresExportTaskQueueStatement{
		SQL: strings.Join([]string{
			"SELECT tenant_id, outbox_id, event_type, publish_attempt, COALESCE(last_error, ''), occurred_at, COALESCE(dead_at, updated_at), payload",
			"FROM admin_audit_outbox",
			"WHERE tenant_id = $1 AND status = 'dead'",
			"ORDER BY COALESCE(dead_at, updated_at) DESC, outbox_id DESC",
			"LIMIT $2",
		}, " "),
		Args: []any{tenantID, limit},
	}, nil
}

func buildPostgresAdminAuditOutboxGetDeadStatement(tenantID, outboxID string) (postgresExportTaskQueueStatement, error) {
	tenantID = strings.TrimSpace(tenantID)
	outboxID = strings.TrimSpace(outboxID)
	if tenantID == "" || outboxID == "" {
		return postgresExportTaskQueueStatement{}, fmt.Errorf("tenant_id and outbox_id are required")
	}
	return postgresExportTaskQueueStatement{
		SQL: strings.Join([]string{
			"SELECT tenant_id, outbox_id, event_type, publish_attempt, COALESCE(last_error, ''), occurred_at, COALESCE(dead_at, updated_at), payload",
			"FROM admin_audit_outbox",
			"WHERE tenant_id = $1 AND outbox_id = $2 AND status = 'dead'",
			"LIMIT 1",
		}, " "),
		Args: []any{tenantID, outboxID},
	}, nil
}

func buildPostgresAdminAuditOutboxStatsStatement(tenantID string) (postgresExportTaskQueueStatement, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return postgresExportTaskQueueStatement{}, fmt.Errorf("tenant_id is required")
	}
	return postgresExportTaskQueueStatement{
		SQL: strings.Join([]string{
			"SELECT status, count(*), MIN(CASE WHEN status = 'dead' THEN COALESCE(dead_at, updated_at) ELSE occurred_at END)",
			"FROM admin_audit_outbox",
			"WHERE tenant_id = $1",
			"GROUP BY status",
		}, " "),
		Args: []any{tenantID},
	}, nil
}

func buildPostgresAdminAuditOutboxReplayDeadStatement(tenantID, outboxID string, now time.Time) (postgresExportTaskQueueStatement, error) {
	tenantID = strings.TrimSpace(tenantID)
	outboxID = strings.TrimSpace(outboxID)
	if tenantID == "" || outboxID == "" {
		return postgresExportTaskQueueStatement{}, fmt.Errorf("tenant_id and outbox_id are required")
	}
	return postgresExportTaskQueueStatement{
		SQL: strings.Join([]string{
			"WITH picked AS (",
			"SELECT tenant_id, outbox_id, publish_attempt, COALESCE(last_error, '') AS previous_last_error, dead_at AS previous_dead_at",
			"FROM admin_audit_outbox",
			"WHERE tenant_id = $1 AND outbox_id = $2 AND status = 'dead'",
			"FOR UPDATE",
			"), updated AS (",
			"UPDATE admin_audit_outbox AS outbox",
			"SET status = 'pending',",
			"publish_attempt = 0,",
			"locked_by = NULL,",
			"locked_until = NULL,",
			"next_attempt_at = NULL,",
			"last_error = NULL,",
			"dead_at = NULL,",
			"updated_at = $3::timestamptz",
			"FROM picked",
			"WHERE outbox.tenant_id = picked.tenant_id AND outbox.outbox_id = picked.outbox_id",
			"RETURNING outbox.tenant_id, outbox.outbox_id, outbox.status, outbox.publish_attempt, outbox.updated_at, picked.publish_attempt AS previous_publish_attempt, picked.previous_last_error, picked.previous_dead_at",
			")",
			"SELECT tenant_id, outbox_id, status, publish_attempt, updated_at, previous_publish_attempt, previous_last_error, previous_dead_at FROM updated",
		}, " "),
		Args: []any{tenantID, outboxID, now.UTC()},
	}, nil
}

func listPostgresAdminAuditOutboxDeadRows(ctx context.Context, db *sql.DB, tenantID string, limit int) ([]postgresAdminAuditOutboxDeadRow, error) {
	if db == nil {
		return nil, fmt.Errorf("postgres admin audit outbox db is not configured")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	statement, err := buildPostgresAdminAuditOutboxListDeadStatement(tenantID, limit)
	if err != nil {
		return nil, err
	}
	rows, err := db.QueryContext(ctx, statement.SQL, statement.Args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var deadRows []postgresAdminAuditOutboxDeadRow
	for rows.Next() {
		var row postgresAdminAuditOutboxDeadRow
		var payload []byte
		if err := rows.Scan(&row.TenantID, &row.OutboxID, &row.EventType, &row.PublishAttempt, &row.LastError, &row.OccurredAt, &row.DeadAt, &payload); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(payload, &row.Audit); err != nil {
			return nil, fmt.Errorf("decode dead admin audit outbox payload: %w", err)
		}
		deadRows = append(deadRows, row)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return deadRows, nil
}

func getPostgresAdminAuditOutboxDeadRow(ctx context.Context, db *sql.DB, tenantID, outboxID string) (postgresAdminAuditOutboxDeadRow, bool, error) {
	if db == nil {
		return postgresAdminAuditOutboxDeadRow{}, false, fmt.Errorf("postgres admin audit outbox db is not configured")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	statement, err := buildPostgresAdminAuditOutboxGetDeadStatement(tenantID, outboxID)
	if err != nil {
		return postgresAdminAuditOutboxDeadRow{}, false, err
	}
	var row postgresAdminAuditOutboxDeadRow
	var payload []byte
	err = db.QueryRowContext(ctx, statement.SQL, statement.Args...).Scan(&row.TenantID, &row.OutboxID, &row.EventType, &row.PublishAttempt, &row.LastError, &row.OccurredAt, &row.DeadAt, &payload)
	if errors.Is(err, sql.ErrNoRows) {
		return postgresAdminAuditOutboxDeadRow{}, false, nil
	}
	if err != nil {
		return postgresAdminAuditOutboxDeadRow{}, false, err
	}
	if err := json.Unmarshal(payload, &row.Audit); err != nil {
		return postgresAdminAuditOutboxDeadRow{}, false, fmt.Errorf("decode dead admin audit outbox payload: %w", err)
	}
	return row, true, nil
}

func postgresAdminAuditOutboxStatsForTenant(ctx context.Context, db *sql.DB, tenantID string) (postgresAdminAuditOutboxStats, error) {
	if db == nil {
		return postgresAdminAuditOutboxStats{}, fmt.Errorf("postgres admin audit outbox db is not configured")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	statement, err := buildPostgresAdminAuditOutboxStatsStatement(tenantID)
	if err != nil {
		return postgresAdminAuditOutboxStats{}, err
	}
	stats := postgresAdminAuditOutboxStats{TenantID: strings.TrimSpace(tenantID)}
	rows, err := db.QueryContext(ctx, statement.SQL, statement.Args...)
	if err != nil {
		return postgresAdminAuditOutboxStats{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var status string
		var count int
		var oldest sql.NullTime
		if err := rows.Scan(&status, &count, &oldest); err != nil {
			return postgresAdminAuditOutboxStats{}, err
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
		return postgresAdminAuditOutboxStats{}, err
	}
	return stats, nil
}

func replayPostgresAdminAuditOutboxDeadRow(ctx context.Context, db *sql.DB, tenantID, outboxID string, now time.Time) (postgresAdminAuditOutboxReplayResult, bool, error) {
	if db == nil {
		return postgresAdminAuditOutboxReplayResult{}, false, fmt.Errorf("postgres admin audit outbox db is not configured")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	statement, err := buildPostgresAdminAuditOutboxReplayDeadStatement(tenantID, outboxID, now)
	if err != nil {
		return postgresAdminAuditOutboxReplayResult{}, false, err
	}
	var result postgresAdminAuditOutboxReplayResult
	var previousDeadAt sql.NullTime
	err = db.QueryRowContext(ctx, statement.SQL, statement.Args...).Scan(&result.TenantID, &result.OutboxID, &result.Status, &result.PublishAttempt, &result.UpdatedAt, &result.PreviousPublishAttempt, &result.PreviousLastError, &previousDeadAt)
	if errors.Is(err, sql.ErrNoRows) {
		return postgresAdminAuditOutboxReplayResult{}, false, nil
	}
	if err != nil {
		return postgresAdminAuditOutboxReplayResult{}, false, err
	}
	if previousDeadAt.Valid {
		normalized := previousDeadAt.Time.UTC()
		result.PreviousDeadAt = &normalized
	}
	return result, true, nil
}

func buildPostgresAdminAuditOutboxMarkDeadStatement(tenantID, outboxID, publisherID, reason string, now time.Time) (postgresExportTaskQueueStatement, error) {
	tenantID = strings.TrimSpace(tenantID)
	outboxID = strings.TrimSpace(outboxID)
	publisherID = strings.TrimSpace(publisherID)
	if tenantID == "" || outboxID == "" || publisherID == "" {
		return postgresExportTaskQueueStatement{}, fmt.Errorf("tenant_id, outbox_id, and publisher_id are required")
	}
	if strings.TrimSpace(reason) == "" {
		reason = "publish_failed"
	}
	return postgresExportTaskQueueStatement{
		SQL: strings.Join([]string{
			"UPDATE admin_audit_outbox",
			"SET status = 'dead', dead_at = $5::timestamptz, last_error = $4, next_attempt_at = NULL, locked_by = NULL, locked_until = NULL, updated_at = $5::timestamptz",
			"WHERE tenant_id = $1 AND outbox_id = $2 AND locked_by = $3 AND status = 'publishing'",
		}, " "),
		Args: []any{tenantID, outboxID, publisherID, reason, now.UTC()},
	}, nil
}

func (publisher postgresAdminAuditOutboxPublisher) PublishOnce(ctx context.Context, now time.Time) (int, error) {
	if publisher.DB == nil {
		return 0, fmt.Errorf("postgres admin audit outbox db is not configured")
	}
	delivery := publisher.delivery()
	if delivery == nil {
		return 0, fmt.Errorf("admin audit outbox delivery is not configured")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	rows, err := publisher.claim(ctx, now)
	if err != nil {
		return 0, err
	}
	published := 0
	for _, row := range rows {
		if err := delivery.DeliverAdminAudit(ctx, row.Audit); err != nil {
			if releaseErr := publisher.release(ctx, row, adminAuditOutboxDeliveryFailureReason(err), now); releaseErr != nil {
				return published, fmt.Errorf("admin audit outbox delivery failed: %w; release failed: %v", err, releaseErr)
			}
			return published, err
		}
		if err := publisher.markPublished(ctx, row, now); err != nil {
			return published, err
		}
		published++
	}
	return published, nil
}

func (publisher postgresAdminAuditOutboxPublisher) claim(ctx context.Context, now time.Time) ([]postgresAdminAuditOutboxClaimedRow, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	limit := publisher.BatchSize
	if limit <= 0 {
		limit = 100
	}
	lockDuration := publisher.LockDuration
	if lockDuration <= 0 {
		lockDuration = time.Minute
	}
	statement, err := buildPostgresAdminAuditOutboxClaimStatement(publisher.TenantID, publisher.PublisherID, limit, publisher.maxAttempts(), now, now.Add(lockDuration))
	if err != nil {
		return nil, err
	}
	rows, err := publisher.DB.QueryContext(ctx, statement.SQL, statement.Args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var claimed []postgresAdminAuditOutboxClaimedRow
	for rows.Next() {
		var tenantID, outboxID string
		var publishAttempt int
		var payload []byte
		if err := rows.Scan(&tenantID, &outboxID, &publishAttempt, &payload); err != nil {
			return nil, err
		}
		var audit model.AuditLog
		if err := json.Unmarshal(payload, &audit); err != nil {
			return nil, fmt.Errorf("decode admin audit outbox payload: %w", err)
		}
		claimed = append(claimed, postgresAdminAuditOutboxClaimedRow{
			TenantID:       tenantID,
			OutboxID:       outboxID,
			PublishAttempt: publishAttempt,
			Audit:          audit,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return claimed, nil
}

func (publisher postgresAdminAuditOutboxPublisher) markPublished(ctx context.Context, row postgresAdminAuditOutboxClaimedRow, now time.Time) error {
	statement, err := buildPostgresAdminAuditOutboxMarkPublishedStatement(row.TenantID, row.OutboxID, publisher.PublisherID, now)
	if err != nil {
		return err
	}
	result, err := publisher.DB.ExecContext(ctx, statement.SQL, statement.Args...)
	if err != nil {
		return err
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("audit outbox mark published rows affected: %w", err)
	}
	if rowsAffected == 0 {
		return fmt.Errorf("audit outbox mark published: lock was stolen for %s", row.OutboxID)
	}
	return nil
}

func (publisher postgresAdminAuditOutboxPublisher) release(ctx context.Context, row postgresAdminAuditOutboxClaimedRow, reason string, now time.Time) error {
	if row.PublishAttempt >= publisher.maxAttempts() {
		return publisher.markDead(ctx, row, reason, now)
	}
	retryDelay := publisher.RetryDelay
	if retryDelay <= 0 {
		retryDelay = 30 * time.Second
	}
	statement, err := buildPostgresAdminAuditOutboxReleaseStatement(row.TenantID, row.OutboxID, publisher.PublisherID, reason, now.Add(retryDelay), now)
	if err != nil {
		return err
	}
	result, err := publisher.DB.ExecContext(ctx, statement.SQL, statement.Args...)
	if err != nil {
		return err
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("audit outbox release rows affected: %w", err)
	}
	if rowsAffected == 0 {
		return fmt.Errorf("audit outbox release: lock was stolen for %s", row.OutboxID)
	}
	return nil
}

func (publisher postgresAdminAuditOutboxPublisher) markDead(ctx context.Context, row postgresAdminAuditOutboxClaimedRow, reason string, now time.Time) error {
	statement, err := buildPostgresAdminAuditOutboxMarkDeadStatement(row.TenantID, row.OutboxID, publisher.PublisherID, reason, now)
	if err != nil {
		return err
	}
	result, err := publisher.DB.ExecContext(ctx, statement.SQL, statement.Args...)
	if err != nil {
		return err
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("audit outbox mark dead rows affected: %w", err)
	}
	if rowsAffected == 0 {
		return fmt.Errorf("audit outbox mark dead: lock was stolen for %s", row.OutboxID)
	}
	return nil
}

func (publisher postgresAdminAuditOutboxPublisher) maxAttempts() int {
	if publisher.MaxAttempts > 0 {
		return publisher.MaxAttempts
	}
	return 5
}

func (publisher postgresAdminAuditOutboxPublisher) delivery() adminAuditOutboxDelivery {
	if publisher.Delivery != nil {
		return publisher.Delivery
	}
	if publisher.Writer == nil {
		return nil
	}
	return jsonlAdminAuditOutboxDelivery{Writer: publisher.Writer}
}

func buildPostgresAdminAuditOutboxReleaseStatement(tenantID, outboxID, publisherID, reason string, nextAttemptAt, now time.Time) (postgresExportTaskQueueStatement, error) {
	tenantID = strings.TrimSpace(tenantID)
	outboxID = strings.TrimSpace(outboxID)
	publisherID = strings.TrimSpace(publisherID)
	if tenantID == "" || outboxID == "" || publisherID == "" {
		return postgresExportTaskQueueStatement{}, fmt.Errorf("tenant_id, outbox_id, and publisher_id are required")
	}
	if strings.TrimSpace(reason) == "" {
		reason = "publish_failed"
	}
	return postgresExportTaskQueueStatement{
		SQL: strings.Join([]string{
			"UPDATE admin_audit_outbox",
			"SET status = 'pending', last_error = $4, next_attempt_at = $5::timestamptz, locked_by = NULL, locked_until = NULL, updated_at = $6::timestamptz",
			"WHERE tenant_id = $1 AND outbox_id = $2 AND locked_by = $3 AND status = 'publishing'",
		}, " "),
		Args: []any{tenantID, outboxID, publisherID, reason, nextAttemptAt.UTC(), now.UTC()},
	}, nil
}
