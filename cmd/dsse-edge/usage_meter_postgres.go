package main

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	usagemeter "github.com/lantern-networks/dsse-core/usagemeter"
)

const (
	postgresUsageMeterTimeout      = 15 * time.Second
	postgresUsageMeterPendingLimit = 1000
	postgresUsageMeterSpoolFile    = "usage_meter_pending.log.jsonl"
)

type postgresUsageMeterStore struct {
	DB         *sql.DB
	SpoolDir   string
	mu         sync.Mutex
	pending    []usagemeter.UsageMeterRecord
	MaxPending int
	// droppedRecords is the cumulative count of usage/billing records DROPPED because the in-memory pending
	// buffer overflowed while Postgres was unreachable and the disk spool was unavailable — irreversible
	// billing data loss. Surfaced via DroppedRecordCount so a health check can alarm on degraded mode
	// (review #33). Guarded by mu.
	droppedRecords int64
}

// DroppedRecordCount returns how many usage/billing records have been irreversibly dropped (Postgres down +
// spool unavailable + memory buffer full). Non-zero means billing data has been lost and the deployment is
// running degraded — a health/status surface should alarm on it.
func (store *postgresUsageMeterStore) DroppedRecordCount() int64 {
	if store == nil {
		return 0
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.droppedRecords
}

var _ usagemeter.UsageMeterRuntimeStore = (*postgresUsageMeterStore)(nil)
var _ usagemeter.UsageMeterRecordReader = (*postgresUsageMeterStore)(nil)

func (store *postgresUsageMeterStore) Record(record usagemeter.UsageMeterRecord) {
	if store == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), postgresUsageMeterTimeout)
	defer cancel()
	if err := store.flushPending(ctx, time.Now().UTC()); err != nil {
		log.Printf("usage meter postgres pending flush failed: %v", err)
	}
	if err := store.Insert(ctx, record, time.Now().UTC()); err != nil {
		log.Printf("usage meter postgres record failed: %v", err)
		store.bufferPending(record)
	}
}

func (store *postgresUsageMeterStore) Summary(tenantID string, periodStart, periodEnd time.Time) usagemeter.UsageMeterSummary {
	if store == nil {
		return usagemeter.SummarizeUsageMeterRecords(nil, tenantID, periodStart, periodEnd)
	}
	ctx, cancel := context.WithTimeout(context.Background(), postgresUsageMeterTimeout)
	defer cancel()
	if err := store.flushPending(ctx, time.Now().UTC()); err != nil {
		log.Printf("usage meter postgres summary pending flush failed: %v", err)
	}
	records, err := store.ListByTenant(ctx, tenantID, periodStart, periodEnd)
	pending := store.pendingSnapshot()
	if err != nil {
		log.Printf("usage meter postgres summary failed: %v", err)
		return usagemeter.SummarizeUsageMeterRecords(pending, tenantID, periodStart, periodEnd)
	}
	records = append(records, pending...)
	return usagemeter.SummarizeUsageMeterRecords(records, tenantID, periodStart, periodEnd)
}

func (store *postgresUsageMeterStore) UsageMeterRecords(tenantID string, periodStart, periodEnd time.Time) ([]usagemeter.UsageMeterRecord, error) {
	if store == nil {
		return nil, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), postgresUsageMeterTimeout)
	defer cancel()
	if err := store.flushPending(ctx, time.Now().UTC()); err != nil {
		log.Printf("usage meter postgres records pending flush failed: %v", err)
	}
	records, err := store.ListByTenant(ctx, tenantID, periodStart, periodEnd)
	pending := store.pendingSnapshot()
	if err != nil {
		return pending, err
	}
	return append(records, pending...), nil
}

func (store *postgresUsageMeterStore) ReplayPending(ctx context.Context) error {
	if store == nil {
		return nil
	}
	if _, ok := ctx.Deadline(); ok {
		return store.flushPending(ctx, time.Now().UTC())
	}
	replayCtx, cancel := context.WithTimeout(ctx, postgresUsageMeterTimeout)
	defer cancel()
	return store.flushPending(replayCtx, time.Now().UTC())
}

func (store *postgresUsageMeterStore) PendingRecordCounts(tenantID string) (int, int, error) {
	if store == nil {
		return 0, 0, nil
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	spooled, err := store.spooledPendingLocked()
	if err != nil {
		return countUsageMeterRecordsForTenant(store.pending, tenantID), 0, err
	}
	return countUsageMeterRecordsForTenant(store.pending, tenantID), countUsageMeterRecordsForTenant(spooled, tenantID), nil
}

func (store *postgresUsageMeterStore) flushPending(ctx context.Context, now time.Time) error {
	pending := store.takePending()
	for i, record := range pending {
		if err := store.Insert(ctx, record, now); err != nil {
			store.requeuePending(pending[i:])
			return err
		}
	}
	return store.flushSpooledPending(ctx, now)
}

func (store *postgresUsageMeterStore) flushSpooledPending(ctx context.Context, now time.Time) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	spooled, err := store.spooledPendingLocked()
	if err != nil {
		return err
	}
	for _, record := range spooled {
		if err := store.Insert(ctx, record, now); err != nil {
			return err
		}
	}
	if len(spooled) > 0 {
		if err := store.removeSpoolLocked(); err != nil {
			return err
		}
	}
	return nil
}

func (store *postgresUsageMeterStore) takePending() []usagemeter.UsageMeterRecord {
	store.mu.Lock()
	defer store.mu.Unlock()
	if len(store.pending) == 0 {
		return nil
	}
	pending := append([]usagemeter.UsageMeterRecord(nil), store.pending...)
	store.pending = nil
	return pending
}

func (store *postgresUsageMeterStore) requeuePending(records []usagemeter.UsageMeterRecord) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.pending = append(append([]usagemeter.UsageMeterRecord(nil), records...), store.pending...)
	store.trimPendingLocked()
}

func (store *postgresUsageMeterStore) bufferPending(record usagemeter.UsageMeterRecord) {
	if err := store.appendSpool(record); err == nil {
		return
	} else if strings.TrimSpace(store.SpoolDir) != "" {
		log.Printf("usage meter postgres spool write failed, falling back to memory buffer: %v", err)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if record.ID != "" && record.TenantID != "" {
		for i, existing := range store.pending {
			if existing.ID == record.ID && existing.TenantID == record.TenantID {
				store.pending[i] = record
				return
			}
		}
	}
	store.pending = append(store.pending, record)
	store.trimPendingLocked()
}

func (store *postgresUsageMeterStore) pendingSnapshot() []usagemeter.UsageMeterRecord {
	store.mu.Lock()
	defer store.mu.Unlock()
	records := append([]usagemeter.UsageMeterRecord(nil), store.pending...)
	spooled, err := store.spooledPendingLocked()
	if err != nil {
		log.Printf("usage meter postgres pending spool read failed: %v", err)
		return records
	}
	return append(records, spooled...)
}

func (store *postgresUsageMeterStore) trimPendingLocked() {
	limit := store.MaxPending
	if limit <= 0 {
		limit = postgresUsageMeterPendingLimit
	}
	if len(store.pending) <= limit {
		return
	}
	dropped := len(store.pending) - limit
	store.pending = append([]usagemeter.UsageMeterRecord(nil), store.pending[dropped:]...)
	store.droppedRecords += int64(dropped)
	// Fail loud: this is IRREVERSIBLE billing/usage data loss (Postgres down + spool unavailable + memory
	// buffer full). Frame it unambiguously and note the missing-spool misconfiguration that makes it
	// possible, so the operator configures a spool dir or restores Postgres (review #33).
	spoolHint := ""
	if strings.TrimSpace(store.SpoolDir) == "" {
		spoolHint = " (no spool dir configured — records had no disk fallback; configure one to stop dropping)"
	}
	log.Printf("WARNING: usage/billing DATA LOSS — dropped %d oldest usage-meter records (cumulative %d); the pending buffer overflowed while durable storage was unavailable%s",
		dropped, store.droppedRecords, spoolHint)
}

func (store *postgresUsageMeterStore) appendSpool(record usagemeter.UsageMeterRecord) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.appendSpoolLocked(record)
}

func (store *postgresUsageMeterStore) appendSpoolLocked(record usagemeter.UsageMeterRecord) error {
	path, err := store.spoolPathLocked()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create usage meter spool dir: %w", err)
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return fmt.Errorf("open usage meter spool: %w", err)
	}
	defer file.Close()
	encoded, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("marshal usage meter spool record: %w", err)
	}
	if _, err := file.Write(append(encoded, '\n')); err != nil {
		return fmt.Errorf("write usage meter spool record: %w", err)
	}
	return nil
}

func (store *postgresUsageMeterStore) spooledPending() ([]usagemeter.UsageMeterRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.spooledPendingLocked()
}

func (store *postgresUsageMeterStore) spooledPendingLocked() ([]usagemeter.UsageMeterRecord, error) {
	path, err := store.spoolPathLocked()
	if err != nil {
		if strings.TrimSpace(store.SpoolDir) == "" {
			return nil, nil
		}
		return nil, err
	}
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("open usage meter spool: %w", err)
	}
	defer file.Close()
	var records []usagemeter.UsageMeterRecord
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var record usagemeter.UsageMeterRecord
		if err := json.Unmarshal(scanner.Bytes(), &record); err != nil {
			return nil, fmt.Errorf("decode usage meter spool record: %w", err)
		}
		records = append(records, record)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan usage meter spool: %w", err)
	}
	return records, nil
}

func (store *postgresUsageMeterStore) removeSpool() error {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.removeSpoolLocked()
}

func (store *postgresUsageMeterStore) removeSpoolLocked() error {
	path, err := store.spoolPathLocked()
	if err != nil {
		if strings.TrimSpace(store.SpoolDir) == "" {
			return nil
		}
		return err
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove usage meter spool: %w", err)
	}
	return nil
}

func (store *postgresUsageMeterStore) spoolPathLocked() (string, error) {
	dir := strings.TrimSpace(store.SpoolDir)
	if dir == "" {
		return "", fmt.Errorf("usage meter spool dir is not configured")
	}
	return filepath.Join(dir, postgresUsageMeterSpoolFile), nil
}

func countUsageMeterRecordsForTenant(records []usagemeter.UsageMeterRecord, tenantID string) int {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return len(records)
	}
	count := 0
	for _, record := range records {
		if record.TenantID == tenantID {
			count++
		}
	}
	return count
}

func (store *postgresUsageMeterStore) Insert(ctx context.Context, record usagemeter.UsageMeterRecord, now time.Time) error {
	if store.DB == nil {
		return fmt.Errorf("postgres usage meter db is not configured")
	}
	statement, err := buildPostgresUsageMeterInsertStatement(record, now)
	if err != nil {
		return err
	}
	if _, err := store.DB.ExecContext(ctx, statement.SQL, statement.Args...); err != nil {
		return fmt.Errorf("insert usage meter record: %w", err)
	}
	return nil
}

func (store *postgresUsageMeterStore) ListByTenant(ctx context.Context, tenantID string, periodStart, periodEnd time.Time) ([]usagemeter.UsageMeterRecord, error) {
	if store.DB == nil {
		return nil, fmt.Errorf("postgres usage meter db is not configured")
	}
	statement, err := buildPostgresUsageMeterListStatement(tenantID, periodStart, periodEnd)
	if err != nil {
		return nil, err
	}
	rows, err := store.DB.QueryContext(ctx, statement.SQL, statement.Args...)
	if err != nil {
		return nil, fmt.Errorf("list usage meter records: %w", err)
	}
	defer rows.Close()

	var records []usagemeter.UsageMeterRecord
	for rows.Next() {
		var payload []byte
		if err := rows.Scan(&payload); err != nil {
			return nil, fmt.Errorf("scan usage meter record: %w", err)
		}
		var record usagemeter.UsageMeterRecord
		if err := json.Unmarshal(payload, &record); err != nil {
			return nil, fmt.Errorf("decode usage meter record: %w", err)
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate usage meter records: %w", err)
	}
	return records, nil
}

func postgresUsageMeterSchemaSQL() []string {
	return []string{
		strings.Join([]string{
			"CREATE TABLE IF NOT EXISTS usage_meter_records (",
			"tenant_id text NOT NULL,",
			"usage_meter_id text NOT NULL,",
			"schema_version text NOT NULL,",
			"meter_type text NOT NULL,",
			"subject_type text NOT NULL,",
			"subject_id text NOT NULL,",
			"unit text NOT NULL,",
			"quantity double precision NOT NULL CHECK (quantity >= 0),",
			"period_start timestamptz NOT NULL,",
			"period_end timestamptz NOT NULL,",
			"collected_at timestamptz NOT NULL,",
			"quota jsonb,",
			"dimensions jsonb NOT NULL DEFAULT '{}'::jsonb,",
			"metadata jsonb NOT NULL DEFAULT '{}'::jsonb,",
			"payload jsonb NOT NULL,",
			"created_at timestamptz NOT NULL DEFAULT now(),",
			"updated_at timestamptz NOT NULL DEFAULT now(),",
			"PRIMARY KEY (tenant_id, usage_meter_id),",
			"CHECK (period_end > period_start)",
			")",
		}, " "),
		"CREATE INDEX IF NOT EXISTS usage_meter_records_period_idx ON usage_meter_records (tenant_id, period_start, period_end)",
		"CREATE INDEX IF NOT EXISTS usage_meter_records_meter_idx ON usage_meter_records (tenant_id, meter_type, period_start)",
		"CREATE INDEX IF NOT EXISTS usage_meter_records_subject_idx ON usage_meter_records (tenant_id, subject_type, subject_id, period_start)",
	}
}

func buildPostgresUsageMeterInsertStatement(record usagemeter.UsageMeterRecord, now time.Time) (postgresExportTaskQueueStatement, error) {
	record.ID = strings.TrimSpace(record.ID)
	record.TenantID = strings.TrimSpace(record.TenantID)
	record.SchemaVersion = strings.TrimSpace(record.SchemaVersion)
	record.MeterType = strings.TrimSpace(record.MeterType)
	record.SubjectType = strings.TrimSpace(record.SubjectType)
	record.Unit = strings.TrimSpace(record.Unit)
	subjectID := ""
	if record.SubjectID != nil {
		subjectID = strings.TrimSpace(*record.SubjectID)
	}
	if record.ID == "" || record.TenantID == "" || record.SchemaVersion == "" || record.MeterType == "" || record.SubjectType == "" || subjectID == "" || record.Unit == "" {
		return postgresExportTaskQueueStatement{}, fmt.Errorf("usage meter id, tenant_id, schema_version, meter_type, subject_type, subject_id, and unit are required")
	}
	if record.Quantity < 0 {
		return postgresExportTaskQueueStatement{}, fmt.Errorf("usage meter quantity must be non-negative")
	}
	if record.PeriodStart.IsZero() || record.PeriodEnd.IsZero() || !record.PeriodEnd.After(record.PeriodStart) {
		return postgresExportTaskQueueStatement{}, fmt.Errorf("usage meter period_start and period_end are required and ordered")
	}
	if record.CollectedAt.IsZero() {
		return postgresExportTaskQueueStatement{}, fmt.Errorf("usage meter collected_at is required")
	}
	if record.Dimensions == nil {
		record.Dimensions = map[string]any{}
	}
	if record.Metadata == nil {
		record.Metadata = map[string]any{}
	}
	quotaBytes, err := json.Marshal(record.Quota)
	if err != nil {
		return postgresExportTaskQueueStatement{}, fmt.Errorf("marshal usage meter quota: %w", err)
	}
	dimensionsBytes, err := json.Marshal(record.Dimensions)
	if err != nil {
		return postgresExportTaskQueueStatement{}, fmt.Errorf("marshal usage meter dimensions: %w", err)
	}
	metadataBytes, err := json.Marshal(record.Metadata)
	if err != nil {
		return postgresExportTaskQueueStatement{}, fmt.Errorf("marshal usage meter metadata: %w", err)
	}
	payloadBytes, err := json.Marshal(record)
	if err != nil {
		return postgresExportTaskQueueStatement{}, fmt.Errorf("marshal usage meter payload: %w", err)
	}
	return postgresExportTaskQueueStatement{
		SQL: strings.Join([]string{
			"INSERT INTO usage_meter_records (tenant_id, usage_meter_id, schema_version, meter_type, subject_type, subject_id, unit, quantity, period_start, period_end, collected_at, quota, dimensions, metadata, payload, created_at, updated_at)",
			"VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12::jsonb, $13::jsonb, $14::jsonb, $15::jsonb, $16, $16)",
			"ON CONFLICT (tenant_id, usage_meter_id) DO UPDATE SET schema_version = EXCLUDED.schema_version, meter_type = EXCLUDED.meter_type, subject_type = EXCLUDED.subject_type, subject_id = EXCLUDED.subject_id, unit = EXCLUDED.unit, quantity = EXCLUDED.quantity, period_start = EXCLUDED.period_start, period_end = EXCLUDED.period_end, collected_at = EXCLUDED.collected_at, quota = EXCLUDED.quota, dimensions = EXCLUDED.dimensions, metadata = EXCLUDED.metadata, payload = EXCLUDED.payload, updated_at = EXCLUDED.updated_at",
		}, " "),
		Args: []any{
			record.TenantID,
			record.ID,
			record.SchemaVersion,
			record.MeterType,
			record.SubjectType,
			subjectID,
			record.Unit,
			record.Quantity,
			record.PeriodStart.UTC(),
			record.PeriodEnd.UTC(),
			record.CollectedAt.UTC(),
			string(quotaBytes),
			string(dimensionsBytes),
			string(metadataBytes),
			string(payloadBytes),
			now.UTC(),
		},
	}, nil
}

func buildPostgresUsageMeterListStatement(tenantID string, periodStart, periodEnd time.Time) (postgresExportTaskQueueStatement, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return postgresExportTaskQueueStatement{}, fmt.Errorf("tenant_id is required")
	}
	if periodStart.IsZero() || periodEnd.IsZero() || !periodEnd.After(periodStart) {
		return postgresExportTaskQueueStatement{}, fmt.Errorf("period_start and period_end are required and ordered")
	}
	return postgresExportTaskQueueStatement{
		SQL: strings.Join([]string{
			"SELECT payload",
			"FROM usage_meter_records",
			"WHERE tenant_id = $1 AND period_end > $2 AND period_start < $3",
			"ORDER BY period_start ASC, usage_meter_id ASC",
		}, " "),
		Args: []any{
			tenantID,
			periodStart.UTC(),
			periodEnd.UTC(),
		},
	}, nil
}
