package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	humanidentity "github.com/lantern-networks/dsse-core/humanidentity"

	"github.com/lantern-networks/dsse-core/model"
)

const postgresHumanIdentityDirectoryTimeout = 15 * time.Second

type postgresHumanIdentityDirectoryStore struct {
	DB *sql.DB
	// gen is the monotonic change signal the config bundle aggregates, bumped on every write this process
	// makes. Kept in memory rather than derived from postgres, matching the NHI registry: it is a "something
	// changed here" counter for the bundle version, not a durable fact about the rows.
	gen *uint64
}

var _ humanidentity.HumanIdentityDirectoryRuntimeStore = postgresHumanIdentityDirectoryStore{}
var _ humanidentity.HumanIdentityDirectoryBulkUpserter = postgresHumanIdentityDirectoryStore{}
var _ humanidentity.HumanIdentityImportRunLister = postgresHumanIdentityDirectoryStore{}
var _ humanidentity.HumanIdentityImportRunGetter = postgresHumanIdentityDirectoryStore{}
var _ humanidentity.HumanIdentitySourceLister = postgresHumanIdentityDirectoryStore{}
var _ humanidentity.HumanIdentitySourceStateRecorder = postgresHumanIdentityDirectoryStore{}
var _ humanidentity.HumanIdentitySourceStateLister = postgresHumanIdentityDirectoryStore{}
var _ humanidentity.HumanIdentitySourcePolicyUpserter = postgresHumanIdentityDirectoryStore{}
var _ humanidentity.HumanIdentitySourcePolicyLister = postgresHumanIdentityDirectoryStore{}

func (store postgresHumanIdentityDirectoryStore) Upsert(ctx context.Context, user model.HumanIdentity, tenantID string, now time.Time) (model.HumanIdentity, error) {
	if store.DB == nil {
		return model.HumanIdentity{}, fmt.Errorf("postgres human identity directory db is not configured")
	}
	normalized, err := humanidentity.NormalizeHumanIdentity(user, tenantID, now)
	if err != nil {
		return model.HumanIdentity{}, err
	}
	statement, err := buildPostgresHumanIdentityDirectoryUpsertStatement(normalized, now)
	if err != nil {
		return model.HumanIdentity{}, err
	}
	if _, err := store.DB.ExecContext(ctx, statement.SQL, statement.Args...); err != nil {
		return model.HumanIdentity{}, fmt.Errorf("upsert human identity: %w", err)
	}
	store.bumpGeneration()
	return normalized, nil
}

// ConfigGeneration returns the monotonic directory version. The config bundle sums it, which is what makes an
// enforcing Edge re-pull after somebody is added — otherwise the bundle's contents change and its version does
// not, and no Edge ever asks again.
func (store postgresHumanIdentityDirectoryStore) ConfigGeneration() uint64 {
	if store.gen == nil {
		return 0
	}
	return atomic.LoadUint64(store.gen)
}

func (store postgresHumanIdentityDirectoryStore) bumpGeneration() {
	if store.gen != nil {
		atomic.AddUint64(store.gen, 1)
	}
}

func (store postgresHumanIdentityDirectoryStore) UpsertMany(ctx context.Context, users []model.HumanIdentity, tenantID string, now time.Time) ([]model.HumanIdentity, error) {
	if store.DB == nil {
		return nil, fmt.Errorf("postgres human identity directory db is not configured")
	}
	if len(users) == 0 {
		return nil, nil
	}
	statements := make([]postgresExportTaskQueueStatement, 0, len(users))
	normalized := make([]model.HumanIdentity, 0, len(users))
	for index, user := range users {
		item, err := humanidentity.NormalizeHumanIdentity(user, tenantID, now)
		if err != nil {
			return nil, fmt.Errorf("normalize human identity at index %d: %w", index, err)
		}
		statement, err := buildPostgresHumanIdentityDirectoryUpsertStatement(item, now)
		if err != nil {
			return nil, fmt.Errorf("build human identity upsert at index %d: %w", index, err)
		}
		normalized = append(normalized, item)
		statements = append(statements, statement)
	}
	tx, err := store.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin human identity import transaction: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()
	for index, statement := range statements {
		if _, err := tx.ExecContext(ctx, statement.SQL, statement.Args...); err != nil {
			return nil, fmt.Errorf("upsert human identity at index %d: %w", index, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit human identity import transaction: %w", err)
	}
	committed = true
	store.bumpGeneration()
	return normalized, nil
}

func (store postgresHumanIdentityDirectoryStore) List(ctx context.Context, tenantID string, options ...humanidentity.HumanIdentityDirectoryListOptions) ([]model.HumanIdentity, error) {
	if store.DB == nil {
		return nil, fmt.Errorf("postgres human identity directory db is not configured")
	}
	statement, err := buildPostgresHumanIdentityDirectoryListStatement(tenantID, options...)
	if err != nil {
		return nil, err
	}
	rows, err := store.DB.QueryContext(ctx, statement.SQL, statement.Args...)
	if err != nil {
		return nil, fmt.Errorf("list human identities: %w", err)
	}
	defer rows.Close()
	users := []model.HumanIdentity{}
	for rows.Next() {
		var payload []byte
		if err := rows.Scan(&payload); err != nil {
			return nil, fmt.Errorf("scan human identity: %w", err)
		}
		var user model.HumanIdentity
		if err := json.Unmarshal(payload, &user); err != nil {
			return nil, fmt.Errorf("decode human identity: %w", err)
		}
		users = append(users, user)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate human identities: %w", err)
	}
	return users, nil
}

func (store postgresHumanIdentityDirectoryStore) Stats(ctx context.Context, tenantID string, now time.Time) (humanidentity.HumanIdentityDirectoryStats, error) {
	if store.DB == nil {
		return humanidentity.HumanIdentityDirectoryStats{}, fmt.Errorf("postgres human identity directory db is not configured")
	}
	statement, err := buildPostgresHumanIdentityDirectoryStatsStatement(tenantID, now)
	if err != nil {
		return humanidentity.HumanIdentityDirectoryStats{}, err
	}
	var stats humanidentity.HumanIdentityDirectoryStats
	if err := store.DB.QueryRowContext(ctx, statement.SQL, statement.Args...).Scan(&stats.Total, &stats.Active); err != nil {
		return humanidentity.HumanIdentityDirectoryStats{}, fmt.Errorf("count human identities: %w", err)
	}
	return stats, nil
}

func (store postgresHumanIdentityDirectoryStore) ListImportRuns(ctx context.Context, tenantID string, options humanidentity.HumanIdentityImportRunListOptions) ([]humanidentity.HumanIdentityImportRunSummary, error) {
	if store.DB == nil {
		return nil, fmt.Errorf("postgres human identity directory db is not configured")
	}
	statement, err := buildPostgresHumanIdentityImportRunListStatement(tenantID, options)
	if err != nil {
		return nil, err
	}
	rows, err := store.DB.QueryContext(ctx, statement.SQL, statement.Args...)
	if err != nil {
		return nil, fmt.Errorf("list human identity import runs: %w", err)
	}
	defer rows.Close()
	runs := []humanidentity.HumanIdentityImportRunSummary{}
	for rows.Next() {
		var summary humanidentity.HumanIdentityImportRunSummary
		var checkpoint string
		var upserted int64
		var deactivated int64
		var active int64
		var deleted int64
		if err := rows.Scan(&summary.ImportRunID, &summary.Source, &checkpoint, &summary.ObservedAt, &upserted, &deactivated, &active, &deleted); err != nil {
			return nil, fmt.Errorf("scan human identity import run: %w", err)
		}
		summary.Checkpoint = checkpoint
		summary.Upserted = int(upserted)
		summary.Deactivated = int(deactivated)
		summary.Active = int(active)
		summary.Deleted = int(deleted)
		runs = append(runs, summary)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate human identity import runs: %w", err)
	}
	return runs, nil
}

func (store postgresHumanIdentityDirectoryStore) GetImportRun(ctx context.Context, tenantID, importRunID string) (humanidentity.HumanIdentityImportRunDetailResponse, bool, error) {
	if store.DB == nil {
		return humanidentity.HumanIdentityImportRunDetailResponse{}, false, fmt.Errorf("postgres human identity directory db is not configured")
	}
	statement, err := buildPostgresHumanIdentityImportRunDetailStatement(tenantID, importRunID)
	if err != nil {
		return humanidentity.HumanIdentityImportRunDetailResponse{}, false, err
	}
	rows, err := store.DB.QueryContext(ctx, statement.SQL, statement.Args...)
	if err != nil {
		return humanidentity.HumanIdentityImportRunDetailResponse{}, false, fmt.Errorf("get human identity import run: %w", err)
	}
	defer rows.Close()
	users := []model.HumanIdentity{}
	for rows.Next() {
		var payload []byte
		if err := rows.Scan(&payload); err != nil {
			return humanidentity.HumanIdentityImportRunDetailResponse{}, false, fmt.Errorf("scan human identity import run detail: %w", err)
		}
		var user model.HumanIdentity
		if err := json.Unmarshal(payload, &user); err != nil {
			return humanidentity.HumanIdentityImportRunDetailResponse{}, false, fmt.Errorf("decode human identity import run detail: %w", err)
		}
		users = append(users, user)
	}
	if err := rows.Err(); err != nil {
		return humanidentity.HumanIdentityImportRunDetailResponse{}, false, fmt.Errorf("iterate human identity import run detail: %w", err)
	}
	return humanidentity.HumanIdentityImportRunDetailFromUsers(strings.TrimSpace(tenantID), strings.TrimSpace(importRunID), users)
}

func (store postgresHumanIdentityDirectoryStore) ListSources(ctx context.Context, tenantID string, now time.Time) ([]humanidentity.HumanIdentitySourceSummary, error) {
	if store.DB == nil {
		return nil, fmt.Errorf("postgres human identity directory db is not configured")
	}
	statement, err := buildPostgresHumanIdentitySourceListStatement(tenantID, now)
	if err != nil {
		return nil, err
	}
	rows, err := store.DB.QueryContext(ctx, statement.SQL, statement.Args...)
	if err != nil {
		return nil, fmt.Errorf("list human identity sources: %w", err)
	}
	defer rows.Close()
	sources := []humanidentity.HumanIdentitySourceSummary{}
	for rows.Next() {
		var summary humanidentity.HumanIdentitySourceSummary
		var total int64
		var active int64
		var suspended int64
		var deleted int64
		var expired int64
		if err := rows.Scan(&summary.Source, &summary.ObservedAt, &summary.LatestImportRunID, &total, &active, &suspended, &deleted, &expired); err != nil {
			return nil, fmt.Errorf("scan human identity source: %w", err)
		}
		summary.Total = int(total)
		summary.Active = int(active)
		summary.Suspended = int(suspended)
		summary.Deleted = int(deleted)
		summary.Expired = int(expired)
		sources = append(sources, summary)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate human identity sources: %w", err)
	}
	return sources, nil
}

func (store postgresHumanIdentityDirectoryStore) RecordSourceImport(ctx context.Context, state humanidentity.HumanIdentitySourceState) error {
	if store.DB == nil {
		return fmt.Errorf("postgres human identity directory db is not configured")
	}
	statement, err := buildPostgresHumanIdentitySourceStateUpsertStatement(state)
	if err != nil {
		return err
	}
	if _, err := store.DB.ExecContext(ctx, statement.SQL, statement.Args...); err != nil {
		return fmt.Errorf("record human identity source state: %w", err)
	}
	return nil
}

func (store postgresHumanIdentityDirectoryStore) ListSourceStates(ctx context.Context, tenantID string) ([]humanidentity.HumanIdentitySourceState, error) {
	if store.DB == nil {
		return nil, fmt.Errorf("postgres human identity directory db is not configured")
	}
	statement, err := buildPostgresHumanIdentitySourceStateListStatement(tenantID)
	if err != nil {
		return nil, err
	}
	rows, err := store.DB.QueryContext(ctx, statement.SQL, statement.Args...)
	if err != nil {
		return nil, fmt.Errorf("list human identity source states: %w", err)
	}
	defer rows.Close()
	states := []humanidentity.HumanIdentitySourceState{}
	for rows.Next() {
		var payload []byte
		if err := rows.Scan(&payload); err != nil {
			return nil, fmt.Errorf("scan human identity source state: %w", err)
		}
		var state humanidentity.HumanIdentitySourceState
		if err := json.Unmarshal(payload, &state); err != nil {
			return nil, fmt.Errorf("decode human identity source state: %w", err)
		}
		states = append(states, state)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate human identity source states: %w", err)
	}
	return states, nil
}

func (store postgresHumanIdentityDirectoryStore) UpsertSourcePolicy(ctx context.Context, policy humanidentity.HumanIdentitySourcePolicy) (humanidentity.HumanIdentitySourcePolicy, error) {
	if store.DB == nil {
		return humanidentity.HumanIdentitySourcePolicy{}, fmt.Errorf("postgres human identity directory db is not configured")
	}
	normalized, err := humanidentity.NormalizeHumanIdentitySourcePolicy(policy)
	if err != nil {
		return humanidentity.HumanIdentitySourcePolicy{}, err
	}
	statement, err := buildPostgresHumanIdentitySourcePolicyUpsertStatement(normalized)
	if err != nil {
		return humanidentity.HumanIdentitySourcePolicy{}, err
	}
	if _, err := store.DB.ExecContext(ctx, statement.SQL, statement.Args...); err != nil {
		return humanidentity.HumanIdentitySourcePolicy{}, fmt.Errorf("upsert human identity source policy: %w", err)
	}
	store.bumpGeneration()
	return normalized, nil
}

func (store postgresHumanIdentityDirectoryStore) ListSourcePolicies(ctx context.Context, tenantID string) ([]humanidentity.HumanIdentitySourcePolicy, error) {
	if store.DB == nil {
		return nil, fmt.Errorf("postgres human identity directory db is not configured")
	}
	statement, err := buildPostgresHumanIdentitySourcePolicyListStatement(tenantID)
	if err != nil {
		return nil, err
	}
	rows, err := store.DB.QueryContext(ctx, statement.SQL, statement.Args...)
	if err != nil {
		return nil, fmt.Errorf("list human identity source policies: %w", err)
	}
	defer rows.Close()
	policies := []humanidentity.HumanIdentitySourcePolicy{}
	for rows.Next() {
		var payload []byte
		if err := rows.Scan(&payload); err != nil {
			return nil, fmt.Errorf("scan human identity source policy: %w", err)
		}
		var policy humanidentity.HumanIdentitySourcePolicy
		if err := json.Unmarshal(payload, &policy); err != nil {
			return nil, fmt.Errorf("decode human identity source policy: %w", err)
		}
		policies = append(policies, policy)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate human identity source policies: %w", err)
	}
	return policies, nil
}

func postgresHumanIdentityDirectorySchemaSQL() []string {
	return []string{
		strings.Join([]string{
			"CREATE TABLE IF NOT EXISTS human_identities (",
			"tenant_id text NOT NULL,",
			"human_identity_id text NOT NULL,",
			"subject text NOT NULL,",
			"email text,",
			"display_name text,",
			"source text NOT NULL,",
			"department text,",
			"last_seen_at timestamptz,",
			"expires_at timestamptz,",
			"status text NOT NULL CHECK (status IN ('active', 'suspended', 'deleted')),",
			"metadata jsonb NOT NULL DEFAULT '{}'::jsonb,",
			"payload jsonb NOT NULL,",
			"created_at timestamptz NOT NULL DEFAULT now(),",
			"updated_at timestamptz NOT NULL DEFAULT now(),",
			"PRIMARY KEY (tenant_id, human_identity_id)",
			")",
		}, " "),
		"CREATE INDEX IF NOT EXISTS human_identities_tenant_status_idx ON human_identities (tenant_id, status)",
		"CREATE INDEX IF NOT EXISTS human_identities_subject_idx ON human_identities (tenant_id, subject)",
		"CREATE INDEX IF NOT EXISTS human_identities_email_idx ON human_identities (tenant_id, email)",
	}
}

func postgresHumanIdentityImportRunIndexSQL() []string {
	return []string{
		"CREATE INDEX IF NOT EXISTS human_identities_import_run_idx ON human_identities (tenant_id, (metadata->>'import_run_id'))",
		"CREATE INDEX IF NOT EXISTS human_identities_deactivated_import_run_idx ON human_identities (tenant_id, (metadata->>'deactivated_by_import_run_id'))",
	}
}

func postgresHumanIdentitySourceIndexSQL() []string {
	return []string{
		"CREATE INDEX IF NOT EXISTS human_identities_source_idx ON human_identities (tenant_id, source, human_identity_id)",
	}
}

func postgresHumanIdentitySourceStateSQL() []string {
	return []string{
		strings.Join([]string{
			"CREATE TABLE IF NOT EXISTS human_identity_source_states (",
			"tenant_id text NOT NULL,",
			"source text NOT NULL,",
			"status text NOT NULL CHECK (status IN ('success', 'error', 'unknown')),",
			"last_import_run_id text,",
			"checkpoint text,",
			"last_success_at timestamptz,",
			"last_error_at timestamptz,",
			"last_error text,",
			"requested integer NOT NULL DEFAULT 0 CHECK (requested >= 0),",
			"upserted integer NOT NULL DEFAULT 0 CHECK (upserted >= 0),",
			"deactivated integer NOT NULL DEFAULT 0 CHECK (deactivated >= 0),",
			"active_count integer NOT NULL DEFAULT 0 CHECK (active_count >= 0),",
			"payload jsonb NOT NULL,",
			"updated_at timestamptz NOT NULL DEFAULT now(),",
			"PRIMARY KEY (tenant_id, source)",
			")",
		}, " "),
		"CREATE INDEX IF NOT EXISTS human_identity_source_states_status_idx ON human_identity_source_states (tenant_id, status, updated_at)",
	}
}

func postgresHumanIdentitySourcePolicySQL() []string {
	return []string{
		strings.Join([]string{
			"CREATE TABLE IF NOT EXISTS human_identity_source_policies (",
			"tenant_id text NOT NULL,",
			"source text NOT NULL,",
			"connector_type text NOT NULL CHECK (connector_type IN ('generic', 'scim', 'oidc', 'hris', 'csv', 'manual')),",
			"enabled boolean NOT NULL DEFAULT true,",
			"reconcile_missing boolean NOT NULL DEFAULT false,",
			"expected_interval_seconds integer NOT NULL DEFAULT 0 CHECK (expected_interval_seconds >= 0),",
			"stale_after_seconds integer NOT NULL DEFAULT 0 CHECK (stale_after_seconds >= 0),",
			"metadata jsonb NOT NULL DEFAULT '{}'::jsonb,",
			"payload jsonb NOT NULL,",
			"updated_at timestamptz NOT NULL DEFAULT now(),",
			"PRIMARY KEY (tenant_id, source)",
			")",
		}, " "),
		"CREATE INDEX IF NOT EXISTS human_identity_source_policies_enabled_idx ON human_identity_source_policies (tenant_id, enabled, source)",
	}
}

func buildPostgresHumanIdentityDirectoryUpsertStatement(user model.HumanIdentity, now time.Time) (postgresExportTaskQueueStatement, error) {
	normalized, err := humanidentity.NormalizeHumanIdentity(user, user.TenantID, now)
	if err != nil {
		return postgresExportTaskQueueStatement{}, err
	}
	metadata, err := json.Marshal(normalized.Metadata)
	if err != nil {
		return postgresExportTaskQueueStatement{}, fmt.Errorf("marshal human identity metadata: %w", err)
	}
	payload, err := json.Marshal(normalized)
	if err != nil {
		return postgresExportTaskQueueStatement{}, fmt.Errorf("marshal human identity payload: %w", err)
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	return postgresExportTaskQueueStatement{
		SQL: strings.Join([]string{
			"INSERT INTO human_identities (tenant_id, human_identity_id, subject, email, display_name, source, department, last_seen_at, expires_at, status, metadata, payload, created_at, updated_at)",
			"VALUES ($1, $2, $3, $4, $5, $6, $7, $8::timestamptz, $9::timestamptz, $10, $11::jsonb, $12::jsonb, $13, $13)",
			"ON CONFLICT (tenant_id, human_identity_id) DO UPDATE SET subject = EXCLUDED.subject, email = EXCLUDED.email, display_name = EXCLUDED.display_name, source = EXCLUDED.source, department = EXCLUDED.department, last_seen_at = EXCLUDED.last_seen_at, expires_at = EXCLUDED.expires_at, status = EXCLUDED.status, metadata = EXCLUDED.metadata, payload = EXCLUDED.payload, updated_at = EXCLUDED.updated_at",
		}, " "),
		Args: []any{
			normalized.TenantID,
			normalized.ID,
			normalized.Subject,
			nullableStringArg(normalized.Email),
			nullableStringArg(normalized.DisplayName),
			normalized.Source,
			nullableStringArg(normalized.Department),
			nullableTimeStringArg(normalized.LastSeenAt),
			nullableTimeStringArg(normalized.ExpiresAt),
			normalized.Status,
			string(metadata),
			string(payload),
			now.UTC(),
		},
	}, nil
}

func buildPostgresHumanIdentityDirectoryListStatement(tenantID string, options ...humanidentity.HumanIdentityDirectoryListOptions) (postgresExportTaskQueueStatement, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return postgresExportTaskQueueStatement{}, fmt.Errorf("tenant_id is required")
	}
	option := humanidentity.NormalizeHumanIdentityDirectoryListOptions(options...)
	if option.Status != "" && !humanidentity.HumanIdentityStatusAllowed(option.Status) {
		return postgresExportTaskQueueStatement{}, fmt.Errorf("unsupported human identity status %q", option.Status)
	}
	args := []any{tenantID}
	conditions := []string{"tenant_id = $1"}
	if option.Source != "" {
		args = append(args, option.Source)
		conditions = append(conditions, fmt.Sprintf("source = $%d", len(args)))
	}
	if option.Status != "" {
		args = append(args, option.Status)
		conditions = append(conditions, fmt.Sprintf("status = $%d", len(args)))
	}
	if option.Subject != "" {
		args = append(args, option.Subject)
		conditions = append(conditions, fmt.Sprintf("subject = $%d", len(args)))
	}
	if option.Email != "" {
		args = append(args, option.Email)
		conditions = append(conditions, fmt.Sprintf("email = $%d", len(args)))
	}
	if option.ImportRunID != "" {
		args = append(args, option.ImportRunID)
		conditions = append(conditions, fmt.Sprintf("(metadata->>'import_run_id' = $%d OR metadata->>'deactivated_by_import_run_id' = $%d)", len(args), len(args)))
	}
	if option.AfterID != "" {
		args = append(args, option.AfterID)
		conditions = append(conditions, fmt.Sprintf("human_identity_id > $%d", len(args)))
	}
	sqlText := "SELECT payload FROM human_identities WHERE " + strings.Join(conditions, " AND ") + " ORDER BY human_identity_id ASC"
	if option.Limit > 0 {
		args = append(args, option.Limit)
		sqlText += fmt.Sprintf(" LIMIT $%d", len(args))
	}
	return postgresExportTaskQueueStatement{
		SQL:  sqlText,
		Args: args,
	}, nil
}

func buildPostgresHumanIdentityDirectoryStatsStatement(tenantID string, now time.Time) (postgresExportTaskQueueStatement, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return postgresExportTaskQueueStatement{}, fmt.Errorf("tenant_id is required")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	return postgresExportTaskQueueStatement{
		SQL: strings.Join([]string{
			"SELECT count(*) AS total,",
			"count(*) FILTER (WHERE status = 'active' AND (expires_at IS NULL OR expires_at > $2::timestamptz)) AS active",
			"FROM human_identities",
			"WHERE tenant_id = $1",
		}, " "),
		Args: []any{tenantID, now.UTC()},
	}, nil
}

func buildPostgresHumanIdentitySourceListStatement(tenantID string, now time.Time) (postgresExportTaskQueueStatement, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return postgresExportTaskQueueStatement{}, fmt.Errorf("tenant_id is required")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	return postgresExportTaskQueueStatement{
		SQL: strings.Join([]string{
			"WITH source_rows AS (",
			"SELECT source, status, expires_at,",
			"GREATEST(COALESCE(NULLIF(metadata->>'imported_at', ''), ''), COALESCE(NULLIF(metadata->>'deactivated_at', ''), '')) AS observed_at,",
			"CASE WHEN COALESCE(NULLIF(metadata->>'deactivated_at', ''), '') >= COALESCE(NULLIF(metadata->>'imported_at', ''), '') THEN metadata->>'deactivated_by_import_run_id' ELSE metadata->>'import_run_id' END AS import_run_id",
			"FROM human_identities",
			"WHERE tenant_id = $1",
			")",
			"SELECT source, COALESCE(max(observed_at), ''),",
			"COALESCE((array_agg(import_run_id ORDER BY observed_at DESC, import_run_id DESC) FILTER (WHERE import_run_id IS NOT NULL AND import_run_id <> ''))[1], ''),",
			"count(*) AS total,",
			"count(*) FILTER (WHERE status = 'active' AND (expires_at IS NULL OR expires_at > $2::timestamptz)) AS active,",
			"count(*) FILTER (WHERE status = 'suspended') AS suspended,",
			"count(*) FILTER (WHERE status = 'deleted') AS deleted,",
			"count(*) FILTER (WHERE status = 'active' AND expires_at IS NOT NULL AND expires_at <= $2::timestamptz) AS expired",
			"FROM source_rows",
			"GROUP BY source",
			"ORDER BY source ASC",
		}, " "),
		Args: []any{tenantID, now.UTC()},
	}, nil
}

func buildPostgresHumanIdentitySourceStateUpsertStatement(state humanidentity.HumanIdentitySourceState) (postgresExportTaskQueueStatement, error) {
	normalized, err := humanidentity.NormalizeHumanIdentitySourceState(state)
	if err != nil {
		return postgresExportTaskQueueStatement{}, err
	}
	payload, err := json.Marshal(normalized)
	if err != nil {
		return postgresExportTaskQueueStatement{}, fmt.Errorf("marshal human identity source state payload: %w", err)
	}
	return postgresExportTaskQueueStatement{
		SQL: strings.Join([]string{
			"INSERT INTO human_identity_source_states (tenant_id, source, status, last_import_run_id, checkpoint, last_success_at, last_error_at, last_error, requested, upserted, deactivated, active_count, payload, updated_at)",
			"VALUES ($1, $2, $3, $4, $5, $6::timestamptz, $7::timestamptz, $8, $9, $10, $11, $12, $13::jsonb, $14::timestamptz)",
			"ON CONFLICT (tenant_id, source) DO UPDATE SET status = EXCLUDED.status, last_import_run_id = EXCLUDED.last_import_run_id, checkpoint = EXCLUDED.checkpoint, last_success_at = EXCLUDED.last_success_at, last_error_at = EXCLUDED.last_error_at, last_error = EXCLUDED.last_error, requested = EXCLUDED.requested, upserted = EXCLUDED.upserted, deactivated = EXCLUDED.deactivated, active_count = EXCLUDED.active_count, payload = EXCLUDED.payload, updated_at = EXCLUDED.updated_at",
		}, " "),
		Args: []any{
			normalized.TenantID,
			normalized.Source,
			normalized.Status,
			nullableTrimmedStringArg(normalized.LastImportRunID),
			nullableTrimmedStringArg(normalized.Checkpoint),
			nullableTrimmedStringArg(normalized.LastSuccessAt),
			nullableTrimmedStringArg(normalized.LastErrorAt),
			nullableTrimmedStringArg(normalized.LastError),
			normalized.Requested,
			normalized.Upserted,
			normalized.Deactivated,
			normalized.ActiveCount,
			string(payload),
			normalized.UpdatedAt,
		},
	}, nil
}

func buildPostgresHumanIdentitySourceStateListStatement(tenantID string) (postgresExportTaskQueueStatement, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return postgresExportTaskQueueStatement{}, fmt.Errorf("tenant_id is required")
	}
	return postgresExportTaskQueueStatement{
		SQL:  "SELECT payload FROM human_identity_source_states WHERE tenant_id = $1 ORDER BY source ASC",
		Args: []any{tenantID},
	}, nil
}

func buildPostgresHumanIdentitySourcePolicyUpsertStatement(policy humanidentity.HumanIdentitySourcePolicy) (postgresExportTaskQueueStatement, error) {
	normalized, err := humanidentity.NormalizeHumanIdentitySourcePolicy(policy)
	if err != nil {
		return postgresExportTaskQueueStatement{}, err
	}
	metadata, err := json.Marshal(normalized.Metadata)
	if err != nil {
		return postgresExportTaskQueueStatement{}, fmt.Errorf("marshal human identity source policy metadata: %w", err)
	}
	payload, err := json.Marshal(normalized)
	if err != nil {
		return postgresExportTaskQueueStatement{}, fmt.Errorf("marshal human identity source policy payload: %w", err)
	}
	return postgresExportTaskQueueStatement{
		SQL: strings.Join([]string{
			"INSERT INTO human_identity_source_policies (tenant_id, source, connector_type, enabled, reconcile_missing, expected_interval_seconds, stale_after_seconds, metadata, payload, updated_at)",
			"VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, $9::jsonb, $10::timestamptz)",
			"ON CONFLICT (tenant_id, source) DO UPDATE SET connector_type = EXCLUDED.connector_type, enabled = EXCLUDED.enabled, reconcile_missing = EXCLUDED.reconcile_missing, expected_interval_seconds = EXCLUDED.expected_interval_seconds, stale_after_seconds = EXCLUDED.stale_after_seconds, metadata = EXCLUDED.metadata, payload = EXCLUDED.payload, updated_at = EXCLUDED.updated_at",
		}, " "),
		Args: []any{
			normalized.TenantID,
			normalized.Source,
			normalized.ConnectorType,
			normalized.Enabled,
			normalized.ReconcileMissing,
			normalized.ExpectedIntervalSeconds,
			normalized.StaleAfterSeconds,
			string(metadata),
			string(payload),
			normalized.UpdatedAt,
		},
	}, nil
}

func buildPostgresHumanIdentitySourcePolicyListStatement(tenantID string) (postgresExportTaskQueueStatement, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return postgresExportTaskQueueStatement{}, fmt.Errorf("tenant_id is required")
	}
	return postgresExportTaskQueueStatement{
		SQL:  "SELECT payload FROM human_identity_source_policies WHERE tenant_id = $1 ORDER BY source ASC",
		Args: []any{tenantID},
	}, nil
}

func nullableTrimmedStringArg(value string) any {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	return value
}

func buildPostgresHumanIdentityImportRunListStatement(tenantID string, options humanidentity.HumanIdentityImportRunListOptions) (postgresExportTaskQueueStatement, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return postgresExportTaskQueueStatement{}, fmt.Errorf("tenant_id is required")
	}
	options.Source = strings.TrimSpace(options.Source)
	if options.Limit <= 0 {
		options.Limit = 25
	}
	if options.Limit > 1000 {
		options.Limit = 1000
	}
	args := []any{tenantID}
	importSourceFilter := ""
	deactivatedSourceFilter := ""
	if options.Source != "" {
		args = append(args, options.Source)
		importSourceFilter = fmt.Sprintf(" AND metadata->>'import_source' = $%d", len(args))
		deactivatedSourceFilter = fmt.Sprintf(" AND metadata->>'deactivated_by_import_source' = $%d", len(args))
	}
	args = append(args, options.Limit)
	limitPlaceholder := fmt.Sprintf("$%d", len(args))
	return postgresExportTaskQueueStatement{
		SQL: strings.Join([]string{
			"WITH import_events AS (",
			"SELECT metadata->>'import_run_id' AS import_run_id, metadata->>'import_source' AS source, metadata->>'import_checkpoint' AS checkpoint, metadata->>'imported_at' AS observed_at, 1 AS upserted, 0 AS deactivated, CASE WHEN status = 'active' THEN 1 ELSE 0 END AS active, CASE WHEN status = 'deleted' THEN 1 ELSE 0 END AS deleted",
			"FROM human_identities",
			"WHERE tenant_id = $1 AND metadata ? 'import_run_id'" + importSourceFilter,
			"UNION ALL",
			"SELECT metadata->>'deactivated_by_import_run_id' AS import_run_id, metadata->>'deactivated_by_import_source' AS source, metadata->>'deactivated_by_import_checkpoint' AS checkpoint, metadata->>'deactivated_at' AS observed_at, 0 AS upserted, 1 AS deactivated, 0 AS active, CASE WHEN status = 'deleted' THEN 1 ELSE 0 END AS deleted",
			"FROM human_identities",
			"WHERE tenant_id = $1 AND metadata ? 'deactivated_by_import_run_id'" + deactivatedSourceFilter,
			")",
			"SELECT import_run_id, COALESCE((array_agg(source ORDER BY observed_at DESC, source DESC) FILTER (WHERE source IS NOT NULL AND source <> ''))[1], ''), COALESCE((array_agg(checkpoint ORDER BY observed_at DESC, checkpoint DESC) FILTER (WHERE checkpoint IS NOT NULL AND checkpoint <> ''))[1], ''), COALESCE(max(observed_at), ''), COALESCE(sum(upserted), 0), COALESCE(sum(deactivated), 0), COALESCE(sum(active), 0), COALESCE(sum(deleted), 0)",
			"FROM import_events",
			"WHERE import_run_id IS NOT NULL AND import_run_id <> ''",
			"GROUP BY import_run_id",
			"ORDER BY COALESCE(max(observed_at), '') DESC, import_run_id DESC",
			"LIMIT " + limitPlaceholder,
		}, " "),
		Args: args,
	}, nil
}

func buildPostgresHumanIdentityImportRunDetailStatement(tenantID, importRunID string) (postgresExportTaskQueueStatement, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return postgresExportTaskQueueStatement{}, fmt.Errorf("tenant_id is required")
	}
	importRunID, err := humanidentity.CleanHumanIdentityImportRunID(importRunID)
	if err != nil {
		return postgresExportTaskQueueStatement{}, err
	}
	return postgresExportTaskQueueStatement{
		SQL: strings.Join([]string{
			"SELECT payload",
			"FROM human_identities",
			"WHERE tenant_id = $1 AND (metadata->>'import_run_id' = $2 OR metadata->>'deactivated_by_import_run_id' = $2)",
			"ORDER BY human_identity_id ASC",
		}, " "),
		Args: []any{tenantID, importRunID},
	}, nil
}

// RiskIdentitySnapshot is used only by the startup migration of untyped risk IDs.
func (store postgresHumanIdentityDirectoryStore) RiskIdentitySnapshot(ctx context.Context) ([]model.HumanIdentity, error) {
	if store.DB == nil {
		return nil, fmt.Errorf("identity directory database is unavailable")
	}
	ctx, cancel := context.WithTimeout(ctx, postgresHumanIdentityDirectoryTimeout)
	defer cancel()
	rows, err := store.DB.QueryContext(ctx, "SELECT payload FROM human_identities ORDER BY tenant_id, human_identity_id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	people := []model.HumanIdentity{}
	for rows.Next() {
		var payload []byte
		if err := rows.Scan(&payload); err != nil {
			return nil, err
		}
		var person model.HumanIdentity
		if err := json.Unmarshal(payload, &person); err != nil {
			return nil, err
		}
		people = append(people, person)
	}
	return people, rows.Err()
}
