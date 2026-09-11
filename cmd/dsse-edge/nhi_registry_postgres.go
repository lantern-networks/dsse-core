package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	nhi "github.com/lantern-networks/dsse-core/nhi"

	"github.com/lantern-networks/dsse-core/model"
)

const postgresNonHumanIdentityTimeout = 15 * time.Second

type postgresNonHumanIdentityStore struct {
	DB *sql.DB
	// gen is an in-memory monotonic config counter bumped on each Upsert. The durable rows live in postgres,
	// but ConfigGeneration only feeds the config-bundle aggregate (a change signal to make Edges re-pull); an
	// in-memory counter that resets on restart is fine there because the bundle's epoch handles CP restarts.
	// Pointer so the value-receiver store copies share the same counter.
	gen *uint64
}

var _ nhi.RuntimeStore = postgresNonHumanIdentityStore{}

func (store postgresNonHumanIdentityStore) Upsert(ctx context.Context, identity model.NonHumanIdentity, tenantID string, now time.Time) (model.NonHumanIdentity, error) {
	if store.DB == nil {
		return model.NonHumanIdentity{}, fmt.Errorf("postgres non-human identity db is not configured")
	}
	normalized, err := nhi.Normalize(identity, tenantID, now)
	if err != nil {
		return model.NonHumanIdentity{}, err
	}
	statement, err := buildPostgresNonHumanIdentityUpsertStatement(normalized, now)
	if err != nil {
		return model.NonHumanIdentity{}, err
	}
	if _, err := store.DB.ExecContext(ctx, statement.SQL, statement.Args...); err != nil {
		return model.NonHumanIdentity{}, fmt.Errorf("upsert non-human identity: %w", err)
	}
	if store.gen != nil {
		atomic.AddUint64(store.gen, 1)
	}
	return normalized, nil
}

// ConfigGeneration returns the monotonic NHI-registry config version (bumped on each Upsert). Kept in memory
// (not derived from postgres) as a change signal for the config-bundle aggregate; see the gen field comment.
func (store postgresNonHumanIdentityStore) ConfigGeneration() uint64 {
	if store.gen == nil {
		return 0
	}
	return atomic.LoadUint64(store.gen)
}

func (store postgresNonHumanIdentityStore) List(ctx context.Context, tenantID string) ([]model.NonHumanIdentity, error) {
	if store.DB == nil {
		return nil, fmt.Errorf("postgres non-human identity db is not configured")
	}
	statement, err := buildPostgresNonHumanIdentityListStatement(tenantID)
	if err != nil {
		return nil, err
	}
	rows, err := store.DB.QueryContext(ctx, statement.SQL, statement.Args...)
	if err != nil {
		return nil, fmt.Errorf("list non-human identities: %w", err)
	}
	defer rows.Close()
	identities := []model.NonHumanIdentity{}
	for rows.Next() {
		var payload []byte
		if err := rows.Scan(&payload); err != nil {
			return nil, fmt.Errorf("scan non-human identity: %w", err)
		}
		var identity model.NonHumanIdentity
		if err := json.Unmarshal(payload, &identity); err != nil {
			return nil, fmt.Errorf("decode non-human identity: %w", err)
		}
		identities = append(identities, identity)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate non-human identities: %w", err)
	}
	return identities, nil
}

func (store postgresNonHumanIdentityStore) CountActive(ctx context.Context, tenantID string, now time.Time) (int, error) {
	if store.DB == nil {
		return 0, fmt.Errorf("postgres non-human identity db is not configured")
	}
	statement, err := buildPostgresNonHumanIdentityCountActiveStatement(tenantID, now)
	if err != nil {
		return 0, err
	}
	var count int
	if err := store.DB.QueryRowContext(ctx, statement.SQL, statement.Args...).Scan(&count); err != nil {
		return 0, fmt.Errorf("count active non-human identities: %w", err)
	}
	return count, nil
}

func (store postgresNonHumanIdentityStore) MarkUsed(ctx context.Context, tenantID, actorNHIID string, now time.Time) (bool, error) {
	if store.DB == nil {
		return false, fmt.Errorf("postgres non-human identity db is not configured")
	}
	statement, err := buildPostgresNonHumanIdentityMarkUsedStatement(tenantID, actorNHIID, now)
	if err != nil {
		return false, err
	}
	result, err := store.DB.ExecContext(ctx, statement.SQL, statement.Args...)
	if err != nil {
		return false, fmt.Errorf("mark non-human identity used: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("mark non-human identity used rows affected: %w", err)
	}
	return rows > 0, nil
}

func postgresNonHumanIdentitySchemaSQL() []string {
	return []string{
		strings.Join([]string{
			"CREATE TABLE IF NOT EXISTS non_human_identities (",
			"tenant_id text NOT NULL,",
			"nhi_id text NOT NULL,",
			"name text NOT NULL,",
			"nhi_type text NOT NULL,",
			"owner_user_id text NOT NULL,",
			"trust_domain text,",
			"issuer text,",
			"subject text,",
			"credential_type text,",
			"allowed_application_ids jsonb NOT NULL DEFAULT '[]'::jsonb,",
			"allowed_scopes jsonb NOT NULL DEFAULT '[]'::jsonb,",
			"last_used_at timestamptz,",
			"expires_at timestamptz,",
			"status text NOT NULL CHECK (status IN ('active', 'suspended', 'expired', 'revoked')),",
			"metadata jsonb NOT NULL DEFAULT '{}'::jsonb,",
			"payload jsonb NOT NULL,",
			"created_at timestamptz NOT NULL DEFAULT now(),",
			"updated_at timestamptz NOT NULL DEFAULT now(),",
			"PRIMARY KEY (tenant_id, nhi_id)",
			")",
		}, " "),
		"CREATE INDEX IF NOT EXISTS non_human_identities_tenant_status_idx ON non_human_identities (tenant_id, status)",
		"CREATE INDEX IF NOT EXISTS non_human_identities_owner_idx ON non_human_identities (tenant_id, owner_user_id)",
		"CREATE INDEX IF NOT EXISTS non_human_identities_subject_idx ON non_human_identities (tenant_id, issuer, subject)",
	}
}

func buildPostgresNonHumanIdentityUpsertStatement(identity model.NonHumanIdentity, now time.Time) (postgresExportTaskQueueStatement, error) {
	normalized, err := nhi.Normalize(identity, identity.TenantID, now)
	if err != nil {
		return postgresExportTaskQueueStatement{}, err
	}
	allowedApplications, err := json.Marshal(normalized.AllowedApplicationIDs)
	if err != nil {
		return postgresExportTaskQueueStatement{}, fmt.Errorf("marshal non-human identity applications: %w", err)
	}
	allowedScopes, err := json.Marshal(normalized.AllowedScopes)
	if err != nil {
		return postgresExportTaskQueueStatement{}, fmt.Errorf("marshal non-human identity scopes: %w", err)
	}
	metadata, err := json.Marshal(normalized.Metadata)
	if err != nil {
		return postgresExportTaskQueueStatement{}, fmt.Errorf("marshal non-human identity metadata: %w", err)
	}
	payload, err := json.Marshal(normalized)
	if err != nil {
		return postgresExportTaskQueueStatement{}, fmt.Errorf("marshal non-human identity payload: %w", err)
	}
	return postgresExportTaskQueueStatement{
		SQL: strings.Join([]string{
			"INSERT INTO non_human_identities (tenant_id, nhi_id, name, nhi_type, owner_user_id, trust_domain, issuer, subject, credential_type, allowed_application_ids, allowed_scopes, last_used_at, expires_at, status, metadata, payload, created_at, updated_at)",
			"VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::jsonb, $11::jsonb, $12::timestamptz, $13::timestamptz, $14, $15::jsonb, $16::jsonb, $17, $17)",
			"ON CONFLICT (tenant_id, nhi_id) DO UPDATE SET name = EXCLUDED.name, nhi_type = EXCLUDED.nhi_type, owner_user_id = EXCLUDED.owner_user_id, trust_domain = EXCLUDED.trust_domain, issuer = EXCLUDED.issuer, subject = EXCLUDED.subject, credential_type = EXCLUDED.credential_type, allowed_application_ids = EXCLUDED.allowed_application_ids, allowed_scopes = EXCLUDED.allowed_scopes, last_used_at = EXCLUDED.last_used_at, expires_at = EXCLUDED.expires_at, status = EXCLUDED.status, metadata = EXCLUDED.metadata, payload = EXCLUDED.payload, updated_at = EXCLUDED.updated_at",
		}, " "),
		Args: []any{
			normalized.TenantID,
			normalized.ID,
			normalized.Name,
			normalized.NHIType,
			normalized.OwnerUserID,
			nullableStringArg(normalized.TrustDomain),
			nullableStringArg(normalized.Issuer),
			nullableStringArg(normalized.Subject),
			nullableStringArg(normalized.CredentialType),
			string(allowedApplications),
			string(allowedScopes),
			nullableTimeStringArg(normalized.LastUsedAt),
			nullableTimeStringArg(normalized.ExpiresAt),
			normalized.Status,
			string(metadata),
			string(payload),
			now.UTC(),
		},
	}, nil
}

func buildPostgresNonHumanIdentityListStatement(tenantID string) (postgresExportTaskQueueStatement, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return postgresExportTaskQueueStatement{}, fmt.Errorf("tenant_id is required")
	}
	return postgresExportTaskQueueStatement{
		SQL:  "SELECT payload FROM non_human_identities WHERE tenant_id = $1 ORDER BY nhi_id ASC",
		Args: []any{tenantID},
	}, nil
}

func buildPostgresNonHumanIdentityCountActiveStatement(tenantID string, now time.Time) (postgresExportTaskQueueStatement, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return postgresExportTaskQueueStatement{}, fmt.Errorf("tenant_id is required")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	return postgresExportTaskQueueStatement{
		SQL: strings.Join([]string{
			"SELECT count(*)",
			"FROM non_human_identities",
			"WHERE tenant_id = $1 AND status = 'active' AND (expires_at IS NULL OR expires_at > $2::timestamptz)",
		}, " "),
		Args: []any{tenantID, now.UTC()},
	}, nil
}

func buildPostgresNonHumanIdentityMarkUsedStatement(tenantID, actorNHIID string, now time.Time) (postgresExportTaskQueueStatement, error) {
	tenantID = strings.TrimSpace(tenantID)
	actorNHIID = strings.TrimSpace(actorNHIID)
	if tenantID == "" {
		return postgresExportTaskQueueStatement{}, fmt.Errorf("tenant_id is required")
	}
	if actorNHIID == "" {
		return postgresExportTaskQueueStatement{}, fmt.Errorf("nhi_id is required")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	lastUsedAt := now.UTC()
	lastUsedAtText := lastUsedAt.Format(time.RFC3339)
	return postgresExportTaskQueueStatement{
		SQL: strings.Join([]string{
			"UPDATE non_human_identities",
			"SET last_used_at = $3::timestamptz,",
			"payload = jsonb_set(payload, '{last_used_at}', to_jsonb($4::text), true),",
			"updated_at = $3::timestamptz",
			"WHERE tenant_id = $1 AND nhi_id = $2",
		}, " "),
		Args: []any{tenantID, actorNHIID, lastUsedAt, lastUsedAtText},
	}, nil
}

func nullableStringArg(value *string) any {
	if value == nil || strings.TrimSpace(*value) == "" {
		return nil
	}
	return strings.TrimSpace(*value)
}

func nullableTimeStringArg(value *string) any {
	if value == nil || strings.TrimSpace(*value) == "" {
		return nil
	}
	parsed, err := time.Parse(time.RFC3339, strings.TrimSpace(*value))
	if err != nil {
		return nil
	}
	return parsed.UTC()
}
