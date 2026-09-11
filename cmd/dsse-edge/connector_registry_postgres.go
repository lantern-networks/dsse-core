package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/model"
)

const postgresConnectorRegistryTimeout = 15 * time.Second

type postgresConnectorRegistryStore struct {
	DB *sql.DB
}

var _ connectorRegistryStore = postgresConnectorRegistryStore{}

func (store postgresConnectorRegistryStore) Register(conn model.ConnectorRegistration, now time.Time) (model.ConnectorRegistration, error) {
	if store.DB == nil {
		return model.ConnectorRegistration{}, fmt.Errorf("postgres connector registry db is not configured")
	}
	normalized, err := normalizeConnectorRegistration(conn, now)
	if err != nil {
		return model.ConnectorRegistration{}, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), postgresConnectorRegistryTimeout)
	defer cancel()
	tx, err := store.DB.BeginTx(ctx, nil)
	if err != nil {
		return model.ConnectorRegistration{}, fmt.Errorf("begin connector registration: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()
	if existing, ok, err := queryPostgresConnectorRegistryByID(ctx, tx, normalized.ID, true); err != nil {
		return model.ConnectorRegistration{}, err
	} else if ok {
		if existing.TenantID != normalized.TenantID {
			return model.ConnectorRegistration{}, fmt.Errorf("connector %s is already registered for tenant %s", normalized.ID, existing.TenantID)
		}
		preserveConnectorRuntimeCredentialMetadata(existing.Metadata, normalized.Metadata)
		preserveConnectorRegistrationLifecycle(existing, &normalized)
	}
	statement, err := buildPostgresConnectorRegistryUpsertStatement(normalized, now)
	if err != nil {
		return model.ConnectorRegistration{}, err
	}
	result, err := tx.ExecContext(ctx, statement.SQL, statement.Args...)
	if err != nil {
		return model.ConnectorRegistration{}, fmt.Errorf("upsert connector registration: %w", err)
	}
	if rows, err := result.RowsAffected(); err == nil && rows == 0 {
		return model.ConnectorRegistration{}, fmt.Errorf("connector %s is already registered for another tenant", normalized.ID)
	}
	if err := tx.Commit(); err != nil {
		return model.ConnectorRegistration{}, fmt.Errorf("commit connector registration: %w", err)
	}
	committed = true
	return normalized, nil
}

func (store postgresConnectorRegistryStore) Heartbeat(heartbeat model.ConnectorHeartbeat, now time.Time) (model.ConnectorRegistration, error) {
	return store.updateByID(heartbeat.ID, now, func(conn *model.ConnectorRegistration) error {
		updated, err := connectorRegistrationWithHeartbeat(*conn, heartbeat, now)
		if err != nil {
			return err
		}
		*conn = updated
		return nil
	})
}

func (store postgresConnectorRegistryStore) RotateRuntimeSecretHashWithMetadata(id, hash string, rotatedAt time.Time, rotatedBy string) (model.ConnectorRegistration, bool, error) {
	return store.rotateRuntimeSecretHashWithMetadata("", id, hash, rotatedAt, rotatedBy)
}

func (store postgresConnectorRegistryStore) RotateRuntimeSecretHashForTenantWithMetadata(tenantID, id, hash string, rotatedAt time.Time, rotatedBy string) (model.ConnectorRegistration, bool, error) {
	return store.rotateRuntimeSecretHashWithMetadata(strings.TrimSpace(tenantID), id, hash, rotatedAt, rotatedBy)
}

func (store postgresConnectorRegistryStore) rotateRuntimeSecretHashWithMetadata(tenantID, id, hash string, rotatedAt time.Time, rotatedBy string) (model.ConnectorRegistration, bool, error) {
	update := store.updateByIDOptional
	if tenantID != "" {
		update = func(id string, now time.Time, mutate func(*model.ConnectorRegistration) error) (model.ConnectorRegistration, bool, error) {
			return store.updateByIDForTenantOptional(tenantID, id, now, mutate)
		}
	}
	conn, ok, err := update(id, time.Now().UTC(), func(conn *model.ConnectorRegistration) error {
		if !connectorRuntimeSecretHashValid(hash) {
			return fmt.Errorf("connector metadata.runtime_secret_hash must be sha256:<64 lowercase hex>")
		}
		if conn.Metadata == nil {
			conn.Metadata = map[string]any{}
		}
		conn.Metadata["runtime_secret_hash"] = strings.TrimSpace(hash)
		if !rotatedAt.IsZero() {
			conn.Metadata["runtime_secret_rotated_at"] = rotatedAt.UTC().Format(time.RFC3339)
		}
		if strings.TrimSpace(rotatedBy) != "" {
			conn.Metadata["runtime_secret_rotated_by"] = strings.TrimSpace(rotatedBy)
		}
		return nil
	})
	return conn, ok, err
}

func (store postgresConnectorRegistryStore) Get(id string) (model.ConnectorRegistration, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), postgresConnectorRegistryTimeout)
	defer cancel()
	conn, ok, err := store.getByID(ctx, id, false)
	if err != nil {
		return model.ConnectorRegistration{}, false
	}
	return conn, ok
}

func (store postgresConnectorRegistryStore) GetByTenant(ctx context.Context, tenantID, id string) (model.ConnectorRegistration, bool, error) {
	if store.DB == nil {
		return model.ConnectorRegistration{}, false, fmt.Errorf("postgres connector registry db is not configured")
	}
	ctx, cancel := context.WithTimeout(ctx, postgresConnectorRegistryTimeout)
	defer cancel()
	return queryPostgresConnectorRegistryByIDForTenant(ctx, store.DB, tenantID, id, false)
}

func (store postgresConnectorRegistryStore) List() []model.ConnectorRegistration {
	if store.DB == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), postgresConnectorRegistryTimeout)
	defer cancel()
	statement := buildPostgresConnectorRegistryListStatement()
	rows, err := store.DB.QueryContext(ctx, statement.SQL, statement.Args...)
	if err != nil {
		return nil
	}
	defer rows.Close()
	connectors := []model.ConnectorRegistration{}
	for rows.Next() {
		var payload []byte
		if err := rows.Scan(&payload); err != nil {
			return nil
		}
		var conn model.ConnectorRegistration
		if err := json.Unmarshal(payload, &conn); err != nil {
			return nil
		}
		connectors = append(connectors, conn)
	}
	if err := rows.Err(); err != nil {
		return nil
	}
	return connectors
}

func (store postgresConnectorRegistryStore) ListByTenant(ctx context.Context, tenantID string) ([]model.ConnectorRegistration, error) {
	if store.DB == nil {
		return nil, fmt.Errorf("postgres connector registry db is not configured")
	}
	ctx, cancel := context.WithTimeout(ctx, postgresConnectorRegistryTimeout)
	defer cancel()
	statement, err := buildPostgresConnectorRegistryListByTenantStatement(tenantID)
	if err != nil {
		return nil, err
	}
	rows, err := store.DB.QueryContext(ctx, statement.SQL, statement.Args...)
	if err != nil {
		return nil, fmt.Errorf("list connector registrations by tenant: %w", err)
	}
	defer rows.Close()
	connectors := []model.ConnectorRegistration{}
	for rows.Next() {
		var payload []byte
		if err := rows.Scan(&payload); err != nil {
			return nil, fmt.Errorf("scan connector registration: %w", err)
		}
		var conn model.ConnectorRegistration
		if err := json.Unmarshal(payload, &conn); err != nil {
			return nil, fmt.Errorf("decode connector registration: %w", err)
		}
		connectors = append(connectors, conn)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list connector registrations by tenant: %w", err)
	}
	return connectors, nil
}

func (store postgresConnectorRegistryStore) updateByID(id string, now time.Time, mutate func(*model.ConnectorRegistration) error) (model.ConnectorRegistration, error) {
	conn, ok, err := store.updateByIDOptional(id, now, mutate)
	if err != nil {
		return model.ConnectorRegistration{}, err
	}
	if !ok {
		return model.ConnectorRegistration{}, fmt.Errorf("connector %s is not registered", strings.TrimSpace(id))
	}
	return conn, nil
}

func (store postgresConnectorRegistryStore) updateByIDOptional(id string, now time.Time, mutate func(*model.ConnectorRegistration) error) (model.ConnectorRegistration, bool, error) {
	return store.updateByIDOptionalWithLookup(id, now, mutate, func(ctx context.Context, tx *sql.Tx, id string) (model.ConnectorRegistration, bool, error) {
		return queryPostgresConnectorRegistryByID(ctx, tx, id, true)
	})
}

func (store postgresConnectorRegistryStore) updateByIDForTenantOptional(tenantID, id string, now time.Time, mutate func(*model.ConnectorRegistration) error) (model.ConnectorRegistration, bool, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return model.ConnectorRegistration{}, false, fmt.Errorf("connector tenant_id is required")
	}
	return store.updateByIDOptionalWithLookup(id, now, mutate, func(ctx context.Context, tx *sql.Tx, id string) (model.ConnectorRegistration, bool, error) {
		return queryPostgresConnectorRegistryByIDForTenant(ctx, tx, tenantID, id, true)
	})
}

func (store postgresConnectorRegistryStore) updateByIDOptionalWithLookup(id string, now time.Time, mutate func(*model.ConnectorRegistration) error, lookup func(context.Context, *sql.Tx, string) (model.ConnectorRegistration, bool, error)) (model.ConnectorRegistration, bool, error) {
	if store.DB == nil {
		return model.ConnectorRegistration{}, false, fmt.Errorf("postgres connector registry db is not configured")
	}
	ctx, cancel := context.WithTimeout(context.Background(), postgresConnectorRegistryTimeout)
	defer cancel()
	tx, err := store.DB.BeginTx(ctx, nil)
	if err != nil {
		return model.ConnectorRegistration{}, false, fmt.Errorf("begin connector registry update: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()
	conn, ok, err := lookup(ctx, tx, id)
	if err != nil || !ok {
		return model.ConnectorRegistration{}, ok, err
	}
	if err := mutate(&conn); err != nil {
		return model.ConnectorRegistration{}, false, err
	}
	statement, err := buildPostgresConnectorRegistryUpsertStatement(conn, now)
	if err != nil {
		return model.ConnectorRegistration{}, false, err
	}
	result, err := tx.ExecContext(ctx, statement.SQL, statement.Args...)
	if err != nil {
		return model.ConnectorRegistration{}, false, fmt.Errorf("update connector registration: %w", err)
	}
	if rows, err := result.RowsAffected(); err == nil && rows == 0 {
		return model.ConnectorRegistration{}, false, fmt.Errorf("connector %s update did not affect a row", strings.TrimSpace(id))
	}
	if err := tx.Commit(); err != nil {
		return model.ConnectorRegistration{}, false, fmt.Errorf("commit connector registry update: %w", err)
	}
	committed = true
	return conn, true, nil
}

func (store postgresConnectorRegistryStore) getByID(ctx context.Context, id string, forUpdate bool) (model.ConnectorRegistration, bool, error) {
	if store.DB == nil {
		return model.ConnectorRegistration{}, false, fmt.Errorf("postgres connector registry db is not configured")
	}
	return queryPostgresConnectorRegistryByID(ctx, store.DB, id, forUpdate)
}

type connectorRegistryQueryer interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

func queryPostgresConnectorRegistryByID(ctx context.Context, queryer connectorRegistryQueryer, id string, forUpdate bool) (model.ConnectorRegistration, bool, error) {
	statement, err := buildPostgresConnectorRegistryGetStatement(id, forUpdate)
	if err != nil {
		return model.ConnectorRegistration{}, false, err
	}
	return queryPostgresConnectorRegistryPayload(ctx, queryer, statement)
}

func queryPostgresConnectorRegistryByIDForTenant(ctx context.Context, queryer connectorRegistryQueryer, tenantID, id string, forUpdate bool) (model.ConnectorRegistration, bool, error) {
	statement, err := buildPostgresConnectorRegistryGetForTenantStatement(tenantID, id, forUpdate)
	if err != nil {
		return model.ConnectorRegistration{}, false, err
	}
	return queryPostgresConnectorRegistryPayload(ctx, queryer, statement)
}

func queryPostgresConnectorRegistryPayload(ctx context.Context, queryer connectorRegistryQueryer, statement postgresExportTaskQueueStatement) (model.ConnectorRegistration, bool, error) {
	var payload []byte
	if err := queryer.QueryRowContext(ctx, statement.SQL, statement.Args...).Scan(&payload); err != nil {
		if err == sql.ErrNoRows {
			return model.ConnectorRegistration{}, false, nil
		}
		return model.ConnectorRegistration{}, false, fmt.Errorf("get connector registration: %w", err)
	}
	var conn model.ConnectorRegistration
	if err := json.Unmarshal(payload, &conn); err != nil {
		return model.ConnectorRegistration{}, false, fmt.Errorf("decode connector registration: %w", err)
	}
	return conn, true, nil
}

func postgresConnectorRegistrySchemaSQL() []string {
	return []string{
		strings.Join([]string{
			"CREATE TABLE IF NOT EXISTS connector_registrations (",
			"connector_id text PRIMARY KEY,",
			"tenant_id text NOT NULL,",
			"connector_group_id text NOT NULL,",
			"name text NOT NULL,",
			"edge_region_id text NOT NULL,",
			"edge_cluster_id text NOT NULL,",
			"application_ids jsonb NOT NULL DEFAULT '[]'::jsonb,",
			"private_base_url text NOT NULL,",
			"status text NOT NULL CHECK (status IN ('registered', 'healthy', 'degraded', 'offline')),",
			"registered_at timestamptz NOT NULL,",
			"last_heartbeat_at timestamptz NOT NULL,",
			"metadata jsonb NOT NULL DEFAULT '{}'::jsonb,",
			"payload jsonb NOT NULL,",
			"created_at timestamptz NOT NULL DEFAULT now(),",
			"updated_at timestamptz NOT NULL DEFAULT now()",
			")",
		}, " "),
		"CREATE INDEX IF NOT EXISTS connector_registrations_tenant_status_idx ON connector_registrations (tenant_id, status)",
		"CREATE INDEX IF NOT EXISTS connector_registrations_group_idx ON connector_registrations (tenant_id, connector_group_id)",
	}
}

func buildPostgresConnectorRegistryUpsertStatement(conn model.ConnectorRegistration, now time.Time) (postgresExportTaskQueueStatement, error) {
	normalized, err := normalizeConnectorRegistrationForStorage(conn)
	if err != nil {
		return postgresExportTaskQueueStatement{}, err
	}
	applications, err := json.Marshal(normalized.ApplicationIDs)
	if err != nil {
		return postgresExportTaskQueueStatement{}, fmt.Errorf("marshal connector applications: %w", err)
	}
	metadata, err := json.Marshal(normalized.Metadata)
	if err != nil {
		return postgresExportTaskQueueStatement{}, fmt.Errorf("marshal connector metadata: %w", err)
	}
	payload, err := json.Marshal(normalized)
	if err != nil {
		return postgresExportTaskQueueStatement{}, fmt.Errorf("marshal connector payload: %w", err)
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	return postgresExportTaskQueueStatement{
		SQL: strings.Join([]string{
			"INSERT INTO connector_registrations (connector_id, tenant_id, connector_group_id, name, edge_region_id, edge_cluster_id, application_ids, private_base_url, status, registered_at, last_heartbeat_at, metadata, payload, created_at, updated_at)",
			"VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8, $9, $10::timestamptz, $11::timestamptz, $12::jsonb, $13::jsonb, $14, $14)",
			"ON CONFLICT (connector_id) DO UPDATE SET tenant_id = EXCLUDED.tenant_id, connector_group_id = EXCLUDED.connector_group_id, name = EXCLUDED.name, edge_region_id = EXCLUDED.edge_region_id, edge_cluster_id = EXCLUDED.edge_cluster_id, application_ids = EXCLUDED.application_ids, private_base_url = EXCLUDED.private_base_url, status = EXCLUDED.status, registered_at = EXCLUDED.registered_at, last_heartbeat_at = EXCLUDED.last_heartbeat_at, metadata = EXCLUDED.metadata, payload = EXCLUDED.payload, " +
				// ★★★ updated_at MOVES WHEN THE ROUTING-RELEVANT CONTENT DOES, NOT ON EVERY HEARTBEAT
				// (2026-08-26). This column is what the config-bundle generation is derived from, and a
				// connector re-registers on a timer: moving it every time made the fleet re-apply the whole
				// bundle every thirty seconds, and each re-apply undid a connector's local registration.
				//
				// The obvious alternative — hashing the class-1 fields — is WORSE, and was measured being
				// worse: the bundle generation is a SUM of monotonic terms, an Edge applies only a generation
				// GREATER than the one it holds, and a hash goes DOWN as readily as up. One decrease and the
				// fleet stops applying configuration for ever. So the term stays a clock; what changes is
				// that the clock only ticks when something an Edge would act on has actually changed.
				"updated_at = CASE WHEN connector_registrations.tenant_id IS DISTINCT FROM EXCLUDED.tenant_id " +
				"OR connector_registrations.connector_group_id IS DISTINCT FROM EXCLUDED.connector_group_id " +
				"OR connector_registrations.edge_region_id IS DISTINCT FROM EXCLUDED.edge_region_id " +
				"OR connector_registrations.edge_cluster_id IS DISTINCT FROM EXCLUDED.edge_cluster_id " +
				"OR connector_registrations.private_base_url IS DISTINCT FROM EXCLUDED.private_base_url " +
				"OR connector_registrations.application_ids IS DISTINCT FROM EXCLUDED.application_ids " +
				"THEN EXCLUDED.updated_at ELSE connector_registrations.updated_at END " +
				"WHERE connector_registrations.tenant_id = EXCLUDED.tenant_id",
		}, " "),
		Args: []any{
			normalized.ID,
			normalized.TenantID,
			normalized.ConnectorGroupID,
			normalized.Name,
			normalized.EdgeRegionID,
			normalized.EdgeClusterID,
			string(applications),
			normalized.PrivateBaseURL,
			normalized.Status,
			normalized.RegisteredAt,
			normalized.LastHeartbeatAt,
			string(metadata),
			string(payload),
			now.UTC(),
		},
	}, nil
}

func buildPostgresConnectorRegistryGetStatement(id string, forUpdate bool) (postgresExportTaskQueueStatement, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return postgresExportTaskQueueStatement{}, fmt.Errorf("connector id is required")
	}
	sqlText := "SELECT payload FROM connector_registrations WHERE connector_id = $1"
	if forUpdate {
		sqlText += " FOR UPDATE"
	}
	return postgresExportTaskQueueStatement{SQL: sqlText, Args: []any{id}}, nil
}

func buildPostgresConnectorRegistryGetForTenantStatement(tenantID, id string, forUpdate bool) (postgresExportTaskQueueStatement, error) {
	tenantID = strings.TrimSpace(tenantID)
	id = strings.TrimSpace(id)
	if tenantID == "" {
		return postgresExportTaskQueueStatement{}, fmt.Errorf("connector tenant_id is required")
	}
	if id == "" {
		return postgresExportTaskQueueStatement{}, fmt.Errorf("connector id is required")
	}
	sqlText := "SELECT payload FROM connector_registrations WHERE tenant_id = $1 AND connector_id = $2"
	if forUpdate {
		sqlText += " FOR UPDATE"
	}
	return postgresExportTaskQueueStatement{SQL: sqlText, Args: []any{tenantID, id}}, nil
}

func buildPostgresConnectorRegistryListStatement() postgresExportTaskQueueStatement {
	return postgresExportTaskQueueStatement{
		SQL:  "SELECT payload FROM connector_registrations ORDER BY connector_id ASC",
		Args: []any{},
	}
}

func buildPostgresConnectorRegistryListByTenantStatement(tenantID string) (postgresExportTaskQueueStatement, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return postgresExportTaskQueueStatement{}, fmt.Errorf("connector tenant_id is required")
	}
	return postgresExportTaskQueueStatement{
		SQL:  "SELECT payload FROM connector_registrations WHERE tenant_id = $1 ORDER BY connector_id ASC",
		Args: []any{tenantID},
	}, nil
}

func normalizeConnectorRegistration(conn model.ConnectorRegistration, now time.Time) (model.ConnectorRegistration, error) {
	normalized, err := normalizeConnectorRegistrationForStorage(conn)
	if err != nil {
		return model.ConnectorRegistration{}, err
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if normalized.Status == "" {
		normalized.Status = "registered"
	}
	if normalized.RegisteredAt == "" {
		normalized.RegisteredAt = now.UTC().Format(time.RFC3339)
	}
	if normalized.LastHeartbeatAt == "" {
		normalized.LastHeartbeatAt = normalized.RegisteredAt
	}
	delete(normalized.Metadata, "runtime_secret_rotated_at")
	delete(normalized.Metadata, "runtime_secret_rotated_by")
	return normalized, nil
}

func preserveConnectorRuntimeCredentialMetadata(existing, next map[string]any) {
	if existing == nil || next == nil {
		return
	}
	for _, key := range []string{"runtime_secret_hash", "runtime_secret_rotated_at", "runtime_secret_rotated_by"} {
		if value, ok := existing[key]; ok {
			next[key] = value
		}
	}
}

func preserveConnectorRegistrationLifecycle(existing model.ConnectorRegistration, next *model.ConnectorRegistration) {
	if next == nil {
		return
	}
	next.Status = existing.Status
	next.RegisteredAt = existing.RegisteredAt
	next.LastHeartbeatAt = existing.LastHeartbeatAt
	// ★ A CONNECTOR NEVER REPORTS WHERE IT IS ATTACHED, SO ITS REGISTRATION MUST NOT CLEAR IT. Only a node
	// terminating the tunnel knows that, and it says so separately. Letting an incoming registration carry the
	// zero value through would erase it on every connector restart — silence read as an instruction.
	if strings.TrimSpace(next.AttachedRegionID) == "" {
		next.AttachedRegionID = existing.AttachedRegionID
	}
}

func normalizeConnectorRegistrationForStorage(conn model.ConnectorRegistration) (model.ConnectorRegistration, error) {
	conn.ID = strings.TrimSpace(conn.ID)
	conn.TenantID = strings.TrimSpace(conn.TenantID)
	conn.ConnectorGroupID = strings.TrimSpace(conn.ConnectorGroupID)
	conn.Name = strings.TrimSpace(conn.Name)
	conn.EdgeRegionID = strings.TrimSpace(conn.EdgeRegionID)
	conn.EdgeClusterID = strings.TrimSpace(conn.EdgeClusterID)
	conn.PrivateBaseURL = strings.TrimSpace(conn.PrivateBaseURL)
	conn.Status = strings.TrimSpace(conn.Status)
	conn.RegisteredAt = strings.TrimSpace(conn.RegisteredAt)
	conn.LastHeartbeatAt = strings.TrimSpace(conn.LastHeartbeatAt)
	if conn.ID == "" {
		return model.ConnectorRegistration{}, fmt.Errorf("connector id is required")
	}
	if conn.TenantID == "" {
		return model.ConnectorRegistration{}, fmt.Errorf("connector tenant_id is required")
	}
	if conn.PrivateBaseURL == "" {
		return model.ConnectorRegistration{}, fmt.Errorf("connector private_base_url is required")
	}
	switch conn.Status {
	case "", "registered", "healthy", "degraded", "offline":
	default:
		return model.ConnectorRegistration{}, fmt.Errorf("connector status %q is invalid", conn.Status)
	}
	conn.ApplicationIDs = append([]string(nil), conn.ApplicationIDs...)
	if conn.Metadata == nil {
		conn.Metadata = map[string]any{}
	} else {
		conn.Metadata = copyAnyMap(conn.Metadata)
	}
	if hash := connectorRuntimeSecretHashFromMetadata(conn.Metadata); hash != "" {
		conn.Metadata["runtime_secret_hash"] = hash
	} else if _, ok := conn.Metadata["runtime_secret_hash"]; ok {
		return model.ConnectorRegistration{}, fmt.Errorf("connector metadata.runtime_secret_hash must be sha256:<64 lowercase hex>")
	}
	return conn, nil
}

func connectorRegistrationWithHeartbeat(conn model.ConnectorRegistration, heartbeat model.ConnectorHeartbeat, now time.Time) (model.ConnectorRegistration, error) {
	heartbeat.ID = strings.TrimSpace(heartbeat.ID)
	heartbeat.TenantID = strings.TrimSpace(heartbeat.TenantID)
	if heartbeat.ID == "" {
		return model.ConnectorRegistration{}, fmt.Errorf("connector id is required")
	}
	if heartbeat.TenantID != "" && heartbeat.TenantID != conn.TenantID {
		return model.ConnectorRegistration{}, fmt.Errorf("connector tenant_id %s does not match registered tenant_id %s", heartbeat.TenantID, conn.TenantID)
	}
	if heartbeat.Status != "" {
		conn.Status = strings.TrimSpace(heartbeat.Status)
	} else {
		conn.Status = "healthy"
	}
	switch conn.Status {
	case "healthy", "degraded", "offline":
	default:
		return model.ConnectorRegistration{}, fmt.Errorf("connector status %q is invalid", conn.Status)
	}
	if strings.TrimSpace(heartbeat.Timestamp) != "" {
		conn.LastHeartbeatAt = strings.TrimSpace(heartbeat.Timestamp)
	} else {
		conn.LastHeartbeatAt = now.UTC().Format(time.RFC3339)
	}
	if conn.Metadata == nil {
		conn.Metadata = map[string]any{}
	}
	for key, value := range heartbeat.Metadata {
		switch key {
		case "runtime_secret_hash", "runtime_secret_rotated_at", "runtime_secret_rotated_by":
			continue
		default:
			conn.Metadata[key] = value
		}
	}
	conn.Metadata["policy_bundle_id"] = heartbeat.PolicyBundleID
	conn.Metadata["policy_bundle_version"] = heartbeat.PolicyBundleVersion
	return normalizeConnectorRegistrationForStorage(conn)
}

func connectorRuntimeSecretHashValid(hash string) bool {
	return connectorRuntimeSecretHashFromMetadata(map[string]any{"runtime_secret_hash": hash}) == strings.TrimSpace(hash)
}

// ★★★ RENAMING AND REMOVING A CONNECTOR HAVE TO WORK ON THE DURABLE STORE (2026-08-25). Both admin acts were
// reached by asserting the in-memory registry's concrete type, so the moment the control plane was moved to
// the deployment's database — which is where the registry belongs, and which fixed two control planes holding
// different connector sets — both answered 501. Removing a connector is how a customer takes its access away;
// a store that cannot revoke is worse than the split it replaced.
//
// Both are tenant-scoped the way the in-memory registry is: a connector owned by another organization is
// refused rather than acted on, and an unknown one answers "not found" rather than "done".

// SetDisplayNameForTenant sets (or clears, when name is empty) the operator display name.
//
// The name lives in the registration's metadata, exactly as it does in memory, so the two stores agree about
// what a rename IS — one place deciding that, rather than two.
func (store postgresConnectorRegistryStore) SetDisplayNameForTenant(tenantID, id, name string) (model.ConnectorRegistration, bool, error) {
	if store.DB == nil {
		return model.ConnectorRegistration{}, false, fmt.Errorf("postgres connector registry db is not configured")
	}
	tenantID, id, name = strings.TrimSpace(tenantID), strings.TrimSpace(id), strings.TrimSpace(name)
	if id == "" {
		return model.ConnectorRegistration{}, false, fmt.Errorf("connector id is required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), postgresConnectorRegistryTimeout)
	defer cancel()
	conn, ok, err := store.getByID(ctx, id, false)
	if err != nil || !ok {
		return model.ConnectorRegistration{}, false, err
	}
	if tenantID != "" && strings.TrimSpace(conn.TenantID) != tenantID {
		return model.ConnectorRegistration{}, false, fmt.Errorf("connector %s belongs to another tenant", id)
	}
	conn = connector.SetDisplayName(conn, name)
	// Written through Register so one path normalizes and persists a registration, whatever changed about it.
	saved, err := store.Register(conn, time.Now().UTC())
	if err != nil {
		return model.ConnectorRegistration{}, false, err
	}
	return saved, true, nil
}

// RemoveForTenant deletes a connector. A LIVE connector re-registers on its next heartbeat, exactly as it does
// against the in-memory registry — this is decommissioning, not a kill switch, and the two stores must not
// disagree about that either.
func (store postgresConnectorRegistryStore) RemoveForTenant(tenantID, id string) (bool, error) {
	if store.DB == nil {
		return false, fmt.Errorf("postgres connector registry db is not configured")
	}
	tenantID, id = strings.TrimSpace(tenantID), strings.TrimSpace(id)
	if id == "" {
		return false, fmt.Errorf("connector id is required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), postgresConnectorRegistryTimeout)
	defer cancel()
	conn, ok, err := store.getByID(ctx, id, false)
	if err != nil || !ok {
		return false, err
	}
	if tenantID != "" && strings.TrimSpace(conn.TenantID) != tenantID {
		return false, fmt.Errorf("connector %s belongs to another tenant", id)
	}
	res, err := store.DB.ExecContext(ctx, "DELETE FROM connector_registrations WHERE connector_id = $1", id)
	if err != nil {
		return false, fmt.Errorf("remove connector: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		// The delete ran; the driver could not say how many rows it touched. Reporting "not removed" here
		// would send an operator to do it again on a connector that is already gone.
		return true, nil
	}
	return n > 0, nil
}

// ★★★ AND THE BUNDLE'S VERSION HAS TO MOVE WHEN THE CATALOG DOES (2026-08-26). The aggregate generation an
// Edge compares against is a SUM, and one of its terms was read from the in-memory registry by concrete type.
// With the control plane's registry in the deployment's database that term was silently zero, so registering
// or removing a connector changed the bundle's CONTENTS and not its VERSION — and no Edge pulls a bundle whose
// version has not moved. A catalog that travels and a version that does not move are the same as not carrying
// it at all.
//
// Derived from what is stored rather than counted in memory: a counter held by one process is not a version
// two control planes can agree on, and this store exists precisely because they must.
func (store postgresConnectorRegistryStore) ConfigGeneration() uint64 {
	if store.DB == nil {
		return 0
	}
	// ★★★ MONOTONIC, BECAUSE AN EDGE APPLIES ONLY WHAT IS NEWER (2026-08-26, measured twice on the way to
	// getting this right).
	//
	// The bundle's generation is a SUM of terms and an Edge applies a generation GREATER than the one it
	// holds. A term that can DECREASE therefore does not slow the fleet down — it stops it: one decrease and
	// no Edge ever applies configuration again, silently, until the control plane restarts and the epoch
	// changes. A fingerprint of the fields was tried here and was exactly that.
	//
	// So it is a clock, and the write path is what keeps it quiet: updated_at moves only when a
	// routing-relevant field changes, never on a heartbeat. See the upsert.
	ctx, cancel := context.WithTimeout(context.Background(), postgresConnectorRegistryTimeout)
	defer cancel()
	var count int64
	var latest sql.NullTime
	if err := store.DB.QueryRowContext(ctx,
		"SELECT count(*), max(updated_at) FROM connector_registrations").Scan(&count, &latest); err != nil {
		return 0
	}
	gen := uint64(count)
	if latest.Valid {
		gen += uint64(latest.Time.UTC().Unix())
	}
	return gen
}

// RecordLiveness writes ONLY what a reporting Edge observed — that this connector was heard from, and what it
// said its status was — leaving every operator-authored field alone. See connector.Registry.RecordLiveness.
//
// ★★★ AND IT EXISTS HERE BECAUSE THE OTHER STORE IS THE ONE NOBODY RUNS (2026-09-01, the second time in one
// day). The method was added to the in-memory registry, the type assertion in the report handler found no
// implementation on the postgres store a generated deployment actually uses, and the liveness was silently
// dropped — the same shape as the enrolment-token refusal that morning, and caught the same way: by asking the
// deployment instead of the tests. A store swapped in and a path quietly off.
func (store postgresConnectorRegistryStore) RecordLiveness(id, status, heartbeatAt string) (bool, error) {
	if store.DB == nil {
		return false, fmt.Errorf("postgres connector registry db is not configured")
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return false, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), postgresConnectorRegistryTimeout)
	defer cancel()
	conn, ok, err := store.getByID(ctx, id, false)
	if err != nil || !ok {
		return false, err
	}
	hb, st := strings.TrimSpace(heartbeatAt), strings.TrimSpace(status)
	if (hb == "" || hb == conn.LastHeartbeatAt) && (st == "" || st == conn.Status) {
		return false, nil
	}
	// ★★★ WRITTEN DIRECTLY, BECAUSE Register REFUSES TO MOVE THESE — DELIBERATELY (2026-09-01, the last link
	// in the chain). A registration carries whatever the connector said when it started, so Register keeps the
	// EXISTING status and heartbeat rather than letting a re-registration rewind them. That is right, and it
	// means liveness can never be written through Register: it logged "recorded", returned true, and the row
	// never moved. The site read Down through four fixes because of this one.
	//
	// So this is the one place that may move them, and it moves nothing else.
	if hb == "" {
		hb = conn.LastHeartbeatAt
	}
	if st == "" {
		st = conn.Status
	}
	// ★★★ AND THE PAYLOAD, WHICH IS THE COPY EVERY READER USES (2026-09-01, the link after the link).
	//
	// This row carries each fact twice: as a column, and inside a JSON payload. The list every screen is built
	// from is `SELECT payload` — the columns exist for querying, not for reading back. So updating only the
	// columns moved the row and changed nothing an operator could see: the database said 03:49 and the API
	// went on answering 02:01, which is the shape of a fact with two homes and one writer.
	//
	// Both are written here, from the same value, in one statement — so they cannot disagree.
	conn.LastHeartbeatAt, conn.Status = hb, st
	payload, err := json.Marshal(conn)
	if err != nil {
		return false, fmt.Errorf("marshal connector liveness payload: %w", err)
	}
	res, err := store.DB.ExecContext(ctx,
		"UPDATE connector_registrations SET last_heartbeat_at = $2, status = $3, payload = $4 WHERE connector_id = $1",
		id, hb, st, payload)
	if err != nil {
		return false, fmt.Errorf("record connector liveness: %w", err)
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// RecordAttachedRegion notes where this connector's tunnel is currently terminating. See
// connector.Registry.RecordAttachedRegion — the two stores must agree about this, because a deployment that
// changes backend must not quietly lose the one fact that keeps a failed-over connector reachable.
//
// ★ IT MUST NOT MOVE THE CATALOG VERSION. It writes through Register, whose upsert moves updated_at only when
// a class-1 column differs — attached_region_id is not one, it rides in the payload — so a connector flapping
// between regions cannot drive the deployment's aggregate generation. Verified by
// TestRecordingTheAttachedRegionDoesNotMoveTheCatalogVersion.
func (store postgresConnectorRegistryStore) RecordAttachedRegion(id, region string) (bool, error) {
	if store.DB == nil {
		return false, fmt.Errorf("postgres connector registry db is not configured")
	}
	id, region = strings.TrimSpace(id), strings.TrimSpace(region)
	if id == "" || region == "" {
		return false, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), postgresConnectorRegistryTimeout)
	defer cancel()
	conn, ok, err := store.getByID(ctx, id, false)
	if err != nil || !ok {
		return false, err
	}
	if strings.EqualFold(strings.TrimSpace(conn.AttachedRegionID), region) {
		return false, nil
	}
	conn.AttachedRegionID = region
	if _, err := store.Register(conn, time.Now().UTC()); err != nil {
		return false, err
	}
	return true, nil
}
