package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/model"
)

const postgresDeviceInventoryTimeout = 15 * time.Second

type postgresDeviceInventoryStore struct {
	DB *sql.DB
}

var _ deviceRuntimeStore = (*postgresDeviceInventoryStore)(nil)
var _ deviceTenantReader = (*postgresDeviceInventoryStore)(nil)
var _ deviceTenantGetter = (*postgresDeviceInventoryStore)(nil)

func (store *postgresDeviceInventoryStore) Register(device model.Device, policyBundle model.PolicyBundle, now time.Time) (model.Device, error) {
	if policyBundle.TenantID != "" && device.TenantID != policyBundle.TenantID {
		return device, fmt.Errorf("device tenant_id %s does not match policy bundle tenant_id %s", device.TenantID, policyBundle.TenantID)
	}
	if device.DeviceTrustLevel == "" {
		device.DeviceTrustLevel = "unknown"
	}
	if device.PolicyBundleID == "" {
		device.PolicyBundleID = policyBundle.ID
	}
	if device.PolicyBundleVersion == "" {
		device.PolicyBundleVersion = policyBundle.Version
	}
	if device.Status == "" {
		device.Status = "registered"
	}
	// ★ A DEVICE RE-REGISTERING MUST NOT UNDO AN OPERATOR (2026-08-13, twenty-eighth review). This defaults an
	// absent status to "registered" and the upsert wrote it over whatever was there — so a machine an operator
	// had REVOKED could call POST /devices/register with its own transport certificate and clear the
	// revocation, silently and indistinguishably from a first registration. The device drives this call; the
	// revocation is the operator's. The conflict clause below keeps 'revoked' whatever the device says, and
	// un-revoking stays what it always was: an administrator's action on the admin route.
	if device.RegisteredAt == "" {
		device.RegisteredAt = now.UTC().Format(time.RFC3339)
	}
	if device.LastSeenAt == "" {
		device.LastSeenAt = device.RegisteredAt
	}
	if device.Metadata == nil {
		device.Metadata = map[string]any{}
	}
	if err := store.upsert(context.Background(), device, now); err != nil {
		return model.Device{}, err
	}
	return normalizePostgresDeviceForStorage(device)
}

func (store *postgresDeviceInventoryStore) Heartbeat(heartbeat model.DeviceHeartbeat, policyBundle model.PolicyBundle, now time.Time) (model.Device, error) {
	if heartbeat.ID == "" {
		return model.Device{}, fmt.Errorf("device id is required")
	}
	device, ok, err := store.getByID(context.Background(), heartbeat.ID)
	if err != nil {
		return model.Device{}, err
	}
	if !ok {
		return model.Device{}, fmt.Errorf("device %s is absent", heartbeat.ID)
	}
	if heartbeat.TenantID != "" && heartbeat.TenantID != device.TenantID {
		return model.Device{}, fmt.Errorf("device tenant_id %s does not match registered tenant_id %s", heartbeat.TenantID, device.TenantID)
	}
	if policyBundle.TenantID != "" && device.TenantID != policyBundle.TenantID {
		return model.Device{}, fmt.Errorf("device tenant_id %s does not match policy bundle tenant_id %s", device.TenantID, policyBundle.TenantID)
	}
	if heartbeat.AgentVersion != "" {
		device.AgentVersion = heartbeat.AgentVersion
	}
	if heartbeat.DeviceTrustLevel != "" {
		device.DeviceTrustLevel = heartbeat.DeviceTrustLevel
	}
	if heartbeat.PolicyBundleID != "" {
		device.PolicyBundleID = heartbeat.PolicyBundleID
	}
	if heartbeat.PolicyBundleVersion != "" {
		device.PolicyBundleVersion = heartbeat.PolicyBundleVersion
	}
	if device.PolicyBundleID == "" {
		device.PolicyBundleID = policyBundle.ID
	}
	if device.PolicyBundleVersion == "" {
		device.PolicyBundleVersion = policyBundle.Version
	}
	// Same rule as Register: a heartbeat is the DEVICE talking, and it must not clear a revocation. The upsert
	// keeps 'revoked' regardless of what is set here; this is the in-memory half so the value this process
	// returns agrees with the row it wrote.
	if strings.EqualFold(strings.TrimSpace(device.Status), "revoked") {
		// leave it
	} else if heartbeat.Status != "" {
		device.Status = heartbeat.Status
	} else {
		device.Status = "healthy"
	}
	if heartbeat.Timestamp != "" {
		device.LastSeenAt = heartbeat.Timestamp
	} else {
		device.LastSeenAt = now.UTC().Format(time.RFC3339)
	}
	if device.Metadata == nil {
		device.Metadata = map[string]any{}
	}
	for key, value := range heartbeat.Metadata {
		device.Metadata[key] = value
	}
	if err := store.upsert(context.Background(), device, now); err != nil {
		return model.Device{}, err
	}
	return normalizePostgresDeviceForStorage(device)
}

func (store *postgresDeviceInventoryStore) Get(id string) (model.Device, bool) {
	device, ok, err := store.getByID(context.Background(), id)
	if err != nil {
		log.Printf("postgres device inventory get failed: %v", err)
		return model.Device{}, false
	}
	return device, ok
}

func (store *postgresDeviceInventoryStore) GetByTenant(tenantID, deviceID string) (model.Device, bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), postgresDeviceInventoryTimeout)
	defer cancel()
	if store == nil || store.DB == nil {
		return model.Device{}, false, fmt.Errorf("postgres device inventory db is not configured")
	}
	statement, err := buildPostgresDeviceInventoryGetForTenantStatement(tenantID, deviceID)
	if err != nil {
		return model.Device{}, false, err
	}
	var payload []byte
	if err := store.DB.QueryRowContext(ctx, statement.SQL, statement.Args...).Scan(&payload); err != nil {
		if err == sql.ErrNoRows {
			return model.Device{}, false, nil
		}
		return model.Device{}, false, err
	}
	device, err := decodePostgresDeviceInventoryPayload(payload)
	if err != nil {
		return model.Device{}, false, err
	}
	return device, true, nil
}

func (store *postgresDeviceInventoryStore) List() []model.Device {
	devices, err := store.list(context.Background(), "")
	if err != nil {
		log.Printf("postgres device inventory list failed: %v", err)
		return nil
	}
	return devices
}

func (store *postgresDeviceInventoryStore) ListByTenant(tenantID string) ([]model.Device, error) {
	return store.list(context.Background(), tenantID)
}

func (store *postgresDeviceInventoryStore) upsert(ctx context.Context, device model.Device, now time.Time) error {
	ctx, cancel := context.WithTimeout(ctx, postgresDeviceInventoryTimeout)
	defer cancel()
	statement, err := buildPostgresDeviceInventoryUpsertStatement(device, now)
	if err != nil {
		return err
	}
	if store == nil || store.DB == nil {
		return fmt.Errorf("postgres device inventory db is not configured")
	}
	result, err := store.DB.ExecContext(ctx, statement.SQL, statement.Args...)
	if err != nil {
		return err
	}
	if rowsAffected, err := result.RowsAffected(); err == nil && rowsAffected == 0 {
		return fmt.Errorf("device inventory upsert affected 0 rows for device_id %s", device.ID)
	}
	return nil
}

func (store *postgresDeviceInventoryStore) getByID(ctx context.Context, id string) (model.Device, bool, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return model.Device{}, false, fmt.Errorf("device_id is required")
	}
	ctx, cancel := context.WithTimeout(ctx, postgresDeviceInventoryTimeout)
	defer cancel()
	if store == nil || store.DB == nil {
		return model.Device{}, false, fmt.Errorf("postgres device inventory db is not configured")
	}
	statement := postgresExportTaskQueueStatement{
		SQL:  "SELECT payload FROM device_inventory WHERE device_id = $1",
		Args: []any{id},
	}
	var payload []byte
	if err := store.DB.QueryRowContext(ctx, statement.SQL, statement.Args...).Scan(&payload); err != nil {
		if err == sql.ErrNoRows {
			return model.Device{}, false, nil
		}
		return model.Device{}, false, err
	}
	device, err := decodePostgresDeviceInventoryPayload(payload)
	if err != nil {
		return model.Device{}, false, err
	}
	return device, true, nil
}

func (store *postgresDeviceInventoryStore) list(ctx context.Context, tenantID string) ([]model.Device, error) {
	ctx, cancel := context.WithTimeout(ctx, postgresDeviceInventoryTimeout)
	defer cancel()
	if store == nil || store.DB == nil {
		return nil, fmt.Errorf("postgres device inventory db is not configured")
	}
	statement, err := buildPostgresDeviceInventoryListStatement(tenantID)
	if err != nil {
		return nil, err
	}
	rows, err := store.DB.QueryContext(ctx, statement.SQL, statement.Args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var devices []model.Device
	for rows.Next() {
		var payload []byte
		if err := rows.Scan(&payload); err != nil {
			return nil, err
		}
		device, err := decodePostgresDeviceInventoryPayload(payload)
		if err != nil {
			return nil, err
		}
		devices = append(devices, device)
	}
	return devices, rows.Err()
}

func decodePostgresDeviceInventoryPayload(payload []byte) (model.Device, error) {
	var device model.Device
	if err := json.Unmarshal(payload, &device); err != nil {
		return device, fmt.Errorf("decode device inventory payload: %w", err)
	}
	return normalizePostgresDeviceForStorage(device)
}

func postgresDeviceInventorySchemaSQL() []string {
	return []string{
		strings.Join([]string{
			"CREATE TABLE IF NOT EXISTS device_inventory (",
			"device_id text PRIMARY KEY,",
			"tenant_id text NOT NULL,",
			"user_id text NOT NULL,",
			"hostname text NOT NULL,",
			"os text NOT NULL,",
			"os_version text NOT NULL DEFAULT '',",
			"agent_version text NOT NULL,",
			"device_trust_level text NOT NULL CHECK (device_trust_level IN ('managed', 'unmanaged', 'unknown')),",
			"policy_bundle_id text NOT NULL,",
			"policy_bundle_version text NOT NULL,",
			"status text NOT NULL CHECK (status IN ('registered', 'healthy', 'degraded', 'offline', 'revoked')),",
			"registered_at timestamptz NOT NULL,",
			"last_seen_at timestamptz NOT NULL,",
			"metadata jsonb NOT NULL DEFAULT '{}'::jsonb,",
			"payload jsonb NOT NULL,",
			"created_at timestamptz NOT NULL DEFAULT now(),",
			"updated_at timestamptz NOT NULL DEFAULT now()",
			")",
		}, " "),
		"CREATE INDEX IF NOT EXISTS device_inventory_tenant_status_idx ON device_inventory (tenant_id, status, last_seen_at DESC)",
		"CREATE INDEX IF NOT EXISTS device_inventory_tenant_user_idx ON device_inventory (tenant_id, user_id, device_id)",
	}
}

func buildPostgresDeviceInventoryUpsertStatement(device model.Device, now time.Time) (postgresExportTaskQueueStatement, error) {
	normalized, err := normalizePostgresDeviceForStorage(device)
	if err != nil {
		return postgresExportTaskQueueStatement{}, err
	}
	metadata, err := json.Marshal(normalized.Metadata)
	if err != nil {
		return postgresExportTaskQueueStatement{}, fmt.Errorf("marshal device metadata: %w", err)
	}
	payload, err := json.Marshal(normalized)
	if err != nil {
		return postgresExportTaskQueueStatement{}, fmt.Errorf("marshal device payload: %w", err)
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	return postgresExportTaskQueueStatement{
		SQL: strings.Join([]string{
			"INSERT INTO device_inventory (device_id, tenant_id, user_id, hostname, os, os_version, agent_version, device_trust_level, policy_bundle_id, policy_bundle_version, status, registered_at, last_seen_at, metadata, payload, created_at, updated_at)",
			"VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12::timestamptz, $13::timestamptz, $14::jsonb, $15::jsonb, $16, $16)",
			"ON CONFLICT (device_id) DO UPDATE SET user_id = EXCLUDED.user_id, hostname = EXCLUDED.hostname, os = EXCLUDED.os, os_version = EXCLUDED.os_version, agent_version = EXCLUDED.agent_version, device_trust_level = EXCLUDED.device_trust_level, policy_bundle_id = EXCLUDED.policy_bundle_id, policy_bundle_version = EXCLUDED.policy_bundle_version, status = CASE WHEN device_inventory.status = 'revoked' THEN device_inventory.status ELSE EXCLUDED.status END, registered_at = EXCLUDED.registered_at, last_seen_at = EXCLUDED.last_seen_at, metadata = EXCLUDED.metadata, payload = EXCLUDED.payload, updated_at = EXCLUDED.updated_at WHERE device_inventory.tenant_id = EXCLUDED.tenant_id",
		}, " "),
		Args: []any{
			normalized.ID,
			normalized.TenantID,
			normalized.UserID,
			normalized.Hostname,
			normalized.OS,
			normalized.OSVersion,
			normalized.AgentVersion,
			normalized.DeviceTrustLevel,
			normalized.PolicyBundleID,
			normalized.PolicyBundleVersion,
			normalized.Status,
			normalized.RegisteredAt,
			normalized.LastSeenAt,
			string(metadata),
			string(payload),
			now.UTC(),
		},
	}, nil
}

func buildPostgresDeviceInventoryGetForTenantStatement(tenantID, deviceID string) (postgresExportTaskQueueStatement, error) {
	tenantID = strings.TrimSpace(tenantID)
	deviceID = strings.TrimSpace(deviceID)
	if tenantID == "" {
		return postgresExportTaskQueueStatement{}, fmt.Errorf("tenant_id is required")
	}
	if deviceID == "" {
		return postgresExportTaskQueueStatement{}, fmt.Errorf("device_id is required")
	}
	return postgresExportTaskQueueStatement{
		SQL:  "SELECT payload FROM device_inventory WHERE tenant_id = $1 AND device_id = $2",
		Args: []any{tenantID, deviceID},
	}, nil
}

func buildPostgresDeviceInventoryListByTenantStatement(tenantID string) (postgresExportTaskQueueStatement, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return postgresExportTaskQueueStatement{}, fmt.Errorf("tenant_id is required")
	}
	return postgresExportTaskQueueStatement{
		SQL:  "SELECT payload FROM device_inventory WHERE tenant_id = $1 ORDER BY device_id ASC",
		Args: []any{tenantID},
	}, nil
}

func buildPostgresDeviceInventoryListStatement(tenantID string) (postgresExportTaskQueueStatement, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return postgresExportTaskQueueStatement{
			SQL:  "SELECT payload FROM device_inventory ORDER BY tenant_id ASC, device_id ASC",
			Args: nil,
		}, nil
	}
	return buildPostgresDeviceInventoryListByTenantStatement(tenantID)
}

func normalizePostgresDeviceForStorage(device model.Device) (model.Device, error) {
	device.ID = strings.TrimSpace(device.ID)
	device.TenantID = strings.TrimSpace(device.TenantID)
	device.UserID = strings.TrimSpace(device.UserID)
	device.Hostname = strings.TrimSpace(device.Hostname)
	device.OS = strings.TrimSpace(device.OS)
	device.AgentVersion = strings.TrimSpace(device.AgentVersion)
	device.DeviceTrustLevel = strings.TrimSpace(device.DeviceTrustLevel)
	device.PolicyBundleID = strings.TrimSpace(device.PolicyBundleID)
	device.PolicyBundleVersion = strings.TrimSpace(device.PolicyBundleVersion)
	device.Status = strings.TrimSpace(device.Status)
	device.RegisteredAt = strings.TrimSpace(device.RegisteredAt)
	device.LastSeenAt = strings.TrimSpace(device.LastSeenAt)
	if device.ID == "" {
		return device, fmt.Errorf("device_id is required")
	}
	if device.TenantID == "" {
		return device, fmt.Errorf("tenant_id is required")
	}
	if device.UserID == "" {
		return device, fmt.Errorf("user_id is required")
	}
	if device.Hostname == "" {
		return device, fmt.Errorf("hostname is required")
	}
	if device.OS == "" {
		return device, fmt.Errorf("os is required")
	}
	if device.AgentVersion == "" {
		return device, fmt.Errorf("agent_version is required")
	}
	if device.DeviceTrustLevel == "" {
		device.DeviceTrustLevel = "unknown"
	}
	if device.PolicyBundleID == "" {
		return device, fmt.Errorf("policy_bundle_id is required")
	}
	if device.PolicyBundleVersion == "" {
		return device, fmt.Errorf("policy_bundle_version is required")
	}
	if device.Status == "" {
		device.Status = "registered"
	}
	if device.RegisteredAt == "" {
		return device, fmt.Errorf("registered_at is required")
	}
	if device.LastSeenAt == "" {
		device.LastSeenAt = device.RegisteredAt
	}
	if device.Metadata == nil {
		device.Metadata = map[string]any{}
	}
	return device, nil
}
