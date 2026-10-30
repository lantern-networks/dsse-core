package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	devicestore "github.com/lantern-networks/dsse-core/device"
	"github.com/lantern-networks/dsse-core/model"
)

const postgresDeviceInventoryTimeout = 15 * time.Second

type postgresDeviceInventoryStore struct {
	DB            *sql.DB
	policyMu      sync.RWMutex
	posturePolicy *devicestore.PosturePolicy
}

var _ deviceRuntimeStore = (*postgresDeviceInventoryStore)(nil)
var _ deviceTenantReader = (*postgresDeviceInventoryStore)(nil)
var _ deviceTenantGetter = (*postgresDeviceInventoryStore)(nil)
var _ posturePolicyConfigurableStore = (*postgresDeviceInventoryStore)(nil)
var _ riskSignalDeviceApplier = (*postgresDeviceInventoryStore)(nil)

// The Edge environment is the policy authority. PostgreSQL keeps each device's
// last derived verdict; new posture reports apply the current ruleset.
func (store *postgresDeviceInventoryStore) SetPosturePolicy(policy devicestore.PosturePolicy) error {
	store.policyMu.Lock()
	defer store.policyMu.Unlock()
	store.posturePolicy = &policy
	return nil
}

func (store *postgresDeviceInventoryStore) effectivePosturePolicy() devicestore.PosturePolicy {
	store.policyMu.RLock()
	defer store.policyMu.RUnlock()
	if store.posturePolicy == nil {
		return devicestore.DefaultPosturePolicy()
	}
	return *store.posturePolicy
}

func (store *postgresDeviceInventoryStore) Register(device model.Device, policyBundle model.PolicyBundle, now time.Time) (model.Device, error) {
	device.ID = strings.TrimSpace(device.ID)
	device.TenantID = strings.TrimSpace(device.TenantID)
	result, err := store.mutateDevice(device.ID, now, func(previous *model.Device) (postgresDeviceMutation, error) {
		updated, err := devicestore.FoldRegistration(previous, device, policyBundle, store.effectivePosturePolicy(), now)
		return postgresDeviceMutation{device: updated, write: true}, err
	})
	return result.device, err
}

func (store *postgresDeviceInventoryStore) Heartbeat(heartbeat model.DeviceHeartbeat, policyBundle model.PolicyBundle, now time.Time) (model.Device, error) {
	heartbeat.ID = strings.TrimSpace(heartbeat.ID)
	heartbeat.TenantID = strings.TrimSpace(heartbeat.TenantID)
	result, err := store.mutateDevice(heartbeat.ID, now, func(previous *model.Device) (postgresDeviceMutation, error) {
		if previous == nil {
			return postgresDeviceMutation{}, fmt.Errorf("device %s is absent", heartbeat.ID)
		}
		updated, err := devicestore.FoldHeartbeat(*previous, heartbeat, policyBundle, store.effectivePosturePolicy(), now)
		return postgresDeviceMutation{device: updated, write: true}, err
	})
	return result.device, err
}

func (store *postgresDeviceInventoryStore) ApplyRiskSignal(deviceID string, signal model.RiskSignal, now time.Time) (model.Device, bool, bool, error) {
	deviceID = strings.TrimSpace(deviceID)
	result, err := store.mutateDevice(deviceID, now, func(previous *model.Device) (postgresDeviceMutation, error) {
		if previous == nil {
			return postgresDeviceMutation{}, nil
		}
		updated, high, err := devicestore.FoldRiskSignal(*previous, signal, now)
		return postgresDeviceMutation{device: updated, write: true, high: high}, err
	})
	return result.device, result.write, result.high, err
}

func (store *postgresDeviceInventoryStore) Get(id string) (model.Device, bool) {
	device, ok, err := store.GetChecked(id)
	if err != nil {
		log.Printf("postgres device inventory get failed: %v", err)
		return model.Device{}, false
	}
	return device, ok
}

// GetChecked preserves read failures for authorization callers that cannot
// infer a tenant before looking up a device in a legacy single-tenant flow.
func (store *postgresDeviceInventoryStore) GetChecked(id string) (model.Device, bool, error) {
	return store.getByID(context.Background(), id)
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

type postgresDeviceMutation struct {
	device model.Device
	write  bool
	high   bool
}

// mutateDevice serializes every writer for a device ID, including the first
// registration when no row exists yet. The transaction row lock alone cannot
// protect an absent row from a concurrent registration/risk update. All domain
// changes are calculated from the locked record and committed with its payload.
func (store *postgresDeviceInventoryStore) mutateDevice(deviceID string, now time.Time, fold func(*model.Device) (postgresDeviceMutation, error)) (postgresDeviceMutation, error) {
	if store == nil || store.DB == nil {
		return postgresDeviceMutation{}, fmt.Errorf("postgres device inventory db is not configured")
	}
	deviceID = strings.TrimSpace(deviceID)
	if deviceID == "" {
		return postgresDeviceMutation{}, fmt.Errorf("device_id is required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), postgresDeviceInventoryTimeout)
	defer cancel()
	tx, err := store.DB.BeginTx(ctx, nil)
	if err != nil {
		return postgresDeviceMutation{}, err
	}
	defer tx.Rollback()

	// A transaction-scoped advisory lock covers the no-row case. A hash
	// collision only serializes unrelated IDs; it cannot join their records.
	var lockResult any
	if err := tx.QueryRowContext(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", deviceID).Scan(&lockResult); err != nil {
		return postgresDeviceMutation{}, err
	}
	var previous *model.Device
	var rowTenant string
	var payload []byte
	err = tx.QueryRowContext(ctx, "SELECT tenant_id, payload FROM device_inventory WHERE device_id = $1 FOR UPDATE", deviceID).Scan(&rowTenant, &payload)
	if err != nil && err != sql.ErrNoRows {
		return postgresDeviceMutation{}, err
	}
	if err == nil {
		prior, err := decodePostgresDeviceInventoryPayload(payload)
		if err != nil {
			return postgresDeviceMutation{}, err
		}
		if prior.ID != deviceID || prior.TenantID != rowTenant {
			return postgresDeviceMutation{}, fmt.Errorf("device inventory row and payload identity disagree")
		}
		previous = &prior
	}
	result, err := fold(previous)
	if err != nil || !result.write {
		return result, err
	}
	statement, err := buildPostgresDeviceInventoryUpsertStatement(result.device, now)
	if err != nil {
		return postgresDeviceMutation{}, err
	}
	if err := tx.QueryRowContext(ctx, statement.SQL, statement.Args...).Scan(&payload); err != nil {
		if err == sql.ErrNoRows {
			return postgresDeviceMutation{}, fmt.Errorf("device %s belongs to another tenant", deviceID)
		}
		return postgresDeviceMutation{}, err
	}
	persisted, err := decodePostgresDeviceInventoryPayload(payload)
	if err != nil {
		return postgresDeviceMutation{}, err
	}
	if persisted.ID != deviceID || persisted.TenantID != result.device.TenantID {
		return postgresDeviceMutation{}, fmt.Errorf("device inventory write returned another identity")
	}
	if err := tx.Commit(); err != nil {
		return postgresDeviceMutation{}, err
	}
	result.device = persisted
	return result, nil
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
			"ON CONFLICT (device_id) DO UPDATE SET user_id = EXCLUDED.user_id, hostname = EXCLUDED.hostname, os = EXCLUDED.os, os_version = EXCLUDED.os_version, agent_version = EXCLUDED.agent_version, device_trust_level = EXCLUDED.device_trust_level, policy_bundle_id = EXCLUDED.policy_bundle_id, policy_bundle_version = EXCLUDED.policy_bundle_version, status = CASE WHEN device_inventory.status = 'revoked' THEN device_inventory.status ELSE EXCLUDED.status END, registered_at = EXCLUDED.registered_at, last_seen_at = EXCLUDED.last_seen_at, metadata = EXCLUDED.metadata, payload = CASE WHEN device_inventory.status = 'revoked' THEN jsonb_set(EXCLUDED.payload, '{status}', to_jsonb(device_inventory.status), true) ELSE EXCLUDED.payload END, updated_at = EXCLUDED.updated_at WHERE device_inventory.tenant_id = EXCLUDED.tenant_id RETURNING payload",
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
