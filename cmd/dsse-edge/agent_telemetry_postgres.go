package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	agenttelemetry "github.com/lantern-networks/dsse-core/agenttelemetry"

	"github.com/lantern-networks/dsse-core/model"
)

const postgresAgentTelemetryTimeout = 15 * time.Second

type postgresAgentTelemetryStore struct {
	DB *sql.DB
}

var _ agenttelemetry.RuntimeStore = (*postgresAgentTelemetryStore)(nil)

func (store *postgresAgentTelemetryStore) RecordUpdate(ctx context.Context, event model.AgentUpdateEvent) error {
	ctx, cancel := context.WithTimeout(ctx, postgresAgentTelemetryTimeout)
	defer cancel()
	if store == nil || store.DB == nil {
		return fmt.Errorf("postgres agent telemetry db is not configured")
	}
	statement, err := buildPostgresAgentUpdateInsertStatement(event, time.Now().UTC())
	if err != nil {
		return err
	}
	_, err = store.DB.ExecContext(ctx, statement.SQL, statement.Args...)
	return err
}

func (store *postgresAgentTelemetryStore) RecordStatus(ctx context.Context, status model.AgentStatus) error {
	ctx, cancel := context.WithTimeout(ctx, postgresAgentTelemetryTimeout)
	defer cancel()
	if store == nil || store.DB == nil {
		return fmt.Errorf("postgres agent telemetry db is not configured")
	}
	statement, err := buildPostgresAgentStatusInsertStatement(status, time.Now().UTC())
	if err != nil {
		return err
	}
	_, err = store.DB.ExecContext(ctx, statement.SQL, statement.Args...)
	return err
}

func (store *postgresAgentTelemetryStore) UpdateSummary(ctx context.Context, tenantID string) (map[string]any, error) {
	events, err := store.listUpdatesByTenant(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	return agenttelemetry.UpdateSummaryFromEvents(events), nil
}

func (store *postgresAgentTelemetryStore) StatusSummary(ctx context.Context, tenantID string) (map[string]any, error) {
	statuses, err := store.listStatusesByTenant(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	return agenttelemetry.StatusSummaryFromEvents(statuses), nil
}

// LatestUpdateByDevice is the newest outcome each device reported.
//
// ★ IT USED TO READ THE TENANT'S WHOLE UPDATE HISTORY TO ANSWER THIS (2026-08-12, fourteenth review). Every
// row, every payload unmarshalled, on every load of the Devices list — and then all but one per device thrown
// away. It gets slower in proportion to how long the fleet has been updating, which is the one axis that only
// ever grows, and the way it fails is the defect above: the 15-second timeout trips, the read errors, and
// before this round that came back as a healthy 0/N.
//
// DISTINCT ON does it in the database, against agent_update_events_tenant_device_idx
// (tenant_id, device_id, occurred_at DESC) — the index that has been sitting there since 019.
//
// ★ AND THE TIE-BREAK CANNOT BE THE EVENT ID (2026-08-12, fifteenth review). A report's timestamp is
// second-precision and the id ends in a decimal counter, so two outcomes from the SAME tick differ only in
// that suffix — and sorted as TEXT, `…_9` comes after `…_10`. The ninth report would be served as the newest
// and the tenth discarded, which on a device that failed and then rolled back in one pass is the wrong half
// of the story. `created_at` is the server's own receipt order, it is on the table already (migration 019),
// and it is what the in-memory store means by "the one recorded later".
func (store *postgresAgentTelemetryStore) LatestUpdateByDevice(ctx context.Context, tenantID string) (map[string]model.AgentUpdateEvent, error) {
	ctx, cancel := context.WithTimeout(ctx, postgresAgentTelemetryTimeout)
	defer cancel()
	if store == nil || store.DB == nil {
		return nil, fmt.Errorf("postgres agent telemetry db is not configured")
	}
	statement, err := buildPostgresAgentUpdateLatestByDeviceStatement(tenantID)
	if err != nil {
		return nil, err
	}
	rows, err := store.DB.QueryContext(ctx, statement.SQL, statement.Args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	latest := map[string]model.AgentUpdateEvent{}
	for rows.Next() {
		var payload []byte
		if err := rows.Scan(&payload); err != nil {
			return nil, err
		}
		var event model.AgentUpdateEvent
		if err := json.Unmarshal(payload, &event); err != nil {
			return nil, fmt.Errorf("decode agent update payload: %w", err)
		}
		device := strings.TrimSpace(event.DeviceID)
		if device == "" {
			continue
		}
		latest[device] = event
	}
	return latest, rows.Err()
}

func (store *postgresAgentTelemetryStore) listUpdatesByTenant(ctx context.Context, tenantID string) ([]model.AgentUpdateEvent, error) {
	ctx, cancel := context.WithTimeout(ctx, postgresAgentTelemetryTimeout)
	defer cancel()
	if store == nil || store.DB == nil {
		return nil, fmt.Errorf("postgres agent telemetry db is not configured")
	}
	statement, err := buildPostgresAgentUpdateListByTenantStatement(tenantID)
	if err != nil {
		return nil, err
	}
	rows, err := store.DB.QueryContext(ctx, statement.SQL, statement.Args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var events []model.AgentUpdateEvent
	for rows.Next() {
		var payload []byte
		if err := rows.Scan(&payload); err != nil {
			return nil, err
		}
		var event model.AgentUpdateEvent
		if err := json.Unmarshal(payload, &event); err != nil {
			return nil, fmt.Errorf("decode agent update payload: %w", err)
		}
		events = append(events, event)
	}
	return events, rows.Err()
}

func (store *postgresAgentTelemetryStore) listStatusesByTenant(ctx context.Context, tenantID string) ([]model.AgentStatus, error) {
	ctx, cancel := context.WithTimeout(ctx, postgresAgentTelemetryTimeout)
	defer cancel()
	if store == nil || store.DB == nil {
		return nil, fmt.Errorf("postgres agent telemetry db is not configured")
	}
	statement, err := buildPostgresAgentStatusListByTenantStatement(tenantID)
	if err != nil {
		return nil, err
	}
	rows, err := store.DB.QueryContext(ctx, statement.SQL, statement.Args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var statuses []model.AgentStatus
	for rows.Next() {
		var payload []byte
		if err := rows.Scan(&payload); err != nil {
			return nil, err
		}
		var status model.AgentStatus
		if err := json.Unmarshal(payload, &status); err != nil {
			return nil, fmt.Errorf("decode agent status payload: %w", err)
		}
		statuses = append(statuses, status)
	}
	return statuses, rows.Err()
}

func postgresAgentTelemetrySchemaSQL() []string {
	return []string{
		strings.Join([]string{
			"CREATE TABLE IF NOT EXISTS agent_update_events (",
			"event_id text PRIMARY KEY,",
			"tenant_id text NOT NULL,",
			"device_id text NOT NULL,",
			"user_id text NOT NULL DEFAULT '',",
			"current_agent_version text NOT NULL,",
			"target_agent_version text NOT NULL,",
			"release_channel text NOT NULL CHECK (release_channel IN ('lab', 'alpha', 'pilot', 'stable')),",
			// `refused` is added by migration 034, not here: this statement must stay identical to 019, which is the
			// contract the schema-drift test enforces. A CREATE that drifted from its migration is how two
			// deployments of one product end up with different constraints.
			"update_status text NOT NULL CHECK (update_status IN ('available', 'downloaded', 'installing', 'installed', 'failed', 'rolled_back')),",
			"update_source text NOT NULL CHECK (update_source IN ('mdm', 'control_plane', 'manual')),",
			"occurred_at timestamptz NOT NULL,",
			"metadata jsonb NOT NULL DEFAULT '{}'::jsonb,",
			"payload jsonb NOT NULL,",
			"created_at timestamptz NOT NULL DEFAULT now(),",
			"updated_at timestamptz NOT NULL DEFAULT now()",
			")",
		}, " "),
		"CREATE INDEX IF NOT EXISTS agent_update_events_tenant_device_idx ON agent_update_events (tenant_id, device_id, occurred_at DESC)",
		"CREATE INDEX IF NOT EXISTS agent_update_events_tenant_status_idx ON agent_update_events (tenant_id, update_status, occurred_at DESC)",
		strings.Join([]string{
			"CREATE TABLE IF NOT EXISTS agent_status_events (",
			"agent_status_id text PRIMARY KEY,",
			"tenant_id text NOT NULL,",
			"device_id text NOT NULL,",
			"policy_bundle_id text NOT NULL,",
			"policy_bundle_version text NOT NULL,",
			"bundle_source text NOT NULL CHECK (bundle_source IN ('remote', 'cache_fallback')),",
			"device_trust_level text NOT NULL CHECK (device_trust_level IN ('managed', 'unmanaged', 'unknown')),",
			"status text NOT NULL CHECK (status IN ('healthy', 'degraded', 'offline')),",
			"occurred_at timestamptz NOT NULL,",
			"metadata jsonb NOT NULL DEFAULT '{}'::jsonb,",
			"payload jsonb NOT NULL,",
			"created_at timestamptz NOT NULL DEFAULT now()",
			")",
		}, " "),
		"CREATE INDEX IF NOT EXISTS agent_status_events_tenant_device_idx ON agent_status_events (tenant_id, device_id, occurred_at DESC)",
		"CREATE INDEX IF NOT EXISTS agent_status_events_tenant_status_idx ON agent_status_events (tenant_id, status, occurred_at DESC)",
	}
}

func buildPostgresAgentUpdateInsertStatement(event model.AgentUpdateEvent, now time.Time) (postgresExportTaskQueueStatement, error) {
	normalized, err := normalizeAgentUpdateEventForStorage(event)
	if err != nil {
		return postgresExportTaskQueueStatement{}, err
	}
	metadata, err := json.Marshal(normalized.Metadata)
	if err != nil {
		return postgresExportTaskQueueStatement{}, fmt.Errorf("marshal agent update metadata: %w", err)
	}
	payload, err := json.Marshal(normalized)
	if err != nil {
		return postgresExportTaskQueueStatement{}, fmt.Errorf("marshal agent update payload: %w", err)
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	return postgresExportTaskQueueStatement{
		SQL: strings.Join([]string{
			"INSERT INTO agent_update_events (event_id, tenant_id, device_id, user_id, current_agent_version, target_agent_version, release_channel, update_status, update_source, occurred_at, metadata, payload, created_at, updated_at)",
			"VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::timestamptz, $11::jsonb, $12::jsonb, $13, $13)",
			// ★ DO NOTHING, NOT DO UPDATE (2026-08-12, seventh review). A retry re-sends the SAME event, so
			// there is nothing to update — and rewriting on conflict is what made a client-chosen id a way to
			// overwrite an existing row's tenant, device and payload. A repeat is now a no-op, and a genuinely
			// different event has a different id.
			// The conflict target is the SCOPE, not the bare id: migration 033 makes (tenant, device, event) the
			// primary key, because a client-chosen id is only meaningful beside the device that chose it. With
			// the bare id, another device's collision silently dropped a legitimate event — answered 202, and
			// the device deleted its only copy.
			"ON CONFLICT (tenant_id, device_id, event_id) DO NOTHING",
		}, " "),
		Args: []any{normalized.ID, normalized.TenantID, normalized.DeviceID, normalized.UserID, normalized.CurrentAgentVersion, normalized.TargetAgentVersion, normalized.ReleaseChannel, normalized.UpdateStatus, normalized.UpdateSource, normalized.Timestamp, string(metadata), string(payload), now.UTC()},
	}, nil
}

func buildPostgresAgentStatusInsertStatement(status model.AgentStatus, now time.Time) (postgresExportTaskQueueStatement, error) {
	normalized, err := normalizeAgentStatusForStorage(status)
	if err != nil {
		return postgresExportTaskQueueStatement{}, err
	}
	metadata, err := json.Marshal(normalized.Metadata)
	if err != nil {
		return postgresExportTaskQueueStatement{}, fmt.Errorf("marshal agent status metadata: %w", err)
	}
	payload, err := json.Marshal(normalized)
	if err != nil {
		return postgresExportTaskQueueStatement{}, fmt.Errorf("marshal agent status payload: %w", err)
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	statusID := randomEdgeID("ags_", now.UTC())
	return postgresExportTaskQueueStatement{
		SQL: strings.Join([]string{
			"INSERT INTO agent_status_events (agent_status_id, tenant_id, device_id, policy_bundle_id, policy_bundle_version, bundle_source, device_trust_level, status, occurred_at, metadata, payload, created_at)",
			"VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::timestamptz, $10::jsonb, $11::jsonb, $12)",
		}, " "),
		Args: []any{statusID, normalized.TenantID, normalized.DeviceID, normalized.PolicyBundleID, normalized.PolicyBundleVersion, normalized.BundleSource, normalized.DeviceTrustLevel, normalized.Status, normalized.Timestamp, string(metadata), string(payload), now.UTC()},
	}, nil
}

func buildPostgresAgentUpdateListByTenantStatement(tenantID string) (postgresExportTaskQueueStatement, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return postgresExportTaskQueueStatement{}, fmt.Errorf("tenant_id is required")
	}
	return postgresExportTaskQueueStatement{
		SQL:  "SELECT payload FROM agent_update_events WHERE tenant_id = $1 ORDER BY occurred_at ASC, event_id ASC",
		Args: []any{tenantID},
	}, nil
}

// buildPostgresAgentUpdateLatestByDeviceStatement returns ONE row per device: its newest outcome. The columns
// in the DISTINCT ON must lead the ORDER BY, which is why device_id appears first there and the recency terms
// follow.
func buildPostgresAgentUpdateLatestByDeviceStatement(tenantID string) (postgresExportTaskQueueStatement, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return postgresExportTaskQueueStatement{}, fmt.Errorf("tenant_id is required")
	}
	return postgresExportTaskQueueStatement{
		SQL: "SELECT DISTINCT ON (device_id) payload FROM agent_update_events WHERE tenant_id = $1 " +
			"ORDER BY device_id, occurred_at DESC, created_at DESC, event_id DESC",
		Args: []any{tenantID},
	}, nil
}

func buildPostgresAgentStatusListByTenantStatement(tenantID string) (postgresExportTaskQueueStatement, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return postgresExportTaskQueueStatement{}, fmt.Errorf("tenant_id is required")
	}
	return postgresExportTaskQueueStatement{
		SQL:  "SELECT payload FROM agent_status_events WHERE tenant_id = $1 ORDER BY occurred_at ASC, agent_status_id ASC",
		Args: []any{tenantID},
	}, nil
}

func normalizeAgentUpdateEventForStorage(event model.AgentUpdateEvent) (model.AgentUpdateEvent, error) {
	event.ID = strings.TrimSpace(event.ID)
	event.TenantID = strings.TrimSpace(event.TenantID)
	event.DeviceID = strings.TrimSpace(event.DeviceID)
	event.UserID = strings.TrimSpace(event.UserID)
	event.CurrentAgentVersion = strings.TrimSpace(event.CurrentAgentVersion)
	event.TargetAgentVersion = strings.TrimSpace(event.TargetAgentVersion)
	event.ReleaseChannel = strings.TrimSpace(event.ReleaseChannel)
	event.UpdateStatus = strings.TrimSpace(event.UpdateStatus)
	event.UpdateSource = strings.TrimSpace(event.UpdateSource)
	event.Timestamp = strings.TrimSpace(event.Timestamp)
	if event.ID == "" {
		return event, fmt.Errorf("agent update event id is required")
	}
	if event.TenantID == "" {
		return event, fmt.Errorf("tenant_id is required")
	}
	if event.DeviceID == "" {
		return event, fmt.Errorf("device_id is required")
	}
	if event.CurrentAgentVersion == "" {
		return event, fmt.Errorf("current_agent_version is required")
	}
	if event.TargetAgentVersion == "" {
		return event, fmt.Errorf("target_agent_version is required")
	}
	if event.ReleaseChannel == "" {
		return event, fmt.Errorf("release_channel is required")
	}
	if event.UpdateStatus == "" {
		return event, fmt.Errorf("update_status is required")
	}
	if event.UpdateSource == "" {
		return event, fmt.Errorf("update_source is required")
	}
	if event.Timestamp == "" {
		return event, fmt.Errorf("timestamp is required")
	}
	if event.Metadata == nil {
		event.Metadata = map[string]any{}
	}
	return event, nil
}

func normalizeAgentStatusForStorage(status model.AgentStatus) (model.AgentStatus, error) {
	status.DeviceID = strings.TrimSpace(status.DeviceID)
	status.TenantID = strings.TrimSpace(status.TenantID)
	status.PolicyBundleID = strings.TrimSpace(status.PolicyBundleID)
	status.PolicyBundleVersion = strings.TrimSpace(status.PolicyBundleVersion)
	status.BundleSource = strings.TrimSpace(status.BundleSource)
	status.DeviceTrustLevel = strings.TrimSpace(status.DeviceTrustLevel)
	status.Status = strings.TrimSpace(status.Status)
	status.Timestamp = strings.TrimSpace(status.Timestamp)
	if status.DeviceID == "" {
		return status, fmt.Errorf("device_id is required")
	}
	if status.TenantID == "" {
		return status, fmt.Errorf("tenant_id is required")
	}
	if status.PolicyBundleID == "" {
		return status, fmt.Errorf("policy_bundle_id is required")
	}
	if status.PolicyBundleVersion == "" {
		return status, fmt.Errorf("policy_bundle_version is required")
	}
	if status.BundleSource == "" {
		return status, fmt.Errorf("bundle_source is required")
	}
	if status.DeviceTrustLevel == "" {
		return status, fmt.Errorf("device_trust_level is required")
	}
	if status.Status == "" {
		return status, fmt.Errorf("status is required")
	}
	if status.Timestamp == "" {
		return status, fmt.Errorf("timestamp is required")
	}
	if status.Metadata == nil {
		status.Metadata = map[string]any{}
	}
	return status, nil
}
