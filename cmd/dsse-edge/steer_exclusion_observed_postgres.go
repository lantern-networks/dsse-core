package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	migrationstore "github.com/lantern-networks/dsse-core/migrations"
)

// steer_exclusion_observed_postgres.go — durable Postgres backend for the observed (reverse-telemetry) steer
// exclusions (Phase 3 of docs/steer_exclusions_observed_telemetry_scale_design.md). It satisfies the same
// observedExclusionStoreAPI contract as the in-memory cache (steer_exclusion_observed.go), so the admin
// handlers and the report path are unchanged; only the durable backend differs.
//
// Like the steer-exclusion persistence, this lives on the report-receiving (control-plane) process — the one
// with Postgres. The Edge is normally zero-DB, so this is opt-in. Each device keeps exactly ONE row
// (PRIMARY KEY (tenant_id, device_identity)); Record is a latest-wins UPSERT. Tenant scoping is enforced by
// the composite key + a tenant_id predicate on every read, so a tenant admin can never read another tenant's
// device reports. The store carries no enforcement weight; it is observability only, so Record is best-effort:
// a DB error is logged and dropped, never panicked or blocked on (the data-plane report path must not stall).
type postgresObservedExclusionStore struct {
	db *sql.DB
}

var _ observedExclusionStoreAPI = (*postgresObservedExclusionStore)(nil)

// observedExclusionColumns is the canonical column order shared by every SELECT/scan in this store. The
// trust-telemetry tail (031) travels with the rest deliberately: this backend once recorded the row and
// silently discarded exactly the fields the PKI gates decide on, which on postgres would have read as
// "every device silent, every retirement safe".
const observedExclusionColumns = "tenant_id, device_identity, device_group, platform, effective_app_signing_ids, admin_app_signing_ids, unmanaged_app_signing_ids, server_app_signing_id_count, reported_at, posture, fail_open_configured, region_failover_enabled, active_region, server_initiated_rule_count, pinned_transport_ca_sha256, adopted_trust_serial, pinned_interception_root_sha256, trust_refusals, fallback_client_cert_pem, agent_policy_public_keys, interception_root_pin_sha256, renewal_recovery_sni_sent, ignored_app_signing_ids, renewal_recovery_target, interception_refusals, transport_server_name_sent"

// observedExclusionOpTimeout bounds each best-effort DB operation so the report path can never block on a slow
// or wedged Postgres.
const observedExclusionOpTimeout = 5 * time.Second

// postgresObservedExclusionSchemaSQL is the in-code schema contract; migrations/027_observed_steer_exclusions.sql
// must match it (asserted by TestPostgresObservedExclusionMigrationMatchesSchemaSQL).
func postgresObservedExclusionSchemaSQL() []string {
	return []string{
		strings.Join([]string{
			"CREATE TABLE IF NOT EXISTS observed_steer_exclusions (",
			"tenant_id text NOT NULL,",
			"device_identity text NOT NULL,",
			"device_group text NOT NULL DEFAULT '',",
			"platform text NOT NULL DEFAULT '',",
			"effective_app_signing_ids jsonb NOT NULL DEFAULT '[]',",
			"admin_app_signing_ids jsonb NOT NULL DEFAULT '[]',",
			"unmanaged_app_signing_ids jsonb NOT NULL DEFAULT '[]',",
			"server_app_signing_id_count integer NOT NULL DEFAULT 0,",
			"reported_at timestamptz NOT NULL,",
			"posture text NOT NULL DEFAULT '',",
			"fail_open_configured boolean NOT NULL DEFAULT false,",
			"region_failover_enabled boolean NOT NULL DEFAULT false,",
			"active_region text NOT NULL DEFAULT '',",
			"server_initiated_rule_count integer NOT NULL DEFAULT 0,",
			"PRIMARY KEY (tenant_id, device_identity)",
			")",
		}, " "),
		"CREATE INDEX IF NOT EXISTS observed_steer_exclusions_tenant_reported_idx ON observed_steer_exclusions (tenant_id, reported_at DESC)",
		"CREATE INDEX IF NOT EXISTS observed_steer_exclusions_effective_gin ON observed_steer_exclusions USING gin (effective_app_signing_ids jsonb_path_ops)",
	}
}

// postgresObservedTrustTelemetrySchemaSQL is the in-code contract for migration 031 — the trust half of the
// report (pinned CAs, adopted serial, interception roots, refusals, fallback credential), which 027 predates.
// migrations/031_observed_trust_telemetry.sql must match it (asserted by
// TestPostgresObservedTrustTelemetryMigrationMatchesSchemaSQL).
func postgresObservedTrustTelemetrySchemaSQL() []string {
	return []string{
		"ALTER TABLE observed_steer_exclusions ADD COLUMN IF NOT EXISTS pinned_transport_ca_sha256 jsonb NOT NULL DEFAULT '[]'",
		"ALTER TABLE observed_steer_exclusions ADD COLUMN IF NOT EXISTS adopted_trust_serial bigint NOT NULL DEFAULT 0",
		"ALTER TABLE observed_steer_exclusions ADD COLUMN IF NOT EXISTS pinned_interception_root_sha256 jsonb NOT NULL DEFAULT '[]'",
		// The ONE root a device is PINNED to, as distinct from the ones it holds. Ending a replacement overlap
		// is decided by this column and cannot be decided by the one above — see migration 039.
		"ALTER TABLE observed_steer_exclusions ADD COLUMN IF NOT EXISTS interception_root_pin_sha256 text NOT NULL DEFAULT ''",
		"ALTER TABLE observed_steer_exclusions ADD COLUMN IF NOT EXISTS trust_refusals jsonb NOT NULL DEFAULT '[]'",
		"ALTER TABLE observed_steer_exclusions ADD COLUMN IF NOT EXISTS fallback_client_cert_pem text NOT NULL DEFAULT ''",
	}
}

// postgresObservedRecoveryNameSchemaSQL is the in-code contract for migration 042 — the recovery name a
// device says it holds, and what it received and deliberately did not apply.
//
// ★ BOTH EXISTED IN THE IN-MEMORY STORE AND IN NEITHER COLUMN. A deployment that turns on the durable backend
// does so because a decision has to survive a restart; dropping a reported field there makes that decision
// unanswerable while looking exactly like a fleet that says nothing.
func postgresObservedRecoveryNameSchemaSQL() []string {
	return []string{
		"ALTER TABLE observed_steer_exclusions ADD COLUMN IF NOT EXISTS renewal_recovery_sni_sent text NOT NULL DEFAULT ''",
		"ALTER TABLE observed_steer_exclusions ADD COLUMN IF NOT EXISTS ignored_app_signing_ids jsonb NOT NULL DEFAULT '[]'",
	}
}

// postgresObservedInterceptionRefusalsSchemaSQL is migration 045 — its own file for the reason 043 gives: an
// applied migration is history, and appending to one means nothing runs and every write is dropped with
// "column does not exist".
func postgresObservedInterceptionRefusalsSchemaSQL() []string {
	return []string{
		"ALTER TABLE observed_steer_exclusions ADD COLUMN IF NOT EXISTS interception_refusals jsonb NOT NULL DEFAULT '[]'",
		"ALTER TABLE observed_steer_exclusions ADD COLUMN IF NOT EXISTS transport_server_name_sent text NOT NULL DEFAULT ''",
	}
}

// postgresObservedRecoveryTargetSchemaSQL is the in-code contract for migration 043 — where a device would
// actually dial to recover, as distinct from the name it holds.
func postgresObservedRecoveryTargetSchemaSQL() []string {
	return []string{
		"ALTER TABLE observed_steer_exclusions ADD COLUMN IF NOT EXISTS renewal_recovery_target text NOT NULL DEFAULT ''",
	}
}

// postgresObservedAgentPolicyKeysSchemaSQL is the in-code contract for migration 032 — the accepted
// policy-signing key set, which the config-signing key rotation reads to know a switch is safe.
func postgresObservedAgentPolicyKeysSchemaSQL() []string {
	return []string{
		"ALTER TABLE observed_steer_exclusions ADD COLUMN IF NOT EXISTS agent_policy_public_keys jsonb NOT NULL DEFAULT '[]'",
	}
}

// setupPostgresObservedExclusionStore opens its own connection (defaulting to -postgres-dsn in main), pings
// it, applies the component migration, and returns the store plus a close func. It fails fast on a missing DSN
// or unreachable database rather than silently degrading.
func setupPostgresObservedExclusionStore(ctx context.Context, dsn, migrationDir string, runMigrations bool) (*postgresObservedExclusionStore, func() error, error) {
	if strings.TrimSpace(dsn) == "" {
		return nil, nil, fmt.Errorf("observed-exclusion-store-postgres-dsn is required")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, nil, err
	}
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, nil, err
	}
	if runMigrations {
		migrations, err := migrationstore.LoadDir(migrationDir)
		if err != nil {
			db.Close()
			return nil, nil, fmt.Errorf("load observed-exclusion migrations: %w", err)
		}
		migrations, err = selectPostgresComponentMigrations(migrations, "observed exclusions", postgresObservedExclusionMigrationVersions()...)
		if err != nil {
			db.Close()
			return nil, nil, err
		}
		if err := migrationstore.Apply(ctx, db, migrations); err != nil {
			db.Close()
			return nil, nil, fmt.Errorf("apply observed-exclusion migrations: %w", err)
		}
	}
	return &postgresObservedExclusionStore{db: db}, db.Close, nil
}

// Record UPSERTs a device's latest report (latest-wins; one row per (tenant, device)). It is best-effort: a DB
// error is logged and dropped so the data-plane report path never blocks or fails on the durable store.
func (p *postgresObservedExclusionStore) Record(e observedExclusionEntry) {
	if p == nil || p.db == nil {
		return
	}
	reportedAt := e.ReportedAt
	if reportedAt.IsZero() {
		reportedAt = time.Now().UTC()
	}
	ctx, cancel := context.WithTimeout(context.Background(), observedExclusionOpTimeout)
	defer cancel()
	_, err := p.db.ExecContext(ctx, strings.Join([]string{
		"INSERT INTO observed_steer_exclusions",
		"(" + observedExclusionColumns + ")",
		"VALUES ($1, $2, $3, $4, $5::jsonb, $6::jsonb, $7::jsonb, $8, $9::timestamptz, $10, $11, $12, $13, $14, $15::jsonb, $16, $17::jsonb, $18::jsonb, $19, $20::jsonb, $21, $22, $23::jsonb, $24, $25::jsonb, $26)",
		"ON CONFLICT (tenant_id, device_identity) DO UPDATE SET",
		"device_group = EXCLUDED.device_group,",
		"platform = EXCLUDED.platform,",
		"effective_app_signing_ids = EXCLUDED.effective_app_signing_ids,",
		"admin_app_signing_ids = EXCLUDED.admin_app_signing_ids,",
		"unmanaged_app_signing_ids = EXCLUDED.unmanaged_app_signing_ids,",
		"server_app_signing_id_count = EXCLUDED.server_app_signing_id_count,",
		"reported_at = EXCLUDED.reported_at,",
		"posture = EXCLUDED.posture,",
		"fail_open_configured = EXCLUDED.fail_open_configured,",
		"region_failover_enabled = EXCLUDED.region_failover_enabled,",
		"active_region = EXCLUDED.active_region,",
		"server_initiated_rule_count = EXCLUDED.server_initiated_rule_count,",
		"pinned_transport_ca_sha256 = EXCLUDED.pinned_transport_ca_sha256,",
		"adopted_trust_serial = EXCLUDED.adopted_trust_serial,",
		"pinned_interception_root_sha256 = EXCLUDED.pinned_interception_root_sha256,",
		"trust_refusals = EXCLUDED.trust_refusals,",
		"fallback_client_cert_pem = EXCLUDED.fallback_client_cert_pem,",
		"agent_policy_public_keys = EXCLUDED.agent_policy_public_keys,",
		"interception_root_pin_sha256 = EXCLUDED.interception_root_pin_sha256,",
		"renewal_recovery_sni_sent = EXCLUDED.renewal_recovery_sni_sent,",
		"ignored_app_signing_ids = EXCLUDED.ignored_app_signing_ids,",
		"renewal_recovery_target = EXCLUDED.renewal_recovery_target,",
		"interception_refusals = EXCLUDED.interception_refusals,",
		"transport_server_name_sent = EXCLUDED.transport_server_name_sent",
	}, " "),
		e.TenantID, e.DeviceIdentity, e.DeviceGroup, e.Platform,
		jsonArrayBytes(e.EffectiveAppSigningIDs), jsonArrayBytes(e.AdminAppSigningIDs), jsonArrayBytes(e.UnmanagedAppSigningIDs),
		e.ServerAppSigningIDCount, reportedAt.UTC(),
		e.Posture, e.FailOpenConfigured, e.RegionFailoverEnabled, e.ActiveRegion, e.ServerInitiatedRuleCount,
		jsonArrayBytes(e.PinnedTransportCASHA256), e.AdoptedTrustSerial,
		jsonArrayBytes(e.PinnedInterceptionRootSHA256), jsonTrustRefusalBytes(e.TrustRefusals), e.FallbackClientCertPEM,
		jsonArrayBytes(e.AgentPolicyPublicKeys), e.InterceptionRootPinSHA256, e.RenewalRecoverySNISent, jsonArrayBytes(e.IgnoredAppSigningIDs), e.RenewalRecoveryTarget,
		jsonTrustRefusalBytes(e.InterceptionRefusals), e.TransportServerNameSent)
	if err != nil {
		// ★★★ THIS IS "BEST-EFFORT" AND IT IS ALSO THE ONLY COPY (2026-08-22, measured after it dropped every
		// report from every device for fourteen hours). Not blocking the data path on a durable write is
		// right; letting the fleet go silent while one line per minute scrolls past is not. Every readiness
		// gate in this product is computed from these rows, so a device whose report is dropped here is
		// INDISTINGUISHABLE from a device that is switched off — and that is precisely how this looked: two
		// platforms "down", one of them investigated on the wrong continent.
		log.Printf("observed-exclusion: DROPPED the report from device %q tenant %q — this device now looks "+
			"SWITCHED OFF to every readiness gate, and no rotation, rename or retirement it is counted in can "+
			"complete: %v", e.DeviceIdentity, e.TenantID, err)
	}
}

// Query returns one filtered, paginated page (newest first) plus the total matching count, computing the filter
// + pagination IN THE DATABASE (the Phase-3 scale win): device (exact or `prefix*` via LIKE), group (exact,
// case-insensitive), app (case-insensitive membership in the effective set), and anomalous (≥1 unmanaged entry).
// On any DB error it logs and returns an empty result (observability, never fatal).
func (p *postgresObservedExclusionStore) Query(tenantID string, f observedQueryFilter) observedQueryResult {
	if p == nil || p.db == nil {
		return observedQueryResult{}
	}
	ctx, cancel := context.WithTimeout(context.Background(), observedExclusionOpTimeout)
	defer cancel()

	args := []any{}
	ph := func(v any) string { args = append(args, v); return "$" + strconv.Itoa(len(args)) }

	where := []string{"tenant_id = " + ph(tenantID)}
	if d := strings.TrimSpace(f.Device); d != "" {
		if strings.HasSuffix(d, "*") {
			prefix := strings.ToLower(strings.TrimSuffix(d, "*"))
			where = append(where, "lower(device_identity) LIKE "+ph(escapeLikePrefix(prefix)+"%")+" ESCAPE '\\'")
		} else {
			where = append(where, "lower(device_identity) = "+ph(strings.ToLower(d)))
		}
	}
	if g := strings.TrimSpace(f.Group); g != "" {
		where = append(where, "lower(device_group) = "+ph(strings.ToLower(g)))
	}
	if a := strings.TrimSpace(f.App); a != "" {
		where = append(where, "EXISTS (SELECT 1 FROM jsonb_array_elements_text(effective_app_signing_ids) elem WHERE lower(trim(elem)) = "+ph(strings.ToLower(a))+")")
	}
	if f.AnomalousOnly {
		where = append(where, "jsonb_array_length(unmanaged_app_signing_ids) > 0")
	}
	whereSQL := strings.Join(where, " AND ")

	var total int
	if err := p.db.QueryRowContext(ctx, "SELECT count(*) FROM observed_steer_exclusions WHERE "+whereSQL, args...).Scan(&total); err != nil {
		log.Printf("observed-exclusion: query count for tenant %q failed: %v", tenantID, err)
		return observedQueryResult{}
	}

	offset := f.Offset
	if offset < 0 || offset > total {
		offset = total
	}

	query := "SELECT " + observedExclusionColumns + " FROM observed_steer_exclusions WHERE " + whereSQL + " ORDER BY reported_at DESC, device_identity ASC OFFSET " + ph(offset)
	if f.Limit > 0 {
		query += " LIMIT " + ph(f.Limit)
	}
	rows, err := p.db.QueryContext(ctx, query, args...)
	if err != nil {
		log.Printf("observed-exclusion: query page for tenant %q failed: %v", tenantID, err)
		return observedQueryResult{}
	}
	defer rows.Close()
	entries := make([]observedExclusionEntry, 0)
	for rows.Next() {
		e, serr := scanObservedExclusionRow(rows.Scan)
		if serr != nil {
			log.Printf("observed-exclusion: scan row for tenant %q failed: %v", tenantID, serr)
			return observedQueryResult{}
		}
		entries = append(entries, e)
	}
	if err := rows.Err(); err != nil {
		log.Printf("observed-exclusion: iterate rows for tenant %q failed: %v", tenantID, err)
		return observedQueryResult{}
	}
	return observedQueryResult{Entries: entries, Total: total, Offset: offset}
}

// ByApp aggregates, fleet-wide, how many of a tenant's devices apply each effective AppID and its class. ByApp
// is inherently a full-tenant aggregation (the in-memory store also scans every device), so rather than
// duplicate the exact class/ordering/first-seen-casing logic in SQL, it loads the tenant's rows and DELEGATES to
// the in-memory store's ByApp — guaranteeing byte-for-byte parity with the in-memory backend. On a DB error it
// logs and returns an empty result.
func (p *postgresObservedExclusionStore) ByApp(tenantID string, limit int) observedByAppResult {
	if p == nil || p.db == nil {
		return observedByAppResult{}
	}
	rows, err := p.loadTenantRows(tenantID)
	if err != nil {
		log.Printf("observed-exclusion: by-app load for tenant %q failed: %v", tenantID, err)
		return observedByAppResult{}
	}
	mem := newObservedExclusionStore(0)
	for _, e := range rows {
		mem.Record(e)
	}
	return mem.ByApp(tenantID, limit)
}

// loadTenantRows returns every device report for one tenant (tenant-scoped by predicate).
func (p *postgresObservedExclusionStore) loadTenantRows(tenantID string) ([]observedExclusionEntry, error) {
	ctx, cancel := context.WithTimeout(context.Background(), observedExclusionOpTimeout)
	defer cancel()
	rows, err := p.db.QueryContext(ctx, "SELECT "+observedExclusionColumns+" FROM observed_steer_exclusions WHERE tenant_id = $1", tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]observedExclusionEntry, 0)
	for rows.Next() {
		e, serr := scanObservedExclusionRow(rows.Scan)
		if serr != nil {
			return nil, serr
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// scanObservedExclusionRow decodes a row in observedExclusionColumns order into an observedExclusionEntry; the
// three array columns are jsonb, reported_at is normalized to UTC.
func scanObservedExclusionRow(scan func(...any) error) (observedExclusionEntry, error) {
	var e observedExclusionEntry
	var eff, adm, unm, pinnedCAs, interceptionRoots, refusals, policyKeys, ignoredAppIDs, interceptionRefusalsRaw []byte
	var reportedAt time.Time
	if err := scan(&e.TenantID, &e.DeviceIdentity, &e.DeviceGroup, &e.Platform, &eff, &adm, &unm, &e.ServerAppSigningIDCount, &reportedAt,
		&e.Posture, &e.FailOpenConfigured, &e.RegionFailoverEnabled, &e.ActiveRegion, &e.ServerInitiatedRuleCount,
		&pinnedCAs, &e.AdoptedTrustSerial, &interceptionRoots, &refusals, &e.FallbackClientCertPEM, &policyKeys,
		&e.InterceptionRootPinSHA256, &e.RenewalRecoverySNISent, &ignoredAppIDs, &e.RenewalRecoveryTarget,
		&interceptionRefusalsRaw, &e.TransportServerNameSent); err != nil {
		return observedExclusionEntry{}, err
	}
	if err := decodeStringArray(eff, &e.EffectiveAppSigningIDs); err != nil {
		return observedExclusionEntry{}, fmt.Errorf("decode effective_app_signing_ids: %w", err)
	}
	if err := decodeStringArray(adm, &e.AdminAppSigningIDs); err != nil {
		return observedExclusionEntry{}, fmt.Errorf("decode admin_app_signing_ids: %w", err)
	}
	if err := decodeStringArray(unm, &e.UnmanagedAppSigningIDs); err != nil {
		return observedExclusionEntry{}, fmt.Errorf("decode unmanaged_app_signing_ids: %w", err)
	}
	if err := decodeStringArray(ignoredAppIDs, &e.IgnoredAppSigningIDs); err != nil {
		return observedExclusionEntry{}, fmt.Errorf("decode ignored_app_signing_ids: %w", err)
	}
	if err := decodeStringArray(pinnedCAs, &e.PinnedTransportCASHA256); err != nil {
		return observedExclusionEntry{}, fmt.Errorf("decode pinned_transport_ca_sha256: %w", err)
	}
	if err := decodeStringArray(interceptionRoots, &e.PinnedInterceptionRootSHA256); err != nil {
		return observedExclusionEntry{}, fmt.Errorf("decode pinned_interception_root_sha256: %w", err)
	}
	if len(interceptionRefusalsRaw) > 0 && string(interceptionRefusalsRaw) != "null" && string(interceptionRefusalsRaw) != "[]" {
		if err := json.Unmarshal(interceptionRefusalsRaw, &e.InterceptionRefusals); err != nil {
			return observedExclusionEntry{}, fmt.Errorf("decode interception_refusals: %w", err)
		}
	}
	if len(refusals) > 0 && string(refusals) != "null" && string(refusals) != "[]" {
		if err := json.Unmarshal(refusals, &e.TrustRefusals); err != nil {
			return observedExclusionEntry{}, fmt.Errorf("decode trust_refusals: %w", err)
		}
	}
	if err := decodeStringArray(policyKeys, &e.AgentPolicyPublicKeys); err != nil {
		return observedExclusionEntry{}, fmt.Errorf("decode agent_policy_public_keys: %w", err)
	}
	e.ReportedAt = reportedAt.UTC()
	return e, nil
}

// jsonTrustRefusalBytes marshals the refusal set for the jsonb column, normalizing empty to "[]" like the
// string-array columns.
func jsonTrustRefusalBytes(refusals []observedTrustRefusal) []byte {
	if len(refusals) == 0 {
		return []byte("[]")
	}
	b, err := json.Marshal(refusals)
	if err != nil || len(b) == 0 {
		return []byte("[]")
	}
	return b
}

// jsonArrayBytes marshals a string slice to a jsonb-ready array, normalizing nil/empty to "[]" so the NOT NULL
// column is always valid.
func jsonArrayBytes(ids []string) []byte {
	if len(ids) == 0 {
		return []byte("[]")
	}
	b, err := json.Marshal(ids)
	if err != nil || len(b) == 0 {
		return []byte("[]")
	}
	return b
}

// decodeStringArray unmarshals a jsonb array column into dst, tolerating empty/null bytes.
func decodeStringArray(raw []byte, dst *[]string) error {
	if len(raw) == 0 || string(raw) == "null" {
		*dst = nil
		return nil
	}
	return json.Unmarshal(raw, dst)
}

// escapeLikePrefix escapes LIKE metacharacters in a user-supplied device prefix so a `prefix*` filter matches
// literally (mirroring the in-memory strings.HasPrefix), using `\` as the LIKE ESCAPE.
func escapeLikePrefix(prefix string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return r.Replace(prefix)
}

// TransportCAReadiness answers CA-rotation readiness from the Postgres-backed telemetry.
//
// It reuses the in-memory computation over a Query snapshot rather than expressing the fingerprint match in
// SQL: the fleets this runs against are device-scale, not event-scale, and one implementation of "who is
// ready" cannot drift from the other. Getting a DIFFERENT answer here than from the file-backed store is the
// failure that matters — an operator would cut over on the strength of whichever backend they happened to ask.
func (s *postgresObservedExclusionStore) TransportCAReadiness(tenantID, sha256Hex string, knownDevices []string) transportCAReadiness {
	entries := s.Query(tenantID, observedQueryFilter{}).Entries
	snapshot := newObservedExclusionStore(len(entries) + 1)
	for _, e := range entries {
		snapshot.Record(e)
	}
	return snapshot.TransportCAReadiness(tenantID, sha256Hex, knownDevices)
}

func (s *postgresObservedExclusionStore) TransportCAReadinessAtSerial(tenantID, sha256Hex string,
	knownDevices []string, currentSerial int64) transportCAReadiness {
	entries := s.Query(tenantID, observedQueryFilter{}).Entries
	snapshot := newObservedExclusionStore(len(entries) + 1)
	for _, e := range entries {
		snapshot.Record(e)
	}
	return snapshot.TransportCAReadinessAtSerial(tenantID, sha256Hex, knownDevices, currentSerial)
}

// RecoveryNameReadiness answers from the same snapshot the rest of the durable telemetry is read through, so
// a deployment on Postgres cannot answer the port-closing question differently from one on the cache.
func (s *postgresObservedExclusionStore) RecoveryNameReadiness(tenantID, name string,
	knownDevices []string) recoveryNameReadiness {
	entries := s.Query(tenantID, observedQueryFilter{}).Entries
	snapshot := newObservedExclusionStore(len(entries) + 1)
	for _, e := range entries {
		snapshot.Record(e)
	}
	return snapshot.RecoveryNameReadiness(tenantID, name, knownDevices)
}
