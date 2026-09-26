package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"sync/atomic"
	"time"

	migrationstore "github.com/lantern-networks/dsse-core/migrations"
	"github.com/lantern-networks/dsse-core/model"
)

// Phase 4 : a Postgres backend for the cross-tenant tenant model
// catalog (the super-admin tenant profile store). It satisfies the same adminTenantModelAdminStore contract as
// the file/in-memory store, so the handlers are unchanged — only the backend differs. The connection is REUSED
// from the admin auth store (the control plane already owns that handle) so we never proliferate DB handles, and
// the tenant model store does not close it (admin auth owns the lifecycle). Every query is tenant-scoped; only
// List is cross-tenant (super-admin gated at the handler).
type postgresAdminTenantModelStore struct {
	db *sql.DB
	// operatorTenantID mirrors the file store: when non-empty (-operator-tenant-id) the matching tenant is stamped
	// IsOperator on read and seeded if absent. "" = feature off (lab default).
	operatorTenantID string
	// gen is the monotonic tenant-registry config version, bumped on every write that the config bundle carries.
	// Kept in memory rather than derived from Postgres, matching postgresNonHumanIdentityStore: it is a CHANGE
	// SIGNAL for the bundle's aggregate generation, not a durable fact, and a restart rewinding it is handled by
	// the bundle epoch. Zero-valued and used through sync/atomic, so the store needs no constructor change.
	gen uint64
}

var (
	_ adminTenantModelAdminStore   = (*postgresAdminTenantModelStore)(nil)
	_ adminTenantModelFleetCarrier = (*postgresAdminTenantModelStore)(nil)
	_ adminTenantModelFleetCarrier = (*adminTenantModelStore)(nil)
)

// adminTenantModelColumns is the canonical column order shared by every SELECT/scan in this store. is_operator is
// added by migration 024 (kept out of postgresAdminTenantModelSchemaSQL so the 023 schema-contract test still
// matches); it is a persisted cache of the derived operator flag — reads re-derive it from operatorTenantID.
const adminTenantModelColumns = "tenant_id, display_name, region, data_residency, allowed_regions, home_region, plan, status, policy_bundle_id, policy_bundle_version, metadata_key_count, is_operator, operator_managed, operator_delegation_changed_at, operator_delegation_changed_by, operator_delegation_withdrawn_by_customer, operator_elevation_requires_approval, operator_elevations, timezone, created_at, updated_at"

// postgresAdminTenantModelSchemaSQL is the in-code schema contract; migrations/023_admin_tenant_models.sql must
// match it (asserted by TestPostgresAdminTenantModelMigrationMatchesSchemaSQL).
func postgresAdminTenantModelSchemaSQL() []string {
	return []string{
		strings.Join([]string{
			"CREATE TABLE IF NOT EXISTS admin_tenant_models (",
			"tenant_id text NOT NULL,",
			"display_name text NOT NULL,",
			"region text NOT NULL DEFAULT '',",
			"data_residency text NOT NULL DEFAULT '',",
			"allowed_regions jsonb NOT NULL DEFAULT '[]',",
			"home_region text NOT NULL DEFAULT '',",
			"plan text NOT NULL DEFAULT '',",
			"status text NOT NULL CHECK (status IN ('active', 'suspended', 'archived')),",
			"policy_bundle_id text NOT NULL DEFAULT '',",
			"policy_bundle_version text NOT NULL DEFAULT '',",
			"metadata_key_count integer NOT NULL DEFAULT 0,",
			"created_at timestamptz NOT NULL,",
			"updated_at timestamptz NOT NULL,",
			"PRIMARY KEY (tenant_id)",
			")",
		}, " "),
		"CREATE INDEX IF NOT EXISTS admin_tenant_models_status_idx ON admin_tenant_models (status, tenant_id)",
	}
}

// setupPostgresAdminTenantModelStore wires the Postgres tenant model backend onto the admin auth connection. It
// requires admin-auth-store=postgres (the shared handle), applies the component migration, and seeds the active
// bundle tenant on first boot (matching the file store's seed-on-empty behavior). Returns an error — never falls
// back silently — so a misconfigured control plane fails fast instead of starting with the wrong backend.
func setupPostgresAdminTenantModelStore(ctx context.Context, adminAuthStore adminAuthRuntimeStore, migrationDir string, runMigrations bool, bundle model.PolicyBundle, operatorTenantID, importFrom string, now time.Time) (*postgresAdminTenantModelStore, error) {
	pg, ok := adminAuthStore.(postgresAdminAuthStore)
	if !ok || pg.DB == nil {
		return nil, fmt.Errorf("tenant-model-store=postgres requires admin-auth-store=postgres (it reuses that connection)")
	}
	if runMigrations {
		migrations, err := migrationstore.LoadDir(migrationDir)
		if err != nil {
			return nil, fmt.Errorf("load tenant-model migrations: %w", err)
		}
		migrations, err = selectPostgresComponentMigrations(migrations, "tenant models", postgresMigrationAdminTenantModel, postgresMigrationAdminTenantModelOperator, postgresMigrationAdminTenantModelDeletions,
			postgresMigrationAdminTenantModelDelegation, postgresMigrationAdminTenantModelEnvelope,
			postgresMigrationAdminTenantModelPurgeOrders, postgresMigrationAdminTenantModelDelegationWithdrawal)
		if err != nil {
			return nil, err
		}
		if err := migrationstore.Apply(ctx, pg.DB, migrations); err != nil {
			return nil, fmt.Errorf("apply tenant-model migrations: %w", err)
		}
	}
	store := &postgresAdminTenantModelStore{db: pg.DB, operatorTenantID: strings.TrimSpace(operatorTenantID)}
	// Before the seeds. The file's own row for the bundle tenant carries its real provenance and profile, and
	// seeding first would put a freshly-invented one in its way.
	if err := store.importFromFileSnapshot(ctx, importFrom); err != nil {
		return nil, err
	}
	if err := store.seedBundleTenant(ctx, bundle, now); err != nil {
		return nil, err
	}
	if err := store.seedOperatorTenant(ctx, now); err != nil {
		return nil, err
	}
	store.reportOrganizationsMissingFromTheCatalog(ctx)
	return store, nil
}

// reportOrganizationsMissingFromTheCatalog names the organizations that have administrators in this database but
// no row in the tenant catalog.
//
// ★ IT EXISTS BECAUSE SWITCHING -tenant-model-store FROM A FILE TO postgres CARRIES NOTHING (2026-08-18). This
// setup seeds exactly two rows — the bundle tenant and the operator tenant — and there is no import. Everything
// the file snapshot held stays in the file: the other organizations, and, more sharply, the TOMBSTONES and the
// ERASURE ORDERS. The file store's own comment states the consequence of losing a tombstone: "a tenant that
// vanishes on restart resurrects the tenant on the next bundle, because the Edge would stop being told about a
// deletion it had not yet applied."
//
// Measured on the reference deployment the night this was written: the file held 4 organizations, 26 tombstones
// and 28 erasure orders, while Postgres held one row — and two of the missing organizations had administrators
// sitting in admin_principals in the same database. Flipping the flag would have taken a paying customer's
// organization out of the catalog while its administrators still existed, and un-deleted 26 organizations.
//
// This does not refuse the boot. A control plane that will not start is an outage, and the discriminator is not
// exact enough to spend one: an organization deleted but not yet purged can legitimately leave principals
// behind, which would read the same. So it reports, by name, in the terms an operator can act on.
func (p *postgresAdminTenantModelStore) reportOrganizationsMissingFromTheCatalog(ctx context.Context) {
	rows, err := p.db.QueryContext(ctx, strings.Join([]string{
		"SELECT p.tenant_id, count(*) FROM admin_principals p",
		"LEFT JOIN admin_tenant_models t ON t.tenant_id = p.tenant_id",
		"WHERE t.tenant_id IS NULL AND coalesce(p.status, '') <> 'deleted'",
		"GROUP BY p.tenant_id ORDER BY p.tenant_id",
	}, " "))
	if err != nil {
		// Not fatal: this is a report, and a deployment whose admin_principals table is not there yet (a first
		// boot ordering the components differently) must still start.
		log.Printf("tenant catalog: could not compare the catalog against the administrators in this database: %v", err)
		return
	}
	defer rows.Close()
	var missing []string
	for rows.Next() {
		var tenantID string
		var principals int
		if err := rows.Scan(&tenantID, &principals); err != nil {
			log.Printf("tenant catalog: scanning the comparison failed: %v", err)
			return
		}
		missing = append(missing, fmt.Sprintf("%s (%d administrator(s))", tenantID, principals))
	}
	if err := rows.Err(); err != nil || len(missing) == 0 {
		return
	}
	log.Printf("★ tenant catalog: %d organization(s) have administrators in this database but NO row in the Postgres tenant catalog: %s. "+
		"If this control plane previously ran with -tenant-model-store pointed at a FILE, that file still holds those organizations, "+
		"the deletion tombstones and the standing erasure orders, and none of it was carried across — the organizations are absent "+
		"from every bundle this node publishes, and previously deleted organizations are no longer being named as deleted.",
		len(missing), strings.Join(missing, ", "))
}

// seedOperatorTenant inserts the operator tenant (display name "Operator", status active) when -operator-tenant-id
// is set and it is absent, mirroring the file store. Idempotent. No-op when the feature is off.
func (p *postgresAdminTenantModelStore) seedOperatorTenant(ctx context.Context, now time.Time) error {
	if p.operatorTenantID == "" {
		return nil
	}
	if _, ok, err := p.find(ctx, p.operatorTenantID); err != nil {
		return fmt.Errorf("probe operator tenant seed: %w", err)
	} else if ok {
		return nil
	}
	if _, err := p.Put(ctx, adminTenantModel{TenantID: p.operatorTenantID, DisplayName: "Operator", Status: "active"}, now); err != nil {
		return fmt.Errorf("seed operator tenant: %w", err)
	}
	return nil
}

// seedBundleTenant inserts the active policy bundle's tenant if it is absent, matching the file store which seeds
// from the bundle tenant on an empty snapshot. Idempotent: a second boot finds the row and does nothing.
func (p *postgresAdminTenantModelStore) seedBundleTenant(ctx context.Context, bundle model.PolicyBundle, now time.Time) error {
	tenantID := strings.TrimSpace(bundle.TenantID)
	if tenantID == "" {
		return nil
	}
	if _, ok, err := p.find(ctx, tenantID); err != nil {
		return fmt.Errorf("probe tenant model seed: %w", err)
	} else if ok {
		return nil
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	timestamp := now.UTC().Format(time.RFC3339)
	seed := adminTenantModel{
		TenantID:            tenantID,
		DisplayName:         tenantID,
		Status:              "active",
		PolicyBundleID:      strings.TrimSpace(bundle.ID),
		PolicyBundleVersion: strings.TrimSpace(bundle.Version),
		MetadataKeyCount:    len(bundle.Metadata),
		CreatedAt:           &timestamp,
		UpdatedAt:           &timestamp,
	}
	if _, err := p.Put(ctx, seed, now); err != nil {
		return fmt.Errorf("seed tenant model: %w", err)
	}
	return nil
}

// Get returns the tenant profile. A missing tenant yields a normalized default (active) — the same contract as
// the file store so the handler behaves identically across backends.
func (p *postgresAdminTenantModelStore) Get(ctx context.Context, tenantID string) (adminTenantModel, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return adminTenantModel{}, fmt.Errorf("tenant_id is required")
	}
	tenant, ok, err := p.find(ctx, tenantID)
	if err != nil {
		return adminTenantModel{}, err
	}
	if !ok {
		now := time.Now().UTC()
		normalized, nerr := normalizeAdminTenantModel(adminTenantModel{TenantID: tenantID, DisplayName: tenantID, Status: "active"}, tenantID, now)
		if nerr != nil {
			return adminTenantModel{}, nerr
		}
		return stampOperatorFlag(normalized, p.operatorTenantID), nil
	}
	return stampOperatorFlag(tenant, p.operatorTenantID), nil
}

// Update upserts the authenticated tenant's own profile (self-scoped). CreatedAt is preserved from the existing
// row when the caller omits it, so an edit never rewrites provenance.
func (p *postgresAdminTenantModelStore) Update(ctx context.Context, tenant adminTenantModel, tenantID string, now time.Time) (adminTenantModel, error) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if tenant.CreatedAt == nil {
		if existing, ok, err := p.find(ctx, strings.TrimSpace(tenantID)); err == nil && ok {
			tenant.CreatedAt = copyStringPtr(existing.CreatedAt)
		}
	}
	normalized, err := normalizeAdminTenantModel(tenant, tenantID, now)
	if err != nil {
		return adminTenantModel{}, err
	}
	if err := p.upsert(ctx, normalized); err != nil {
		return adminTenantModel{}, fmt.Errorf("%w: %v", errAdminTenantSaveUnconfirmed, err)
	}
	return stampOperatorFlag(normalized, p.operatorTenantID), nil
}

// List returns every tenant profile sorted by tenant_id (cross-tenant / super-admin surface).
func (p *postgresAdminTenantModelStore) List(ctx context.Context) ([]adminTenantModel, error) {
	rows, err := p.db.QueryContext(ctx, "SELECT "+adminTenantModelColumns+" FROM admin_tenant_models ORDER BY tenant_id ASC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []adminTenantModel{}
	for rows.Next() {
		tenant, err := scanAdminTenantModelRow(rows.Scan)
		if err != nil {
			return nil, err
		}
		out = append(out, stampOperatorFlag(tenant, p.operatorTenantID))
	}
	return out, rows.Err()
}

// Put creates or upserts a tenant by its OWN tenant_id (cross-tenant / super-admin surface). CreatedAt is
// preserved on an existing tenant so a super-admin edit never rewrites provenance.
func (p *postgresAdminTenantModelStore) Put(ctx context.Context, tenant adminTenantModel, now time.Time) (adminTenantModel, error) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	tenantID := strings.TrimSpace(tenant.TenantID)
	if tenantID == "" {
		return adminTenantModel{}, fmt.Errorf("tenant_id is required")
	}
	if tenant.CreatedAt == nil {
		if existing, ok, err := p.find(ctx, tenantID); err == nil && ok {
			tenant.CreatedAt = copyStringPtr(existing.CreatedAt)
		}
	}
	normalized, err := normalizeAdminTenantModel(tenant, tenantID, now)
	if err != nil {
		return adminTenantModel{}, err
	}
	if err := p.upsert(ctx, normalized); err != nil {
		return adminTenantModel{}, fmt.Errorf("%w: %v", errAdminTenantSaveUnconfirmed, err)
	}
	return stampOperatorFlag(normalized, p.operatorTenantID), nil
}

// Delete removes a tenant profile (cross-tenant / super-admin surface). Removing a non-existent tenant is an
// idempotent success, matching the file store.
func (p *postgresAdminTenantModelStore) Delete(ctx context.Context, tenantID string) error {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return fmt.Errorf("tenant_id is required")
	}
	// The profile and its carried deletion are one committed change. Otherwise a
	// failed tombstone write removes it from the CP while leaving Edge copies live.
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("%w: %v", errAdminTenantSaveUnconfirmed, err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, "DELETE FROM admin_tenant_models WHERE tenant_id = $1", tenantID); err != nil {
		return fmt.Errorf("%w: %v", errAdminTenantSaveUnconfirmed, err)
	}
	// Record the tombstone (migration 038). Written even when the row was already absent: that is the ghost
	// case, where the control plane no longer holds the tenant but an Edge still does, and naming the deletion
	// is the only way to say so. See DeletedTenants for why absence cannot be used instead.
	_, err = tx.ExecContext(ctx,
		"INSERT INTO admin_tenant_model_deletions (tenant_id, deleted_at) VALUES ($1, now()) "+
			"ON CONFLICT (tenant_id) DO UPDATE SET deleted_at = EXCLUDED.deleted_at",
		tenantID)
	if err != nil {
		return fmt.Errorf("%w: %v", errAdminTenantSaveUnconfirmed, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("%w: %v", errAdminTenantSaveUnconfirmed, err)
	}
	atomic.AddUint64(&p.gen, 1) // publish only the confirmed transaction
	return nil
}

// DeletedTenants returns the carried deletions, oldest id first. The config bundle publishes these so an Edge
// removes a tenant because it was named, not because it was missing — the section UPSERTs, and inferring a
// deletion from an absent entry would turn a truncated payload into a wipe.
func (p *postgresAdminTenantModelStore) DeletedTenants() []tenantDeletion {
	rows, err := p.db.QueryContext(context.Background(),
		"SELECT tenant_id, deleted_at FROM admin_tenant_model_deletions ORDER BY tenant_id")
	if err != nil {
		// Publishing an empty list here means deletions stop propagating until the query works again. That is
		// the safe direction (nothing is deleted that should not be), but it is silent, so it is logged.
		log.Printf("tenant tombstones: reading admin_tenant_model_deletions failed, so this bundle carries NO deletions: %v", err)
		return nil
	}
	defer rows.Close()
	out := []tenantDeletion{}
	for rows.Next() {
		var tenantID string
		var deletedAt time.Time
		if err := rows.Scan(&tenantID, &deletedAt); err != nil {
			log.Printf("tenant tombstones: scanning a deletion row failed: %v", err)
			return nil
		}
		out = append(out, tenantDeletion{TenantID: tenantID, DeletedAt: deletedAt.UTC().Format(time.RFC3339)})
	}
	if err := rows.Err(); err != nil {
		log.Printf("tenant tombstones: iterating deletions failed, so this bundle carries NO deletions: %v", err)
		return nil
	}
	return out
}

// ConfigGeneration returns the monotonic tenant-registry config version, bumped on every write the bundle
// carries (Put, Update, Delete, OrderPurge). It feeds the config bundle's aggregate generation, which is how an
// Edge decides a bundle is worth applying — so while this returned a constant 0, a tenant-only change was
// published as a bundle with an unchanged aggregate version.
func (p *postgresAdminTenantModelStore) ConfigGeneration() uint64 {
	return atomic.LoadUint64(&p.gen)
}

// OrderPurge records that an operator has ordered this tenant ERASED, so the order can be carried to every node
// that ever held its data. Idempotent, and the FIRST instant wins: ordering twice is not a new fact, and a
// moving timestamp would make the audit harder to read. ON CONFLICT DO NOTHING is what keeps it first.
func (p *postgresAdminTenantModelStore) OrderPurge(tenantID string, now time.Time) error {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return fmt.Errorf("tenant_id is required")
	}
	result, err := p.db.ExecContext(context.Background(),
		"INSERT INTO admin_tenant_model_purge_orders (tenant_id, ordered_at) VALUES ($1, $2) "+
			"ON CONFLICT (tenant_id) DO NOTHING", tenantID, now.UTC())
	if err != nil {
		return fmt.Errorf("%w: %v", errAdminTenantSaveUnconfirmed, err)
	}
	n, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("%w: %v", errAdminTenantSaveUnconfirmed, err)
	}
	if n > 0 {
		atomic.AddUint64(&p.gen, 1)
	}
	return nil
}

// PurgeOrders returns the standing erasure orders, oldest id first. They are never cleared: an Edge that was
// offline when the order was given is only ever told by this list, and an order that disappears once "most"
// nodes have acted is how one node quietly keeps a customer's data.
func (p *postgresAdminTenantModelStore) PurgeOrders() []tenantPurgeOrder {
	rows, err := p.db.QueryContext(context.Background(),
		"SELECT tenant_id, ordered_at FROM admin_tenant_model_purge_orders ORDER BY tenant_id")
	if err != nil {
		// Same direction as DeletedTenants: publishing an empty list stops orders propagating until the query
		// works again, which erases nothing that should not be erased — but it is silent, so it is logged.
		log.Printf("tenant purge orders: reading admin_tenant_model_purge_orders failed, so this bundle carries NO erasure orders: %v", err)
		return nil
	}
	defer rows.Close()
	out := []tenantPurgeOrder{}
	for rows.Next() {
		var tenantID string
		var orderedAt time.Time
		if err := rows.Scan(&tenantID, &orderedAt); err != nil {
			log.Printf("tenant purge orders: scanning an order row failed: %v", err)
			return nil
		}
		out = append(out, tenantPurgeOrder{TenantID: tenantID, OrderedAt: orderedAt.UTC().Format(time.RFC3339)})
	}
	if err := rows.Err(); err != nil {
		log.Printf("tenant purge orders: iterating orders failed, so this bundle carries NO erasure orders: %v", err)
		return nil
	}
	return out
}

// find loads a single tenant by id. ok=false (no error) when the row is absent.
func (p *postgresAdminTenantModelStore) find(ctx context.Context, tenantID string) (adminTenantModel, bool, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return adminTenantModel{}, false, fmt.Errorf("tenant_id is required")
	}
	row := p.db.QueryRowContext(ctx, "SELECT "+adminTenantModelColumns+" FROM admin_tenant_models WHERE tenant_id = $1", tenantID)
	tenant, err := scanAdminTenantModelRow(row.Scan)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return adminTenantModel{}, false, nil
		}
		return adminTenantModel{}, false, err
	}
	return tenant, true, nil
}

// upsert writes a normalized tenant, preserving created_at on conflict and advancing updated_at.
func (p *postgresAdminTenantModelStore) upsert(ctx context.Context, tenant adminTenantModel) error {
	regions, err := json.Marshal(tenant.AllowedRegions)
	if err != nil {
		return err
	}
	// The elevations travel as the row's own jsonb rather than a side table, for the reason the model states:
	// an elevation decided on whichever node the operator reached is the per-Edge shape this repository has
	// already paid for twice. nil marshals to "null", and a null column would make every read that decodes it
	// carry a nil list from a row that says nothing — so an absent history is written as the empty list it is.
	//
	// Granting an elevation is therefore a read-modify-write of this column, and two grants racing would lose
	// one. That is the file store's shape too, and the control plane is active/standby (§HA), so there is one
	// writer — but it is a property of the choice rather than an accident, and a side table is the answer if
	// the control plane ever writes from two nodes at once.
	elevations, err := json.Marshal(tenant.OperatorElevations)
	if err != nil {
		return err
	}
	if len(tenant.OperatorElevations) == 0 {
		elevations = []byte("[]")
	}
	createdAt, err := parseAdminAuthRequiredTime(derefStringPtr(tenant.CreatedAt), "tenant model created_at")
	if err != nil {
		return err
	}
	updatedAt, err := parseAdminAuthRequiredTime(derefStringPtr(tenant.UpdatedAt), "tenant model updated_at")
	if err != nil {
		return err
	}
	isOperator := p.operatorTenantID != "" && tenant.TenantID == p.operatorTenantID
	// ★ THE STANDING DELEGATION TRAVELS WITH THE ROW (2026-08-17). It did not: this store wrote fourteen
	// columns and the delegation was not among them, so PUT /admin/operator-delegation returned 200 and the
	// next read answered false. In the backend the deployment documentation names for production, an
	// organization could grant the operator its management and nothing would happen — and the organization's
	// own screen would say "not allowed" one second after it allowed it.
	//
	// The stamp is nullable because "never moved" and "moved at the zero time" are different facts, and a
	// column that cannot tell them apart is how a delegation nobody has ever touched reads as freshly granted.
	var delegationChangedAt any
	if at := derefStringPtr(tenant.OperatorDelegationChangedAt); strings.TrimSpace(at) != "" {
		parsed, perr := parseAdminAuthRequiredTime(at, "operator delegation changed_at")
		if perr != nil {
			return perr
		}
		delegationChangedAt = parsed.UTC()
	}
	delegationChangedBy := derefStringPtr(tenant.OperatorDelegationChangedBy)
	_, err = p.db.ExecContext(ctx, strings.Join([]string{
		"INSERT INTO admin_tenant_models",
		"(" + adminTenantModelColumns + ")",
		// ★ THE PLACEHOLDERS ARE PART OF THE COLUMN LIST (2026-08-20, found in one live call and in no test).
		// Adding operator_delegation_withdrawn_by_customer to the columns and to the arguments without adding
		// $17 here produced "got 21 parameters but the statement requires 20" — on the Postgres backend only,
		// which every unit test in this package replaces with the file store. Same family as 039/040: the
		// production store is the one nothing exercises.
		"VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7, $8, $9, $10, $11, $12, $13, $14::timestamptz, $15, $16, $17, $18::jsonb, $19, $20::timestamptz, $21::timestamptz)",
		"ON CONFLICT (tenant_id) DO UPDATE SET",
		"display_name = EXCLUDED.display_name,",
		"region = EXCLUDED.region,",
		"data_residency = EXCLUDED.data_residency,",
		"allowed_regions = EXCLUDED.allowed_regions,",
		"home_region = EXCLUDED.home_region,",
		"plan = EXCLUDED.plan,",
		"status = EXCLUDED.status,",
		"policy_bundle_id = EXCLUDED.policy_bundle_id,",
		"policy_bundle_version = EXCLUDED.policy_bundle_version,",
		"metadata_key_count = EXCLUDED.metadata_key_count,",
		"is_operator = EXCLUDED.is_operator,",
		"operator_managed = EXCLUDED.operator_managed,",
		"operator_delegation_changed_at = EXCLUDED.operator_delegation_changed_at,",
		"operator_delegation_changed_by = EXCLUDED.operator_delegation_changed_by,",
		"operator_delegation_withdrawn_by_customer = EXCLUDED.operator_delegation_withdrawn_by_customer,",
		"operator_elevation_requires_approval = EXCLUDED.operator_elevation_requires_approval,",
		"operator_elevations = EXCLUDED.operator_elevations,",
		"timezone = EXCLUDED.timezone,",
		"updated_at = EXCLUDED.updated_at",
	}, " "),
		tenant.TenantID, tenant.DisplayName, tenant.Region, tenant.DataResidency, string(regions),
		tenant.HomeRegion, tenant.Plan, tenant.Status, tenant.PolicyBundleID, tenant.PolicyBundleVersion,
		tenant.MetadataKeyCount, isOperator, tenant.OperatorManaged, delegationChangedAt, delegationChangedBy,
		tenant.OperatorDelegationWithdrawnByCustomer, tenant.OperatorElevationRequiresApproval, string(elevations), tenant.Timezone,
		createdAt.UTC(), updatedAt.UTC())
	if err != nil {
		return err
	}
	// A re-creation supersedes the deletion. Leaving the tombstone behind would put the tenant into the next
	// bundle as both present and deleted, and the receiving Edge refuses that pair rather than guessing.
	_, err = p.db.ExecContext(ctx, "DELETE FROM admin_tenant_model_deletions WHERE tenant_id = $1", tenant.TenantID)
	if err == nil {
		// Bumped here rather than in Put and Update separately, so no future write path can add itself to the
		// registry without advancing the version the fleet uses to decide a bundle is worth applying.
		atomic.AddUint64(&p.gen, 1)
	}
	return err
}

// scanAdminTenantModelRow decodes a row in adminTenantModelColumns order into an adminTenantModel, rendering the
// timestamptz columns back to RFC3339 strings (the model's wire shape).
func scanAdminTenantModelRow(scan func(...any) error) (adminTenantModel, error) {
	var tenant adminTenantModel
	var regions []byte
	var elevations []byte
	var createdAt, updatedAt time.Time
	var delegationChangedAt sql.NullTime
	var delegationChangedBy string
	if err := scan(
		&tenant.TenantID, &tenant.DisplayName, &tenant.Region, &tenant.DataResidency, &regions,
		&tenant.HomeRegion, &tenant.Plan, &tenant.Status, &tenant.PolicyBundleID, &tenant.PolicyBundleVersion,
		&tenant.MetadataKeyCount, &tenant.IsOperator, &tenant.OperatorManaged, &delegationChangedAt, &delegationChangedBy,
		&tenant.OperatorDelegationWithdrawnByCustomer, &tenant.OperatorElevationRequiresApproval, &elevations, &tenant.Timezone,
		&createdAt, &updatedAt,
	); err != nil {
		return adminTenantModel{}, err
	}
	if len(regions) > 0 {
		if err := json.Unmarshal(regions, &tenant.AllowedRegions); err != nil {
			return adminTenantModel{}, fmt.Errorf("decode allowed_regions: %w", err)
		}
	}
	if len(elevations) > 0 {
		if err := json.Unmarshal(elevations, &tenant.OperatorElevations); err != nil {
			return adminTenantModel{}, fmt.Errorf("decode operator_elevations: %w", err)
		}
	}
	if delegationChangedAt.Valid {
		changed := delegationChangedAt.Time.UTC().Format(time.RFC3339)
		tenant.OperatorDelegationChangedAt = &changed
	}
	if strings.TrimSpace(delegationChangedBy) != "" {
		by := delegationChangedBy
		tenant.OperatorDelegationChangedBy = &by
	}
	created := createdAt.UTC().Format(time.RFC3339)
	tenant.CreatedAt = &created
	updated := updatedAt.UTC().Format(time.RFC3339)
	tenant.UpdatedAt = &updated
	return tenant, nil
}

func derefStringPtr(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

// importFromFileSnapshot carries a file-store snapshot into Postgres when the control plane is moved onto the
// shared backend (-tenant-model-store=postgres+import:<path>). It is ADDITIVE: a row Postgres already holds is
// never touched, so the shared store stays the authority and a stale file on one node can never overwrite it.
// Idempotent by construction — a second boot finds every row present and writes nothing.
//
// All three sections travel, because all three are how this node tells the fleet about an organization:
//
//	tenants       the catalog itself. Without it the organizations simply cease to exist, while their
//	              administrators keep sitting in admin_principals in the same database.
//	tombstones    ★ the deletions, BY NAME. The bundle's tenant section upserts, so a deletion only travels if
//	              it is named — and the file store's own comment is that a tombstone which vanishes "resurrects
//	              the tenant on the next bundle". Measured on the reference deployment: 26 of them.
//	purge orders  the standing erasure orders. A node that has not yet erased a terminated tenant is only ever
//	              told by this list. Measured on the same deployment: 28.
//
// A named source that cannot be read is a REFUSAL, not a warning: continuing would produce a control plane that
// looks like a clean move and has quietly forgotten every deletion it ever carried.
func (p *postgresAdminTenantModelStore) importFromFileSnapshot(ctx context.Context, sourcePath string) error {
	sourcePath = strings.TrimSpace(sourcePath)
	if sourcePath == "" {
		return nil
	}
	if _, err := os.Stat(sourcePath); errors.Is(err, os.ErrNotExist) {
		log.Printf("tenant catalog import: nothing to carry across — %s does not exist", sourcePath)
		return nil
	} else if err != nil {
		return fmt.Errorf("tenant catalog import: %s is named as the source but could not be examined: %w", sourcePath, err)
	}
	tenants, tombstones, orders, ok := loadAdminTenantModelSnapshot(sourcePath)
	if !ok {
		// loadAdminTenantModelSnapshot folds "unreadable", "not JSON" and "no tenants key" into one false, and
		// any of them means the operator named a file this cannot carry. Starting empty here is the failure.
		return fmt.Errorf("tenant catalog import: %s could not be read as a tenant-model snapshot, and starting with an empty catalog would look identical to a successful move", sourcePath)
	}

	imported, skipped, filled := 0, 0, 0
	for tenantID, tenant := range tenants {
		if existing, present, err := p.find(ctx, tenantID); err != nil {
			return fmt.Errorf("tenant catalog import: probing %q failed: %w", tenantID, err)
		} else if present {
			skipped++
			// ★ A ROW THAT IS ALREADY THERE CAN STILL BE MISSING SETTINGS (2026-08-18, measured on the first
			// real move). The reference control plane had ONE row in Postgres — a seed written by an earlier
			// boot, carrying nothing but the id — and the additive rule left it exactly as it was, so the
			// organization's own timezone silently did not survive the move. "Never overwrite what the shared
			// store holds" is right, and an EMPTY field holds nothing: filling one takes nothing away from
			// anybody, and dropping a setting an administrator chose is the failure this whole path exists to
			// prevent. Every field that is filled is named in the log; nothing non-empty is touched.
			merged, names := mergeEmptyTenantFields(existing, tenant)
			if len(names) > 0 {
				if _, err := p.Put(ctx, merged, time.Now().UTC()); err != nil {
					return fmt.Errorf("tenant catalog import: filling %v on %q failed: %w", names, tenantID, err)
				}
				log.Printf("★ tenant catalog import: %q was already in the shared store but held nothing for %v — filled from %s (fields the shared store already had were left alone)",
					tenantID, names, sourcePath)
				filled++
			}
			continue
		}
		// Put rather than a raw insert, so normalisation and the operator flag are applied exactly as they are
		// for any other write. CreatedAt travels with the row, so provenance is not rewritten by the move.
		if _, err := p.Put(ctx, tenant, time.Now().UTC()); err != nil {
			return fmt.Errorf("tenant catalog import: carrying organization %q failed: %w", tenantID, err)
		}
		imported++
	}

	// The tombstones go in after the tenants, because upsert() DELETES a tombstone for any tenant it writes —
	// a re-creation supersedes a deletion. Writing them first would have the import erase its own tombstones.
	carriedDeletions := 0
	for tenantID, deletedAt := range tombstones {
		if _, err := p.db.ExecContext(ctx,
			"INSERT INTO admin_tenant_model_deletions (tenant_id, deleted_at) VALUES ($1, $2::timestamptz) ON CONFLICT (tenant_id) DO NOTHING",
			strings.TrimSpace(tenantID), strings.TrimSpace(deletedAt)); err != nil {
			return fmt.Errorf("tenant catalog import: carrying the deletion of %q failed, and a deletion that does not travel un-deletes the organization on every node that has not applied it: %w", tenantID, err)
		}
		carriedDeletions++
	}

	carriedOrders := 0
	for tenantID, orderedAt := range orders {
		if _, err := p.db.ExecContext(ctx,
			"INSERT INTO admin_tenant_model_purge_orders (tenant_id, ordered_at) VALUES ($1, $2::timestamptz) ON CONFLICT (tenant_id) DO NOTHING",
			strings.TrimSpace(tenantID), strings.TrimSpace(orderedAt)); err != nil {
			return fmt.Errorf("tenant catalog import: carrying the erasure order for %q failed: %w", tenantID, err)
		}
		carriedOrders++
	}

	if imported+carriedDeletions+carriedOrders+filled > 0 {
		log.Printf("★ tenant catalog import: carried %d organization(s), %d deletion tombstone(s) and %d erasure order(s) from %s into the shared store (%d organization(s) were already there; %d of them had empty settings filled in)",
			imported, carriedDeletions, carriedOrders, sourcePath, skipped, filled)
	}
	atomic.AddUint64(&p.gen, 1)
	return nil
}

// mergeEmptyTenantFields returns `existing` with every EMPTY field taken from `carried`, plus the names of the
// fields that were filled. A field the shared store already holds is never touched — this is the difference
// between "the shared store is the authority" and "the shared store is the only thing that ever existed".
//
// Status is deliberately absent: it is NOT NULL with a CHECK, so it is never empty, and a status is a decision
// rather than a setting. IsOperator is derived on read. CreatedAt is filled because provenance that reads as
// "created at the moment of the migration" is worse than no answer.
func mergeEmptyTenantFields(existing, carried adminTenantModel) (adminTenantModel, []string) {
	var filled []string
	fill := func(name string, empty bool, apply func()) {
		if empty {
			apply()
			filled = append(filled, name)
		}
	}
	// The seed writes display_name = tenant_id, so a name that is still the id holds nothing an administrator
	// chose — but only take the file's if IT says something different, or this trades one placeholder for another.
	if (strings.TrimSpace(existing.DisplayName) == "" || existing.DisplayName == existing.TenantID) &&
		strings.TrimSpace(carried.DisplayName) != "" && carried.DisplayName != carried.TenantID {
		existing.DisplayName = carried.DisplayName
		filled = append(filled, "display_name")
	}
	fill("timezone", strings.TrimSpace(existing.Timezone) == "" && strings.TrimSpace(carried.Timezone) != "",
		func() { existing.Timezone = carried.Timezone })
	fill("region", strings.TrimSpace(existing.Region) == "" && strings.TrimSpace(carried.Region) != "",
		func() { existing.Region = carried.Region })
	fill("data_residency", strings.TrimSpace(existing.DataResidency) == "" && strings.TrimSpace(carried.DataResidency) != "",
		func() { existing.DataResidency = carried.DataResidency })
	fill("home_region", strings.TrimSpace(existing.HomeRegion) == "" && strings.TrimSpace(carried.HomeRegion) != "",
		func() { existing.HomeRegion = carried.HomeRegion })
	fill("plan", strings.TrimSpace(existing.Plan) == "" && strings.TrimSpace(carried.Plan) != "",
		func() { existing.Plan = carried.Plan })
	fill("allowed_regions", len(existing.AllowedRegions) == 0 && len(carried.AllowedRegions) > 0,
		func() { existing.AllowedRegions = append([]string(nil), carried.AllowedRegions...) })
	// ★ The delegation and its history: false/absent in the shared store is indistinguishable from "never
	// granted", and that is exactly what the file can settle. Filling it CANNOT widen anything on its own — the
	// operator envelope still needs the customer's own record, which is what these fields ARE.
	//
	// ★★★ EXCEPT ONCE THE ORGANIZATION HAS WRITTEN IT (2026-08-20, measured on the running lab). Northwind
	// withdrew its delegation through the API; the row read false; the control plane was restarted; the row
	// read true again. Nobody performed an act, so there is no audit entry and no actor — the operator simply
	// had it back. Measured immediately after the operator decided that an MSSP operator may not reopen what
	// the customer closed: the API door was shut and this one was still open.
	//
	// The premise above is right for a row that has never been written and wrong for one that has. A false
	// that arrived through a decision is not an absence, and the fact that says which is already stored: the
	// delegation carries when it last moved. So the file settles a row nobody has touched, and never overrides
	// a customer.
	delegationNeverWritten := existing.OperatorDelegationChangedAt == nil && !existing.OperatorDelegationWithdrawnByCustomer
	fill("operator_managed", delegationNeverWritten && !existing.OperatorManaged && carried.OperatorManaged,
		func() { existing.OperatorManaged = true })
	// And the withdrawal itself is carried, or a file→Postgres migration would lose the one bit the reopen rule
	// rests on and the operator could grant it again on the far side of the switch.
	fill("operator_delegation_withdrawn_by_customer",
		!existing.OperatorDelegationWithdrawnByCustomer && carried.OperatorDelegationWithdrawnByCustomer,
		func() { existing.OperatorDelegationWithdrawnByCustomer = true })
	fill("operator_elevations", len(existing.OperatorElevations) == 0 && len(carried.OperatorElevations) > 0,
		func() { existing.OperatorElevations = append([]operatorElevation(nil), carried.OperatorElevations...) })
	fill("operator_elevation_requires_approval", !existing.OperatorElevationRequiresApproval && carried.OperatorElevationRequiresApproval,
		func() { existing.OperatorElevationRequiresApproval = true })
	fill("created_at", existing.CreatedAt == nil && carried.CreatedAt != nil,
		func() { existing.CreatedAt = copyStringPtr(carried.CreatedAt) })
	return existing, filled
}
