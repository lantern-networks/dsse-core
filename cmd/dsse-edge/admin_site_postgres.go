package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	migrationstore "github.com/lantern-networks/dsse-core/migrations"
)

// admin_site_postgres.go — Connector UX Slice 1b Postgres backend for the persistent Site / Connector Group
// store. It satisfies the same adminSiteStore contract as the file/in-memory store, so the handlers are unchanged;
// only the backend differs. The connection is REUSED from the admin auth store (the control plane already owns
// that handle) exactly like the tenant model store, so no extra DB handle is opened and this store never closes
// it. Every query is tenant-scoped: the primary key is (tenant_id, site_id) and every statement filters on
// tenant_id, so a tenant can never read or mutate another tenant's Sites.
type postgresAdminSiteStore struct {
	db *sql.DB
	// lastGeneration is the last generation this process published for the Site catalogue. It is what
	// ConfigGeneration falls back to when the database cannot be reached, so a blip cannot make the bundle's
	// version go backwards and freeze every Edge's configuration.
	lastGeneration atomic.Uint64
	// ★★★ THE SEQUENCE IS NOT MONOTONIC ACROSS A CHANGE OF PRIMARY (2026-11-15, measured on a three-region
	// rolling upgrade). PostgreSQL ships a sequence to its replicas logged ahead — about thirty-two values past
	// the one in use — so a replica that is promoted carries on from the logged value, and the old primary,
	// when it leads again, carries on from the value it really had. The primary moved a -> b -> c -> a; this
	// process read 52 while b led and 19 once a led again, and remembering the larger number froze the Site
	// catalogue's term: Sites created, rotated or deleted after the upgrade reached no Edge (no connector could
	// enrol, and a deleted Site's bootstrap secret stayed accepted) until thirty-odd more Site writes or an
	// unrelated change moved the bundle. The generation an Edge compares is this PROCESS's number (the epoch
	// beside it changes with the process), so it has to move whenever the counter moves, in either direction:
	// rawSeen/lastRaw/offset turn the counter into that.
	generationMu sync.Mutex
	rawSeen      bool
	lastRaw      uint64
	offset       uint64
}

var _ adminSiteStore = (*postgresAdminSiteStore)(nil)

// adminSiteColumns is the canonical column order shared by every SELECT/scan in this store.
const adminSiteColumns = "tenant_id, site_id, name, region, expected_connector_count, routing_namespace, deployment_type, ha_policy, bootstrap_secret_hash, bootstrap_secret_rotated_at, created_at, updated_at, door_order"

// postgresAdminSiteSchemaSQL is the in-code schema contract; migrations/025_admin_sites.sql must match it
// (asserted by TestPostgresAdminSiteMigrationMatchesSchemaSQL).
func postgresAdminSiteSchemaSQL() []string {
	return []string{
		strings.Join([]string{
			"CREATE TABLE IF NOT EXISTS admin_sites (",
			"tenant_id text NOT NULL,",
			"site_id text NOT NULL,",
			"name text NOT NULL DEFAULT '',",
			"region text NOT NULL DEFAULT '',",
			"expected_connector_count integer NOT NULL DEFAULT 0,",
			"routing_namespace text NOT NULL DEFAULT '',",
			"deployment_type text NOT NULL DEFAULT '',",
			"ha_policy text NOT NULL DEFAULT '',",
			"bootstrap_secret_hash text NOT NULL DEFAULT '',",
			"bootstrap_secret_rotated_at timestamptz,",
			"created_at timestamptz NOT NULL,",
			"updated_at timestamptz NOT NULL,",
			"PRIMARY KEY (tenant_id, site_id)",
			")",
		}, " "),
		"CREATE INDEX IF NOT EXISTS admin_sites_tenant_idx ON admin_sites (tenant_id, site_id)",
	}
}

// postgresAdminSiteDoorOrderSQL is migrations/061_admin_site_door_order.sql, held here as the 025 contract is
// (asserted by TestPostgresAdminSiteDoorOrderMigrationMatches).
func postgresAdminSiteDoorOrderSQL() []string {
	return []string{"ALTER TABLE admin_sites ADD COLUMN IF NOT EXISTS door_order text NOT NULL DEFAULT ''"}
}

// setupPostgresAdminSiteStore wires the Postgres Site backend onto the admin auth connection. It requires
// admin-auth-store=postgres (the shared handle) and applies the component migration. Returns an error — never
// falls back silently — so a misconfigured control plane fails fast instead of starting with the wrong backend.
func setupPostgresAdminSiteStore(ctx context.Context, adminAuthStore adminAuthRuntimeStore, migrationDir string, runMigrations bool) (*postgresAdminSiteStore, error) {
	pg, ok := adminAuthStore.(postgresAdminAuthStore)
	if !ok || pg.DB == nil {
		return nil, fmt.Errorf("site-store=postgres requires admin-auth-store=postgres (it reuses that connection)")
	}
	if runMigrations {
		migrations, err := migrationstore.LoadDir(migrationDir)
		if err != nil {
			return nil, fmt.Errorf("load site migrations: %w", err)
		}
		migrations, err = selectPostgresComponentMigrations(migrations, "sites", postgresAdminSiteMigrationVersions()...)
		if err != nil {
			return nil, err
		}
		if err := migrationstore.Apply(ctx, pg.DB, migrations); err != nil {
			return nil, fmt.Errorf("apply site migrations: %w", err)
		}
	}
	// ★★★ THE COUNTER THE BUNDLE'S VERSION IS BUILT FROM. Without it, authoring a Site changes the bundle's
	// CONTENTS and not its VERSION, and no Edge ever re-pulls — see ConfigGeneration below.
	//
	// A SEQUENCE rather than a column or an in-process counter, because the number has to survive a control
	// plane failover: two control planes share this database and the standby becomes the leader mid-life, so
	// a counter living in one process would jump BACKWARDS at exactly the moment everything is already
	// changing. An Edge that has applied a higher number never applies a lower one, so a number that can go
	// down is a fleet that stops taking configuration and says nothing.
	// ★★★ IF NOT EXISTS IS NOT ATOMIC AGAINST A CONCURRENT CREATE (2026-08-24, and this is the second time
	// tonight). Two control planes start together and both run this; one of them gets
	//
	//   pq: duplicate key value violates unique constraint "pg_class_relname_nsp_index"
	//
	// which is Postgres's system catalogue refusing the duplicate, and the node then REFUSES TO START. The
	// standby died on every boot, which is worse than the problem this sequence was added to fix — and it
	// looked, from outside, exactly like the standby holding no state. An advisory lock serialises the two,
	// the same way the schema-migration ledger's own creation is serialised, and for the same reason.
	if err := createSiteGenerationSequence(ctx, pg.DB); err != nil {
		return nil, fmt.Errorf("create the Site catalogue's generation counter: %w", err)
	}
	return &postgresAdminSiteStore{db: pg.DB}, nil
}

// ConfigGeneration is what makes an authored Site travel.
//
// ★★★ IT WAS MISSING, AND ONLY ON THE PRODUCTION BACKEND (2026-08-24, measured on a generated deployment).
// The bundle's version is a sum of every store's counter, collected through a type assertion:
//
//	if carrier, ok := config.SiteStore.(interface{ ConfigGeneration() uint64 }); ok { ... }
//
// The FILE store has the method. This one did not, so the assertion failed silently, the Site catalogue
// contributed 0 for ever, and creating a Site left the bundle's version exactly where it was. Measured: a
// Site created on the control plane at 13:28, present and correct in the signed payload with its bootstrap
// secret hash, and both Edges still holding generation 6 from 13:27 — polling every ten seconds and rightly
// concluding there was nothing new. No connector could enrol on any deployment using the production backend,
// and the refusal it produced named the secret rather than the version: "the bootstrap secret is not this
// Site's", which is true and three components away from the cause.
//
// The same shape as the tenant store that told nobody. An interface a backend can fail to implement in
// silence needs a test that FAILS when it does — see TestPostgresSiteStoreCarriesAConfigGeneration.
func (p *postgresAdminSiteStore) ConfigGeneration() uint64 {
	if p == nil || p.db == nil {
		return 0
	}
	generation, err := p.ConfigGenerationChecked(context.Background())
	if err != nil {
		return p.lastGeneration.Load()
	}
	return generation
}

// Bundle publication needs to distinguish an unreadable counter from an
// unchanged counter. The legacy value-only method retains its cached fallback
// for health readers; issuing a signed bundle must instead fail and retry.
func (p *postgresAdminSiteStore) ConfigGenerationChecked(parent context.Context) (uint64, error) {
	if p == nil || p.db == nil {
		return 0, errAdminSitePersistence
	}
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	// nextval is visible before its writer commits. Use the same transaction
	// lock as Site writes so the generation can never describe rows that are
	// still uncommitted, nor miss a write that commits after a later number.
	if _, err := tx.ExecContext(ctx, "SELECT pg_advisory_xact_lock(hashtext($1))", "dsse_admin_sites_write_generation"); err != nil {
		return 0, err
	}
	var n int64
	// ★ is_called IS NOT COSMETIC (2026-08-24, measured — the first write moved nothing). A sequence that has
	// never been called reports last_value = 1 with is_called = false, and after its FIRST nextval it reports
	// last_value = 1 with is_called = true. Reading last_value alone therefore gives the same number before
	// and after the first write, which on a new deployment is the only write that has happened.
	if err := tx.QueryRowContext(ctx,
		"SELECT CASE WHEN is_called THEN last_value ELSE 0 END FROM admin_sites_config_generation").Scan(&n); err != nil {
		// ★ AND AN UNREADABLE COUNTER IS NOT ZERO. Returning 0 here would DROP the aggregate generation for
		// every other store too, and an Edge that has applied a higher number applies nothing again. A brief
		// database blip would silently freeze the fleet's configuration.
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	if n < 0 {
		n = 0
	}
	return p.observeReadGeneration(uint64(n)), nil
}

// observeReadGeneration turns a counter value read under the Site writers' lock into this process's
// generation. Reads are serialised with commits, so on one primary they never go backwards; a value lower than
// the last one read means the primary changed (see the struct), and the generation moves on past everything
// already published instead of waiting for the counter to catch up.
func (p *postgresAdminSiteStore) observeReadGeneration(raw uint64) uint64 {
	p.generationMu.Lock()
	defer p.generationMu.Unlock()
	last := p.lastGeneration.Load()
	switch {
	case p.rawSeen && raw < p.lastRaw:
		p.offset = last + 1 - raw
	case raw+p.offset < last:
		// Nothing read yet in this process, but a generation is already published: keep it, move from it.
		p.offset = last - raw
	}
	p.rawSeen, p.lastRaw = true, raw
	out := raw + p.offset
	if out > last {
		p.lastGeneration.Store(out)
		return out
	}
	return last
}

// observeWrittenGeneration records the value a committed Site write drew. Writers finish in any order, so a
// smaller value here is a slower writer and not a change of primary: it may only move the generation forward.
func (p *postgresAdminSiteStore) observeWrittenGeneration(n uint64) {
	p.generationMu.Lock()
	defer p.generationMu.Unlock()
	if p.rawSeen && n <= p.lastRaw {
		return
	}
	p.rawSeen, p.lastRaw = true, n
	if out := n + p.offset; out > p.lastGeneration.Load() {
		p.lastGeneration.Store(out)
	}
}

// A Site write and its generation advance share one transaction. A failed
// counter update therefore rolls back the row instead of reporting success to
// the administrator while every Edge keeps the previous bundle version.
func (p *postgresAdminSiteStore) bumpConfigGeneration(ctx context.Context, tx *sql.Tx) (uint64, error) {
	var n int64
	if err := tx.QueryRowContext(ctx, "SELECT nextval('admin_sites_config_generation')").Scan(&n); err != nil {
		return 0, err
	}
	if n <= 0 {
		return 0, fmt.Errorf("site generation did not advance")
	}
	return uint64(n), nil
}

func (p *postgresAdminSiteStore) List(ctx context.Context, tenantID string) ([]adminSiteModel, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return nil, fmt.Errorf("tenant_id is required")
	}
	rows, err := p.db.QueryContext(ctx, "SELECT "+adminSiteColumns+" FROM admin_sites WHERE tenant_id = $1 ORDER BY site_id ASC", tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []adminSiteModel{}
	for rows.Next() {
		site, err := scanAdminSiteRow(rows.Scan)
		if err != nil {
			return nil, err
		}
		out = append(out, site)
	}
	return out, rows.Err()
}

func (p *postgresAdminSiteStore) Get(ctx context.Context, tenantID, siteID string) (adminSiteModel, bool, error) {
	tenantID = strings.TrimSpace(tenantID)
	siteID = strings.TrimSpace(siteID)
	if tenantID == "" {
		return adminSiteModel{}, false, fmt.Errorf("tenant_id is required")
	}
	if siteID == "" {
		return adminSiteModel{}, false, fmt.Errorf("site_id is required")
	}
	row := p.db.QueryRowContext(ctx, "SELECT "+adminSiteColumns+" FROM admin_sites WHERE tenant_id = $1 AND site_id = $2", tenantID, siteID)
	site, err := scanAdminSiteRow(row.Scan)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return adminSiteModel{}, false, nil
		}
		return adminSiteModel{}, false, err
	}
	return site, true, nil
}

func (p *postgresAdminSiteStore) Upsert(ctx context.Context, site adminSiteModel, now time.Time) (adminSiteModel, error) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	normalized, err := normalizeAdminSiteModel(site, now)
	if err != nil {
		return adminSiteModel{}, err
	}
	createdAt, err := parseAdminAuthRequiredTime(derefStringPtr(normalized.CreatedAt), "site created_at")
	if err != nil {
		return adminSiteModel{}, err
	}
	updatedAt, err := parseAdminAuthRequiredTime(derefStringPtr(normalized.UpdatedAt), "site updated_at")
	if err != nil {
		return adminSiteModel{}, err
	}
	var rotatedAt any
	if normalized.BootstrapSecretRotatedAt != nil && strings.TrimSpace(*normalized.BootstrapSecretRotatedAt) != "" {
		t, perr := parseAdminAuthRequiredTime(*normalized.BootstrapSecretRotatedAt, "site bootstrap_secret_rotated_at")
		if perr != nil {
			return adminSiteModel{}, perr
		}
		rotatedAt = t.UTC()
	}
	tx, err := p.beginSiteWrite(ctx)
	if err != nil {
		return adminSiteModel{}, fmt.Errorf("%w: %v", errAdminSitePersistence, err)
	}
	defer func() { _ = tx.Rollback() }()
	row := tx.QueryRowContext(ctx, strings.Join([]string{
		"INSERT INTO admin_sites",
		"(tenant_id, site_id, name, region, expected_connector_count, routing_namespace, deployment_type, ha_policy, bootstrap_secret_hash, bootstrap_secret_rotated_at, created_at, updated_at, door_order)",
		"VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::timestamptz, $11::timestamptz, $12::timestamptz, $13)",
		"ON CONFLICT (tenant_id, site_id) DO UPDATE SET",
		"name = EXCLUDED.name,",
		"region = EXCLUDED.region,",
		"expected_connector_count = EXCLUDED.expected_connector_count,",
		"routing_namespace = EXCLUDED.routing_namespace,",
		"deployment_type = EXCLUDED.deployment_type,",
		"ha_policy = EXCLUDED.ha_policy,",
		"door_order = EXCLUDED.door_order,",
		"bootstrap_secret_hash = CASE WHEN EXCLUDED.bootstrap_secret_hash = '' THEN admin_sites.bootstrap_secret_hash ELSE EXCLUDED.bootstrap_secret_hash END,",
		"bootstrap_secret_rotated_at = CASE WHEN EXCLUDED.bootstrap_secret_hash = '' THEN admin_sites.bootstrap_secret_rotated_at ELSE EXCLUDED.bootstrap_secret_rotated_at END,",
		"updated_at = EXCLUDED.updated_at",
		"RETURNING " + adminSiteColumns,
	}, " "),
		normalized.TenantID, normalized.SiteID, normalized.Name, normalized.Region, normalized.ExpectedConnectorCount,
		normalized.RoutingNamespace, normalized.DeploymentType, normalized.HAPolicy, normalized.BootstrapSecretHash,
		rotatedAt, createdAt.UTC(), updatedAt.UTC(), strings.Join(normalized.DoorOrder, ","))
	saved, err := scanAdminSiteRow(row.Scan)
	if err != nil {
		return adminSiteModel{}, fmt.Errorf("%w: %v", errAdminSitePersistence, err)
	}
	// Every write moves the number the bundle's version is built from, or the change is published in every
	// bundle and applied by nobody.
	generation, err := p.bumpConfigGeneration(ctx, tx)
	if err != nil {
		return adminSiteModel{}, fmt.Errorf("%w: %v", errAdminSitePersistence, err)
	}
	if err := tx.Commit(); err != nil {
		return adminSiteModel{}, fmt.Errorf("%w: %v", errAdminSitePersistence, err)
	}
	p.observeWrittenGeneration(generation)
	return saved, nil
}

func (p *postgresAdminSiteStore) Delete(ctx context.Context, tenantID, siteID string) error {
	tenantID = strings.TrimSpace(tenantID)
	siteID = strings.TrimSpace(siteID)
	if tenantID == "" {
		return fmt.Errorf("tenant_id is required")
	}
	if siteID == "" {
		return fmt.Errorf("site_id is required")
	}
	tx, err := p.beginSiteWrite(ctx)
	if err != nil {
		return fmt.Errorf("%w: %v", errAdminSitePersistence, err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, "DELETE FROM admin_sites WHERE tenant_id = $1 AND site_id = $2", tenantID, siteID); err != nil {
		return fmt.Errorf("%w: %v", errAdminSitePersistence, err)
	}
	// A deletion has to travel too — an Edge that keeps honouring a removed Site's bootstrap secret is the
	// half of this that is hardest to see.
	generation, err := p.bumpConfigGeneration(ctx, tx)
	if err != nil {
		return fmt.Errorf("%w: %v", errAdminSitePersistence, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("%w: %v", errAdminSitePersistence, err)
	}
	p.observeWrittenGeneration(generation)
	return nil
}

func (p *postgresAdminSiteStore) beginSiteWrite(ctx context.Context) (*sql.Tx, error) {
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, "SELECT pg_advisory_xact_lock(hashtext($1))", "dsse_admin_sites_write_generation"); err != nil {
		_ = tx.Rollback()
		return nil, err
	}
	return tx, nil
}

// scanAdminSiteRow decodes a row in adminSiteColumns order, rendering timestamptz columns back to RFC3339 strings
// (the model's wire shape). bootstrap_secret_rotated_at is nullable.
func scanAdminSiteRow(scan func(...any) error) (adminSiteModel, error) {
	var site adminSiteModel
	var rotatedAt sql.NullTime
	var createdAt, updatedAt time.Time
	// NULL reads as no order: a row written before migration 061, or by anything that leaves the column unset.
	var doorOrder sql.NullString
	if err := scan(
		&site.TenantID, &site.SiteID, &site.Name, &site.Region, &site.ExpectedConnectorCount,
		&site.RoutingNamespace, &site.DeploymentType, &site.HAPolicy, &site.BootstrapSecretHash, &rotatedAt,
		&createdAt, &updatedAt, &doorOrder,
	); err != nil {
		return adminSiteModel{}, err
	}
	if order := strings.TrimSpace(doorOrder.String); doorOrder.Valid && order != "" {
		site.DoorOrder = strings.Split(order, ",")
	}
	if rotatedAt.Valid {
		rotated := rotatedAt.Time.UTC().Format(time.RFC3339)
		site.BootstrapSecretRotatedAt = &rotated
	}
	created := createdAt.UTC().Format(time.RFC3339)
	site.CreatedAt = &created
	updated := updatedAt.UTC().Format(time.RFC3339)
	site.UpdatedAt = &updated
	return site, nil
}

// createSiteGenerationSequence creates the counter, serialised against every other node doing the same.
func createSiteGenerationSequence(ctx context.Context, db *sql.DB) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, "SELECT pg_advisory_xact_lock(hashtext($1))", "dsse_admin_sites_config_generation"); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "CREATE SEQUENCE IF NOT EXISTS admin_sites_config_generation"); err != nil {
		return err
	}
	return tx.Commit()
}
