package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"reflect"
	"strings"
	"time"

	appcatalog "github.com/lantern-networks/dsse-core/appcatalog"
	"github.com/lantern-networks/dsse-core/edgeplane"
	migrationstore "github.com/lantern-networks/dsse-core/migrations"
	"github.com/lantern-networks/dsse-core/model"
)

// admin_application_catalog_postgres.go — Postgres backend for the operator-authored Application Catalog. It
// satisfies the same appcatalog.RuntimeStore contract as the file/in-memory store, so the admin handlers are
// unchanged; only the durable backend differs. The connection is REUSED from the admin auth store (the control
// plane already owns that handle), exactly like the tenant model and site stores, so no extra DB handle is opened
// and this store never closes it. Every query is tenant-scoped: the primary key is (tenant_id, application_id) and
// every statement filters on tenant_id, so a tenant can never read or mutate another tenant's applications.
//
// Seed/merge parity with the file store: the config-derived catalog (route profiles + SaaS catalog) is re-derived
// on every boot and held in memory as the SEED (base layer). Only operator-authored Upserts are persisted to
// Postgres (the durable overlay). Reads merge the seed with the authored DB rows — authored entries WIN — which
// reproduces how SetStatePath/loadLocked overlay the persisted set on top of the seed in the file store, so
// authored applications and edits survive a restart while config-seeded entries always reflect current config.
type postgresApplicationCatalogStore struct {
	db *sql.DB
	// seed is the immutable config-derived base layer (tenant_id -> application_id -> entry). It is never written
	// to Postgres; authored entries overlay it at read time.
	seed map[string]map[string]appcatalog.Entry
}

var _ appcatalog.RuntimeStore = (*postgresApplicationCatalogStore)(nil)

// applicationCatalogColumns is the canonical column order shared by every SELECT/scan in this store.
const applicationCatalogColumns = "tenant_id, application_id, name, application_type, service_family, protocol, destination_role, application_sensitivity, route_ref, saas_provider, saas_category, saas_risk_tier, domain_pattern_count, sni_pattern_count, tags, status, destination, destination_port, publish_protocol, connector_group_id, published, last_probe_at, routing_namespace, updated_at"

// postgresApplicationCatalogSchemaSQL is the in-code schema contract; migrations/026_application_catalog.sql must
// match it (asserted by TestPostgresApplicationCatalogMigrationMatchesSchemaSQL).
func postgresApplicationCatalogSchemaSQL() []string {
	return []string{
		strings.Join([]string{
			"CREATE TABLE IF NOT EXISTS application_catalog (",
			"tenant_id text NOT NULL,",
			"application_id text NOT NULL,",
			"name text NOT NULL DEFAULT '',",
			"application_type text NOT NULL DEFAULT '',",
			"service_family text NOT NULL DEFAULT '',",
			"protocol text NOT NULL DEFAULT '',",
			"destination_role text NOT NULL DEFAULT '',",
			"application_sensitivity text NOT NULL DEFAULT '',",
			"route_ref text NOT NULL DEFAULT '',",
			"saas_provider text NOT NULL DEFAULT '',",
			"saas_category text NOT NULL DEFAULT '',",
			"saas_risk_tier text NOT NULL DEFAULT '',",
			"domain_pattern_count integer NOT NULL DEFAULT 0,",
			"sni_pattern_count integer NOT NULL DEFAULT 0,",
			"tags jsonb NOT NULL DEFAULT '[]',",
			"status text NOT NULL DEFAULT '',",
			"destination text NOT NULL DEFAULT '',",
			"destination_port integer NOT NULL DEFAULT 0,",
			"publish_protocol text NOT NULL DEFAULT '',",
			"connector_group_id text NOT NULL DEFAULT '',",
			"published boolean NOT NULL DEFAULT false,",
			"last_probe_at text,",
			"routing_namespace text NOT NULL DEFAULT '',",
			"updated_at timestamptz NOT NULL,",
			"PRIMARY KEY (tenant_id, application_id)",
			")",
		}, " "),
		"CREATE INDEX IF NOT EXISTS application_catalog_tenant_idx ON application_catalog (tenant_id, application_id)",
	}
}

// setupApplicationCatalogStore builds the catalog store from the deployment config: it seeds the config-derived
// catalog (route profiles + SaaS catalog) and then selects the durable backend by storePath. Empty path / a file
// path keeps the lab default (in-memory seed + optional file/JSON durability of authored entries, unchanged);
// "postgres" wires the Postgres backend on the shared admin auth connection. This mirrors how -site-store /
// -tenant-model-store select their backend in main.
func setupApplicationCatalogStore(ctx context.Context, storePath string, adminAuthStore adminAuthRuntimeStore, migrationDir string, runMigrations bool, tenantID string, routeProfiles map[string]edgeplane.ApplicationRouteProfile, saasCatalog []model.SaaSCatalogEntry) (appcatalog.RuntimeStore, error) {
	seedStore := newAdminApplicationCatalogStore(tenantID, routeProfiles, saasCatalog)
	// "postgres+import:<path>" is the same backend, carrying the authored entries this control plane used to
	// keep on disk — see cpStateBlobPersisterImportPrefix for why the move needs one at all.
	//
	// ★ THE SEED IS NOT AN IMPORT, WHICH IS EASY TO MISREAD HERE (2026-08-18). The Postgres backend is handed
	// seedStore.Snapshot(), and that snapshot is the CONFIG-DERIVED catalog — route profiles and the SaaS list.
	// The applications an operator AUTHORED live in the file at storePath, and moving to postgres left them
	// there: the catalog came up looking complete, because the config-derived half is the bigger half.
	if strings.EqualFold(storeBackend(storePath), "postgres") {
		importFrom := storeImportSource(storePath)
		store, err := setupPostgresApplicationCatalogStore(ctx, adminAuthStore, migrationDir, runMigrations, seedStore.Snapshot())
		if err != nil {
			return nil, err
		}
		if err := importAuthoredApplicationsOnce(ctx, store, seedStore, importFrom); err != nil {
			return nil, err
		}
		return store, nil
	}
	// SetStatePath AFTER the config seed so persisted operator apps/edits overlay (and survive) the seed.
	if err := seedStore.SetStatePath(storePath); err != nil {
		return nil, fmt.Errorf("load application catalog store: %w", err)
	}
	return seedStore, nil
}

// setupPostgresApplicationCatalogStore wires the Postgres catalog backend onto the admin auth connection. It
// requires admin-auth-store=postgres (the shared handle) and applies the component migration. Returns an error —
// never falls back silently — so a misconfigured control plane fails fast instead of starting with the wrong
// backend. The seed is the config-derived base layer captured from the in-memory store.
func setupPostgresApplicationCatalogStore(ctx context.Context, adminAuthStore adminAuthRuntimeStore, migrationDir string, runMigrations bool, seed map[string]map[string]appcatalog.Entry) (*postgresApplicationCatalogStore, error) {
	pg, ok := adminAuthStore.(postgresAdminAuthStore)
	if !ok || pg.DB == nil {
		return nil, fmt.Errorf("application-catalog-store=postgres requires admin-auth-store=postgres (it reuses that connection)")
	}
	if runMigrations {
		migrations, err := migrationstore.LoadDir(migrationDir)
		if err != nil {
			return nil, fmt.Errorf("load application catalog migrations: %w", err)
		}
		migrations, err = selectPostgresComponentMigrations(migrations, "application catalog", postgresMigrationApplicationCatalog)
		if err != nil {
			return nil, err
		}
		if err := migrationstore.Apply(ctx, pg.DB, migrations); err != nil {
			return nil, fmt.Errorf("apply application catalog migrations: %w", err)
		}
	}
	if seed == nil {
		seed = map[string]map[string]appcatalog.Entry{}
	}
	return &postgresApplicationCatalogStore{db: pg.DB, seed: seed}, nil
}

// List returns the merged catalog (config seed + durable authored overlay) for a tenant, filtered/sorted/limited
// identically to the file store. The seed is the base; authored DB rows overlay it (authored wins).
func (p *postgresApplicationCatalogStore) List(ctx context.Context, tenantID string, options appcatalog.ListOptions) (appcatalog.ListResponse, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return appcatalog.ListResponse{}, fmt.Errorf("tenant_id is required")
	}
	applicationType := strings.TrimSpace(options.ApplicationType)
	if applicationType != "" && !appcatalog.ValidApplicationType(applicationType) {
		return appcatalog.ListResponse{}, fmt.Errorf("application_type %s is invalid", applicationType)
	}
	status := strings.TrimSpace(options.Status)
	if status != "" && !appcatalog.ValidStatus(status) {
		return appcatalog.ListResponse{}, fmt.Errorf("application status %s is invalid", status)
	}
	limit := options.Limit
	if limit <= 0 {
		limit = 100
	}

	merged := map[string]appcatalog.Entry{}
	for id, application := range p.seed[tenantID] {
		merged[id] = appcatalog.CopyEntry(application)
	}
	rows, err := p.db.QueryContext(ctx, "SELECT "+applicationCatalogColumns+" FROM application_catalog WHERE tenant_id = $1", tenantID)
	if err != nil {
		return appcatalog.ListResponse{}, err
	}
	defer rows.Close()
	for rows.Next() {
		entry, serr := scanApplicationCatalogRow(rows.Scan)
		if serr != nil {
			return appcatalog.ListResponse{}, serr
		}
		merged[entry.ApplicationID] = entry // authored overlays the seed
	}
	if err := rows.Err(); err != nil {
		return appcatalog.ListResponse{}, err
	}

	out := []appcatalog.Entry{}
	for _, application := range merged {
		if applicationType != "" && application.ApplicationType != applicationType {
			continue
		}
		if status != "" && application.Status != status {
			continue
		}
		out = append(out, application)
	}
	appcatalog.SortEntries(out)
	count := len(out)
	if len(out) > limit {
		out = out[:limit]
	}
	return appcatalog.ListResponse{Applications: out, Count: count, Limit: limit}, nil
}

// Get returns a single application. A durable authored row wins; otherwise the config seed is consulted, matching
// the file store where authored entries overlay the in-memory seed.
func (p *postgresApplicationCatalogStore) Get(ctx context.Context, tenantID, applicationID string) (appcatalog.Entry, bool, error) {
	tenantID = strings.TrimSpace(tenantID)
	applicationID = strings.TrimSpace(applicationID)
	if tenantID == "" {
		return appcatalog.Entry{}, false, fmt.Errorf("tenant_id is required")
	}
	if applicationID == "" {
		return appcatalog.Entry{}, false, fmt.Errorf("application_id is required")
	}
	row := p.db.QueryRowContext(ctx, "SELECT "+applicationCatalogColumns+" FROM application_catalog WHERE tenant_id = $1 AND application_id = $2", tenantID, applicationID)
	entry, err := scanApplicationCatalogRow(row.Scan)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			if seed, ok := p.seed[tenantID][applicationID]; ok {
				return appcatalog.CopyEntry(seed), true, nil
			}
			return appcatalog.Entry{}, false, nil
		}
		return appcatalog.Entry{}, false, err
	}
	return entry, true, nil
}

// Upsert normalizes the entry identically to the file store (stamping UpdatedAt) and persists it as the durable
// authored overlay. Tenant scoping is enforced by Normalize (entry tenant_id must match the authenticated tenant)
// and by the (tenant_id, application_id) primary key.
func (p *postgresApplicationCatalogStore) Upsert(ctx context.Context, application appcatalog.Entry, tenantID string, now time.Time) (appcatalog.Entry, error) {
	normalized, err := appcatalog.Normalize(application, tenantID, now)
	if err != nil {
		return appcatalog.Entry{}, err
	}
	tags, err := json.Marshal(normalized.Tags)
	if err != nil {
		return appcatalog.Entry{}, err
	}
	if len(tags) == 0 {
		tags = []byte("[]")
	}
	updatedAt, err := parseAdminAuthRequiredTime(derefStringPtr(normalized.UpdatedAt), "application updated_at")
	if err != nil {
		return appcatalog.Entry{}, err
	}
	var lastProbe any
	if normalized.LastProbeAt != nil && strings.TrimSpace(*normalized.LastProbeAt) != "" {
		lastProbe = *normalized.LastProbeAt
	}
	_, err = p.db.ExecContext(ctx, strings.Join([]string{
		"INSERT INTO application_catalog",
		"(" + applicationCatalogColumns + ")",
		"VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15::jsonb, $16, $17, $18, $19, $20, $21, $22, $23, $24::timestamptz)",
		"ON CONFLICT (tenant_id, application_id) DO UPDATE SET",
		"name = EXCLUDED.name,",
		"application_type = EXCLUDED.application_type,",
		"service_family = EXCLUDED.service_family,",
		"protocol = EXCLUDED.protocol,",
		"destination_role = EXCLUDED.destination_role,",
		"application_sensitivity = EXCLUDED.application_sensitivity,",
		"route_ref = EXCLUDED.route_ref,",
		"saas_provider = EXCLUDED.saas_provider,",
		"saas_category = EXCLUDED.saas_category,",
		"saas_risk_tier = EXCLUDED.saas_risk_tier,",
		"domain_pattern_count = EXCLUDED.domain_pattern_count,",
		"sni_pattern_count = EXCLUDED.sni_pattern_count,",
		"tags = EXCLUDED.tags,",
		"status = EXCLUDED.status,",
		"destination = EXCLUDED.destination,",
		"destination_port = EXCLUDED.destination_port,",
		"publish_protocol = EXCLUDED.publish_protocol,",
		"connector_group_id = EXCLUDED.connector_group_id,",
		"published = EXCLUDED.published,",
		"last_probe_at = EXCLUDED.last_probe_at,",
		"routing_namespace = EXCLUDED.routing_namespace,",
		"updated_at = EXCLUDED.updated_at",
	}, " "),
		normalized.TenantID, normalized.ApplicationID, normalized.Name, normalized.ApplicationType, normalized.ServiceFamily,
		normalized.Protocol, normalized.DestinationRole, normalized.ApplicationSensitivity, normalized.RouteRef,
		normalized.SaaSProvider, normalized.SaaSCategory, normalized.SaaSRiskTier, normalized.DomainPatternCount,
		normalized.SNIPatternCount, string(tags), normalized.Status, normalized.Destination, normalized.DestinationPort,
		normalized.PublishProtocol, normalized.ConnectorGroupID, normalized.Published, lastProbe, normalized.RoutingNamespace,
		updatedAt.UTC())
	if err != nil {
		return appcatalog.Entry{}, err
	}
	return appcatalog.CopyEntry(normalized), nil
}

// Delete removes the durable authored row for a tenant. It mirrors the file store's contract exactly: a
// config-seed id (present in the in-memory seed) is non-deletable (ErrApplicationNotDeletable) because it is
// re-derived from configuration on every boot; an id with no authored DB row returns ErrApplicationNotFound.
// Tenant scoping is enforced by the (tenant_id, application_id) predicate, so a tenant can never delete another
// tenant's authored entry. On success the row is gone, so the entry drops out of List/Get and the published
// route overlay (fail-closed: a deleted published app is no longer reachable).
func (p *postgresApplicationCatalogStore) Delete(ctx context.Context, tenantID, applicationID string) error {
	tenantID = strings.TrimSpace(tenantID)
	applicationID = strings.TrimSpace(applicationID)
	if tenantID == "" {
		return fmt.Errorf("tenant_id is required")
	}
	if applicationID == "" {
		return fmt.Errorf("application_id is required")
	}
	if _, ok := p.seed[tenantID][applicationID]; ok {
		return appcatalog.ErrApplicationNotDeletable
	}
	res, err := p.db.ExecContext(ctx, "DELETE FROM application_catalog WHERE tenant_id = $1 AND application_id = $2", tenantID, applicationID)
	if err != nil {
		return err
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return appcatalog.ErrApplicationNotFound
	}
	return nil
}

// scanApplicationCatalogRow decodes a row in applicationCatalogColumns order into an appcatalog.Entry. tags is
// jsonb; updated_at is rendered back to an RFC3339 string (the model's wire shape); last_probe_at is a nullable
// free-form diagnostics string preserved verbatim.
func scanApplicationCatalogRow(scan func(...any) error) (appcatalog.Entry, error) {
	var entry appcatalog.Entry
	var tags []byte
	var lastProbe sql.NullString
	var updatedAt time.Time
	if err := scan(
		&entry.TenantID, &entry.ApplicationID, &entry.Name, &entry.ApplicationType, &entry.ServiceFamily,
		&entry.Protocol, &entry.DestinationRole, &entry.ApplicationSensitivity, &entry.RouteRef,
		&entry.SaaSProvider, &entry.SaaSCategory, &entry.SaaSRiskTier, &entry.DomainPatternCount,
		&entry.SNIPatternCount, &tags, &entry.Status, &entry.Destination, &entry.DestinationPort,
		&entry.PublishProtocol, &entry.ConnectorGroupID, &entry.Published, &lastProbe, &entry.RoutingNamespace,
		&updatedAt,
	); err != nil {
		return appcatalog.Entry{}, err
	}
	if len(tags) > 0 {
		if err := json.Unmarshal(tags, &entry.Tags); err != nil {
			return appcatalog.Entry{}, fmt.Errorf("decode tags: %w", err)
		}
	}
	if lastProbe.Valid {
		probe := lastProbe.String
		entry.LastProbeAt = &probe
	}
	updated := updatedAt.UTC().Format(time.RFC3339)
	entry.UpdatedAt = &updated
	return entry, nil
}

// importAuthoredApplicationsOnce carries the applications an operator AUTHORED from the file the control plane
// used to persist to into the shared Postgres catalog. Additive: a row Postgres already holds is never touched,
// so the shared store stays the authority and a stale file cannot overwrite it on a later boot.
//
// Only the authored entries travel. The config-derived seed (route profiles + the SaaS catalog) is rebuilt from
// configuration on every boot and is already the Postgres backend's seed — carrying it too would turn entries
// that are regenerated anyway into durable rows, and a config change would then no longer be able to remove one.
// The discriminator is the snapshot taken BEFORE the file is loaded: whatever the file adds or changes on top of
// it is what an operator did.
func importAuthoredApplicationsOnce(ctx context.Context, store *postgresApplicationCatalogStore, seedStore *appcatalog.Store, sourcePath string) error {
	sourcePath = strings.TrimSpace(sourcePath)
	if sourcePath == "" {
		return nil
	}
	if _, err := os.Stat(sourcePath); errors.Is(err, os.ErrNotExist) {
		log.Printf("application catalog import: nothing to carry across — %s does not exist", sourcePath)
		return nil
	} else if err != nil {
		return fmt.Errorf("application catalog import: %s is named as the source but could not be examined: %w", sourcePath, err)
	}
	configOnly := seedStore.Snapshot()
	if err := seedStore.SetStatePath(sourcePath); err != nil {
		// A named source that cannot be read is a refusal: the catalog would come up looking complete, because
		// the config-derived half is the bigger half, with every authored application missing.
		return fmt.Errorf("application catalog import: %s could not be read, and the catalog would come up looking complete with every authored application missing: %w", sourcePath, err)
	}
	withFile := seedStore.Snapshot()

	carried, skipped := 0, 0
	now := time.Now().UTC()
	for tenantID, byID := range withFile {
		for applicationID, entry := range byID {
			if before, ok := configOnly[tenantID][applicationID]; ok && reflect.DeepEqual(before, entry) {
				continue // config-derived and untouched: rebuilt from configuration on every boot
			}
			// A ROW check, not Get: Get falls back to the seed, so it answers true for entries that have no
			// durable row at all — which would skip exactly the applications this is here to carry.
			var present int
			if err := store.db.QueryRowContext(ctx,
				"SELECT 1 FROM application_catalog WHERE tenant_id = $1 AND application_id = $2",
				tenantID, applicationID).Scan(&present); err == nil {
				skipped++
				continue
			} else if !errors.Is(err, sql.ErrNoRows) {
				return fmt.Errorf("application catalog import: probing %s/%s failed: %w", tenantID, applicationID, err)
			}
			if _, err := store.Upsert(ctx, entry, tenantID, now); err != nil {
				return fmt.Errorf("application catalog import: carrying %s/%s failed: %w", tenantID, applicationID, err)
			}
			carried++
		}
	}
	if carried+skipped > 0 {
		log.Printf("★ application catalog import: carried %d authored application(s) from %s into the shared store (%d were already there and were left alone)",
			carried, sourcePath, skipped)
	}
	return nil
}
