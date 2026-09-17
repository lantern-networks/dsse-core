package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"

	steerexclusion "github.com/lantern-networks/dsse-core/steerexclusion"

	migrationstore "github.com/lantern-networks/dsse-core/migrations"
)

// Durable persistence for admin-managed steer exclusions (slice 1). Lives on the control plane (the admin
// authority) so admin-set exclusions survive a restart.
type postgresSteerExclusionPersistence struct{ db *sql.DB }

func (p postgresSteerExclusionPersistence) LoadAll(ctx context.Context) ([]*steerexclusion.Policy, error) {
	rows, err := p.db.QueryContext(ctx, `
		SELECT id, tenant_id, scope_type, scope_id, excluded_app_signing_ids, note, status, created_at, updated_at
		FROM steer_exclusion_policies`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*steerexclusion.Policy
	for rows.Next() {
		e := &steerexclusion.Policy{}
		var idsJSON []byte
		if err := rows.Scan(&e.ID, &e.TenantID, &e.ScopeType, &e.ScopeID, &idsJSON, &e.Note, &e.Status, &e.CreatedAt, &e.UpdatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(idsJSON, &e.ExcludedAppSigningIDs)
		out = append(out, e)
	}
	return out, rows.Err()
}

func (p postgresSteerExclusionPersistence) Upsert(ctx context.Context, e *steerexclusion.Policy) error {
	ids, err := json.Marshal(e.ExcludedAppSigningIDs)
	if err != nil {
		return err
	}
	result, err := p.db.ExecContext(ctx, `
		INSERT INTO steer_exclusion_policies (id, tenant_id, scope_type, scope_id, excluded_app_signing_ids, note, status, created_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
		ON CONFLICT (id) DO UPDATE SET
			scope_type=EXCLUDED.scope_type, scope_id=EXCLUDED.scope_id,
			excluded_app_signing_ids=EXCLUDED.excluded_app_signing_ids, note=EXCLUDED.note,
			status=EXCLUDED.status, updated_at=EXCLUDED.updated_at
  WHERE steer_exclusion_policies.tenant_id = EXCLUDED.tenant_id`,
		e.ID, e.TenantID, e.ScopeType, e.ScopeID, ids, e.Note, e.Status, e.CreatedAt, e.UpdatedAt)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return steerexclusion.ErrTenantConflict
	}
	return nil
}

func (p postgresSteerExclusionPersistence) Delete(ctx context.Context, id, tenantID string) error {
	_, err := p.db.ExecContext(ctx, `DELETE FROM steer_exclusion_policies WHERE id=$1 AND tenant_id=$2`, id, tenantID)
	return err
}

// setupSteerExclusionPersistence returns a durable persistence for the given mode. "memory"/empty => nil.
func setupSteerExclusionPersistence(ctx context.Context, mode, dsn, migrationDir string, runMigrations bool) (steerexclusion.Persistence, func() error, error) {
	switch storeBackend(strings.TrimSpace(strings.ToLower(mode))) {
	case "", "memory", "inmemory", "in-memory":
		return nil, func() error { return nil }, nil
	case "postgres":
		if strings.TrimSpace(dsn) == "" {
			return nil, nil, fmt.Errorf("steer-exclusion-store-postgres-dsn is required")
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
				return nil, nil, fmt.Errorf("load steer-exclusion migrations: %w", err)
			}
			migrations, err = selectPostgresComponentMigrations(migrations, "steer exclusions", postgresMigrationSteerExclusions)
			if err != nil {
				db.Close()
				return nil, nil, err
			}
			if err := migrationstore.Apply(ctx, db, migrations); err != nil {
				db.Close()
				return nil, nil, fmt.Errorf("apply steer-exclusion migrations: %w", err)
			}
		}
		return postgresSteerExclusionPersistence{db: db}, db.Close, nil
	default:
		// A FILE PATH — durable without Postgres. The enforcement Edge is deliberately zero-DB (the control
		// plane is the config authority), so postgres would be durable-and-unread here; a file snapshot on the
		// shared mount is the right durable option. Use the RAW value, not the lowercased mode: a path is
		// case-sensitive. Reject anything that does not LOOK like a path so a typo ("postgress") fails loudly
		// instead of quietly persisting to a file named after the typo — worse than refusing to start.
		path := strings.TrimSpace(mode)
		if !looksLikeStorePath(path) {
			return nil, nil, fmt.Errorf("unsupported steer-exclusion store mode %q (want \"memory\", \"postgres\", or a file path)", mode)
		}
		return steerexclusion.NewFilePersistence(path), func() error { return nil }, nil
	}
}
