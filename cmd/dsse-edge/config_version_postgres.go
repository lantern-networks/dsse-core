package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	configversion "github.com/lantern-networks/dsse-core/configversion"

	migrationstore "github.com/lantern-networks/dsse-core/migrations"
)

// Durable config-version store on the control plane. Each Record appends the next monotonic version_no for
// (tenant, resource_type, resource_id) in one statement (the UNIQUE constraint guards against races).
type postgresConfigVersionStore struct{ db *sql.DB }

func (p postgresConfigVersionStore) Record(ctx context.Context, tenantID, resourceType, resourceID, action, actor, note string, payload any) (configversion.Version, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return configversion.Version{}, err
	}
	id := randomEdgeID("cv_", time.Now())
	var v configversion.Version
	err = p.db.QueryRowContext(ctx, `
		INSERT INTO config_versions (id, tenant_id, resource_type, resource_id, version_no, payload, action, actor, note)
		SELECT $1,$2,$3,$4, COALESCE(MAX(version_no),0)+1, $5::jsonb,$6,$7,$8
		FROM config_versions WHERE tenant_id=$2 AND resource_type=$3 AND resource_id=$4
		RETURNING id, tenant_id, resource_type, resource_id, version_no, payload, action, actor, note, created_at`,
		id, tenantID, resourceType, resourceID, string(raw), action, actor, note).
		Scan(&v.ID, &v.TenantID, &v.ResourceType, &v.ResourceID, &v.VersionNo, &v.Payload, &v.Action, &v.Actor, &v.Note, &v.CreatedAt)
	if err != nil {
		return configversion.Version{}, err
	}
	return v, nil
}

func (p postgresConfigVersionStore) List(ctx context.Context, tenantID, resourceType, resourceID string) ([]configversion.Version, error) {
	rows, err := p.db.QueryContext(ctx, `
		SELECT id, tenant_id, resource_type, resource_id, version_no, payload, action, actor, note, created_at
		FROM config_versions WHERE tenant_id=$1 AND resource_type=$2 AND resource_id=$3
		ORDER BY version_no DESC`, tenantID, resourceType, resourceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []configversion.Version{}
	for rows.Next() {
		var v configversion.Version
		if err := rows.Scan(&v.ID, &v.TenantID, &v.ResourceType, &v.ResourceID, &v.VersionNo, &v.Payload, &v.Action, &v.Actor, &v.Note, &v.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (p postgresConfigVersionStore) Get(ctx context.Context, tenantID, resourceType, resourceID string, versionNo int64) (configversion.Version, bool, error) {
	var v configversion.Version
	err := p.db.QueryRowContext(ctx, `
		SELECT id, tenant_id, resource_type, resource_id, version_no, payload, action, actor, note, created_at
		FROM config_versions WHERE tenant_id=$1 AND resource_type=$2 AND resource_id=$3 AND version_no=$4`,
		tenantID, resourceType, resourceID, versionNo).
		Scan(&v.ID, &v.TenantID, &v.ResourceType, &v.ResourceID, &v.VersionNo, &v.Payload, &v.Action, &v.Actor, &v.Note, &v.CreatedAt)
	if err == sql.ErrNoRows {
		return configversion.Version{}, false, nil
	}
	if err != nil {
		return configversion.Version{}, false, err
	}
	return v, true, nil
}

// setupConfigVersionStore returns a durable config-version store. Empty dsn => nil (versioning disabled,
// e.g. on the enforcing Edge). Used on the control plane (the admin authority).
func setupConfigVersionStore(ctx context.Context, dsn, migrationDir string, runMigrations bool) (configversion.Store, func() error, error) {
	if strings.TrimSpace(dsn) == "" {
		return nil, func() error { return nil }, nil
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
			return nil, nil, fmt.Errorf("load config-version migrations: %w", err)
		}
		migrations, err = selectPostgresComponentMigrations(migrations, "config versions", postgresMigrationConfigVersions)
		if err != nil {
			db.Close()
			return nil, nil, err
		}
		if err := migrationstore.Apply(ctx, db, migrations); err != nil {
			db.Close()
			return nil, nil, fmt.Errorf("apply config-version migrations: %w", err)
		}
	}
	return postgresConfigVersionStore{db: db}, db.Close, nil
}
