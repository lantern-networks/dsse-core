package main

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/lantern-networks/dsse-core/internalca"
	migrationstore "github.com/lantern-networks/dsse-core/migrations"
)

// Durable home for the authorities an organization vouches for. Lives on the control plane, like every other
// authored object: an Edge that kept this in memory would forget every organization's private assets on
// restart and refuse them until somebody noticed a page that used to work.
type postgresInternalCAPersistence struct{ db *sql.DB }

func (p postgresInternalCAPersistence) LoadAll() ([]internalca.Authority, error) {
	rows, err := p.db.Query(`SELECT id, tenant_id, name, certificate_pem, created_at, updated_at
		FROM internal_certificate_authorities`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []internalca.Authority{}
	for rows.Next() {
		a := internalca.Authority{}
		if err := rows.Scan(&a.ID, &a.TenantID, &a.Name, &a.CertificatePEM, &a.CreatedAt, &a.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (p postgresInternalCAPersistence) Upsert(a internalca.Authority) error {
	_, err := p.db.Exec(`
		INSERT INTO internal_certificate_authorities (id, tenant_id, name, certificate_pem, created_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6)
		ON CONFLICT (id, tenant_id) DO UPDATE SET
			name=EXCLUDED.name, certificate_pem=EXCLUDED.certificate_pem, updated_at=EXCLUDED.updated_at`,
		a.ID, a.TenantID, a.Name, a.CertificatePEM, a.CreatedAt, a.UpdatedAt)
	return err
}

func (p postgresInternalCAPersistence) Delete(id, tenantID string) error {
	_, err := p.db.Exec(`DELETE FROM internal_certificate_authorities WHERE id=$1 AND tenant_id=$2`, id, tenantID)
	return err
}

// ★ The store must keep accepting this. Compile-time, because a persistence that stops satisfying the
// interface would otherwise leave the Edge silently on the memory path.
var _ internalca.Persistence = postgresInternalCAPersistence{}

// setupInternalCAPersistence opens the durable home AND APPLIES THIS COMPONENT'S MIGRATION.
//
// ★★★ THE MIGRATION IS THE HALF I FORGOT, AND IT COST A REGION (2026-09-01). The first version opened the
// database directly and never selected its migration, so the table existed only in the source tree: every node
// answered `relation "internal_certificate_authorities" does not exist`, and because init was fatal at the
// time, both control planes of tokyo-west entered a restart loop within a minute of the roll.
//
// Migrations here are COMPONENT-SCOPED — each component selects the versions it owns, so a node running one
// component does not create another's tables. Opening the database without that step is not a shortcut; it is
// the step that makes the object exist on a machine.
func setupInternalCAPersistence(ctx context.Context, dsn, migrationDir string, runMigrations bool) (internalca.Persistence, func() error, error) {
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
		migrations, loadErr := migrationstore.LoadDir(migrationDir)
		if loadErr != nil {
			db.Close()
			return nil, nil, fmt.Errorf("load internal-certificate-authority migrations: %w", loadErr)
		}
		migrations, selErr := selectPostgresComponentMigrations(migrations, "internal certificate authorities", postgresMigrationInternalCAs)
		if selErr != nil {
			db.Close()
			return nil, nil, selErr
		}
		if applyErr := migrationstore.Apply(ctx, db, migrations); applyErr != nil {
			db.Close()
			return nil, nil, fmt.Errorf("apply internal-certificate-authority migrations: %w", applyErr)
		}
	}
	return postgresInternalCAPersistence{db: db}, db.Close, nil
}
