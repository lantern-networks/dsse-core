package main

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	migrationstore "github.com/lantern-networks/dsse-core/migrations"
)

type edgeAdminAuthStoreConfig struct {
	Mode          string
	DSN           string
	MigrationDir  string
	RunMigrations bool
}

func setupEdgeAdminAuthStore(ctx context.Context, config edgeAdminAuthStoreConfig) (adminAuthRuntimeStore, func() error, error) {
	mode := strings.TrimSpace(strings.ToLower(config.Mode))
	if mode == "" {
		mode = "memory"
	}
	switch storeBackend(mode) {
	case "memory", "inmemory", "in-memory":
		return newAdminAuthStore(), func() error { return nil }, nil
	case "postgres":
		dsn := strings.TrimSpace(config.DSN)
		if dsn == "" {
			return nil, nil, fmt.Errorf("admin-auth-postgres-dsn is required")
		}
		db, err := sql.Open("postgres", dsn)
		if err != nil {
			return nil, nil, err
		}
		if err := db.PingContext(ctx); err != nil {
			db.Close()
			return nil, nil, err
		}
		if config.RunMigrations {
			migrations, err := migrationstore.LoadDir(config.MigrationDir)
			if err != nil {
				db.Close()
				return nil, nil, fmt.Errorf("load admin auth migrations: %w", err)
			}
			migrations, err = selectPostgresComponentMigrations(migrations, "admin auth", postgresMigrationAdminAuth)
			if err != nil {
				db.Close()
				return nil, nil, err
			}
			if err := migrationstore.Apply(ctx, db, migrations); err != nil {
				db.Close()
				return nil, nil, fmt.Errorf("apply admin auth migrations: %w", err)
			}
		}
		return postgresAdminAuthStore{DB: db}, db.Close, nil
	default:
		return nil, nil, fmt.Errorf("unsupported admin auth store mode %q", config.Mode)
	}
}
