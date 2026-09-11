package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"strings"

	usagemeter "github.com/lantern-networks/dsse-core/usagemeter"

	migrationstore "github.com/lantern-networks/dsse-core/migrations"

	_ "github.com/lib/pq"
)

type edgeUsageMeterStoreConfig struct {
	Mode          string
	DSN           string
	SpoolDir      string
	MigrationDir  string
	RunMigrations bool
}

func setupEdgeUsageMeterStore(ctx context.Context, config edgeUsageMeterStoreConfig) (usagemeter.UsageMeterRuntimeStore, func() error, error) {
	mode := strings.TrimSpace(strings.ToLower(config.Mode))
	if mode == "" {
		mode = "memory"
	}
	switch storeBackend(mode) {
	case "memory", "inmemory", "in-memory":
		return usagemeter.NewUsageMeterStore(), func() error { return nil }, nil
	case "postgres":
		dsn := strings.TrimSpace(config.DSN)
		if dsn == "" {
			return nil, nil, fmt.Errorf("usage-meter-postgres-dsn is required")
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
				return nil, nil, fmt.Errorf("load usage meter migrations: %w", err)
			}
			migrations, err = selectPostgresComponentMigrations(migrations, "usage meter", postgresUsageMeterMigrationVersions()...)
			if err != nil {
				db.Close()
				return nil, nil, err
			}
			if err := migrationstore.Apply(ctx, db, migrations); err != nil {
				db.Close()
				return nil, nil, fmt.Errorf("apply usage meter migrations: %w", err)
			}
		}
		store := &postgresUsageMeterStore{DB: db, SpoolDir: config.SpoolDir}
		if err := store.ReplayPending(ctx); err != nil {
			log.Printf("usage meter pending replay on startup failed: %v", err)
		}
		return store, db.Close, nil
	default:
		return nil, nil, fmt.Errorf("unsupported usage meter store mode %q", config.Mode)
	}
}
