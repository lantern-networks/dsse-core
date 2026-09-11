package main

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	agenttelemetry "github.com/lantern-networks/dsse-core/agenttelemetry"

	migrationstore "github.com/lantern-networks/dsse-core/migrations"

	_ "github.com/lib/pq"
)

type edgeAgentTelemetryStoreConfig struct {
	Mode          string
	DSN           string
	MigrationDir  string
	RunMigrations bool
}

func setupEdgeAgentTelemetryStore(ctx context.Context, config edgeAgentTelemetryStoreConfig) (agenttelemetry.RuntimeStore, func() error, error) {
	mode := strings.TrimSpace(strings.ToLower(config.Mode))
	if mode == "" {
		mode = "memory"
	}
	switch storeBackend(mode) {
	case "memory", "inmemory", "in-memory":
		return agenttelemetry.NewStore(), func() error { return nil }, nil
	case "postgres":
		dsn := strings.TrimSpace(config.DSN)
		if dsn == "" {
			return nil, nil, fmt.Errorf("agent-telemetry-postgres-dsn is required")
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
				return nil, nil, fmt.Errorf("load agent telemetry migrations: %w", err)
			}
			migrations, err = selectPostgresComponentMigrations(migrations, "agent telemetry", postgresAgentTelemetryMigrationVersions()...)
			if err != nil {
				db.Close()
				return nil, nil, err
			}
			if err := migrationstore.Apply(ctx, db, migrations); err != nil {
				db.Close()
				return nil, nil, fmt.Errorf("apply agent telemetry migrations: %w", err)
			}
		}
		return &postgresAgentTelemetryStore{DB: db}, db.Close, nil
	default:
		return nil, nil, fmt.Errorf("unsupported agent telemetry store mode %q", config.Mode)
	}
}
