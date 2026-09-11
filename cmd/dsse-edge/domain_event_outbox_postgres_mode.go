package main

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	migrationstore "github.com/lantern-networks/dsse-core/migrations"

	_ "github.com/lib/pq"
)

type edgeDomainEventOutboxConfig struct {
	Mode          string
	DSN           string
	MigrationDir  string
	RunMigrations bool
}

func setupEdgeDomainEventOutbox(ctx context.Context, config edgeDomainEventOutboxConfig) (domainEventOutboxWriter, func() error, error) {
	mode := strings.TrimSpace(strings.ToLower(config.Mode))
	if mode == "" {
		mode = "disabled"
	}
	switch storeBackend(mode) {
	case "disabled", "off", "none":
		return nil, func() error { return nil }, nil
	case "postgres":
		dsn := strings.TrimSpace(config.DSN)
		if dsn == "" {
			return nil, nil, fmt.Errorf("domain-event-outbox-postgres-dsn is required")
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
				return nil, nil, fmt.Errorf("load domain event outbox migrations: %w", err)
			}
			migrations, err = selectPostgresComponentMigrations(migrations, "domain event outbox", postgresDomainEventOutboxMigrationVersions()...)
			if err != nil {
				db.Close()
				return nil, nil, err
			}
			if err := migrationstore.Apply(ctx, db, migrations); err != nil {
				db.Close()
				return nil, nil, fmt.Errorf("apply domain event outbox migrations: %w", err)
			}
		}
		return postgresDomainEventOutboxStore{DB: db}, db.Close, nil
	default:
		return nil, nil, fmt.Errorf("unsupported domain event outbox mode %q", config.Mode)
	}
}
