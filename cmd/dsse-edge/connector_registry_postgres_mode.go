package main

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/connector"
	migrationstore "github.com/lantern-networks/dsse-core/migrations"

	_ "github.com/lib/pq"
)

type edgeConnectorRegistryStoreConfig struct {
	Mode          string
	DSN           string
	MigrationDir  string
	RunMigrations bool
}

func setupEdgeConnectorRegistryStore(ctx context.Context, config edgeConnectorRegistryStoreConfig) (connectorRegistryStore, func() error, error) {
	mode := strings.TrimSpace(strings.ToLower(config.Mode))
	if mode == "" {
		mode = "memory"
	}
	switch storeBackend(mode) {
	case "memory", "inmemory", "in-memory":
		return connector.NewRegistry(), func() error { return nil }, nil
	case "postgres":
		dsn := strings.TrimSpace(config.DSN)
		if dsn == "" {
			return nil, nil, fmt.Errorf("connector-registry-postgres-dsn is required")
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
				return nil, nil, fmt.Errorf("load connector registry migrations: %w", err)
			}
			migrations, err = selectPostgresComponentMigrations(migrations, "connector registry", postgresConnectorRegistryMigrationVersions()...)
			if err != nil {
				db.Close()
				return nil, nil, err
			}
			if err := migrationstore.Apply(ctx, db, migrations); err != nil {
				db.Close()
				return nil, nil, fmt.Errorf("apply connector registry migrations: %w", err)
			}
		}
		return postgresConnectorRegistryStore{DB: db}, db.Close, nil
	default:
		// A FILE PATH — the same shape as -connector-route-governance-store, which the reference deployment
		// already points at the shared ./dataplane-ne mount.
		//
		// Why this case exists: the registry was memory-or-postgres only, so the reference Edge — deliberately
		// ZERO-DB, because the CP is the config authority — had NO durable option and ran on `memory`. An Edge
		// restart therefore deleted the fleet: a connector registers only at startup, so every heartbeat
		// afterwards gets 404 (unknown connector) forever and the Console shows an empty fleet, with nothing to
		// recover it but restarting every connector. Observed live 2026-07-17. The Edge had been warning about
		// exactly this at boot, listing "-connector-registry-store (registered connectors)" as in-memory.
		//
		// postgres is NOT the answer for this Edge: it is durable but the enforcement Edge never reads the CP's
		// database, so it would be durable-and-unread here.
		//
		// Use the RAW value, not the lowercased mode: a path is case-sensitive.
		path := strings.TrimSpace(config.Mode)
		// Only accept something that actually LOOKS like a path. Without this a typo ("postgress") is silently
		// accepted as a file named after the typo — a store that "works" while pointing somewhere nobody
		// intended, which for a durability-critical store is worse than refusing to start.
		if !looksLikeStorePath(path) {
			return nil, nil, fmt.Errorf("unsupported connector registry store mode %q (want \"memory\", \"postgres\", or a file path)", config.Mode)
		}
		registry := connector.NewRegistry()
		if err := registry.SetPersister(blobstore.FilePersister{Path: path}); err != nil {
			// Fail closed: a store that exists but cannot be read must not silently start as an empty fleet.
			return nil, nil, fmt.Errorf("load connector registry from %q: %w", path, err)
		}
		return registry, func() error { return nil }, nil
	}
}

// looksLikeStorePath reports whether a store-mode value is a file path rather than a mistyped keyword. A
// durability-critical store must fail loudly on a typo, not quietly persist to a file named after it.
func looksLikeStorePath(v string) bool {
	return strings.ContainsAny(v, "/\\") || strings.HasSuffix(strings.ToLower(v), ".json")
}
