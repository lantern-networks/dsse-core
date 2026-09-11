package main

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/lantern-networks/dsse-core/blobstore"
	migrationstore "github.com/lantern-networks/dsse-core/migrations"
	nhi "github.com/lantern-networks/dsse-core/nhi"

	_ "github.com/lib/pq"
)

type edgeNonHumanIdentityStoreConfig struct {
	Mode          string
	DSN           string
	MigrationDir  string
	RunMigrations bool
}

func setupEdgeNonHumanIdentityStore(ctx context.Context, config edgeNonHumanIdentityStoreConfig) (nhi.RuntimeStore, func() error, error) {
	mode := strings.TrimSpace(strings.ToLower(config.Mode))
	if mode == "" {
		mode = "memory"
	}
	switch storeBackend(mode) {
	case "memory", "inmemory", "in-memory":
		return nhi.NewStore(), func() error { return nil }, nil
	case "postgres":
		dsn := strings.TrimSpace(config.DSN)
		if dsn == "" {
			return nil, nil, fmt.Errorf("nhi-registry-postgres-dsn is required")
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
				return nil, nil, fmt.Errorf("load NHI registry migrations: %w", err)
			}
			migrations, err = selectPostgresComponentMigrations(migrations, "NHI registry", postgresNonHumanIdentityMigrationVersions()...)
			if err != nil {
				db.Close()
				return nil, nil, err
			}
			if err := migrationstore.Apply(ctx, db, migrations); err != nil {
				db.Close()
				return nil, nil, fmt.Errorf("apply NHI registry migrations: %w", err)
			}
		}
		return postgresNonHumanIdentityStore{DB: db, gen: new(uint64)}, db.Close, nil
	default:
		// A FILE PATH — the same durable-file shape used by the connector registry and vlan stores, which the
		// reference deployment points at the shared ./dataplane-ne mount.
		//
		// Why this case exists: the NHI registry was memory-or-postgres only, so the reference Edge — deliberately
		// ZERO-DB, because the CP is the config authority — had NO durable option and ran on `memory`. An Edge
		// restart therefore wiped every registered non-human identity, and postgres is durable-but-unread here
		// (the enforcement Edge never reads the CP's database).
		//
		// Use the RAW value, not the lowercased mode: a path is case-sensitive. looksLikeStorePath (defined in
		// connector_registry_postgres_mode.go) refuses a value that does not look like a path so a typo
		// ("postgress") cannot be quietly accepted as a file named after the typo.
		path := strings.TrimSpace(config.Mode)
		if !looksLikeStorePath(path) {
			return nil, nil, fmt.Errorf("unsupported NHI registry store mode %q (want \"memory\", \"postgres\", or a file path)", config.Mode)
		}
		store := nhi.NewStore()
		if err := store.SetPersister(blobstore.FilePersister{Path: path}); err != nil {
			// Fail closed: a store that exists but cannot be read must not silently start as an empty registry.
			return nil, nil, fmt.Errorf("load NHI registry from %q: %w", path, err)
		}
		return store, func() error { return nil }, nil
	}
}
