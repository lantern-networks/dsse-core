package main

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/lantern-networks/dsse-core/blobstore"
	devicestore "github.com/lantern-networks/dsse-core/device"
	migrationstore "github.com/lantern-networks/dsse-core/migrations"

	_ "github.com/lib/pq"
)

type edgeDeviceStoreConfig struct {
	Mode          string
	DSN           string
	MigrationDir  string
	RunMigrations bool
}

func setupEdgeDeviceStore(ctx context.Context, config edgeDeviceStoreConfig) (deviceRuntimeStore, func() error, error) {
	mode := strings.TrimSpace(strings.ToLower(config.Mode))
	if mode == "" {
		mode = "memory"
	}
	switch storeBackend(mode) {
	case "memory", "inmemory", "in-memory":
		return devicestore.NewStore(), func() error { return nil }, nil
	case "postgres":
		dsn := strings.TrimSpace(config.DSN)
		if dsn == "" {
			return nil, nil, fmt.Errorf("device-postgres-dsn is required")
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
				return nil, nil, fmt.Errorf("load device inventory migrations: %w", err)
			}
			migrations, err = selectPostgresComponentMigrations(migrations, "device inventory", postgresDeviceInventoryMigrationVersions()...)
			if err != nil {
				db.Close()
				return nil, nil, err
			}
			if err := migrationstore.Apply(ctx, db, migrations); err != nil {
				db.Close()
				return nil, nil, fmt.Errorf("apply device inventory migrations: %w", err)
			}
		}
		return &postgresDeviceInventoryStore{DB: db}, db.Close, nil
	default:
		// A FILE PATH — the same durable-file shape used for the connector registry and the CP-state stores. The
		// device inventory was memory-or-postgres only, so the reference Edge — deliberately ZERO-DB, the CP being
		// the config authority — had NO durable option and ran on `memory`. An Edge restart therefore wiped every
		// registered device: risk markings, posture verdicts and the catalog itself vanished until each endpoint
		// re-registered. postgres is durable but the enforcement Edge never reads the CP's database, so it would be
		// durable-and-unread here; a file on the shared mount is the right backend.
		//
		// Use the RAW value, not the lowercased mode: a path is case-sensitive.
		path := strings.TrimSpace(config.Mode)
		// Only accept something that actually LOOKS like a path (helper defined in connector_registry_postgres_mode.go,
		// same package). Without this a typo ("postgress") is silently accepted as a file named after the typo — a
		// store that "works" while pointing somewhere nobody intended, worse than refusing to start.
		if !looksLikeStorePath(path) {
			return nil, nil, fmt.Errorf("unsupported device store mode %q (want \"memory\", \"postgres\", or a file path)", config.Mode)
		}
		store := devicestore.NewStore()
		if err := store.SetPersister(blobstore.FilePersister{Path: path}); err != nil {
			// Fail closed: a store that exists but cannot be read must not silently start as an empty inventory.
			return nil, nil, fmt.Errorf("load device inventory from %q: %w", path, err)
		}
		return store, func() error { return nil }, nil
	}
}
