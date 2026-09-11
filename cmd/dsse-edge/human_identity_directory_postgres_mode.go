package main

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/lantern-networks/dsse-core/blobstore"
	humanidentity "github.com/lantern-networks/dsse-core/humanidentity"
	migrationstore "github.com/lantern-networks/dsse-core/migrations"

	_ "github.com/lib/pq"
)

type edgeHumanIdentityDirectoryConfig struct {
	Mode          string
	DSN           string
	MigrationDir  string
	RunMigrations bool
}

func setupEdgeHumanIdentityDirectory(ctx context.Context, config edgeHumanIdentityDirectoryConfig) (humanidentity.HumanIdentityDirectoryRuntimeStore, func() error, error) {
	mode := strings.TrimSpace(strings.ToLower(config.Mode))
	if mode == "" {
		mode = "memory"
	}
	switch storeBackend(mode) {
	case "memory", "inmemory", "in-memory":
		return humanidentity.NewHumanIdentityDirectoryStore(), func() error { return nil }, nil
	case "postgres":
		dsn := strings.TrimSpace(config.DSN)
		if dsn == "" {
			return nil, nil, fmt.Errorf("identity-directory-postgres-dsn is required")
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
				return nil, nil, fmt.Errorf("load human identity directory migrations: %w", err)
			}
			migrations, err = selectPostgresComponentMigrations(migrations, "human identity directory", postgresHumanIdentityDirectoryMigrationVersions()...)
			if err != nil {
				db.Close()
				return nil, nil, err
			}
			if err := migrationstore.Apply(ctx, db, migrations); err != nil {
				db.Close()
				return nil, nil, fmt.Errorf("apply human identity directory migrations: %w", err)
			}
		}
		return postgresHumanIdentityDirectoryStore{DB: db, gen: new(uint64)}, db.Close, nil
	default:
		// A FILE PATH — the same shape as the connector registry and route-governance stores, which the
		// reference deployment already points at the shared ./dataplane-ne mount.
		//
		// Why this case exists: the human identity directory was memory-or-postgres only, so the reference Edge
		// — deliberately ZERO-DB, because the CP is the config authority — had NO durable option and ran on
		// `memory`. The directory is populated by IMPORT RUNS (and single upserts) at runtime and never
		// re-seeded, so an Edge restart erased every identity and every identity-scoped decision lost its
		// subject until the next import landed. postgres is durable but the enforcement Edge never reads the
		// CP's database, so it would be durable-and-unread here.
		//
		// Use the RAW value, not the lowercased mode: a path is case-sensitive.
		path := strings.TrimSpace(config.Mode)
		// Only accept something that actually LOOKS like a path (reusing looksLikeStorePath from the connector
		// registry factory). Without this a typo ("postgress") is silently accepted as a file named after the
		// typo — a store that "works" while pointing somewhere nobody intended.
		if !looksLikeStorePath(path) {
			return nil, nil, fmt.Errorf("unsupported identity directory store mode %q (want \"memory\", \"postgres\", or a file path)", config.Mode)
		}
		store := humanidentity.NewHumanIdentityDirectoryStore()
		if err := store.SetPersister(blobstore.FilePersister{Path: path}); err != nil {
			// Fail closed: a store that exists but cannot be read must not silently start as an empty directory.
			return nil, nil, fmt.Errorf("load human identity directory from %q: %w", path, err)
		}
		return store, func() error { return nil }, nil
	}
}
