package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"strings"
	"time"

	migrationstore "github.com/lantern-networks/dsse-core/migrations"

	_ "github.com/lib/pq"
)

type edgeWorkloadAttestationNonceStoreConfig struct {
	Mode          string
	DSN           string
	MigrationDir  string
	RunMigrations bool
}

func setupEdgeWorkloadAttestationNonceStore(ctx context.Context, config edgeWorkloadAttestationNonceStoreConfig) (runtimeWorkloadAttestationNonceStore, func() error, error) {
	mode := strings.TrimSpace(strings.ToLower(config.Mode))
	if mode == "" {
		mode = "memory"
	}
	switch storeBackend(mode) {
	case "memory", "inmemory", "in-memory":
		return newRuntimeWorkloadAttestationReplayCache(), func() error { return nil }, nil
	case "postgres":
		dsn := strings.TrimSpace(config.DSN)
		if dsn == "" {
			return nil, nil, fmt.Errorf("workload-attestation-nonce-postgres-dsn is required")
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
				return nil, nil, fmt.Errorf("load workload attestation nonce migrations: %w", err)
			}
			migrations, err = selectPostgresComponentMigrations(migrations, "workload attestation nonce", postgresWorkloadAttestationNonceMigrationVersions()...)
			if err != nil {
				db.Close()
				return nil, nil, err
			}
			if err := migrationstore.Apply(ctx, db, migrations); err != nil {
				db.Close()
				return nil, nil, fmt.Errorf("apply workload attestation nonce migrations: %w", err)
			}
		}
		store := &postgresWorkloadAttestationNonceStore{DB: db}
		stopCleanup := startPostgresWorkloadAttestationNonceCleanup(store)
		return store, func() error {
			stopCleanup()
			return db.Close()
		}, nil
	default:
		return nil, nil, fmt.Errorf("unsupported workload attestation nonce store mode %q", config.Mode)
	}
}

func startPostgresWorkloadAttestationNonceCleanup(store *postgresWorkloadAttestationNonceStore) func() {
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		ticker := time.NewTicker(postgresWorkloadAttestationNonceCleanupInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-ticker.C:
				cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), postgresWorkloadAttestationNonceTimeout)
				if err := store.cleanupExpired(cleanupCtx, now.UTC()); err != nil {
					log.Printf("workload attestation nonce cleanup failed: %v", err)
				}
				cleanupCancel()
			}
		}
	}()
	return cancel
}
