package main

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	migrationstore "github.com/lantern-networks/dsse-core/migrations"

	_ "github.com/lib/pq"
)

type edgeAdminExportJobStoreConfig struct {
	Mode          string
	DSN           string
	MigrationDir  string
	RunMigrations bool
}

type edgeAdminExportWorkerConfig struct {
	Mode                    string
	DSN                     string
	MigrationDir            string
	RunMigrations           bool
	Timeout                 time.Duration
	DisableDirectAuditJSONL bool
}

func setupEdgeAdminExportJobStore(ctx context.Context, config edgeAdminExportJobStoreConfig) (adminExportJobAdminStore, func() error, error) {
	mode := strings.TrimSpace(strings.ToLower(config.Mode))
	if mode == "" {
		mode = "memory"
	}
	switch storeBackend(mode) {
	case "memory", "inmemory", "in-memory":
		return newAdminExportJobStore(), func() error { return nil }, nil
	case "postgres":
		dsn := strings.TrimSpace(config.DSN)
		if dsn == "" {
			return nil, nil, fmt.Errorf("admin-export-job-postgres-dsn is required")
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
				return nil, nil, fmt.Errorf("load admin export job migrations: %w", err)
			}
			migrations, err = selectPostgresComponentMigrations(migrations, "admin export job", postgresMigrationAdminExportJobs)
			if err != nil {
				db.Close()
				return nil, nil, err
			}
			if err := migrationstore.Apply(ctx, db, migrations); err != nil {
				db.Close()
				return nil, nil, fmt.Errorf("apply admin export job migrations: %w", err)
			}
		}
		return postgresAdminExportJobStore{DB: db}, db.Close, nil
	default:
		return nil, nil, fmt.Errorf("unsupported admin export job store mode %q", config.Mode)
	}
}

func setupEdgeAdminExportWorker(ctx context.Context, config edgeAdminExportWorkerConfig) (adminExportWorker, func() error, error) {
	mode := strings.TrimSpace(strings.ToLower(config.Mode))
	if mode == "" {
		mode = "sync"
	}
	switch storeBackend(mode) {
	case "sync", "synchronous":
		return synchronousAdminExportWorker{}, func() error { return nil }, nil
	case "local-async":
		return localAsyncAdminExportWorker{Timeout: config.Timeout}, func() error { return nil }, nil
	case "postgres-queue":
		dsn := strings.TrimSpace(config.DSN)
		if dsn == "" {
			return nil, nil, fmt.Errorf("admin-export-queue-postgres-dsn is required")
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
				return nil, nil, fmt.Errorf("load admin export queue migrations: %w", err)
			}
			migrations, err = selectPostgresComponentMigrations(migrations, "admin export queue", postgresMigrationExportWorkerQueue, postgresMigrationAdminAuditOutbox)
			if err != nil {
				db.Close()
				return nil, nil, err
			}
			if err := migrationstore.Apply(ctx, db, migrations); err != nil {
				db.Close()
				return nil, nil, fmt.Errorf("apply admin export queue migrations: %w", err)
			}
		}
		return postgresQueueAdminExportWorker{
			Queue:                   postgresExportTaskQueueAdapter{DB: postgresExportTaskSQLDB{DB: db}},
			DB:                      db,
			DisableDirectAuditJSONL: config.DisableDirectAuditJSONL,
		}, db.Close, nil
	default:
		return nil, nil, fmt.Errorf("unsupported admin export worker mode %q", config.Mode)
	}
}
