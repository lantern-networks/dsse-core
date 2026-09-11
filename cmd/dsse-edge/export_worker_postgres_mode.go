package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/hotstore"
	"github.com/lantern-networks/dsse-core/logs"
	migrationstore "github.com/lantern-networks/dsse-core/migrations"

	_ "github.com/lib/pq"
)

type postgresExportWorkerConfig struct {
	DSN                    string
	MigrationDir           string
	RunMigrations          bool
	SchemaDir              string
	TenantID               string
	WorkerID               string
	HotStoreMode           string
	PollInterval           time.Duration
	LeaseDuration          time.Duration
	LeaseExtensionInterval time.Duration
	Timeout                time.Duration
	Writer                 *logs.Writer
	ObjectStore            adminExportObjectStore
	Evaluator              decision.Evaluator
}

func runPostgresExportWorker(ctx context.Context, config postgresExportWorkerConfig) error {
	if ctx == nil {
		ctx = context.Background()
	}
	dsn := strings.TrimSpace(config.DSN)
	if dsn == "" {
		return fmt.Errorf("postgres-dsn is required")
	}
	tenantID := strings.TrimSpace(config.TenantID)
	if tenantID == "" {
		return fmt.Errorf("worker tenant_id is required")
	}
	workerID := strings.TrimSpace(config.WorkerID)
	if workerID == "" {
		return fmt.Errorf("worker-id is required")
	}
	if config.Writer == nil {
		return fmt.Errorf("export log writer is required")
	}
	if config.ObjectStore == nil {
		return fmt.Errorf("export object store is required")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return err
	}
	defer db.Close()
	if err := db.PingContext(ctx); err != nil {
		return err
	}
	if config.RunMigrations {
		migrations, err := migrationstore.LoadDir(config.MigrationDir)
		if err != nil {
			return fmt.Errorf("load migrations: %w", err)
		}
		migrations, err = selectPostgresComponentMigrations(migrations, "export worker", postgresExportWorkerMigrationVersions(config.HotStoreMode)...)
		if err != nil {
			return err
		}
		if err := migrationstore.Apply(ctx, db, migrations); err != nil {
			return fmt.Errorf("apply migrations: %w", err)
		}
	}
	schemaData, err := os.ReadFile(filepath.Join(config.SchemaDir, "export_worker_task.schema.json"))
	if err != nil {
		return fmt.Errorf("read export worker task schema: %w", err)
	}
	runtimeHotStore, err := postgresExportWorkerHotStore(config.HotStoreMode, db, config.Writer)
	if err != nil {
		return err
	}
	runCtx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	worker := postgresQueuedAdminExportWorker{
		Queue: postgresExportTaskQueueAdapter{
			DB:            postgresExportTaskSQLDB{DB: db},
			TenantID:      tenantID,
			WorkerID:      workerID,
			LeaseDuration: config.LeaseDuration,
			SchemaData:    schemaData,
			Resolver: adminExportRuntimeResolver{
				Writer:           config.Writer,
				AdminAuditOutbox: postgresAdminAuditOutboxReader{DB: db},
				ObjectStore:      config.ObjectStore,
				HotStore:         runtimeHotStore,
				Store:            postgresAdminExportJobStore{DB: db},
				Evaluator:        config.Evaluator,
			},
		},
		Timeout:                config.Timeout,
		PollInterval:           config.PollInterval,
		LeaseExtensionInterval: config.LeaseExtensionInterval,
	}
	logDebugf("postgres export worker polling tenant=%s worker_id=%s", tenantID, workerID)
	if err := worker.Run(runCtx); err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	return nil
}

func postgresExportWorkerHotStore(mode string, db *sql.DB, writer *logs.Writer) (hotstore.Store, error) {
	switch storeBackend(strings.TrimSpace(strings.ToLower(mode))) {
	case "", "jsonl":
		if writer == nil {
			return nil, fmt.Errorf("export log writer is required")
		}
		return hotstore.NewJSONLStore(writer, adminLogStreamFilenameMap()), nil
	case "postgres":
		if db == nil {
			return nil, fmt.Errorf("postgres db is required for postgres hot store")
		}
		return hotstore.NewPostgresStore(db), nil
	default:
		return nil, fmt.Errorf("unsupported worker hot store %q", mode)
	}
}
