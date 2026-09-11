package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/lantern-networks/dsse-core/logs"
	migrationstore "github.com/lantern-networks/dsse-core/migrations"

	_ "github.com/lib/pq"
)

type postgresAuditOutboxPublisherConfig struct {
	DSN            string
	MigrationDir   string
	RunMigrations  bool
	TenantID       string
	PublisherID    string
	PollInterval   time.Duration
	BatchSize      int
	LockDuration   time.Duration
	RetryDelay     time.Duration
	MaxAttempts    int
	Writer         *logs.Writer
	Delivery       adminAuditOutboxDelivery
	DeliveryMode   string
	WebhookURL     string
	WebhookToken   string
	WebhookSecret  string
	WebhookKeyID   string
	WebhookTimeout time.Duration
}

func runPostgresAuditOutboxPublisher(ctx context.Context, config postgresAuditOutboxPublisherConfig) error {
	if ctx == nil {
		ctx = context.Background()
	}
	dsn := strings.TrimSpace(config.DSN)
	if dsn == "" {
		return fmt.Errorf("postgres-dsn is required")
	}
	tenantID := strings.TrimSpace(config.TenantID)
	if tenantID == "" {
		return fmt.Errorf("audit publisher tenant_id is required")
	}
	publisherID := strings.TrimSpace(config.PublisherID)
	if publisherID == "" {
		return fmt.Errorf("audit-publisher-id is required")
	}
	delivery := config.Delivery
	if delivery == nil {
		var err error
		delivery, err = adminAuditOutboxDeliveryFromConfig(config)
		if err != nil {
			return err
		}
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
		migrations, err = selectPostgresComponentMigrations(migrations, "audit outbox", postgresMigrationAdminAuditOutbox)
		if err != nil {
			return err
		}
		if err := migrationstore.Apply(ctx, db, migrations); err != nil {
			return fmt.Errorf("apply migrations: %w", err)
		}
	}
	pollInterval := config.PollInterval
	if pollInterval <= 0 {
		pollInterval = 250 * time.Millisecond
	}
	publisher := postgresAdminAuditOutboxPublisher{
		DB:           db,
		TenantID:     tenantID,
		PublisherID:  publisherID,
		Writer:       config.Writer,
		Delivery:     delivery,
		BatchSize:    config.BatchSize,
		LockDuration: config.LockDuration,
		RetryDelay:   config.RetryDelay,
		MaxAttempts:  config.MaxAttempts,
	}
	runCtx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	logDebugf("postgres audit outbox publisher polling tenant=%s publisher_id=%s", tenantID, publisherID)
	for {
		if err := runCtx.Err(); err != nil {
			if errors.Is(err, context.Canceled) {
				return nil
			}
			return err
		}
		published, err := publisher.PublishOnce(runCtx, time.Now().UTC())
		if err != nil {
			if runErr := runCtx.Err(); errors.Is(runErr, context.Canceled) {
				return nil
			}
			// PostgreSQL outbox errors are process-level signals: a supervisor should restart
			// or alert rather than silently losing audit delivery.
			return err
		}
		if published > 0 {
			continue
		}
		timer := time.NewTimer(pollInterval)
		select {
		case <-runCtx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return nil
		case <-timer.C:
		}
	}
}

func adminAuditOutboxDeliveryFromConfig(config postgresAuditOutboxPublisherConfig) (adminAuditOutboxDelivery, error) {
	mode := strings.ToLower(strings.TrimSpace(config.DeliveryMode))
	if mode == "" {
		mode = "jsonl"
	}
	switch mode {
	case "jsonl":
		if config.Writer == nil {
			return nil, fmt.Errorf("audit log writer is required for jsonl delivery")
		}
		return jsonlAdminAuditOutboxDelivery{Writer: config.Writer}, nil
	case "webhook":
		return httpAdminAuditOutboxDelivery{
			Endpoint:      config.WebhookURL,
			BearerToken:   config.WebhookToken,
			SigningSecret: config.WebhookSecret,
			SigningKeyID:  config.WebhookKeyID,
			Timeout:       config.WebhookTimeout,
		}, nil
	default:
		return nil, fmt.Errorf("unknown audit outbox delivery mode %q", config.DeliveryMode)
	}
}
