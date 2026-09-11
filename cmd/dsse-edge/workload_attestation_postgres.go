package main

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"
)

const (
	postgresWorkloadAttestationNonceTimeout         = 5 * time.Second
	postgresWorkloadAttestationNonceCleanupInterval = 30 * time.Second
)

type postgresWorkloadAttestationNonceStore struct {
	DB *sql.DB
}

var _ runtimeWorkloadAttestationNonceStore = (*postgresWorkloadAttestationNonceStore)(nil)

func (store *postgresWorkloadAttestationNonceStore) Remember(tenantID, nonce string, now, expiresAt time.Time) error {
	if store == nil || store.DB == nil {
		return fmt.Errorf("postgres workload attestation nonce db is not configured")
	}
	ctx, cancel := context.WithTimeout(context.Background(), postgresWorkloadAttestationNonceTimeout)
	defer cancel()
	statement, err := buildPostgresWorkloadAttestationNonceInsertStatement(tenantID, nonce, now, expiresAt)
	if err != nil {
		return err
	}
	result, err := store.DB.ExecContext(ctx, statement.SQL, statement.Args...)
	if err != nil {
		return fmt.Errorf("insert workload attestation nonce: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("inspect workload attestation nonce insert: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("runtime workload attestation nonce was already used")
	}
	return nil
}

func (store *postgresWorkloadAttestationNonceStore) cleanupExpired(ctx context.Context, now time.Time) error {
	if store == nil || store.DB == nil {
		return fmt.Errorf("postgres workload attestation nonce db is not configured")
	}
	statement := buildPostgresWorkloadAttestationNonceCleanupStatement(now)
	if _, err := store.DB.ExecContext(ctx, statement.SQL, statement.Args...); err != nil {
		return fmt.Errorf("cleanup workload attestation nonces: %w", err)
	}
	return nil
}

func postgresWorkloadAttestationNonceSchemaSQL() []string {
	return []string{
		strings.Join([]string{
			"CREATE TABLE IF NOT EXISTS workload_attestation_nonces (",
			"tenant_id text NOT NULL,",
			"nonce_hash text NOT NULL,",
			"expires_at timestamptz NOT NULL,",
			"created_at timestamptz NOT NULL DEFAULT now(),",
			"PRIMARY KEY (tenant_id, nonce_hash)",
			")",
		}, " "),
		"CREATE INDEX IF NOT EXISTS workload_attestation_nonces_expires_idx ON workload_attestation_nonces (expires_at)",
	}
}

func buildPostgresWorkloadAttestationNonceInsertStatement(tenantID, nonce string, now, expiresAt time.Time) (postgresExportTaskQueueStatement, error) {
	tenantID = strings.TrimSpace(tenantID)
	nonce = strings.TrimSpace(nonce)
	if tenantID == "" || nonce == "" {
		return postgresExportTaskQueueStatement{}, fmt.Errorf("workload attestation tenant_id and nonce are required")
	}
	now = now.UTC()
	expiresAt = expiresAt.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if !expiresAt.After(now) {
		expiresAt = now.Add(time.Second)
	}
	return postgresExportTaskQueueStatement{
		SQL: strings.Join([]string{
			"INSERT INTO workload_attestation_nonces (tenant_id, nonce_hash, expires_at, created_at)",
			"VALUES ($1, $2, $3, $4)",
			"ON CONFLICT (tenant_id, nonce_hash) DO UPDATE SET",
			"expires_at = EXCLUDED.expires_at,",
			"created_at = EXCLUDED.created_at",
			"WHERE workload_attestation_nonces.expires_at <= EXCLUDED.created_at",
		}, " "),
		Args: []any{
			tenantID,
			runtimeWorkloadAttestationNonceHash(tenantID, nonce),
			expiresAt,
			now,
		},
	}, nil
}

func buildPostgresWorkloadAttestationNonceCleanupStatement(now time.Time) postgresExportTaskQueueStatement {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	return postgresExportTaskQueueStatement{
		SQL:  "DELETE FROM workload_attestation_nonces WHERE expires_at <= $1",
		Args: []any{now.UTC()},
	}
}
