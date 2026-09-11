package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	migrationstore "github.com/lantern-networks/dsse-core/migrations"
)

// Durable persistence for first-party admin credentials (slice 2 of
// docs/admin_auth_centralization_design.md). The control plane is the admin auth authority; without a durable
// store a control-plane restart loses every SaaS-issued admin account (the operator can no longer sign in).
// Postgres-backed write-through: the in-memory store stays the hot path, each mutation mirrors to Postgres,
// and LoadAll repopulates on startup.

// postgresCredentialPersistence implements credentialPersistence over a *sql.DB.
type postgresCredentialPersistence struct{ db *sql.DB }

func (p postgresCredentialPersistence) LoadAll(ctx context.Context) ([]*localAdminCredential, error) {
	rows, err := p.db.QueryContext(ctx, `
		SELECT email, principal_id, tenant_id, roles, status, password_hash, totp_secret, totp_enrolled,
		       recovery_code_hashes, failed_attempts, locked_until, activation_token_hash,
		       activation_expires_at, created_at, updated_at
		FROM admin_local_credentials`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*localAdminCredential
	for rows.Next() {
		c := &localAdminCredential{}
		var rolesJSON, recoveryJSON []byte
		var lockedUntil, activationExpiresAt sql.NullTime
		if err := rows.Scan(&c.Email, &c.PrincipalID, &c.TenantID, &rolesJSON, &c.Status, &c.PasswordHash,
			&c.TOTPSecret, &c.TOTPEnrolled, &recoveryJSON, &c.FailedAttempts, &lockedUntil,
			&c.ActivationTokenHash, &activationExpiresAt, &c.CreatedAt, &c.UpdatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(rolesJSON, &c.Roles)
		_ = json.Unmarshal(recoveryJSON, &c.RecoveryCodeHashes)
		// Unseal the at-rest TOTP secret (no-op when stored as plaintext / no KEK). Fail-closed: a sealed
		// secret with no KEK aborts the load rather than silently dropping every operator's 2FA.
		if c.TOTPSecret, err = unsealTOTPSecretFromStore(c.TOTPSecret); err != nil {
			return nil, fmt.Errorf("unseal totp secret for %s: %w", c.Email, err)
		}
		if lockedUntil.Valid {
			c.LockedUntil = lockedUntil.Time.UTC()
		}
		if activationExpiresAt.Valid {
			c.ActivationExpiresAt = activationExpiresAt.Time.UTC()
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (p postgresCredentialPersistence) Upsert(ctx context.Context, c *localAdminCredential) error {
	roles, err := json.Marshal(c.Roles)
	if err != nil {
		return err
	}
	recovery, err := json.Marshal(c.RecoveryCodeHashes)
	if err != nil {
		return err
	}
	// Seal the TOTP secret at rest (no-op when no KEK is configured). The in-memory store keeps the plaintext;
	// only the durable column gets the sealed value.
	sealedTOTP, err := sealTOTPSecretForStore(c.TOTPSecret)
	if err != nil {
		return err
	}
	_, err = p.db.ExecContext(ctx, `
		INSERT INTO admin_local_credentials (
			email, principal_id, tenant_id, roles, status, password_hash, totp_secret, totp_enrolled,
			recovery_code_hashes, failed_attempts, locked_until, activation_token_hash,
			activation_expires_at, created_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
		ON CONFLICT (email) DO UPDATE SET
			principal_id=EXCLUDED.principal_id, tenant_id=EXCLUDED.tenant_id, roles=EXCLUDED.roles,
			status=EXCLUDED.status, password_hash=EXCLUDED.password_hash, totp_secret=EXCLUDED.totp_secret,
			totp_enrolled=EXCLUDED.totp_enrolled, recovery_code_hashes=EXCLUDED.recovery_code_hashes,
			failed_attempts=EXCLUDED.failed_attempts, locked_until=EXCLUDED.locked_until,
			activation_token_hash=EXCLUDED.activation_token_hash,
			activation_expires_at=EXCLUDED.activation_expires_at, updated_at=EXCLUDED.updated_at`,
		c.Email, c.PrincipalID, c.TenantID, roles, c.Status, c.PasswordHash, sealedTOTP, c.TOTPEnrolled,
		recovery, c.FailedAttempts, nullTime(c.LockedUntil), c.ActivationTokenHash,
		nullTime(c.ActivationExpiresAt), c.CreatedAt, c.UpdatedAt)
	return err
}

// Delete removes a credential durably. The (email, tenant_id) predicate keeps the delete tenant-scoped so an
// account can never be removed across tenants even though email is the table's primary key.
func (p postgresCredentialPersistence) Delete(ctx context.Context, tenantID, email string) error {
	_, err := p.db.ExecContext(ctx,
		`DELETE FROM admin_local_credentials WHERE email=$1 AND tenant_id=$2`,
		credentialEmailKey(email), tenantID)
	return err
}

func nullTime(t time.Time) sql.NullTime {
	if t.IsZero() {
		return sql.NullTime{}
	}
	return sql.NullTime{Time: t, Valid: true}
}

// setupLocalCredentialPersistence returns a durable credential persistence for the given mode. "memory" (or
// empty) => nil (in-memory only). "postgres" => a write-through Postgres store (migrations applied first).
func setupLocalCredentialPersistence(ctx context.Context, mode, dsn, migrationDir string, runMigrations bool) (credentialPersistence, func() error, error) {
	switch storeBackend(strings.TrimSpace(strings.ToLower(mode))) {
	case "", "memory", "inmemory", "in-memory":
		return nil, func() error { return nil }, nil
	case "postgres":
		if strings.TrimSpace(dsn) == "" {
			return nil, nil, fmt.Errorf("first-party-store-postgres-dsn is required")
		}
		db, err := sql.Open("postgres", dsn)
		if err != nil {
			return nil, nil, err
		}
		if err := db.PingContext(ctx); err != nil {
			db.Close()
			return nil, nil, err
		}
		if runMigrations {
			migrations, err := migrationstore.LoadDir(migrationDir)
			if err != nil {
				db.Close()
				return nil, nil, fmt.Errorf("load local-credential migrations: %w", err)
			}
			migrations, err = selectPostgresComponentMigrations(migrations, "admin local credentials", postgresMigrationLocalCredentials)
			if err != nil {
				db.Close()
				return nil, nil, err
			}
			if err := migrationstore.Apply(ctx, db, migrations); err != nil {
				db.Close()
				return nil, nil, fmt.Errorf("apply local-credential migrations: %w", err)
			}
		}
		return postgresCredentialPersistence{db: db}, db.Close, nil
	default:
		// A FILE PATH — the durable option for the reference, zero-DB Edge. Postgres is durable but the
		// enforcement Edge never reads the CP's database, so it would be durable-and-unread here; a local
		// snapshot file survives a restart and keeps SaaS-issued admin accounts alive. Same shape as
		// -connector-registry-store's file backend.
		//
		// Use the RAW mode value (not lowercased): a path is case-sensitive. looksLikeStorePath is defined in
		// connector_registry_postgres_mode.go — reused so a typo ("postgress") fails loudly instead of quietly
		// persisting to a file named after the typo, which for admin credentials is worse than refusing to start.
		path := strings.TrimSpace(mode)
		if !looksLikeStorePath(path) {
			return nil, nil, fmt.Errorf("unsupported first-party store mode %q (want \"memory\", \"postgres\", or a file path)", mode)
		}
		return newFileCredentialPersistence(path), func() error { return nil }, nil
	}
}
