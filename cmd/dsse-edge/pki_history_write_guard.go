package main

import (
	"context"
	"database/sql"
	"fmt"
)

// Migrations install the guard in PostgreSQL itself, so an older writer cannot
// bypass it by calling Save instead of the current authority CAS adapter.
func requirePKIHistoryWriteGuard(db *sql.DB) error {
	ctx, cancel := context.WithTimeout(context.Background(), cpStateBlobDBTimeout)
	defer cancel()
	var enabled bool
	err := db.QueryRowContext(ctx, `SELECT EXISTS (
 SELECT 1 FROM pg_trigger t JOIN pg_proc p ON p.oid=t.tgfoid
 WHERE t.tgrelid=to_regclass('cp_state_blobs')
 AND t.tgname='dsse_pki_history_write_guard' AND t.tgenabled IN ('O','A')
 AND p.proname='dsse_guard_pki_history' AND NOT t.tgisinternal
 )`).Scan(&enabled)
	if err != nil {
		return fmt.Errorf("verify PKI history write guard: %w", err)
	}
	if !enabled {
		return fmt.Errorf("PKI history write guard is missing or disabled; apply database migration 047 before starting a PKI writer")
	}
	return nil
}
