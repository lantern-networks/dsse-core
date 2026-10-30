// dsse-grant-migrate prepares an offline, revoking downgrade of grant storage.
package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/lantern-networks/dsse-core/grantstore"
	_ "github.com/lib/pq"
)

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "grant migration failed:", err)
		os.Exit(1)
	}
}
func digest(raw []byte) string { h := sha256.Sum256(raw); return hex.EncodeToString(h[:]) }
func exclusiveFile(path string, raw []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return errors.New("cannot create private output file (it must not already exist)")
	}
	defer f.Close()
	if _, err = f.Write(raw); err != nil {
		return errors.New("output write failed")
	}
	if err = f.Sync(); err != nil {
		return errors.New("output sync failed")
	}
	return nil
}
func run(args []string, output io.Writer) error {
	flags := flag.NewFlagSet("dsse-grant-migrate", flag.ContinueOnError)
	input := flags.String("input", "", "snapshot file; mutually exclusive with --postgres")
	dest := flags.String("output", "", "new legacy-format output file")
	postgres := flags.Bool("postgres", false, "migrate cp_state_blobs/grants; DSSE_GRANT_MIGRATION_DSN environment variable supplies DSN")
	backup := flags.String("backup", "", "new private snapshot backup file (required for Postgres apply)")
	apply := flags.Bool("apply", false, "write changes; default is read-only inspection")
	stopped := flags.Bool("writers-stopped", false, "operator assertion that all CP/Edge readers and writers are stopped")
	expected := flags.String("expect-sha256", "", "source hash from read-only inspection, required for apply")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || (*input == "") == !*postgres {
		return errors.New("select exactly one of --input or --postgres")
	}
	if *apply && (!*stopped || len(*expected) != 64) {
		return errors.New("apply requires --writers-stopped and --expect-sha256")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var raw []byte
	var tx *sql.Tx
	if *postgres {
		if *dest != "" {
			return errors.New("--output is only for snapshot files")
		}
		dsn := os.Getenv("DSSE_GRANT_MIGRATION_DSN")
		if dsn == "" {
			return errors.New("DSSE_GRANT_MIGRATION_DSN is required")
		}
		db, err := sql.Open("postgres", dsn)
		if err != nil {
			return errors.New("database configuration invalid")
		}
		defer db.Close()
		tx, err = db.BeginTx(ctx, nil)
		if err != nil {
			return errors.New("database transaction unavailable")
		}
		defer tx.Rollback()
		query := "SELECT payload FROM cp_state_blobs WHERE store_key='grants'"
		if *apply {
			query += " FOR UPDATE"
		}
		if tx.QueryRowContext(ctx, query).Scan(&raw) != nil {
			return errors.New("grant snapshot unavailable")
		}
	} else {
		info, err := os.Lstat(*input)
		if err != nil || !info.Mode().IsRegular() || info.Size() > 64<<20 {
			return errors.New("input must be a regular snapshot file no larger than 64 MiB")
		}
		raw, err = os.ReadFile(*input)
		if err != nil {
			return errors.New("input read failed")
		}
	}
	if len(raw) > 64<<20 {
		return errors.New("snapshot exceeds 64 MiB")
	}
	converted, count, err := grantstore.LegacyRollbackSnapshot(raw)
	if err != nil {
		return errors.New("invalid or unsupported grant snapshot; no records changed")
	}
	if !*apply {
		_, err = fmt.Fprintf(output, "source_sha256=%s grants=%d action=revoke_all_and_convert_to_legacy dry_run=true\n", digest(raw), count)
		return err
	}
	if digest(raw) != *expected {
		return errors.New("source changed since inspection; no records changed")
	}
	if *postgres {
		if *backup == "" {
			return errors.New("--backup is required for Postgres apply")
		}
		if err = exclusiveFile(*backup, raw); err != nil {
			return err
		}
		result, e := tx.ExecContext(ctx, "UPDATE cp_state_blobs SET payload=$1,updated_at=now() WHERE store_key='grants' AND payload=$2", converted, raw)
		if e != nil {
			return errors.New("database update failed; backup retained")
		}
		n, e := result.RowsAffected()
		if e != nil || n != 1 {
			return errors.New("database compare-and-set failed; backup retained")
		}
		if tx.Commit() != nil {
			return errors.New("commit acknowledgement unavailable; inspect current snapshot before any further action")
		}
	} else {
		if *dest == "" {
			return errors.New("--output is required for file apply")
		}
		if err = exclusiveFile(*dest, converted); err != nil {
			return err
		}
	}
	_, err = fmt.Fprintf(output, "grants=%d all_revoked=true output_sha256=%s\n", count, digest(converted))
	return err
}
