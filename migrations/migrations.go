package migrations

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type Migration struct {
	Version    string
	Name       string
	Path       string
	Statements []string
}

func LoadDir(dir string) ([]Migration, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var migrations []Migration
	seenVersions := map[string]string{}
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".sql" {
			continue
		}
		version, name, err := parseMigrationFilename(entry.Name())
		if err != nil {
			return nil, err
		}
		if previous := seenVersions[version]; previous != "" {
			return nil, fmt.Errorf("duplicate migration version %q in %s and %s", version, previous, entry.Name())
		}
		seenVersions[version] = entry.Name()
		path := filepath.Join(dir, entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		migrations = append(migrations, Migration{
			Version:    version,
			Name:       name,
			Path:       path,
			Statements: SplitSQLStatements(string(data)),
		})
	}
	sort.Slice(migrations, func(i, j int) bool {
		if migrations[i].Version == migrations[j].Version {
			return migrations[i].Name < migrations[j].Name
		}
		return migrations[i].Version < migrations[j].Version
	})
	return migrations, nil
}

func SelectVersions(migrations []Migration, versions ...string) ([]Migration, error) {
	wanted := map[string]bool{}
	for _, version := range versions {
		version = strings.TrimSpace(version)
		if version != "" {
			wanted[version] = false
		}
	}
	if len(wanted) == 0 {
		return nil, fmt.Errorf("migration versions are required")
	}
	selected := []Migration{}
	for _, migration := range migrations {
		if _, ok := wanted[migration.Version]; !ok {
			continue
		}
		selected = append(selected, migration)
		wanted[migration.Version] = true
	}
	missing := []string{}
	for version, found := range wanted {
		if !found {
			missing = append(missing, version)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		// ★ SAY WHICH KIND OF MISSING (2026-08-13, after it cost a lab outage). "missing migration version(s):
		// 035, 036, 037" reads as "the database is behind", and the operator goes looking at the database. The
		// actual cause was that the FILES were not in the image: a deployment rebuilt without re-staging carried
		// migrations four versions old, and the barrier — correctly — refused to start a node whose schema it
		// could not guarantee. Two different fixes, one sentence, and the wrong one was the obvious reading.
		//
		// The set this function was given IS the set of files it can see, so it can tell the operator exactly
		// that, and name the newest one it does have as the evidence.
		newest := ""
		if len(migrations) > 0 {
			newest = migrations[len(migrations)-1].Version
		}
		return nil, fmt.Errorf("missing migration version(s): %s — these are not among the %d migration FILES "+
			"available to this process (newest: %s). If the files should be there, this build's migration "+
			"directory is stale; if they are there, the selection asked for versions that do not exist",
			strings.Join(missing, ", "), len(migrations), newest)
	}
	return selected, nil
}

func Apply(ctx context.Context, db *sql.DB, migrations []Migration) error {
	if db == nil {
		return fmt.Errorf("migration db is not configured")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	// ★★★ THE LEDGER'S OWN TABLE HAS TO BE CREATED UNDER THE LOCK TOO (2026-08-24, measured by starting two
	// control planes at once). Every migration below is applied under pg_advisory_xact_lock, which is right —
	// but the statement that creates the table that lock exists to protect ran OUTSIDE it, and
	// CREATE TABLE IF NOT EXISTS is NOT concurrency-safe in Postgres: the existence check looks at the
	// catalogue, and the insert into pg_type that follows is not serialised against another session doing the
	// same thing. Two control planes starting together produced
	//
	//   ensure schema_migrations: pq: duplicate key value violates unique constraint "pg_type_typname_nsp_index"
	//
	// and one of the pair refused to start. A deployment whose authority is a leader and a warm standby cannot
	// have a start-up order; they come up together or the pair is not a pair.
	if err := withMigrationLock(ctx, db, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, strings.Join([]string{
			"CREATE TABLE IF NOT EXISTS schema_migrations (",
			"version text PRIMARY KEY,",
			"name text NOT NULL,",
			"applied_at timestamptz NOT NULL DEFAULT now()",
			")",
		}, " "))
		return err
	}); err != nil {
		return fmt.Errorf("ensure schema_migrations: %w", err)
	}
	for _, migration := range migrations {
		if err := applyOne(ctx, db, migration); err != nil {
			return err
		}
	}
	return nil
}

func SplitSQLStatements(sqlText string) []string {
	statements := []string{}
	var current strings.Builder
	inSingleQuote := false
	inDoubleQuote := false
	inLineComment := false
	inBlockComment := false
	dollarQuoteTag := ""
	for i := 0; i < len(sqlText); i++ {
		ch := sqlText[i]
		next := byte(0)
		if i+1 < len(sqlText) {
			next = sqlText[i+1]
		}
		if inLineComment {
			current.WriteByte(ch)
			if ch == '\n' {
				inLineComment = false
			}
			continue
		}
		if inBlockComment {
			current.WriteByte(ch)
			if ch == '*' && next == '/' {
				current.WriteByte(next)
				i++
				inBlockComment = false
			}
			continue
		}
		if dollarQuoteTag != "" {
			if strings.HasPrefix(sqlText[i:], dollarQuoteTag) {
				current.WriteString(dollarQuoteTag)
				i += len(dollarQuoteTag) - 1
				dollarQuoteTag = ""
				continue
			}
			current.WriteByte(ch)
			continue
		}
		if inSingleQuote {
			current.WriteByte(ch)
			if ch == '\'' {
				if next == '\'' {
					current.WriteByte(next)
					i++
				} else {
					inSingleQuote = false
				}
			}
			continue
		}
		if inDoubleQuote {
			current.WriteByte(ch)
			if ch == '"' {
				if next == '"' {
					current.WriteByte(next)
					i++
				} else {
					inDoubleQuote = false
				}
			}
			continue
		}
		switch {
		case ch == '-' && next == '-':
			current.WriteByte(ch)
			current.WriteByte(next)
			i++
			inLineComment = true
		case ch == '/' && next == '*':
			current.WriteByte(ch)
			current.WriteByte(next)
			i++
			inBlockComment = true
		case ch == '\'':
			current.WriteByte(ch)
			inSingleQuote = true
		case ch == '"':
			current.WriteByte(ch)
			inDoubleQuote = true
		case ch == '$':
			if tag, ok := readDollarQuoteTag(sqlText[i:]); ok {
				current.WriteString(tag)
				i += len(tag) - 1
				dollarQuoteTag = tag
				continue
			}
			current.WriteByte(ch)
		case ch == ';':
			appendSQLStatement(&statements, current.String())
			current.Reset()
		default:
			current.WriteByte(ch)
		}
	}
	appendSQLStatement(&statements, current.String())
	return statements
}

func appendSQLStatement(statements *[]string, statement string) {
	statement = strings.TrimSpace(statement)
	if statement != "" {
		*statements = append(*statements, statement)
	}
}

func readDollarQuoteTag(input string) (string, bool) {
	if input == "" || input[0] != '$' {
		return "", false
	}
	for i := 1; i < len(input); i++ {
		ch := input[i]
		if ch == '$' {
			return input[:i+1], true
		}
		if !((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '_') {
			return "", false
		}
	}
	return "", false
}

func applyOne(ctx context.Context, db *sql.DB, migration Migration) error {
	if strings.TrimSpace(migration.Version) == "" {
		return fmt.Errorf("migration version is required")
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin migration %s: %w", migration.Version, err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()
	if _, err := tx.ExecContext(ctx, "SELECT pg_advisory_xact_lock(hashtext($1))", "dsse_schema_migrations"); err != nil {
		return fmt.Errorf("lock migration %s: %w", migration.Version, err)
	}
	var exists bool
	if err := tx.QueryRowContext(ctx, "SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE version = $1)", migration.Version).Scan(&exists); err != nil {
		return fmt.Errorf("check migration %s: %w", migration.Version, err)
	}
	if exists {
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit skipped migration %s: %w", migration.Version, err)
		}
		committed = true
		return nil
	}
	for _, statement := range migration.Statements {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("apply migration %s statement %q: %w", migration.Version, statement, err)
		}
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO schema_migrations (version, name) VALUES ($1, $2)", migration.Version, migration.Name); err != nil {
		return fmt.Errorf("record migration %s: %w", migration.Version, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit migration %s: %w", migration.Version, err)
	}
	committed = true
	return nil
}

func parseMigrationFilename(filename string) (string, string, error) {
	base := strings.TrimSuffix(filename, filepath.Ext(filename))
	parts := strings.SplitN(base, "_", 2)
	if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" {
		return "", "", fmt.Errorf("migration filename %q must be <version>_<name>.sql", filename)
	}
	return parts[0], parts[1], nil
}

// withMigrationLock runs fn inside a transaction holding the migration advisory lock, so two nodes doing the
// same thing at the same time take turns instead of colliding. The lock is transaction-scoped: it is released
// when the transaction ends, including when the process dies mid-way, so a crashed migrator does not wedge
// the other node.
//
// ★ THE SAME KEY applyOne USES, deliberately. Two different keys would serialise each caller against itself
// and neither against the other, which is the shape of a lock that looks present and holds nothing.
func withMigrationLock(ctx context.Context, db *sql.DB, fn func(*sql.Tx) error) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, "SELECT pg_advisory_xact_lock(hashtext($1))", "dsse_schema_migrations"); err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit()
}
