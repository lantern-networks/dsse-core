package migrations

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSplitSQLStatementsTrimsEmptyParts(t *testing.T) {
	statements := SplitSQLStatements("CREATE TABLE a (id text);  \n\nCREATE INDEX b ON a(id); ;")
	if len(statements) != 2 {
		t.Fatalf("statement count = %d, want 2: %#v", len(statements), statements)
	}
	if statements[0] != "CREATE TABLE a (id text)" || statements[1] != "CREATE INDEX b ON a(id)" {
		t.Fatalf("statements = %#v", statements)
	}
}

func TestSplitSQLStatementsIgnoresSemicolonsInsideLiteralsAndComments(t *testing.T) {
	sql := strings.Join([]string{
		"INSERT INTO audit_messages (body) VALUES ('alpha; beta');",
		`INSERT INTO quoted_names ("semi;colon") VALUES ('ok');`,
		"-- comment with ; should stay with next statement",
		"INSERT INTO audit_messages (body) VALUES ($tag$one;two$tag$);",
		"/* block ; comment */ CREATE INDEX audit_messages_body_idx ON audit_messages(body);",
	}, "\n")
	statements := SplitSQLStatements(sql)
	if len(statements) != 4 {
		t.Fatalf("statement count = %d, want 4: %#v", len(statements), statements)
	}
	if !strings.Contains(statements[0], "'alpha; beta'") {
		t.Fatalf("first statement = %q, want semicolon inside single-quoted string", statements[0])
	}
	if !strings.Contains(statements[1], `"semi;colon"`) {
		t.Fatalf("second statement = %q, want semicolon inside quoted identifier", statements[1])
	}
	if !strings.Contains(statements[2], "$tag$one;two$tag$") {
		t.Fatalf("third statement = %q, want semicolon inside dollar-quoted string", statements[2])
	}
	if !strings.Contains(statements[3], "/* block ; comment */") {
		t.Fatalf("fourth statement = %q, want semicolon inside block comment", statements[3])
	}
}

func TestLoadDirSortsMigrationsByVersion(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{
		"002_second.sql": "CREATE TABLE second (id text);",
		"001_first.sql":  "CREATE TABLE first (id text);",
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	migrations, err := LoadDir(dir)
	if err != nil {
		t.Fatalf("LoadDir returned error: %v", err)
	}
	if len(migrations) != 2 {
		t.Fatalf("migration count = %d, want 2", len(migrations))
	}
	if migrations[0].Version != "001" || migrations[0].Name != "first" || migrations[1].Version != "002" {
		t.Fatalf("migrations = %#v", migrations)
	}
}

func TestSelectVersionsKeepsRequestedMigrationsOnly(t *testing.T) {
	migrations := []Migration{
		{Version: "001", Name: "queue"},
		{Version: "002", Name: "jobs"},
		{Version: "005", Name: "admin_auth"},
	}
	selected, err := SelectVersions(migrations, "005")
	if err != nil {
		t.Fatalf("SelectVersions returned error: %v", err)
	}
	if len(selected) != 1 || selected[0].Version != "005" || selected[0].Name != "admin_auth" {
		t.Fatalf("selected = %#v, want only 005 admin_auth", selected)
	}
}

func TestSelectVersionsRejectsMissingVersion(t *testing.T) {
	_, err := SelectVersions([]Migration{{Version: "001", Name: "queue"}}, "005")
	if err == nil || !strings.Contains(err.Error(), "missing migration version") {
		t.Fatalf("SelectVersions missing version error = %v, want missing migration version", err)
	}
}

func TestLoadDirRejectsInvalidMigrationFilename(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "broken.sql"), []byte("SELECT 1;"), 0o600); err != nil {
		t.Fatalf("write migration: %v", err)
	}
	if _, err := LoadDir(dir); err == nil {
		t.Fatalf("LoadDir accepted invalid migration filename")
	}
}

func TestLoadDirRejectsDuplicateMigrationVersion(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{
		"001_first.sql": "SELECT 1;",
		"001_again.sql": "SELECT 2;",
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	if _, err := LoadDir(dir); err == nil || !strings.Contains(err.Error(), "duplicate migration version") {
		t.Fatalf("LoadDir duplicate version error = %v, want duplicate migration version", err)
	}
}
