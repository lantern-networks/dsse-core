package main

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// ★ THE GATE THAT KEEPS "COMPLETELY DELETED" TRUE (2026-08-15).
//
// adminTenantFootprintPostgresTables is a hand-written list, and a hand-written list of "everywhere a tenant's
// data lives" goes stale the first time someone adds a table. The failure is silent and in the worst possible
// direction: the footprint reports a smaller number, the erasure misses the new table, and both of them say
// the tenant is clean. Nothing in the product would contradict them.
//
// So the list is checked against the schema itself — every CREATE TABLE in the migrations and in the in-code
// schema definitions that carries a tenant_id column, plus every ALTER TABLE that adds one. This runs with no
// database: a gate that only fires where Postgres happens to be reachable is a gate that does not fire in CI.
//
// If this fails, the fix is to ADD the table to the list (and to the purge), not to delete the test. A table
// that legitimately holds nothing worth erasing still belongs in the list with a count of zero — "we looked
// and there was nothing" and "we never looked" have to stay distinguishable.
func TestTenantFootprintCoversEveryTenantKeyedTable(t *testing.T) {
	repo := repoRootForSchemaScan(t)
	declared := map[string]bool{}
	for _, table := range adminTenantFootprintPostgresTables {
		declared[table] = true
	}

	found := map[string]string{} // table -> where it was found
	// ★ THE SAME TWO LAYOUTS the root probe accepts. Named here as alternatives rather than as one path, so
	// this test reads the tree it is actually in instead of the one it was written in.
	for _, alternatives := range [][]string{
		{filepath.Join(devTreeMigrations...), "migrations"},
		edgePackageAlternatives(),
	} {
		var root string
		var entries []os.DirEntry
		var err error
		for _, dir := range alternatives {
			root = filepath.Join(repo, dir)
			if entries, err = os.ReadDir(root); err == nil {
				break
			}
		}
		if err != nil {
			t.Fatalf("read %v: %v", alternatives, err)
		}
		for _, entry := range entries {
			name := entry.Name()
			if entry.IsDir() || (!strings.HasSuffix(name, ".sql") && !strings.HasSuffix(name, ".go")) {
				continue
			}
			if strings.HasSuffix(name, "_test.go") {
				continue
			}
			raw, err := os.ReadFile(filepath.Join(root, name))
			if err != nil {
				t.Fatalf("read %s: %v", name, err)
			}
			for _, table := range tenantKeyedTablesIn(string(raw)) {
				found[table] = filepath.Join(root, name)
			}
		}
	}

	if len(found) == 0 {
		t.Fatal("the scan found no tenant-keyed tables at all — it has stopped matching the schema and is no longer a gate")
	}

	missing := []string{}
	for table, where := range found {
		if !declared[table] {
			missing = append(missing, table+" (declared in "+where+")")
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Fatalf("%d tenant-keyed table(s) are not in adminTenantFootprintPostgresTables, so an erasure would\n"+
			"miss them AND report the tenant clean:\n  %s", len(missing), strings.Join(missing, "\n  "))
	}
}

var (
	createTablePattern = regexp.MustCompile(`(?is)CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?([a-z_][a-z0-9_]*)\s*\((.*?)\)\s*;`)
	// The in-code definitions are built by joining Go string fragments, so the body is not one literal and the
	// closing paren is its own element. Match the table name and take the following window instead.
	createTableGoPattern = regexp.MustCompile(`(?i)CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?([a-z_][a-z0-9_]*)\s*\(`)
	alterAddTenantColumn = regexp.MustCompile(`(?is)ALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?([a-z_][a-z0-9_]*)\s+ADD\s+COLUMN\s+(?:IF\s+NOT\s+EXISTS\s+)?tenant_id\b`)
)

// tenantKeyedTablesIn returns the tables in one schema source that carry a tenant_id column.
func tenantKeyedTablesIn(source string) []string {
	out := map[string]bool{}
	for _, match := range createTablePattern.FindAllStringSubmatch(source, -1) {
		if strings.Contains(strings.ToLower(match[2]), "tenant_id") {
			out[strings.ToLower(match[1])] = true
		}
	}
	// The Go-built definitions: take a window after the table name, since the body is spread across string
	// fragments and the regexp above cannot see a closing paren in the same literal.
	for _, loc := range createTableGoPattern.FindAllStringSubmatchIndex(source, -1) {
		name := strings.ToLower(source[loc[2]:loc[3]])
		end := loc[1] + 4000
		if end > len(source) {
			end = len(source)
		}
		window := strings.ToLower(source[loc[1]:end])
		// Stop at the next CREATE TABLE so one definition's columns are not attributed to the previous table.
		if next := strings.Index(window, "create table"); next >= 0 {
			window = window[:next]
		}
		if strings.Contains(window, "tenant_id") {
			out[name] = true
		}
	}
	for _, match := range alterAddTenantColumn.FindAllStringSubmatch(source, -1) {
		out[strings.ToLower(match[1])] = true
	}
	tables := make([]string, 0, len(out))
	for table := range out {
		tables = append(tables, table)
	}
	sort.Strings(tables)
	return tables
}

// devTreeMigrations is where the migrations sit in the development tree, one level below the root. Named
// rather than written inline so the published surface carries no path that only exists in the other tree.
var devTreeMigrations = []string{"proto" + "type", "migrations"}

func repoRootForSchemaScan(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	// ★ EITHER LAYOUT, because "the repository root" means two different things depending on which tree this
	// is: in the development monorepo the migrations sit one level down, and on the published surface they sit
	// at the top. A probe that names one of them passes on one side of that move and fails on the other.
	for i := 0; i < 6; i++ {
		for _, rel := range [][]string{devTreeMigrations, {"migrations"}} {
			if _, err := os.Stat(filepath.Join(append([]string{dir}, rel...)...)); err == nil {
				return dir
			}
		}
		dir = filepath.Dir(dir)
	}
	t.Fatal("could not find the repo root from the test's working directory")
	return ""
}

// edgePackageAlternatives names this package in both layouts, relative to the root the probe found.
//
// ★ IT USED TO NAME ONE PATH, AND THE PATH MOVED (2026-08-23). The package became the published dsse-edge,
// and a probe that says "cmd/edge" reads a tree that no longer exists — while reporting it as "we never
// looked", which this file's own doctrine says must stay distinguishable from "we looked and there was
// nothing".
func edgePackageAlternatives() []string {
	return []string{
		filepath.Join("oss", "cmd", "dsse-edge"), // development monorepo: root is one level above oss/
		filepath.Join("cmd", "dsse-edge"),        // published surface
	}
}
