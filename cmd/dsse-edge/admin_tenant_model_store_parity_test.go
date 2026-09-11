package main

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// ★★★ EVERY FIELD OF THE TENANT MODEL MUST HAVE A COLUMN, OR BE EXCUSED IN WRITING (2026-08-17).
//
// The file store persists this model by marshalling the whole struct, so a new field is durable the moment it
// is declared. The Postgres store names its columns one by one — so a new field is silently dropped unless
// somebody remembers, and for four fields nobody did:
//
//	operator_managed                      the standing delegation. Granted -> 200 -> read back false. Fails CLOSED.
//	operator_elevation_requires_approval   the organization's "ask me first". Dropped, an elevation is created
//	                                       with ApprovalRequired=false. **Fails OPEN.**
//	operator_elevations                    every elevation ever taken. Dropped, the customer's "when they used
//	                                       it" list is permanently empty — the transparency half of the envelope design.
//	timezone                               every organization reads UTC, and the setting does not stick.
//
// None of it failed anywhere. The lab uses the file store, the E2E test round-tripped the fields somebody had
// remembered (region, plan, allowed_regions), and the design document said the two backends behaved
// identically. A second store for one thing is a claim of equivalence, and the claim needs a check that fails.
//
// This test is that check, and it is deliberately about the SHAPE rather than any one field: it reads the
// model's json tags and the store's column list, and demands a written reason for any field that has no
// column. Adding a field to the model now forces the author to either carry it or say why not.
func TestEveryTenantModelFieldHasAPostgresColumn(t *testing.T) {
	source, err := os.ReadFile(filepath.Join("admin_tenant_model_postgres.go"))
	if err != nil {
		t.Fatalf("read the Postgres store: %v", err)
	}
	const marker = `const adminTenantModelColumns = "`
	i := strings.Index(string(source), marker)
	if i < 0 {
		t.Fatal("adminTenantModelColumns is gone — this check can no longer see the store's columns")
	}
	rest := string(source)[i+len(marker):]
	columns := map[string]bool{}
	for _, c := range strings.Split(rest[:strings.Index(rest, `"`)], ",") {
		columns[strings.TrimSpace(c)] = true
	}
	if len(columns) < 10 {
		t.Fatalf("only %d columns parsed — the pattern stopped matching, so this check asserts nothing", len(columns))
	}

	// Fields that legitimately have no column of their own, each with the reason. Keep this list short: an
	// entry here is a promise that the field is derived or carried elsewhere, not a place to park work.
	excused := map[string]string{}

	var missing []string
	model := reflect.TypeOf(adminTenantModel{})
	for i := 0; i < model.NumField(); i++ {
		tag := model.Field(i).Tag.Get("json")
		name := strings.TrimSpace(strings.Split(tag, ",")[0])
		if name == "" || name == "-" {
			continue
		}
		if columns[name] || excused[name] != "" {
			continue
		}
		missing = append(missing, model.Field(i).Name+" (json:"+name+")")
	}

	// Positive control: a field the store certainly does not have must be seen as missing, or the comparison is
	// only ever going to agree with itself.
	if columns["a_column_the_store_does_not_have"] {
		t.Fatal("the control column exists, so the comparison proves nothing")
	}

	if len(missing) > 0 {
		t.Fatalf("the Postgres tenant-model store cannot carry %d field(s) of adminTenantModel: %s\n\n"+
			"Add the column (a migration + adminTenantModelColumns + the INSERT + the scan), or add the field to "+
			"`excused` with the reason it needs no column. A field the file store persists and this one drops is "+
			"a setting that works in the lab and silently does nothing in production.",
			len(missing), strings.Join(missing, ", "))
	}
}

// ★★★ AND EVERY METHOD, WHICH IS WHERE THE NEXT THREE WERE HIDING (2026-08-18).
//
// The check above compares FIELDS to COLUMNS, and it is good at that. It is also structurally blind to
// everything the store does that is not a field, and three of those were missing from the Postgres backend:
//
//	ConfigGeneration   the tenant registry's config version. Absent, it read as a constant 0 through an
//	                   anonymous type assertion, so creating, renaming or deleting an organization published a
//	                   bundle whose aggregate version had not moved — and an Edge applies a bundle only when
//	                   that number is newer.
//	PurgeOrders        the standing erasure orders. Absent, every bundle carried none.
//	OrderPurge         recording an erasure order. Absent, ordering an erasure recorded NOTHING, the handler
//	                   went on to erase this node's own copy, and answered with a result — while every other
//	                   node that ever served the tenant kept the data and was never told.
//
// All three were reached as `if x, ok := store.(interface{ ... }); ok`, which is false rather than loud, so
// none of them failed anywhere. The lab runs the file store; the Postgres backend is what the deployment
// documentation names for production.
//
// So this check is about the same claim as its neighbour — "a second store for one thing is a claim of
// equivalence" — applied to the store's BEHAVIOUR rather than its columns.
func TestEveryTenantModelStoreMethodExistsOnBothBackends(t *testing.T) {
	fileStore := reflect.TypeOf((*adminTenantModelStore)(nil))
	pgStore := reflect.TypeOf((*postgresAdminTenantModelStore)(nil))

	// Methods that legitimately exist on one side only, each with the reason. Keep this list short: an entry
	// here is a promise that the difference is inherent to the backend, not a place to park work.
	// Empty on purpose: as of the fix the two backends expose the same exported surface, and an entry here is
	// a promise that a difference is inherent to the backend rather than work left undone.
	excused := map[string]string{}

	names := func(t reflect.Type) map[string]bool {
		out := map[string]bool{}
		for i := 0; i < t.NumMethod(); i++ {
			m := t.Method(i)
			if m.PkgPath != "" { // unexported: backend-internal plumbing, not the shared contract
				continue
			}
			out[m.Name] = true
		}
		return out
	}
	onFile, onPG := names(fileStore), names(pgStore)
	if len(onFile) < 5 {
		t.Fatalf("only %d exported methods found on the file store — the reflection stopped working, so this check asserts nothing", len(onFile))
	}

	var missing []string
	for name := range onFile {
		if onPG[name] || excused[name] != "" {
			continue
		}
		missing = append(missing, name)
	}
	sort.Strings(missing)

	// Positive control: a method neither store has must be seen as missing, or the comparison only ever agrees
	// with itself.
	if onPG["AMethodNeitherStoreHas"] {
		t.Fatal("the control method exists, so the comparison proves nothing")
	}

	if len(missing) > 0 {
		t.Fatalf("the Postgres tenant-model store is missing %d method(s) the file store has: %s\n\n"+
			"Implement it, or add it to `excused` with the reason. Every one of these is reached through a type "+
			"assertion at the call site, so a missing method does not fail — it silently does nothing, on the "+
			"backend the deployment documentation names for production.",
			len(missing), strings.Join(missing, ", "))
	}
}
