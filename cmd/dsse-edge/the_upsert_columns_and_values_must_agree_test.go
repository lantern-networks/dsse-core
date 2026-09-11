package main

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// ★★★ TWO COLUMNS WITHOUT PLACEHOLDERS TOOK THE WHOLE FLEET SILENT (2026-08-22, measured).
//
// interception_refusals and transport_server_name_sent were added to observedExclusionColumns, to the
// ON CONFLICT SET clause and to the argument list — and not to VALUES. Postgres answered every write with
//
//	pq: INSERT has more target columns than expressions
//
// and the store is deliberately best-effort, so each failure was one log line and the report was dropped.
// Every readiness gate in this product is computed from these rows, so both devices in the lab became
// indistinguishable from devices that were switched off. A morning was spent on the trust path of one of
// them, and a message went to the other platform's maintainer describing their box as "down". It was not.
//
// The three lists have to agree, and counting them is the only thing that notices when they do not: a Go
// vet cannot see inside a SQL string, and the runtime error is swallowed by the same best-effort rule that
// keeps the data path unblocked.
func TestTheObservedExclusionUpsertCountsAgree(t *testing.T) {
	raw, err := os.ReadFile("steer_exclusion_observed_postgres.go")
	if err != nil {
		t.Fatalf("read the store's source: %v", err)
	}
	src := string(raw)

	cols := regexp.MustCompile(`const observedExclusionColumns = "([^"]+)"`).FindStringSubmatch(src)
	if cols == nil {
		t.Fatal("observedExclusionColumns not found — this check would silently measure nothing")
	}
	columns := len(strings.Split(cols[1], ","))

	values := regexp.MustCompile(`"VALUES \(([^)]*)\)"`).FindStringSubmatch(src)
	if values == nil {
		t.Fatal("the VALUES clause not found — this check would silently measure nothing")
	}
	placeholders := len(regexp.MustCompile(`\$\d+`).FindAllString(values[1], -1))

	if columns != placeholders {
		t.Fatalf("observed_steer_exclusions upsert: %d columns and %d placeholders. Postgres refuses the "+
			"whole statement, the store drops the report, and every device it carries reads as switched off",
			columns, placeholders)
	}

	// ★ And the SET clause has to carry every column too, or a field arrives once on INSERT and never
	// updates again — the quieter half of the same defect.
	set := regexp.MustCompile(`ON CONFLICT \(tenant_id, device_identity\) DO UPDATE SET`).FindStringIndex(src)
	if set == nil {
		t.Fatal("the ON CONFLICT clause not found")
	}
	tail := src[set[1]:]
	if end := strings.Index(tail, "}, \" \")"); end > 0 {
		tail = tail[:end]
	}
	// tenant_id and device_identity are the conflict key and are never in the SET clause.
	for _, c := range strings.Split(cols[1], ",") {
		name := strings.TrimSpace(c)
		if name == "tenant_id" || name == "device_identity" {
			continue
		}
		if !strings.Contains(tail, name+" = EXCLUDED."+name) {
			t.Errorf("column %q is inserted but never updated on conflict — it will hold whatever the first "+
				"report of this device said, for ever", name)
		}
	}
}
