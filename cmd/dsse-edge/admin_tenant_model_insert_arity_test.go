package main

import (
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// ★★★ THE COLUMN LIST, THE PLACEHOLDERS AND THE ARGUMENTS ARE ONE LIST IN THREE PLACES (2026-08-20).
//
// Adding operator_delegation_withdrawn_by_customer to two of them and not the third produced
// "pq: got 21 parameters but the statement requires 20" — every write to the tenant model failed, on the
// Postgres backend ONLY, which every unit test in this package replaces with the file store. It was found by
// a customer withdrawing their delegation on the running lab, which is the last place to find it.
//
// This counts them in the source. It is cheap, it needs no database, and it fails for exactly the reason the
// live call did.
func TestTheTenantModelInsertHasOnePlaceholderPerColumn(t *testing.T) {
	blob, err := os.ReadFile("admin_tenant_model_postgres.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(blob)

	columns := strings.Count(adminTenantModelColumns, ",") + 1

	values := regexp.MustCompile(`"VALUES \(([^"]*)\)"`).FindStringSubmatch(source)
	if values == nil {
		t.Fatal("the INSERT's VALUES list is not where this gate looks — find it and point this at it, rather " +
			"than leaving a gate that passes because it reads nothing")
	}
	placeholders := map[string]bool{}
	for _, m := range regexp.MustCompile(`\$(\d+)`).FindAllStringSubmatch(values[1], -1) {
		placeholders[m[1]] = true
	}
	if len(placeholders) != columns {
		t.Fatalf("the tenant model INSERT names %d column(s) and binds %d placeholder(s) — every write to the "+
			"tenant model fails on Postgres, and on the file store every test still passes",
			columns, len(placeholders))
	}
	// The highest placeholder must be the count too: $1..$N with none skipped, or the arguments line up with
	// the wrong columns and the failure is silent instead of loud.
	for i := 1; i <= columns; i++ {
		if !placeholders[strconv.Itoa(i)] {
			t.Fatalf("placeholder $%d is missing from the INSERT: the arguments after it bind to the wrong "+
				"columns", i)
		}
	}
}
