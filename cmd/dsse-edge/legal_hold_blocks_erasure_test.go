package main

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// ★★★ A LEGAL HOLD IS A PROMISE TO KEEP DATA, AND ERASURE WALKED THROUGH IT (2026-08-19).
//
// The hold store existed and exactly one thing read it: the retention pruner, which preserves a held tenant's
// logs instead of ageing them out. The most complete deletion the product offers — POST
// /admin/tenants/{id}/purge, which erases every store and tells the rest of the fleet to do the same — never
// asked. Neither did DELETE /admin/tenants/{id}, which is its precondition.
//
// So a hold survived the AUTOMATIC deletion and not the DELIBERATE one, which is the opposite of what a hold
// is for. Nothing about an operator being authorised to erase makes the hold irrelevant: the hold is what says
// this particular organization must not be erased yet, and it is released by lifting it, on the record.
//
// Found by asking the same question that found the admission doors — a decision is enforced where somebody
// remembered to enforce it, and the way to find the gaps is to count the doors rather than read the intent.
func TestALegalHoldIsReadByEveryPathThatDestroysData(t *testing.T) {
	raw, err := os.ReadFile("admin_tenant_routes.go")
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	lines := strings.Split(string(raw), "\n")
	route := regexp.MustCompile(`mux\.HandleFunc\("((?:POST|DELETE) /admin/tenants[^"]*)"`)

	want := map[string]bool{
		"DELETE /admin/tenants/{tenant_id}":     false,
		"POST /admin/tenants/{tenant_id}/purge": false,
	}
	for i, l := range lines {
		m := route.FindStringSubmatch(l)
		if m == nil {
			continue
		}
		if _, tracked := want[m[1]]; !tracked {
			continue
		}
		// Comments do not count: mentioning a guard is not calling one.
		for _, line := range lines[i:minInt(i+120, len(lines))] {
			code := line
			if j := strings.Index(code, "//"); j >= 0 {
				code = code[:j]
			}
			if strings.Contains(code, "LegalHold.IsHeld(") {
				want[m[1]] = true
				break
			}
		}
	}
	for path, guarded := range want {
		if !guarded {
			t.Fatalf("%s destroys a tenant's data and never asks whether it is under a legal hold", path)
		}
	}

	// ★ THE CONTROL, and it is the reason this is not simply "call IsHeld everywhere": the pruner must STILL
	// read it. If the hold stopped preserving logs, this gate would be satisfied while the hold had become
	// decorative in the one place it originally worked.
	pruner, err := os.ReadFile("retention_pruner.go")
	if err != nil {
		t.Fatalf("read the pruner: %v", err)
	}
	if !strings.Contains(string(pruner), "IsHeld(") {
		t.Fatal("the retention pruner no longer preserves a held tenant's data")
	}
}
