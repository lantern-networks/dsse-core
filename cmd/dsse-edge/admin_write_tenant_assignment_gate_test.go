package main

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// ★★ ASSIGNING THE CALLER'S ORGANIZATION OVER A BODY THAT NAMED ONE IS A SILENT REDIRECT (2026-08-18).
//
// Measured on the reference deployment: an operator registered an end-user IdP FOR a customer, naming that
// customer in the body. The response was 200 and the connection was filed under the OPERATOR's own
// organization — where the customer will never see it, and where nothing said so. The handler did:
//
//	conn.TenantID = adminTenantIDFromRequest(r)
//
// which is the same shape adminTenantForWrite exists to replace: an operator MAY name another organization, a
// customer naming one is REFUSED rather than redirected, and either way the caller learns which happened.
//
// The audit record for a purge is the one legitimate exception and it is excused by name: that record is
// deliberately filed under the operator who performed the erasure, because the evidence that an erasure was
// authorised must not live inside the thing that was erased.
func TestNoWriteAssignsTheCallersTenantOverANamedOne(t *testing.T) {
	// ★ THE PACKAGE IS THE WORKING DIRECTORY (2026-08-23). This named the package by PATH, so it broke
	// the moment the package moved — and it would break again on the published surface, where the
	// same package sits at a different depth. A test binary runs in its own package directory; that
	// is the one fact about the layout that cannot drift.
	root := "."
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("read the package: %v", err)
	}
	assign := regexp.MustCompile(`(\w+)\.TenantID\s*=\s*adminTenantIDFromRequest\(r\)`)

	// Excused, by file:line subject, with the reason. Keep this list short — an entry is a promise that the
	// record does NOT belong to the organization the body names.
	excused := map[string]string{
		"inspection_posture_admin.go:result": "a new read-only response snapshot identifies the requesting tenant; no request body or stored tenant is assigned",
		"auditRecord":                        "a purge is recorded in the OPERATOR's audit, with the erased customer as the target: the evidence that an erasure was authorised must not live inside the thing that was erased",
	}

	var offenders []string
	scanned := 0
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		scanned++
		for i, line := range strings.Split(string(raw), "\n") {
			m := assign.FindStringSubmatch(line)
			if m == nil || excused[m[1]] != "" || excused[name+":"+m[1]] != "" {
				continue
			}
			offenders = append(offenders, name+":"+itoa(i+1)+": "+strings.TrimSpace(line))
		}
	}
	sort.Strings(offenders)
	if scanned < 50 {
		t.Fatalf("only %d files scanned — the gate stopped seeing the package", scanned)
	}
	if len(offenders) > 0 {
		t.Fatalf("%d write(s) assign the caller's organization over whatever the body named:\n  %s\n\n"+
			"Use adminTenantForWrite(r, <body>.TenantID): an operator may name another organization, a customer "+
			"naming one is refused rather than redirected, and either way the caller is told which happened. "+
			"Measured: an operator registered an IdP for a customer, got 200, and it was filed under the "+
			"operator — invisible to that customer, with nothing said.",
			len(offenders), strings.Join(offenders, "\n  "))
	}
}
