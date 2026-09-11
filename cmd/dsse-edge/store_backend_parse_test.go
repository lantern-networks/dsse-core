package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// ★★ THE IMPORT FORM MUST NOT TURN A GUARD OFF (2026-08-18).
//
// -X-store gained "postgres+import:<path>" so a control plane moving to shared state carries what it had. Four
// places were already comparing the raw flag value to "postgres" exactly, and two of them fail SILENTLY on the
// new form — the double-enrolment guard switches off, and "the connector runtime secret is required when the
// registry is on postgres" stops applying. A convenience that quietly disarms a security requirement is worse
// than no convenience.
func TestTheImportFormStillSelectsThePostgresBackend(t *testing.T) {
	for _, value := range []string{
		"postgres",
		"postgres+import:/cp-state/enrolled_inventory.json",
		"  postgres+import:/cp-state/x.json  ",
	} {
		if got := storeBackend(value); got != "postgres" {
			t.Fatalf("storeBackend(%q) = %q, want postgres", value, got)
		}
	}
	// A file path and in-memory are returned unchanged, or every store would read as postgres.
	for _, value := range []string{"", "memory", "/cp-state/x.json"} {
		if got := storeBackend(value); got != strings.TrimSpace(value) {
			t.Fatalf("storeBackend(%q) = %q, want it unchanged", value, got)
		}
	}
	if got := storeImportSource("postgres+import:/cp-state/x.json"); got != "/cp-state/x.json" {
		t.Fatalf("storeImportSource = %q", got)
	}
	if got := storeImportSource("postgres"); got != "" {
		t.Fatalf("plain postgres named an import source: %q", got)
	}

	// ★ The guard itself, not just the parser: this is the one whose failure is silent and whose subject is a
	// device name being enrolled twice on two nodes.
	if !enrolIssuerNeedsExclusiveStore(true, "postgres+import:/cp-state/enrolled_inventory.json") {
		t.Fatal("the exclusive-claim guard switched off for a store that IS on postgres")
	}
	// Control: it must still be off for a file store, or the assertion above proves nothing.
	if enrolIssuerNeedsExclusiveStore(true, "/cp-state/enrolled_inventory.json") {
		t.Fatal("the guard fires for a file store, so the assertion above is not measuring the backend")
	}
}

// ★ AND NO NEW PLACE MAY COMPARE A STORE VALUE TO "postgres" BY HAND.
//
// The four that did were found by reading, one week after the stores they guard were written. The comparison
// looks harmless at every single call site; it is only wrong in aggregate, once a second spelling of the same
// backend exists. So the spelling lives in one function and this gate keeps it there.
func TestNothingComparesAStoreValueToPostgresByHand(t *testing.T) {
	allowed := map[string]bool{
		// The parser itself, and the persister that resolves the value into a backend.
		"cp_state_blob_persister.go": true,
	}
	// ★ AND A switch CASE IS A COMPARISON TOO (2026-08-18, found by auditing this gate against a broader
	// search after a sibling gate turned out to be reading half its call sites). Fourteen files selected their
	// backend with `switch mode { case "postgres": }`, which this pattern could not see — so "postgres+import:"
	// would have fallen to the default and answered with a DIFFERENT backend, silently, in every one of them.
	pattern := regexp.MustCompile(`(==|!=)\s*"postgres"|EqualFold\([^)]*"postgres"\)|case\s+"postgres"\s*:`)
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read the package: %v", err)
	}
	var offenders []string
	scanned := 0
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") || allowed[name] {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(".", name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		scanned++
		for i, line := range strings.Split(string(raw), "\n") {
			// A `case "postgres":` is answered by the switch EXPRESSION, not by the case line, so the check
			// looks at the enclosing switch — the nearest preceding one in the same file.
			if !pattern.MatchString(line) {
				continue
			}
			if strings.Contains(line, "storeBackend(") {
				continue
			}
			if strings.Contains(line, "case") && switchGuardedByStoreBackend(string(raw), i) {
				continue
			}
			{
				offenders = append(offenders, name+":"+itoa(i+1)+": "+strings.TrimSpace(line))
			}
		}
	}
	if scanned < 50 {
		t.Fatalf("only %d files scanned — the gate stopped seeing the package", scanned)
	}
	if len(offenders) > 0 {
		t.Fatalf("%d place(s) compare a store value to \"postgres\" without going through storeBackend():\n  %s\n\n"+
			"Use storeBackend(value) == \"postgres\". A raw comparison is false for \"postgres+import:<path>\", "+
			"which selects the SAME backend — and two of the four that did this disarmed a guard rather than "+
			"failing.", len(offenders), strings.Join(offenders, "\n  "))
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// switchGuardedByStoreBackend reports whether the switch enclosing line `at` resolves its subject through
// storeBackend(). Scans upward for the nearest `switch ... {`, which is where a case's comparison is actually
// decided.
func switchGuardedByStoreBackend(source string, at int) bool {
	lines := strings.Split(source, "\n")
	for i := at; i >= 0 && i > at-40; i-- {
		if strings.Contains(lines[i], "switch ") {
			return strings.Contains(lines[i], "storeBackend(")
		}
	}
	return false
}
