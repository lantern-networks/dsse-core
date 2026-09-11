package logs

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

// Review #32: the open-handle set must be LRU-capped. On a multi-tenant Edge each distinct tenant-partitioned
// path opened a persistent fd that was never closed — unbounded fd growth. Writing to many more distinct
// files than the cap must keep the number of open handles at the cap, and every file's data must still be
// intact (an evicted handle reopens on its next append).
func TestOpenFileHandlesAreLRUCapped(t *testing.T) {
	w, err := NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	w.SetMaxOpenFiles(4)

	// 20 distinct files, far over the cap of 4.
	for i := 0; i < 20; i++ {
		name := fmt.Sprintf("f%02d.log.jsonl", i)
		if err := w.Append(name, map[string]any{"i": i}); err != nil {
			t.Fatalf("append %s: %v", name, err)
		}
	}

	w.mu.Lock()
	open := len(w.openFiles)
	w.mu.Unlock()
	if open > 4 {
		t.Fatalf("open handles = %d, want <= 4 (LRU cap)", open)
	}

	// Every file's row survived (evicted handles reopen and appends still land).
	for i := 0; i < 20; i++ {
		name := fmt.Sprintf("f%02d.log.jsonl", i)
		rows, rerr := w.ReadJSONL(name)
		if rerr != nil {
			t.Fatalf("read %s: %v", name, rerr)
		}
		if len(rows) != 1 {
			t.Fatalf("%s has %d rows, want 1 (data lost on eviction?)", name, len(rows))
		}
	}

	// Re-appending to an evicted file reopens it and both rows are present.
	if err := w.Append("f00.log.jsonl", map[string]any{"i": 100}); err != nil {
		t.Fatalf("re-append: %v", err)
	}
	rows, _ := w.ReadJSONL("f00.log.jsonl")
	if len(rows) != 2 {
		t.Fatalf("f00 after re-append has %d rows, want 2", len(rows))
	}
}

// Review #32: safeTenantSegment must contain a hostile tenant id — a traversal attempt must never escape the
// tenants/ directory. The whole partition path stays under tenants/<sanitized>/.
func TestSafeTenantSegmentContainsHostileIDs(t *testing.T) {
	for _, id := range []string{
		"../../etc/passwd",
		"..",
		".",
		"",
		"a/b/c",
		`..\..\windows`,
		"foo/../../bar",
		"tenant\x00null",
		"C:evil",
		"con",
		strings.Repeat("x", 300),
	} {
		seg := safeTenantSegment(id)
		if strings.ContainsAny(seg, `/\`) || seg == "." || seg == ".." || seg == "" {
			t.Fatalf("safeTenantSegment(%q) = %q escapes or is a traversal segment", id, seg)
		}
		// The full partition path must stay under tenants/ with NO ".." path COMPONENT (a segment like
		// ".._.." merely contains dots and is safe — only a standalone ".." component would traverse).
		p := filepath.Clean(tenantPartitionPath(id, "audit.log.jsonl"))
		parts := strings.Split(p, string(filepath.Separator))
		if parts[0] != "tenants" {
			t.Fatalf("tenantPartitionPath(%q, ...) = %q not under tenants/", id, p)
		}
		for _, part := range parts {
			if part == ".." {
				t.Fatalf("tenantPartitionPath(%q, ...) = %q has a traversal component", id, p)
			}
		}
	}
}
