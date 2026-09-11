package logs

import (
	"compress/gzip"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func countLines(t *testing.T, path string) int {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	n := 0
	for _, c := range b {
		if c == '\n' {
			n++
		}
	}
	return n
}

func TestRotationCapsFileSizeAndKeepsBackups(t *testing.T) {
	dir := t.TempDir()
	w, err := NewWriter(dir)
	if err != nil {
		t.Fatal(err)
	}
	// Tiny threshold so a few rows trigger several rotations; keep 2 gzip backups.
	w.SetRotation(200, 2, true)

	for i := 0; i < 200; i++ {
		if err := w.Append("access.log.jsonl", map[string]any{"i": i, "pad": "xxxxxxxxxxxxxxxxxxxx"}); err != nil {
			t.Fatal(err)
		}
	}

	// The live file must be bounded (≈ < threshold + one row), not the full 200 rows.
	cur := filepath.Join(dir, "access.log.jsonl")
	st, err := os.Stat(cur)
	if err != nil {
		t.Fatal(err)
	}
	if st.Size() > 400 {
		t.Fatalf("current file should be capped near 200B, got %d (rotation not bounding)", st.Size())
	}

	// Retention: only maxBackups (2) gzip backups kept; no .3.
	for _, b := range []string{"access.log.jsonl.1.gz", "access.log.jsonl.2.gz"} {
		if _, err := os.Stat(filepath.Join(dir, b)); err != nil {
			t.Fatalf("expected backup %s: %v", b, err)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "access.log.jsonl.3.gz")); !os.IsNotExist(err) {
		t.Fatal("backup .3.gz must not exist (retention exceeded)")
	}

	// A gzip backup must be valid + non-empty (real archived content).
	f, err := os.Open(filepath.Join(dir, "access.log.jsonl.1.gz"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatalf("backup is not valid gzip: %v", err)
	}
	buf := make([]byte, 16)
	if n, _ := gz.Read(buf); n == 0 {
		t.Fatal("gzip backup is empty")
	}
}

func TestRotationDisabledByDefault(t *testing.T) {
	dir := t.TempDir()
	w, _ := NewWriter(dir)
	for i := 0; i < 50; i++ {
		w.Append("audit.log.jsonl", map[string]any{"i": i, "pad": "xxxxxxxxxxxxxxxxxxxx"})
	}
	// No SetRotation → all 50 rows in the single file, no backups.
	if got := countLines(t, filepath.Join(dir, "audit.log.jsonl")); got != 50 {
		t.Fatalf("rotation must be OFF by default: want 50 lines, got %d", got)
	}
	if _, err := os.Stat(filepath.Join(dir, "audit.log.jsonl.1")); !os.IsNotExist(err) {
		t.Fatal("no backups when rotation disabled")
	}
}

func TestRotationCapOnlyNoBackups(t *testing.T) {
	dir := t.TempDir()
	w, _ := NewWriter(dir)
	w.SetRotation(150, 0, false) // cap only: discard rotated content
	for i := 0; i < 100; i++ {
		w.Append("decision_trace.log.jsonl", map[string]any{"i": i, "pad": fmt.Sprintf("%020d", i)})
	}
	st, _ := os.Stat(filepath.Join(dir, "decision_trace.log.jsonl"))
	if st.Size() > 300 {
		t.Fatalf("cap-only rotation must bound the file, got %d", st.Size())
	}
	if _, err := os.Stat(filepath.Join(dir, "decision_trace.log.jsonl.1")); !os.IsNotExist(err) {
		t.Fatal("cap-only (maxBackups=0) must keep no backups")
	}
}
