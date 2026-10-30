package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFileRollbackRequiresOfflineAssertionAndExactSource(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "source.json")
	out := filepath.Join(dir, "legacy.json")
	raw := []byte(`{"schema_version":3,"grants":{}}`)
	os.WriteFile(input, raw, 0600)
	var status bytes.Buffer
	if e := run([]string{"--input", input}, &status); e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(status.String(), "dry_run=true") {
		t.Fatal("missing dry run")
	}
	for _, args := range [][]string{{"--input", input, "--output", out, "--apply"}, {"--input", input, "--output", out, "--apply", "--writers-stopped", "--expect-sha256", strings.Repeat("0", 64)}} {
		if e := run(args, &status); e == nil {
			t.Fatal("unsafe apply allowed")
		}
	}
	if _, e := os.Stat(out); !os.IsNotExist(e) {
		t.Fatal("failed apply wrote output")
	}
	args := []string{"--input", input, "--output", out, "--apply", "--writers-stopped", "--expect-sha256", digest(raw)}
	if e := run(args, &status); e != nil {
		t.Fatal(e)
	}
	fi, _ := os.Stat(out)
	if fi.Mode().Perm() != 0600 {
		t.Fatal("output not private")
	}
	source, _ := os.ReadFile(input)
	if !bytes.Equal(source, raw) {
		t.Fatal("original overwritten")
	}
	if e := run(args, &status); e == nil {
		t.Fatal("existing output overwritten")
	}
}
