package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func steerMutationAudits(t *testing.T, root string) []map[string]any {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, "logs", "audit.log.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	var rows []map[string]any
	for _, line := range bytes.Split(bytes.TrimSpace(b), []byte("\n")) {
		var a map[string]any
		if err := json.Unmarshal(line, &a); err != nil {
			t.Fatal(err)
		}
		rows = append(rows, a)
	}
	return rows
}
