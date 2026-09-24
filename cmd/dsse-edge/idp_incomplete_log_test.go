package main

import (
	"fmt"
	"strings"
	"testing"

	"github.com/lantern-networks/dsse-core/idpregistry"
)

// The incomplete-registry branch was unreachable until sections could be marked
// incomplete; its log line then printed "%!d(MISSING)" instead of the count, at
// the moment an operator is diagnosing why the Edge kept its connections.
func TestIncompleteIdPSectionLogsTheCountItKeeps(t *testing.T) {
	store := idpregistry.NewStore()
	var lines []string
	logf := func(format string, args ...interface{}) { lines = append(lines, fmt.Sprintf(format, args...)) }
	count, applied := applyIdPConnectionBundleSection(store, &idpConnectionBundle{Complete: false}, logf)
	if applied || len(lines) != 1 {
		t.Fatalf("applied=%v lines=%v", applied, lines)
	}
	if strings.Contains(lines[0], "%!") || !strings.Contains(lines[0], fmt.Sprintf("keeping the %d connection", count)) {
		t.Fatalf("malformed log line: %q", lines[0])
	}
}
