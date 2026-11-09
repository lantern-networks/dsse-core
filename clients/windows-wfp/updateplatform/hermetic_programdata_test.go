package updateplatform

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// ★★ NO TEST HERE MAY WRITE THE MACHINE'S OWN %ProgramData% (2026-11-06, found running these tests on a Windows
// box with no agent installed). Two tests that call Stage did not point ProgramData at a scratch tree, so they
// created C:\ProgramData\DSSE on the machine running them — and the next run passed or failed depending on
// whether that folder was already there. A real install that found it would take it for an existing data
// directory it did not create, and leave its permissions alone.
//
// So the whole package runs with ProgramData pointed at a scratch tree (a test that needs its own still sets it
// with stagedInto), and the run fails if the machine's own DSSE directory appeared while it ran.
func TestMain(m *testing.M) {
	real := os.Getenv("ProgramData")
	var realDSSE string
	existed := false
	if real != "" {
		realDSSE = filepath.Join(real, "DSSE")
		_, err := os.Stat(realDSSE)
		existed = err == nil
	}
	scratch, err := os.MkdirTemp("", "dsse-updateplatform-programdata-")
	if err != nil {
		fmt.Fprintln(os.Stderr, "updateplatform tests: make a scratch ProgramData:", err)
		os.Exit(1)
	}
	if err := os.Setenv("ProgramData", scratch); err != nil {
		fmt.Fprintln(os.Stderr, "updateplatform tests: point ProgramData at the scratch tree:", err)
		os.Exit(1)
	}
	code := m.Run()
	_ = os.RemoveAll(scratch)
	if realDSSE != "" && !existed {
		if _, err := os.Stat(realDSSE); err == nil {
			fmt.Fprintf(os.Stderr, "updateplatform tests: %s did not exist before this run and does now; a test "+
				"wrote the machine's own data directory\n", realDSSE)
			code = 1
		}
	}
	os.Exit(code)
}
