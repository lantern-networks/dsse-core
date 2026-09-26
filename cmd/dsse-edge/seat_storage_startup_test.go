package main

import (
	"bytes"
	"context"
	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/seatallocation"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSeatAllocationStartupRequiresReadableState(t *testing.T) {
	if path := os.Getenv("DSSE_SEAT_STARTUP_TEST_PATH"); path != "" {
		mustLoadSeatAllocations(seatallocation.NewStore(), blobstore.FilePersister{Path: path})
		return
	}
	for _, fixture := range []struct {
		name, raw     string
		valid, exists bool
	}{
		{"first-boot", "", true, false}, {"empty", "", false, true}, {"corrupt", "PRIVATE_TEST_MARKER", false, true},
		{"valid", `{"schema_version":"dsse.seat_allocations.v1","allocations":{}}`, true, true},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "seats.json")
			if fixture.exists {
				if err := os.WriteFile(path, []byte(fixture.raw), 0600); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestSeatAllocationStartupRequiresReadableState$")
			cmd.Env = append(os.Environ(), "DSSE_SEAT_STARTUP_TEST_PATH="+path)
			out, err := cmd.CombinedOutput()
			if fixture.valid {
				if err != nil {
					t.Fatalf("valid startup: %v %s", err, out)
				}
			} else {
				e, ok := err.(*exec.ExitError)
				if !ok || e.ExitCode() != 1 || !strings.Contains(string(out), "seat allocations: invalid or unavailable saved configuration") {
					t.Fatalf("load error was ignored: %v %s", err, out)
				}
			}
			if strings.Contains(string(out), "PRIVATE_TEST_MARKER") {
				t.Fatal("saved contents exposed")
			}
			if fixture.exists {
				after, e := os.ReadFile(path)
				if e != nil || !bytes.Equal(after, []byte(fixture.raw)) {
					t.Fatal("startup rewrote storage")
				}
			}
		})
	}
}
