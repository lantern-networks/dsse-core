//go:build !windows

package blobstore

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
)

// single_writer_crossprocess_test.go — the guard's whole purpose is to survive ANOTHER PROCESS, so the test
// uses one.
//
// ★ THE SEQUENTIAL TEST COULD NOT SEE THE HOLE (2026-08-12, twenty-fourth review). It had B check after A had
// finished saving, which is the interleaving that was never in question. The one that mattered — both read
// the same old bytes, both find them unchanged, both write — needs two writers running at once, and two
// writers in one process share a mutex that hides it. Real processes share nothing but the file.

// TestManyProcessesIncrementingTheSameStoreLoseNoUpdates is the classic lost-update shape: read, add one,
// write. With a compare that is not atomic, the total comes out short, and each missing increment is an
// enrolment record that a second node erased.
func TestManyProcessesIncrementingTheSameStoreLoseNoUpdates(t *testing.T) {
	if os.Getenv("DSSE_BLOBSTORE_CHILD") != "" {
		return // the child path runs in TestMain-free style below; nothing to do here
	}
	path := filepath.Join(t.TempDir(), "counter.json")
	if err := os.WriteFile(path, []byte(`{"n":0}`), 0o600); err != nil {
		t.Fatal(err)
	}

	const children, each = 6, 15
	var wg sync.WaitGroup
	for i := 0; i < children; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cmd := exec.Command(os.Args[0], "-test.run", "TestChildIncrementsTheStore")
			cmd.Env = append(os.Environ(), "DSSE_BLOBSTORE_CHILD=1",
				"DSSE_BLOBSTORE_PATH="+path, "DSSE_BLOBSTORE_ROUNDS="+strconv.Itoa(each))
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Errorf("child failed: %v\n%s", err, out)
			}
		}()
	}
	wg.Wait()

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		N int `json:"n"`
	}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if want := children * each; got.N != want {
		t.Fatalf("%d of %d writes were lost: the store ended at %d. Each lost write is one process overwriting "+
			"a change another had already made — on the enrolment ledger that is a spent identity becoming "+
			"available again.", want-got.N, want, got.N)
	}
}

// TestChildIncrementsTheStore is the child half. It is a test only so the parent can re-invoke this binary;
// under `go test` without the environment it does nothing.
func TestChildIncrementsTheStore(t *testing.T) {
	path := os.Getenv("DSSE_BLOBSTORE_PATH")
	if os.Getenv("DSSE_BLOBSTORE_CHILD") == "" || path == "" {
		t.Skip("child-only")
	}
	rounds, _ := strconv.Atoi(os.Getenv("DSSE_BLOBSTORE_ROUNDS"))
	p := NewSingleWriterFilePersister(FilePersister{Path: path})
	for i := 0; i < rounds; i++ {
		for {
			raw, err := p.Load()
			if err != nil {
				t.Fatal(err)
			}
			var v struct {
				N int `json:"n"`
			}
			if err := json.Unmarshal(raw, &v); err != nil {
				// A torn read is the OTHER half of the same defect: without the lock, two savers share one
				// fixed ".tmp" name and a reader can see a partial file.
				t.Fatalf("the store could not be parsed (%v): another process was writing it at the same time, "+
					"through the same temporary file", err)
			}
			v.N++
			out, _ := json.Marshal(v)
			// A refusal means somebody else wrote in between: re-read and try again, which is what a caller
			// that cares about its update is supposed to do with ErrConcurrentWriter.
			if err := p.Save(out); err != nil {
				continue
			}
			break
		}
	}
}
