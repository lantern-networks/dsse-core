package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// A disabled (empty-path) spool is a nil *shipSpool whose every method is a safe no-op.
func TestShipSpoolDisabledIsNilNoop(t *testing.T) {
	s, replay, err := newShipSpool("", 0)
	if err != nil || s != nil || replay != nil {
		t.Fatalf("empty path should yield a nil disabled spool, got s=%v replay=%v err=%v", s, replay, err)
	}
	// None of these must panic on a nil spool.
	s.append(auditShipItem{stream: "x", record: []byte("y")})
	s.maybeCompact(nil)
	s.compact([]auditShipItem{{stream: "x", record: []byte("y")}})
	s.close()
}

// Records appended to the spool are recovered, in order and byte-exact, by a fresh open (the restart path).
func TestShipSpoolAppendThenReplay(t *testing.T) {
	path := filepath.Join(t.TempDir(), "spool.ndjson")
	s, replay, err := newShipSpool(path, 4096)
	if err != nil || len(replay) != 0 {
		t.Fatalf("fresh spool: replay=%v err=%v", replay, err)
	}
	items := []auditShipItem{
		{stream: "audit.log.jsonl", record: []byte(`{"event":"a"}`)},
		{stream: "access.log.jsonl", record: []byte(`{"event":"b","nl":"line\nbreak"}`)}, // embedded newline survives (base64)
		{stream: "audit.log.jsonl", record: []byte(`{"event":"c"}`)},
	}
	for _, it := range items {
		s.append(it)
	}
	s.close()

	// Close the reopened spool too. On Unix an unclosed handle is invisible; on Windows the open file keeps
	// t.TempDir's cleanup from removing the directory, and the test fails after every assertion has passed.
	reopened, replay, err := newShipSpool(path, 4096)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer reopened.close()
	if len(replay) != len(items) {
		t.Fatalf("replayed %d records, want %d", len(replay), len(items))
	}
	for i, it := range items {
		if replay[i].stream != it.stream || string(replay[i].record) != string(it.record) {
			t.Fatalf("record %d mismatch: got {%s,%s} want {%s,%s}", i, replay[i].stream, replay[i].record, it.stream, it.record)
		}
	}
}

// Compaction rewrites the file to exactly the given (un-acked) set, dropping acked/dropped records from disk.
func TestShipSpoolCompactDropsAcked(t *testing.T) {
	path := filepath.Join(t.TempDir(), "spool.ndjson")
	s, _, err := newShipSpool(path, 4096)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	all := []auditShipItem{}
	for i := 0; i < 5; i++ {
		it := auditShipItem{stream: "audit.log.jsonl", record: []byte{byte('0' + i)}}
		all = append(all, it)
		s.append(it)
	}
	// Simulate the first three shipped+acked: compact to the remaining two.
	s.compact(all[3:])
	s.close()

	reopened, replay, err := newShipSpool(path, 4096)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer reopened.close()
	if len(replay) != 2 || string(replay[0].record) != "3" || string(replay[1].record) != "4" {
		t.Fatalf("after compaction replay = %+v, want the last two (3,4)", replay)
	}
}

// A torn final line (a crash mid-append) is skipped on replay, not fatal — the earlier records survive.
func TestShipSpoolTornLineSkipped(t *testing.T) {
	path := filepath.Join(t.TempDir(), "spool.ndjson")
	s, _, _ := newShipSpool(path, 4096)
	s.append(auditShipItem{stream: "audit.log.jsonl", record: []byte(`{"ok":1}`)})
	s.close()
	// Append a truncated (torn) JSON line, as a crash mid-write would leave.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	_, _ = f.WriteString(`{"s":"audit.log.jsonl","r":"eyJ0`) // no newline, invalid JSON
	_ = f.Close()

	reopened, replay, err := newShipSpool(path, 4096)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer reopened.close()
	if len(replay) != 1 || string(replay[0].record) != `{"ok":1}` {
		t.Fatalf("torn line should be skipped, leaving the 1 good record; got %+v", replay)
	}
}

// End-to-end restart recovery: a shipper constructed over a spool file that already holds un-acked records (as an
// Edge that stopped mid-outage would leave) RE-SHIPS them on startup — the durable-spool guarantee.
func TestRemoteAuditShipperReplaysSpoolOnStartup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "spool.ndjson")
	// Pre-populate the spool as if these two records were queued but never acked before the "restart".
	pre, _, err := newShipSpool(path, 4096)
	if err != nil {
		t.Fatalf("pre spool: %v", err)
	}
	pre.append(auditShipItem{stream: "audit.log.jsonl", record: []byte(`{"event":"one"}`)})
	pre.append(auditShipItem{stream: "audit.log.jsonl", record: []byte(`{"event":"two"}`)})
	pre.close()

	var mu sync.Mutex
	var bodies []string
	var got int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, string(b))
		mu.Unlock()
		atomic.AddInt64(&got, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// The "restarted" Edge: a new shipper over the same spool path. No hook calls — the records come purely from
	// the durable spool, proving in-flight records survive the restart.
	s, err := newRemoteAuditShipper(srv.URL, "", "", []string{"audit.log.jsonl"}, 64, path, "", "")
	if err != nil {
		t.Fatalf("new shipper: %v", err)
	}
	// The constructor starts run, which owns the spool handle and releases it on the way out. Until stop
	// existed there was no way out, so the handle lived until the process did — invisible on Unix, and on
	// Windows the reason t.TempDir could not clean up after a test that had otherwise passed.
	defer s.stop()
	deadline := time.Now().Add(3 * time.Second)
	for atomic.LoadInt64(&got) < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if atomic.LoadInt64(&got) != 2 {
		t.Fatalf("expected both spooled records re-shipped on startup, got %d", got)
	}
	if s.dropped.Load() != 0 {
		t.Fatalf("recovered records must not be dropped, dropped=%d", s.dropped.Load())
	}
	mu.Lock()
	sort.Strings(bodies)
	mu.Unlock()
	if len(bodies) != 2 || bodies[0] != `{"event":"one"}` || bodies[1] != `{"event":"two"}` {
		t.Fatalf("replayed bodies mismatch: %v", bodies)
	}
	// After a clean drain the durable spool is emptied.
	deadline = time.Now().Add(2 * time.Second)
	for s.pending.Load() != 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if _, replay, _ := readReplayFor(t, path); len(replay) != 0 {
		t.Fatalf("spool should be empty after a clean drain, still holds %d", len(replay))
	}
}

// readReplayFor reopens the spool at path purely to inspect its current contents (test helper).
func readReplayFor(t *testing.T, path string) (*shipSpool, []auditShipItem, error) {
	t.Helper()
	recs, err := readShipSpool(path)
	return nil, recs, err
}

// ★ BOTH SPOOLS RELEASE THEIR HANDLE ON SHUTDOWN (2026-08-17, found on win-dev-1).
//
// The refused spool was opened beside the pending one and never closed, so its append handle leaked for the
// life of the process. POSIX hides that — an open file still unlinks — so every macOS run was green while
// four tests failed on Windows in TempDir cleanup with "the process cannot access the file because it is
// being used by another process", and, worse than the tests, the record of what the control plane refused
// could not be rotated or removed on Windows while the Edge ran.
//
// Asserted on the handle rather than by removing the file, so the check means the same thing on every
// platform: os.Remove of an open file succeeds on POSIX and would pass vacuously there.
func TestBothSpoolsReleaseTheirHandleOnStop(t *testing.T) {
	dir := t.TempDir()
	spoolPath := filepath.Join(dir, "ship_spool.jsonl")

	s, err := newRemoteAuditShipper("https://127.0.0.1:1/audit-ingest", "t", "", []string{"audit.log.jsonl"}, 8, spoolPath, "", "")
	if err != nil {
		t.Fatalf("new shipper: %v", err)
	}
	if s.deadSpool == nil {
		t.Fatal("no refused spool was created, so this test would pass without checking anything")
	}
	// newRemoteAuditShipper already starts run(); starting it again double-closes s.done.
	s.stop()

	if s.spool != nil && s.spool.f != nil {
		t.Error("the pending spool still holds its append handle after stop")
	}
	if s.deadSpool.f != nil {
		t.Error("the REFUSED spool still holds its append handle after stop — on Windows that file can then " +
			"be neither rotated nor removed")
	}
}

// A record handed to the hook just before stop is in the spool afterwards. The reports an Edge writes on SIGTERM
// (observation_report.go) arrive exactly then. This states the contract; it also held before stop drained the
// channel, because run absorbs the channel at the top of each loop and the only losing window (a record and stop
// both arriving between that absorb and the next select) cannot be forced from a test.
func TestRecordsHandedOverBeforeStopAreSpooled(t *testing.T) {
	for i := 0; i < 30; i++ {
		spoolPath := filepath.Join(t.TempDir(), "spool.ndjson")
		s, err := newRemoteAuditShipper("", "", "", []string{"audit.log.jsonl"}, 8, spoolPath, "", "")
		if err != nil {
			t.Fatal(err)
		}
		hook := s.hook()
		_ = hook("audit.log.jsonl", []byte(`{"event":"first"}`))
		// No control plane: the first record fails and the shipper waits to retry.
		deadline := time.Now().Add(2 * time.Second)
		for s.health(time.Now())["failing_since"] == nil && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
		_ = hook("audit.log.jsonl", []byte(`{"event":"last"}`))
		s.stop()
		if _, replay, err := readReplayFor(t, spoolPath); err != nil || len(replay) != 2 {
			t.Fatalf("attempt %d: spool holds %d record(s) after stop (%v)", i, len(replay), err)
		}
	}
}
