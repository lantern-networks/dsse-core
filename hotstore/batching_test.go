package hotstore

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// batching_test.go — the property that matters is ROWS PER INSERT. One row per insert is what took a lab's
// ClickHouse to 429% CPU on 2.4M rows, and no amount of tuning downstream fixes the shape of the writes.

type recordedInsert struct {
	rows  int
	token string
}

func clickHouseRecorder(t *testing.T) (*ClickHouseStore, func() []recordedInsert) {
	t.Helper()
	var mu sync.Mutex
	var inserts []recordedInsert
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// io.ReadAll, not one Read: a single Read returns whatever chunk happens to be buffered, which made this
		// test count 16 of 500 rows and blame the ingestor.
		body, _ := io.ReadAll(r.Body)
		text := string(body)
		rows := 0
		for _, line := range strings.Split(text, "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "{") {
				rows++
			}
		}
		mu.Lock()
		inserts = append(inserts, recordedInsert{rows: rows, token: r.URL.Query().Get("insert_deduplication_token")})
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)
	return NewClickHouseStore(server.URL, "", "", "dsse", "events"), func() []recordedInsert {
		mu.Lock()
		defer mu.Unlock()
		out := make([]recordedInsert, len(inserts))
		copy(out, inserts)
		return out
	}
}

// ★ MANY RECORDS, ONE INSERT. This is the whole point: 500 records must not become 500 parts.
func TestManyRecordsBecomeOneInsert(t *testing.T) {
	store, recorded := clickHouseRecorder(t)
	ingestor := NewBatchIngestor(store, BatchIngestorConfig{QueueSize: 1000, MaxRows: 1000,
		FlushInterval: 50 * time.Millisecond})

	for i := 0; i < 500; i++ {
		ingestor.Add(IngestRecord{Stream: "audit", Row: map[string]any{"id": i}, ReceivedAt: time.Now()})
	}
	if err := ingestor.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	inserts := recorded()
	total := 0
	for _, insert := range inserts {
		total += insert.rows
	}
	if total != 500 {
		t.Fatalf("%d rows reached the store, want 500", total)
	}
	if len(inserts) > 3 {
		t.Fatalf("500 records became %d inserts — one part per insert is the defect this exists to remove",
			len(inserts))
	}
}

// A batch retried as itself carries the SAME token, so ClickHouse drops the repeat. The token is derived from
// the batch's contents rather than assigned, which is what makes a retry identifiable.
func TestTheSameBatchCarriesTheSameToken(t *testing.T) {
	store, recorded := clickHouseRecorder(t)
	records := []IngestRecord{
		{Stream: "audit", Row: map[string]any{"id": "aue_1"}, ReceivedAt: time.Unix(0, 0)},
		{Stream: "audit", Row: map[string]any{"id": "aue_2"}, ReceivedAt: time.Unix(0, 0)},
	}
	for i := 0; i < 2; i++ {
		if err := store.IngestBatch(t.Context(), records); err != nil {
			t.Fatalf("ingest: %v", err)
		}
	}
	inserts := recorded()
	if len(inserts) != 2 {
		t.Fatalf("expected two attempts, got %d", len(inserts))
	}
	if inserts[0].token == "" {
		t.Fatalf("a batch went out with no deduplication token: a retry would duplicate every row")
	}
	if inserts[0].token != inserts[1].token {
		t.Fatalf("the same batch produced different tokens (%s vs %s): a retry would duplicate every row",
			inserts[0].token, inserts[1].token)
	}
	// And a DIFFERENT batch is a different token, or one batch would suppress another.
	other := append([]IngestRecord{}, records...)
	other[0] = IngestRecord{Stream: "audit", Row: map[string]any{"id": "aue_9"}, ReceivedAt: time.Unix(0, 0)}
	if err := store.IngestBatch(t.Context(), other); err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if inserts = recorded(); inserts[2].token == inserts[0].token {
		t.Fatalf("two different batches share a token: the second would be dropped as a repeat")
	}
}

// ★ A FULL QUEUE IS REPORTED, NEVER SILENT. An OLAP tier quietly missing events is what this whole subsystem
// exists to avoid — and blocking instead would put ClickHouse back on the critical path of recording.
func TestAFullQueueDropsLoudly(t *testing.T) {
	blocked := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-blocked
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	defer close(blocked)

	var mu sync.Mutex
	dropped := 0
	ingestor := NewBatchIngestor(NewClickHouseStore(server.URL, "", "", "dsse", "events"),
		BatchIngestorConfig{QueueSize: 4, MaxRows: 1, FlushInterval: time.Millisecond,
			OnDrop: func(IngestRecord) { mu.Lock(); dropped++; mu.Unlock() }})

	for i := 0; i < 200; i++ {
		ingestor.Add(IngestRecord{Stream: "audit", Row: map[string]any{"id": i}, ReceivedAt: time.Now()})
	}
	mu.Lock()
	got := dropped
	mu.Unlock()
	if got == 0 {
		t.Fatalf("a full queue blocked instead of dropping: the writer is back on ClickHouse's latency")
	}
}

// Add must not block, whatever the store is doing — that is the second half of the defect.
func TestAddDoesNotWaitForTheStore(t *testing.T) {
	blocked := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-blocked
	}))
	defer server.Close()
	defer close(blocked)

	ingestor := NewBatchIngestor(NewClickHouseStore(server.URL, "", "", "dsse", "events"),
		BatchIngestorConfig{QueueSize: 100, MaxRows: 1, FlushInterval: time.Millisecond})
	done := make(chan struct{})
	go func() {
		for i := 0; i < 50; i++ {
			ingestor.Add(IngestRecord{Stream: "audit", Row: map[string]any{"id": i}, ReceivedAt: time.Now()})
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("Add blocked on a stalled store: an audit append is bounded by ClickHouse's latency again")
	}
}

// ★ A FAILED BATCH IS RETRIED. The first version reported the error and cleared the buffer, so a momentary
// ClickHouse hiccup lost every row in flight — permanently — and the next successful flush reset the monitor to
// "ok" so the gap looked healthy.
func TestAFailedBatchIsRetriedBeforeItIsDropped(t *testing.T) {
	var mu sync.Mutex
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		attempts++
		n := attempts
		mu.Unlock()
		if n < 3 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	flushed := make(chan int, 4)
	ingestor := NewBatchIngestor(NewClickHouseStore(server.URL, "", "", "dsse", "events"),
		BatchIngestorConfig{QueueSize: 100, MaxRows: 10, FlushInterval: 20 * time.Millisecond,
			OnFlush: func(rows int) { flushed <- rows }})
	ingestor.Add(IngestRecord{Stream: "audit", Row: map[string]any{"id": 1}, ReceivedAt: time.Now()})

	select {
	case rows := <-flushed:
		if rows != 1 {
			t.Fatalf("flushed %d rows, want 1", rows)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("a batch that failed twice was never retried into success — those rows are gone")
	}
	_ = ingestor.Close()
	mu.Lock()
	defer mu.Unlock()
	if attempts < 3 {
		t.Fatalf("only %d attempts were made", attempts)
	}
}

// ★ AN OUTAGE LONGER THAN 750ms MUST NOT LOSE THE ROWS. Three quick attempts and then clearing the buffer
// meant a ClickHouse restart — the exact condition this whole change exists for — discarded everything in
// flight, and the next successful flush reported ok so the gap looked healthy.
func TestABatchSurvivesAnOutageLongerThanItsRetries(t *testing.T) {
	var mu sync.Mutex
	down := true
	var rows int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		isDown := down
		mu.Unlock()
		if isDown {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		for _, line := range strings.Split(string(body), "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "{") {
				rows++
			}
		}
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	ingestor := NewBatchIngestor(NewClickHouseStore(server.URL, "", "", "dsse", "events"),
		BatchIngestorConfig{QueueSize: 100, MaxRows: 5, FlushInterval: 30 * time.Millisecond})
	for i := 0; i < 5; i++ {
		ingestor.Add(IngestRecord{Stream: "audit", Row: map[string]any{"id": i}, ReceivedAt: time.Now()})
	}
	// Long enough that the three in-line retries are spent and the batch has moved to the backlog.
	time.Sleep(1500 * time.Millisecond)
	mu.Lock()
	down = false
	mu.Unlock()

	deadline := time.After(5 * time.Second)
	for {
		mu.Lock()
		got := rows
		mu.Unlock()
		if got >= 5 {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("%d of 5 rows reached the store after the outage ended — the rest were discarded", got)
		case <-time.After(50 * time.Millisecond):
		}
	}
	_ = ingestor.Close()
}

// ★ THE BACKLOG MUST SURVIVE THE PROCESS. Reporting how many rows were held on shutdown improved visibility
// and nothing else: the process exits, the rows are gone from the hot store forever, and nothing replays the
// canonical jsonl.
func TestABacklogSurvivesARestart(t *testing.T) {
	var mu sync.Mutex
	down := true
	var rows int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		isDown := down
		mu.Unlock()
		if isDown {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		for _, line := range strings.Split(string(body), "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "{") {
				rows++
			}
		}
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	spool := filepath.Join(t.TempDir(), "spool.json")
	store := NewClickHouseStore(server.URL, "", "", "dsse", "events")

	// A process that could not write, and then exits.
	first := NewBatchIngestor(store, BatchIngestorConfig{QueueSize: 50, MaxRows: 5,
		FlushInterval: 30 * time.Millisecond, SpoolPath: spool})
	for i := 0; i < 5; i++ {
		first.Add(IngestRecord{Stream: "audit", Row: map[string]any{"id": i}, ReceivedAt: time.Now()})
	}
	time.Sleep(1500 * time.Millisecond) // its in-line retries are spent; the batch is in the backlog
	_ = first.Close()

	if _, err := os.Stat(spool); err != nil {
		t.Fatalf("the backlog was not spooled: %v — those rows are gone with the process", err)
	}

	// The next process, with the store back.
	mu.Lock()
	down = false
	mu.Unlock()
	second := NewBatchIngestor(store, BatchIngestorConfig{QueueSize: 50, MaxRows: 5,
		FlushInterval: 30 * time.Millisecond, SpoolPath: spool})
	defer second.Close()

	deadline := time.After(5 * time.Second)
	for {
		mu.Lock()
		got := rows
		mu.Unlock()
		if got >= 5 {
			return
		}
		select {
		case <-deadline:
			t.Fatalf("%d of 5 rows reached the store after the restart — a backlog that dies with the process", got)
		case <-time.After(50 * time.Millisecond):
		}
	}
}

// ★ THE SPOOL IS WRITTEN WHERE THE BACKLOG CHANGES, not deferred. A defer is the one thing a crash never runs,
// and this one also captured the slice BEFORE the prune, so it could persist entries already dropped.
func TestTheSpoolIsWrittenAsSoonAsABatchFails(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	spool := filepath.Join(t.TempDir(), "spool.json")
	ingestor := NewBatchIngestor(NewClickHouseStore(server.URL, "", "", "dsse", "events"),
		BatchIngestorConfig{QueueSize: 50, MaxRows: 2, FlushInterval: 20 * time.Millisecond, SpoolPath: spool})
	defer ingestor.Close()
	ingestor.Add(IngestRecord{Stream: "audit", Row: map[string]any{"id": 1}, ReceivedAt: time.Now()})

	// No Close(): the file must exist while the process is still running, because a crash is not a Close.
	deadline := time.After(6 * time.Second)
	for {
		if _, err := os.Stat(spool); err == nil {
			return
		}
		select {
		case <-deadline:
			t.Fatalf("the backlog was never spooled while the process was running — a crash would lose it")
		case <-time.After(50 * time.Millisecond):
		}
	}
}

// A spool that cannot be written must SAY SO. Configured-and-broken is the state that reads as durable.
func TestAnUnwritableSpoolIsReported(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	// A path under a FILE, so every write fails.
	blocker := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var reported []string
	ingestor := NewBatchIngestor(NewClickHouseStore(server.URL, "", "", "dsse", "events"),
		BatchIngestorConfig{QueueSize: 50, MaxRows: 2, FlushInterval: 20 * time.Millisecond,
			SpoolPath: filepath.Join(blocker, "spool.json"),
			OnFlushError: func(err error, _ int) {
				mu.Lock()
				reported = append(reported, err.Error())
				mu.Unlock()
			}})
	defer ingestor.Close()
	ingestor.Add(IngestRecord{Stream: "audit", Row: map[string]any{"id": 1}, ReceivedAt: time.Now()})

	deadline := time.After(6 * time.Second)
	for {
		mu.Lock()
		got := strings.Join(reported, "|")
		mu.Unlock()
		if strings.Contains(got, "could NOT be spooled") {
			return
		}
		select {
		case <-deadline:
			t.Fatalf("an unwritable spool was silent: the deployment looks durable and is not (%s)", got)
		case <-time.After(50 * time.Millisecond):
		}
	}
}

// ★ A TOKEN OVER NOTHING IS A TOKEN TWO DIFFERENT BATCHES SHARE (2026-08-13). The batch token hashes
// (stream, event_id) pairs, so records with no event id make it a function of the stream names and the count:
// the next batch of the same shape gets the SAME token and ClickHouse drops it as a replay. The single-row
// path already omits the token in that case and says why; this holds the batch path to the same rule.
func TestABatchWithNoEventIDsCarriesNoDeduplicationToken(t *testing.T) {
	var got []map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := map[string]string{}
		for k, v := range r.URL.Query() {
			q[k] = v[0]
		}
		got = append(got, q)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	store := NewClickHouseStore(srv.URL, "dsse", "events", "", "")

	// Two DIFFERENT batches, same shape, no event ids: distinguishable only by content.
	first := []IngestRecord{{Stream: "audit_logs", Row: map[string]any{"msg": "one"}}}
	second := []IngestRecord{{Stream: "audit_logs", Row: map[string]any{"msg": "two"}}}
	if err := store.IngestBatch(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	if err := store.IngestBatch(context.Background(), second); err != nil {
		t.Fatal(err)
	}

	if len(got) != 2 {
		t.Fatalf("expected two inserts, saw %d", len(got))
	}
	for i, q := range got {
		if tok, ok := q["insert_deduplication_token"]; ok {
			t.Fatalf("insert %d carried a token (%q) although its records have no event id — the next batch of "+
				"the same shape would hash identically and be dropped as a replay", i, tok)
		}
	}
}

// And a batch whose records DO carry ids keeps the token, or the replay safety it was added for is gone.
func TestABatchWithEventIDsKeepsItsToken(t *testing.T) {
	var got []map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := map[string]string{}
		for k, v := range r.URL.Query() {
			q[k] = v[0]
		}
		got = append(got, q)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	store := NewClickHouseStore(srv.URL, "dsse", "events", "", "")

	if err := store.IngestBatch(context.Background(), []IngestRecord{
		{Stream: "audit_logs", Row: map[string]any{"event_id": "aud_1"}},
		{Stream: "audit_logs", Row: map[string]any{"event_id": "aud_2"}},
	}); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0]["insert_deduplication_token"] == "" {
		t.Fatalf("a batch of identified records lost its replay token: %v", got)
	}
}
