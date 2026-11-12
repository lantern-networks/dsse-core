package main

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

// A queue is full exactly when records arrive faster than they ship. While it was full, every arriving record
// rewrote the whole spool file: with 10,006 devices that was about forty 3 MB rewrites a second from one Edge
// (measured 2026-11-11). The spool must stay bounded without a rewrite per record.
func TestAFullSpoolIsNotRewrittenForEveryRecord(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable) // shipping stays behind for the whole test
	}))
	defer srv.Close()
	const capacity = 32
	path := filepath.Join(t.TempDir(), "spool.ndjson")
	s, err := newRemoteAuditShipper(srv.URL, "", "", []string{"audit.log.jsonl"}, capacity, path, "", "")
	if err != nil {
		t.Fatalf("new shipper: %v", err)
	}
	hook := s.hook()
	const sent = 40 * capacity
	for i := 0; i < sent; i++ {
		_ = hook("audit.log.jsonl", []byte(`{"n":1}`))
		if i%8 == 0 {
			time.Sleep(time.Millisecond) // let the shipper take them off the channel, so they reach the queue
		}
	}
	deadline := time.Now().Add(5 * time.Second)
	for s.dropped.Load() < sent/2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	overflowed := s.dropped.Load()
	s.stop()
	if overflowed < sent/2 {
		t.Fatalf("the queue never overflowed (%d dropped of %d sent), so this test measured nothing", overflowed, sent)
	}
	rewrites := s.spool.compactions.Load()
	// One rewrite per `capacity` appended records is the ordinary bound; allow a few more for the stop and the
	// set-aside path. Before the fix this was one per dropped record — over a thousand here.
	if limit := int64(sent/capacity + 8); rewrites > limit {
		t.Fatalf("the spool was rewritten %d times for %d records over a full queue of %d (want at most %d)", rewrites, sent, capacity, limit)
	}
	// And what a restart would replay is still only the queue's worth, newest kept.
	_, replay, err := newShipSpool(path, capacity)
	if err != nil {
		t.Fatalf("reopen spool: %v", err)
	}
	if len(replay) > capacity {
		t.Fatalf("after a clean stop the spool holds %d records, more than the queue of %d", len(replay), capacity)
	}
}
