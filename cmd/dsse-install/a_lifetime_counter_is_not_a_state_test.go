package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// ★★★ A LIFETIME COUNTER IS NOT A STATE (2026-08-28, measured on a deployment that was working).
//
// The hot-store check failed on ingest_failures > 0 — a number that only ever grows — so a store that dropped
// one batch while its containers were being recreated, and had succeeded on everything since, could never be
// handed over. It said
//
//	hot store "ok": [] (2 ingest failure(s), 0 decode failure(s))
//
// about a store whose own answer was status ok, 143 records, last success THAT SECOND and last failure
// thirty-five minutes earlier. A check that cannot tell "is failing" from "once failed" makes its own verdict
// worthless: every long-lived deployment eventually fails it and stays failed.
func hotStore(t *testing.T, body map[string]any) []verifyResult {
	t.Helper()
	// The stub's answer never changes, so waiting the operator's 90 seconds for it to change proves nothing
	// except that the gate is slow (measured: this one helper was 90s of a 99s package).
	prevWait, prevPoll := hotStoreAcceptanceWait, hotStoreAcceptancePoll
	hotStoreAcceptanceWait, hotStoreAcceptancePoll = 200*time.Millisecond, 20*time.Millisecond
	t.Cleanup(func() { hotStoreAcceptanceWait, hotStoreAcceptancePoll = prevWait, prevPoll })
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/admin/hot-store/health") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(body)
	}))
	t.Cleanup(srv.Close)
	// The whole check runs; only its hot-store half is being measured, so the Edge half is pointed at the
	// same stub and its answers ignored.
	all := verifyLogPath(srv.Client(), srv.URL, srv.URL, "tok")
	out := []verifyResult{}
	for _, r := range all {
		if r.name == "the authority keeps what the fleet reports" {
			out = append(out, r)
		}
	}
	if len(out) == 0 {
		t.Fatal("the check said nothing at all")
	}
	return out
}

func TestAStoreThatRecoveredIsNotHeldAgainstTheDeployment(t *testing.T) {
	got := hotStore(t, map[string]any{
		"status": "ok", "reasons": []string{},
		"stats":           map[string]any{"mirrored": 143, "ingest_failures": 2, "decode_failures": 0},
		"last_success_at": "2026-08-28T00:31:52Z",
		"last_failure_at": "2026-08-27T23:56:37Z",
		"last_filename":   "clickhouse",
	})
	last := got[len(got)-1]
	if !last.ok {
		t.Fatalf("a store that has succeeded since its last failure was reported as a fault: %s", last.note)
	}
	// ★ AND THE PAST FAILURE IS STILL SAID OUT LOUD. Not a reason to refuse a handover, and not something an
	// operator should have to go looking for.
	for _, want := range []string{"2", "lifetime", "23:56:37"} {
		if !strings.Contains(last.note, want) {
			t.Errorf("the pass does not mention %q, so a real past failure is invisible: %s", want, last.note)
		}
	}
}

// ★★★ THE CONTROL, AND IT IS THE ONE THAT MATTERS: a store that is failing NOW still fails. Without this the
// fix above would be "stop checking".
func TestAStoreThatIsFailingNowStillFails(t *testing.T) {
	got := hotStore(t, map[string]any{
		"status": "ok", "reasons": []string{},
		"stats":           map[string]any{"mirrored": 143, "ingest_failures": 2, "decode_failures": 0},
		"last_success_at": "2026-08-27T23:00:00Z",
		"last_failure_at": "2026-08-28T00:31:52Z",
		"last_error":      "ingest_failed: 1 batch(es) still waiting to reach the hot store",
	})
	if last := got[len(got)-1]; last.ok {
		t.Fatalf("a store whose last event was a FAILURE was passed: %s", last.note)
	}
}

// ★★ AND A STORE THAT SAYS IT IS NOT OK FAILS WHATEVER ITS TIMESTAMPS SAY.
func TestAStoreThatSaysItIsNotOkFails(t *testing.T) {
	got := hotStore(t, map[string]any{
		"status": "degraded", "reasons": []string{"the archive is unreachable"},
		"stats":           map[string]any{"mirrored": 143, "ingest_failures": 0, "decode_failures": 0},
		"last_success_at": "2026-08-28T00:31:52Z",
		"last_failure_at": "2026-08-27T23:00:00Z",
	})
	if last := got[len(got)-1]; last.ok {
		t.Fatalf("a store reporting itself degraded was passed: %s", last.note)
	}
}

// ★★ AND ONE THAT HAS ACCEPTED NOTHING IS NOT "FINE BECAUSE NOTHING FAILED". A store that is reachable and a
// store that holds this deployment's history are different facts.
func TestAStoreThatHasAcceptedNothingFails(t *testing.T) {
	got := hotStore(t, map[string]any{
		"status": "ok", "reasons": []string{},
		"stats":           map[string]any{"mirrored": 0, "ingest_failures": 0, "decode_failures": 0},
		"last_success_at": "2026-08-28T00:31:52Z",
		"last_failure_at": "",
	})
	if last := got[len(got)-1]; last.ok {
		t.Fatalf("a store holding nothing was passed: %s", last.note)
	}
	_ = fmt.Sprint()
}
