package main

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestConsoleReadyFollowsOnlyLocalCPLeader(t *testing.T) {
	leaderStatus := http.StatusServiceUnavailable
	var receivedCookie string
	cp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/leader" {
			t.Errorf("unexpected CP probe path %q", r.URL.Path)
		}
		receivedCookie = r.Header.Get("Cookie")
		w.WriteHeader(leaderStatus)
	}))
	defer cp.Close()

	probe := consoleReadyHandler(cp.URL+"/leader", cp.Client()).(*consoleReadiness)
	now := time.Now()
	probe.now = func() time.Time { return now }
	check := func(want int) {
		t.Helper()
		now = now.Add(time.Second)
		req := httptest.NewRequest(http.MethodGet, "/ready", nil)
		req.Header.Set("Cookie", "admin-session=secret")
		rec := httptest.NewRecorder()
		probe.ServeHTTP(rec, req)
		if rec.Code != want {
			t.Fatalf("local CP status %d gave Console readiness %d, want %d", leaderStatus, rec.Code, want)
		}
		if receivedCookie != "" {
			t.Fatal("Console readiness forwarded a browser cookie to the CP")
		}
	}
	check(http.StatusServiceUnavailable)
	leaderStatus = http.StatusOK
	check(http.StatusOK)
	leaderStatus = http.StatusServiceUnavailable
	check(http.StatusServiceUnavailable)
}

func TestConsoleReadyCachesBothResultsUntilExpiry(t *testing.T) {
	var calls atomic.Int32
	var leader atomic.Bool
	leader.Store(true)
	cp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if leader.Load() {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
	}))
	defer cp.Close()
	probe := consoleReadyHandler(cp.URL+"/leader", cp.Client()).(*consoleReadiness)
	now := time.Now()
	probe.now = func() time.Time { return now }
	check := func(wantStatus int, wantCalls int32) {
		t.Helper()
		rec := httptest.NewRecorder()
		probe.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/ready", nil))
		if rec.Code != wantStatus || calls.Load() != wantCalls {
			t.Fatalf("readiness=%d CP calls=%d; want %d and %d", rec.Code, calls.Load(), wantStatus, wantCalls)
		}
		if rec.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("readiness must not be cached by clients")
		}
	}
	check(http.StatusOK, 1)
	leader.Store(false)
	now = now.Add(time.Second - time.Nanosecond)
	for range 10 {
		check(http.StatusOK, 1)
	}
	// Requests inside the window must not extend it. At the exact boundary a
	// fresh probe notices leadership loss, even after an anonymous burst.
	now = now.Add(time.Nanosecond)
	check(http.StatusServiceUnavailable, 2)
	leader.Store(true)
	check(http.StatusServiceUnavailable, 2)
	now = now.Add(time.Second)
	check(http.StatusOK, 3)
}

func TestConsoleReadySharesConcurrentProbe(t *testing.T) {
	var calls atomic.Int32
	entered := make(chan struct{}, 32)
	release := make(chan struct{})
	cp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		entered <- struct{}{}
		<-release
		w.WriteHeader(http.StatusOK)
	}))
	defer cp.Close()
	// Release even if the probe never arrives and this test fails.
	var releaseOnce sync.Once
	releaseProbe := func() { releaseOnce.Do(func() { close(release) }) }
	defer releaseProbe()
	probe := consoleReadyHandler(cp.URL+"/leader", cp.Client()).(*consoleReadiness)
	now := time.Now()
	probe.now = func() time.Time { return now }
	var requests sync.WaitGroup
	start := make(chan struct{})
	for range 32 {
		requests.Add(1)
		go func() {
			defer requests.Done()
			<-start
			rec := httptest.NewRecorder()
			probe.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/ready", nil))
			if rec.Code != http.StatusOK {
				t.Errorf("concurrent probe returned %d", rec.Code)
			}
		}()
	}
	close(start)
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("readiness did not reach the CP")
	}
	// Let the shared upstream complete, then check all callers use its result.
	releaseProbe()
	requests.Wait()
	if calls.Load() != 1 {
		t.Fatalf("one burst caused %d CP calls, want 1", calls.Load())
	}
}

func TestConsoleReadyFailsClosedWithoutLeader(t *testing.T) {
	for _, probe := range []http.Handler{
		consoleReadyHandler("", nil),
		consoleReadyHandler("https://127.0.0.1:1/leader", &http.Client{}),
	} {
		rec := httptest.NewRecorder()
		probe.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/ready", nil))
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("unavailable CP gave Console readiness %d", rec.Code)
		}
	}
	rec := httptest.NewRecorder()
	consoleReadyHandler("", nil).ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/ready", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST /ready gave %d", rec.Code)
	}
}
