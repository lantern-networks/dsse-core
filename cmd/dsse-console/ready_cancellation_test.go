package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

type consoleReadyRoundTripper func(*http.Request) (*http.Response, error)

func (f consoleReadyRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func TestConsoleReadyCallerCancellationDoesNotPoisonSharedResult(t *testing.T) {
	for _, cancelCaller := range []bool{false, true} {
		name := "caller waits"
		if cancelCaller {
			name = "caller disconnects"
		}
		t.Run(name, func(t *testing.T) {
			release := make(chan struct{})
			cpEntered := make(chan struct{}, 4)
			cp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				cpEntered <- struct{}{}
				<-release
				w.WriteHeader(http.StatusOK)
			}))
			defer cp.Close()
			var releaseOnce sync.Once
			releaseProbe := func() { releaseOnce.Do(func() { close(release) }) }
			defer releaseProbe()
			// Observe the actual outgoing request without replacing its HTTP
			// transport or copying the production readiness implementation.
			probeContexts := make(chan context.Context, 4)
			client := cp.Client()
			transport := client.Transport
			client.Transport = consoleReadyRoundTripper(func(r *http.Request) (*http.Response, error) {
				probeContexts <- r.Context()
				return transport.RoundTrip(r)
			})
			probe := consoleReadyHandler(cp.URL+"/leader", client)
			caller, cancel := context.WithCancel(context.Background())
			defer cancel()
			first := httptest.NewRecorder()
			finished := make(chan struct{})
			go func() {
				defer close(finished)
				probe.ServeHTTP(first, httptest.NewRequest(http.MethodGet, "/ready", nil).WithContext(caller))
			}()
			var shared context.Context
			select {
			case shared = <-probeContexts:
			case <-time.After(3 * time.Second):
				t.Fatal("Console did not start its CP probe")
			}
			select {
			case <-cpEntered:
			case <-time.After(3 * time.Second):
				t.Fatal("Console probe did not reach the healthy CP")
			}
			if cancelCaller {
				// net/http cancels this same incoming context on disconnect.
				// Cancel explicitly so the regression needs no timing sleeps.
				cancel()
			}
			if err := shared.Err(); err != nil {
				t.Errorf("caller cancellation reached the shared CP probe: %v", err)
			}
			if deadline, ok := shared.Deadline(); !ok || time.Until(deadline) > 2*time.Second {
				t.Error("shared CP probe lost its independent two-second deadline")
			}
			// The CP remains healthy. Complete its response after the caller
			// disconnects, then check the next caller gets its cached success.
			releaseProbe()
			select {
			case <-finished:
			case <-time.After(3 * time.Second):
				t.Fatal("Console did not complete the shared CP probe")
			}
			second := httptest.NewRecorder()
			probe.ServeHTTP(second, httptest.NewRequest(http.MethodGet, "/ready", nil))
			if second.Code != http.StatusOK {
				t.Fatalf("healthy CP became unavailable to the next caller: %d", second.Code)
			}
			if len(probeContexts) != 0 {
				t.Fatal("next caller did not share the completed CP probe")
			}
		})
	}
}
