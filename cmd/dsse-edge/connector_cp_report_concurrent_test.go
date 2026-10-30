package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/model"
)

type connectorReportRoundTripFunc func(*http.Request) (*http.Response, error)

func (f connectorReportRoundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func TestConnectorReportQueuedDuringDrainIsNotLost(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	var requests atomic.Int32
	client := &http.Client{Transport: connectorReportRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		if requests.Add(1) == 1 {
			close(entered)
			select {
			case <-release:
			case <-r.Context().Done():
				return nil, r.Context().Err()
			}
		}
		return &http.Response{StatusCode: http.StatusNoContent, Body: io.NopCloser(strings.NewReader("")), Header: http.Header{}}, nil
	})}
	reporter := &connectorCPReporter{url: "https://example.invalid/connector-report", client: client,
		outboxPath: filepath.Join(t.TempDir(), "connector-outbox.json")}
	first := connectorReport{Registration: model.ConnectorRegistration{ID: "first"}, TenantID: "tenant-a"}
	second := connectorReport{Registration: model.ConnectorRegistration{ID: "second"}, TenantID: "tenant-a"}
	reporter.queue(first, errors.New("control plane temporarily unavailable"))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan struct{})
	go func() {
		reporter.drainOnce(ctx)
		close(done)
	}()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("outbox replay did not start")
	}
	reporter.queue(second, errors.New("control plane temporarily unavailable"))
	close(release)
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("outbox replay did not finish")
	}

	raw, err := os.ReadFile(reporter.outboxPath)
	if err != nil {
		t.Fatalf("a report queued during replay disappeared: %v", err)
	}
	var remaining connectorReport
	if err := json.Unmarshal(raw, &remaining); err != nil {
		t.Fatalf("outbox must contain exactly one remaining report: %v", err)
	}
	if remaining.Registration.ID != "second" {
		t.Fatalf("outbox retained the wrong report: %q", remaining.Registration.ID)
	}
	reporter.drainOnce(ctx)
	if requests.Load() != 2 {
		t.Fatalf("second report was not replayed: requests=%d", requests.Load())
	}
	if _, err := os.Stat(reporter.outboxPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("fully replayed outbox remains: %v", err)
	}
}
