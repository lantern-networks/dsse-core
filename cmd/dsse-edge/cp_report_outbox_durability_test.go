package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/lantern-networks/dsse-core/model"
)

func TestCPReportDrainsPreserveUnreadableOutboxes(t *testing.T) {
	for _, kind := range []string{"directory", "enrolment", "connector"} {
		t.Run(kind, func(t *testing.T) {
			requests := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				requests++
				w.WriteHeader(http.StatusNoContent)
			}))
			defer server.Close()
			path := filepath.Join(t.TempDir(), "outbox.jsonl")
			var first, last []byte
			var drain func()
			switch kind {
			case "directory":
				first, _ = json.Marshal(directoryReportFixture())
				last, _ = json.Marshal(directoryReportFixture())
				reporter := &directoryCPReporter{url: server.URL, client: server.Client(), outboxPath: path}
				drain = func() { reporter.drainOnce(context.Background()) }
			case "enrolment":
				first, _ = json.Marshal(enrolmentReport{Identity: "first", TenantID: "tenant-a"})
				last, _ = json.Marshal(enrolmentReport{Identity: "last", TenantID: "tenant-a"})
				reporter := &enrolmentCPReporter{url: server.URL, client: server.Client(), outboxPath: path}
				drain = func() { reporter.drainOnce(context.Background()) }
			case "connector":
				first, _ = json.Marshal(connectorReport{Registration: model.ConnectorRegistration{ID: "first"}, TenantID: "tenant-a"})
				last, _ = json.Marshal(connectorReport{Registration: model.ConnectorRegistration{ID: "last"}, TenantID: "tenant-a"})
				reporter := &connectorCPReporter{url: server.URL, client: server.Client(), outboxPath: path}
				drain = func() { reporter.drainOnce(context.Background()) }
			}
			original := bytes.Join([][]byte{first, []byte(`{"broken":`), last, nil}, []byte{'\n'})
			if err := os.WriteFile(path, original, 0o600); err != nil {
				t.Fatal(err)
			}
			drain()
			got, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("corrupt outbox was removed: %v", err)
			}
			if !bytes.Equal(got, original) {
				t.Fatal("corrupt outbox was rewritten and lost original bytes")
			}
			if requests != 0 {
				t.Fatalf("replayed %d report(s) before detecting interior corruption", requests)
			}
		})
	}
}

func TestEnrolmentReportDrainPreservesOversizedUnreadableTail(t *testing.T) {
	path := filepath.Join(t.TempDir(), "outbox.jsonl")
	// The old scanner stopped at 1 MiB without checking Err, then removed the
	// queue as if it had been empty.
	original := append(bytes.Repeat([]byte{'x'}, 1024*1024+1), '\n')
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}
	reporter := &enrolmentCPReporter{outboxPath: path}
	reporter.drainOnce(context.Background())
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("oversized outbox was removed: %v", err)
	}
	if !bytes.Equal(got, original) {
		t.Fatal("oversized unreadable outbox changed")
	}
}

func TestCPReportDrainsRejectNullRecords(t *testing.T) {
	for _, kind := range []string{"directory", "enrolment", "connector"} {
		t.Run(kind, func(t *testing.T) {
			requests := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				requests++
				w.WriteHeader(http.StatusNoContent)
			}))
			defer server.Close()
			path := filepath.Join(t.TempDir(), "outbox.jsonl")
			original := []byte("null\n")
			if err := os.WriteFile(path, original, 0o600); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "directory":
				(&directoryCPReporter{url: server.URL, client: server.Client(), outboxPath: path}).drainOnce(context.Background())
			case "enrolment":
				(&enrolmentCPReporter{url: server.URL, client: server.Client(), outboxPath: path}).drainOnce(context.Background())
			case "connector":
				(&connectorCPReporter{url: server.URL, client: server.Client(), outboxPath: path}).drainOnce(context.Background())
			}
			got, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(got, original) || requests != 0 {
				t.Fatalf("null record was treated as an acknowledged report: read=%v requests=%d", err, requests)
			}
		})
	}
}

func TestCPReportQueueSeparatesTornTailFromNextReport(t *testing.T) {
	for _, kind := range []string{"directory", "enrolment", "connector"} {
		t.Run(kind, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "outbox.jsonl")
			original := []byte(`{"incomplete":`)
			if err := os.WriteFile(path, original, 0o600); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "directory":
				(&directoryCPReporter{outboxPath: path}).queue(directoryReportFixture(), errors.New("offline"))
			case "enrolment":
				(&enrolmentCPReporter{outboxPath: path}).queue(enrolmentReport{Identity: "next", TenantID: "tenant-a"}, errors.New("offline"))
			case "connector":
				(&connectorCPReporter{outboxPath: path}).queue(connectorReport{Registration: model.ConnectorRegistration{ID: "next"}, TenantID: "tenant-a"}, errors.New("offline"))
			}
			got, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.HasPrefix(got, append(append([]byte(nil), original...), '\n')) {
				t.Fatalf("the next report was concatenated with a torn line: %q", got[:min(len(got), 80)])
			}
			parts := bytes.Split(bytes.TrimSpace(got), []byte{'\n'})
			if len(parts) != 2 || !json.Valid(parts[1]) {
				t.Fatal("the next queued report is not a separate valid JSON line")
			}
		})
	}
}
