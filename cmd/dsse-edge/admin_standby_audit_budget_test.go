package main

import (
	"bytes"
	"errors"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/logs"
)

func TestStandbyAuditBudgetPreservesCountsAndObservationTimes(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	a := newAdminStandbyAudit(writer, testEvaluator())
	now := time.Date(2026, 9, 18, 9, 0, 0, 0, time.FixedZone("JST", 9*60*60))
	a.now = func() time.Time { return now }
	one, same, other := a.forPermission("admin.policy.write"), a.forPermission("admin.policy.write"), a.forPermission("admin.risk.write")
	read := a.forPermission("admin.state.read")
	read()
	one()
	other()
	now = now.Add(10 * time.Second)
	for i := 0; i < 10000; i++ {
		same()
	}
	now = now.Add(49 * time.Second)
	a.flush(false)
	if n := writer.AuditHealth().Attempts; n != 2 {
		t.Fatal("early writes", n)
	}
	now = now.Add(time.Second)
	a.flush(false)
	rows := readTransportAudits(t, writer)
	if len(rows) != 3 {
		t.Fatal("expected one summary", len(rows))
	}
	summary := rows[2]
	assertStandbyAudit(t, summary, "admin.policy.write")
	if summary.Metadata["request_count"] != float64(10000) || summary.Metadata["first_seen"] != "2026-09-18T00:00:10Z" || summary.Metadata["last_seen"] != "2026-09-18T00:00:10Z" || summary.Timestamp != "2026-09-18T00:01:00Z" {
		t.Fatal("summary disagrees with observations", summary)
	}
	a.flush(false)
	if writer.AuditHealth().Attempts != 3 {
		t.Fatal("empty bucket emitted")
	}
	one()
	if writer.AuditHealth().Attempts != 3 {
		t.Fatal("flush and next request bypassed budget")
	}
	now = now.Add(time.Minute)
	one()
	rows = readTransportAudits(t, writer)
	if len(rows) != 4 || rows[3].Metadata["request_count"] != float64(2) {
		t.Fatal("next window count")
	}
	if len(a.buckets) != 2 {
		t.Fatal("read or duplicate registration allocated a bucket")
	}
	a.flush(true)
	if writer.AuditHealth().Attempts != 4 {
		t.Fatal("final flush repeated a batch")
	}
}

func TestStandbyAuditBudgetFailuresAreBoundedAndNotReplayed(t *testing.T) {
	for _, kind := range []string{"primary", "hook", "missing"} {
		t.Run(kind, func(t *testing.T) {
			writer, err := logs.NewWriter(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			defer writer.Close()
			if kind == "primary" {
				if err := os.Mkdir(filepath.Join(writer.Dir(), "audit.log.jsonl"), 0700); err != nil {
					t.Fatal(err)
				}
			}
			if kind == "hook" {
				writer.SetAppendHook(func(string, []byte) error { return errors.New("synthetic hook failure") })
			}
			sink := writer
			if kind == "missing" {
				sink = nil
			}
			a := newAdminStandbyAudit(sink, testEvaluator())
			now := time.Date(2026, 9, 18, 0, 0, 0, 0, time.UTC)
			a.now = func() time.Time { return now }
			record := a.forPermission("admin.policy.write")
			var output bytes.Buffer
			old := log.Writer()
			log.SetOutput(&output)
			defer log.SetOutput(old)
			for i := 0; i < 1000; i++ {
				record()
			}
			if n := strings.Count(output.String(), "standby audit summary unconfirmed"); n != 1 {
				t.Fatal("error amplification", n)
			}
			if kind != "missing" && writer.AuditHealth().Attempts != 1 {
				t.Fatal("disk amplification")
			}
			now = now.Add(time.Minute)
			a.flush(false)
			if !strings.Contains(output.String(), "request_count=999") || strings.Count(output.String(), "standby audit summary unconfirmed") != 2 {
				t.Fatal("failed summary count missing")
			}
			if kind == "primary" {
				if err := os.Remove(filepath.Join(writer.Dir(), "audit.log.jsonl")); err != nil {
					t.Fatal(err)
				}
			}
			writer.SetAppendHook(nil)
			now = now.Add(time.Minute)
			record()
			if kind != "missing" {
				rows := readTransportAudits(t, writer)
				want := 1
				if kind == "hook" {
					want = 3
				}
				if len(rows) != want || rows[len(rows)-1].Metadata["request_count"] != float64(1) {
					t.Fatal("replayed an uncertain batch", len(rows))
				}
				if kind == "hook" && (writer.AuditHealth().PrimarySuccesses != 3 || writer.AuditHealth().HookFailures != 2) {
					t.Fatal("hook health changed")
				}
			}
		})
	}
}

func TestStandbyAuditBudgetPeriodicAndFinalFlush(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	a := newAdminStandbyAudit(writer, testEvaluator())
	now := time.Date(2026, 9, 18, 0, 0, 0, 0, time.UTC)
	a.now = func() time.Time { return now }
	record := a.forPermission("admin.policy.write")
	record()
	record()
	// Run the production loop with deterministic tick delivery and no wall-clock wait.
	stop, ticks, done := make(chan struct{}), make(chan time.Time), make(chan struct{})
	now = now.Add(time.Minute)
	go func() { defer close(done); a.run(stop, ticks) }()
	ticks <- now
	// Sending the next tick synchronizes with completion of the first flush.
	ticks <- now
	if writer.AuditHealth().Attempts != 2 {
		t.Fatal("idle burst did not flush")
	}
	record()
	close(stop)
	<-done
	rows := readTransportAudits(t, writer)
	if len(rows) != 3 {
		t.Fatal("final pending count not flushed")
	}
	for _, row := range rows {
		if row.Metadata["request_count"] != float64(1) {
			t.Fatal("double-counted")
		}
	}
}

func TestStandbyAuditBudgetStopWaitsAndIsIdempotent(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	a := newAdminStandbyAudit(writer, testEvaluator())
	stop := a.start()
	record := a.forPermission("admin.policy.write")
	record()
	record()
	stop()
	stop()
	rows := readTransportAudits(t, writer)
	if len(rows) != 2 {
		t.Fatal("stop returned before flush or repeated it", len(rows))
	}
}
