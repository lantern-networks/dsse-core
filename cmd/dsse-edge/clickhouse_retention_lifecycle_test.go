package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/hotstore"
)

func TestPostgresClickHouseRetentionLifecycle(t *testing.T) {
	endpoint := os.Getenv("CLICKHOUSE_TEST_ENDPOINT")
	if endpoint == "" {
		t.Skip("CLICKHOUSE_TEST_ENDPOINT not set")
	}
	p, _, _ := blobWriterPostgresFixture(t)
	ctx := context.Background()
	table := fmt.Sprintf("retention_lifecycle_%d", time.Now().UnixNano())
	query := func(statement string) {
		t.Helper()
		req, err := http.NewRequestWithContext(ctx, "POST", endpoint, strings.NewReader(statement))
		if err != nil {
			t.Fatal(err)
		}
		req.SetBasicAuth(os.Getenv("CLICKHOUSE_TEST_USER"), os.Getenv("CLICKHOUSE_TEST_PASSWORD"))
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		b, err := io.ReadAll(res.Body)
		if err != nil || res.StatusCode != 200 {
			t.Fatalf("ClickHouse fixture: status=%d %s %v", res.StatusCode, b, err)
		}
	}
	query("CREATE TABLE dsse." + table + " (event_id String, retention_id UUID DEFAULT generateUUIDv4(), tenant_id String, stream String, ts DateTime64(3,'UTC'), raw String) ENGINE=MergeTree ORDER BY(tenant_id,ts,event_id)")
	defer query("DROP TABLE dsse." + table)
	hot := hotstore.NewClickHouseStore(endpoint, os.Getenv("CLICKHOUSE_TEST_USER"), os.Getenv("CLICKHOUSE_TEST_PASSWORD"), "dsse", table)
	holds := newLegalHoldStore(postgresBlobPersister{db: p.db, key: "legal_hold"})
	overrides := newRetentionOverrideStore(postgresBlobPersister{db: p.db, key: "retention_override"})
	chain := newAuditChainStore(postgresBlobPersister{db: p.db, key: "audit_chain"})
	arc := &retentionTestArchive{fakeArchive: &fakeArchive{objs: map[string][]byte{}}}
	cfg := retentionConfig{hotEvents: 24 * time.Hour, legalHold: holds, override: overrides, auditChain: chain, archive: arc, auditColdRetain: 365 * 24 * time.Hour}
	life := &clickhouseRetentionLifecycle{db: p.db, hot: hot, cfg: cfg}
	now := time.Now().UTC()
	query("INSERT INTO dsse." + table + " (event_id,tenant_id,stream,ts,raw) VALUES ('old','a','audit','2020-01-01 00:00:00.123','{\"id\":\"old\"}'),('held','b','audit','2020-01-01 00:00:00.123','{\"id\":\"held\"}')")
	if err := holds.Set("b", "admin", "case", true, now); err != nil {
		t.Fatal(err)
	}
	if err := overrides.Set("audit", 0); err != nil {
		t.Fatal(err)
	}
	if err := life.sweep(ctx, now); err != nil {
		t.Fatal(err)
	}
	if len(arc.objs) != 0 {
		t.Fatal("keep forever archived records")
	}
	if err := overrides.Set("audit", 1); err != nil {
		t.Fatal(err)
	}
	rows, err := hot.RetentionBatch(ctx, "a", "audit", now.Add(-24*time.Hour), 1000)
	if err != nil || len(rows) != 1 {
		t.Fatal(rows, err)
	}
	if err = life.prepare(ctx, "a", "audit", now.Add(-24*time.Hour), now, rows); err != nil {
		t.Fatal(err)
	}
	pending, err := life.pending()
	if err != nil || pending == nil {
		t.Fatal("journal absent", err)
	}
	// Failed archive readback leaves both the hot data and durable journal intact.
	arc.failRead = true
	if err = life.resume(ctx, pending); err == nil {
		t.Fatal("archive read failure accepted")
	}
	remaining, err := hot.RetentionBatch(ctx, "a", "audit", now, 1000)
	if err != nil || len(remaining) != 1 {
		t.Fatal("unverified archive deleted hot data", err)
	}
	if retained, err := life.pending(); err != nil || retained == nil || retained.Phase != "prepared" {
		t.Fatal("lost pending batch", err)
	}
	arc.failRead = false
	// Reloaded policy writers cannot acknowledge a hold/config update while a
	// previously admitted cross-store delete may still be outstanding.
	peerHold := newLegalHoldStore(postgresBlobPersister{db: p.db, key: "legal_hold"})
	peerOverride := newRetentionOverrideStore(postgresBlobPersister{db: p.db, key: "retention_override"})
	if err = peerHold.Set("a", "admin", "case", true, now); err == nil {
		t.Fatal("hold accepted during pending delete")
	}
	if err = peerOverride.Set("audit", 0); err == nil {
		t.Fatal("retention changed during pending delete")
	}
	// A new lifecycle instance resumes the committed journal without selecting a
	// different batch or inventing a new archive segment.
	reloaded := &clickhouseRetentionLifecycle{db: p.db, hot: hot, cfg: cfg}
	if err = reloaded.resume(ctx, pending); err != nil {
		t.Fatal(err)
	}
	if b, err := life.pending(); err != nil || b != nil {
		t.Fatal("journal not completed", b, err)
	}
	if len(arc.objs) != 1 {
		t.Fatalf("archive objects=%d", len(arc.objs))
	}
	verified, err := verifyAuditChain(ctx, arc, "a")
	if err != nil || !verified.OK || verified.Segments != 1 {
		t.Fatalf("chain=%+v err=%v", verified, err)
	}
	if err = peerHold.Set("a", "admin", "accepted after completion", true, now); err != nil {
		t.Fatal(err)
	}
	if err = peerOverride.Set("audit", 1); err != nil {
		t.Fatal(err)
	}
	if err = life.sweep(ctx, now); err != nil {
		t.Fatal(err)
	}
	held, err := hot.RetentionBatch(ctx, "b", "audit", now, 1000)
	if err != nil || len(held) != 1 {
		t.Fatal("held rows lost", held, err)
	}
	if err = holds.Set("b", "admin", "release", false, now); err != nil {
		t.Fatal(err)
	}
	if err = life.sweep(ctx, now); err != nil {
		t.Fatal(err)
	}
	if len(arc.objs) != 2 {
		t.Fatal("released hold not archived")
	}
}

// The production stores are real; only archive failure injection is synthetic.
type retentionTestArchive struct {
	*fakeArchive
	failRead bool
}

func (a *retentionTestArchive) Get(ctx context.Context, key string) (io.ReadCloser, error) {
	if a.failRead {
		return nil, fmt.Errorf("archive unavailable")
	}
	return a.fakeArchive.Get(ctx, key)
}
