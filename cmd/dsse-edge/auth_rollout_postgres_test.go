package main

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/authrollout"
)

func TestPostgresAuthRolloutConcurrentCPsAndPromotion(t *testing.T) {
	dsn := os.Getenv("DSSE_ROLLING_TEST_DSN")
	if dsn == "" {
		t.Skip("dedicated DSSE_ROLLING_TEST_DSN not set")
	}
	db, e := sql.Open("postgres", dsn)
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	if _, e = db.Exec(`CREATE TABLE cp_state_blobs (store_key TEXT PRIMARY KEY,payload BYTEA NOT NULL,updated_at TIMESTAMPTZ NOT NULL DEFAULT now())`); e != nil {
		t.Fatal("requires a fresh disposable database:", e)
	}
	defer db.Exec(`DROP TABLE cp_state_blobs`)
	_, m := rolloutFixture(t)
	s := authrollout.NewStore(postgresBlobPersister{db: db, key: "auth_rollout_v1"})
	if e = s.Configure(context.Background(), 0, m); e != nil {
		t.Fatal(e)
	}
	report := func(i int) error {
		n := m.Members[i]
		peer := authrollout.NewStore(postgresBlobPersister{db: db, key: "auth_rollout_v1"})
		return peer.Record(context.Background(), n.CertificateSHA256, authrollout.Report{Generation: 1, NodeID: n.ID, Version: "next", Features: []string{authrollout.EvidenceFeature, authrollout.SingleRequestFeature}}, time.Now())
	}
	// Two independent CP Store instances serialize their observations in SQL.
	var wg sync.WaitGroup
	failures := make(chan error, len(m.Members))
	for i := range m.Members {
		wg.Add(1)
		go func(i int) { defer wg.Done(); failures <- report(i) }(i)
	}
	wg.Wait()
	close(failures)
	for e := range failures {
		if e != nil {
			t.Fatal(e)
		}
	}
	state, e := s.Read()
	if e != nil || len(state.Observed) != len(m.Members) {
		t.Fatalf("reports lost: %v", e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if e = s.Activate(ctx, 1, []string{authrollout.EvidenceFeature}, time.Now()); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	state, e = s.Read()
	if e != nil || state.Complete {
		t.Fatal("cancelled activation became effective")
	}
	if e = s.Activate(context.Background(), 1, []string{authrollout.EvidenceFeature, authrollout.SingleRequestFeature}, time.Now()); e != nil {
		t.Fatal(e)
	}
	promoted := authrollout.NewStore(postgresBlobPersister{db: db, key: "auth_rollout_v1"})
	state, e = promoted.Read()
	if e != nil || !state.Complete {
		t.Fatal("promoted CP lost completion")
	}
	stale := m
	stale.Generation = 1
	if promoted.Configure(context.Background(), 0, stale) == nil {
		t.Fatal("old bootstrap overwrote authority")
	}
}
