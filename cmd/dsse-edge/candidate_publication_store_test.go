package main

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/appcatalog"
)

func checkCandidatePublicationStore(t *testing.T, store appcatalog.RuntimeStore, reload func() appcatalog.RuntimeStore) {
	t.Helper()
	ctx, now := context.Background(), time.Now().UTC().Truncate(time.Second)
	desired := appcatalog.Entry{ApplicationID: "adoption", ApplicationType: "private_app", Name: "Target", Destination: "original.example", DestinationPort: 443, PublishProtocol: "web", Published: true, Status: "active"}
	publisher := store.(appcatalog.CandidatePublisher)
	initial, err := publisher.CreateOrMatch(ctx, desired, "own", now)
	if err != nil {
		t.Fatal(err)
	}
	peer := desired
	peer.Destination = "peer.example"
	if _, err = publisher.CreateOrMatch(ctx, peer, "peer", now); err != nil {
		t.Fatal(err)
	}
	store = reload()
	publisher = store.(appcatalog.CandidatePublisher)
	retry, err := publisher.CreateOrMatch(ctx, desired, "own", now.Add(time.Hour))
	if err != nil || !reflect.DeepEqual(initial, retry) {
		t.Fatal("restart retry rewrote saved application", retry, err)
	}
	changed := desired
	changed.Destination = "different.example"
	if _, err = publisher.CreateOrMatch(ctx, changed, "own", now); !errors.Is(err, appcatalog.ErrCandidateApplicationConflict) {
		t.Fatal("conflict accepted", err)
	}
	got, _, err := store.Get(ctx, "own", "adoption")
	if err != nil || !reflect.DeepEqual(appcatalog.CopyEntry(got), initial) {
		t.Fatal("conflict changed existing entry", got, err)
	}
	got, _, err = store.Get(ctx, "peer", "adoption")
	if err != nil || got.Destination != "peer.example" {
		t.Fatal("peer changed", got, err)
	}
	// Concurrent conflicting creators must not overwrite the first committed target.
	var wg sync.WaitGroup
	outcomes := make(chan error, 2)
	for _, host := range []string{"first.example", "second.example"} {
		wg.Add(1)
		go func(host string) {
			defer wg.Done()
			e := desired
			e.ApplicationID = "concurrent"
			e.Destination = host
			_, err := publisher.CreateOrMatch(ctx, e, "own", now)
			outcomes <- err
		}(host)
	}
	wg.Wait()
	close(outcomes)
	successes, conflicts := 0, 0
	for err := range outcomes {
		if err == nil {
			successes++
		} else if errors.Is(err, appcatalog.ErrCandidateApplicationConflict) {
			conflicts++
		} else {
			t.Fatal(err)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatal("concurrent creators", successes, conflicts)
	}
	ctx, cancel := context.WithCancel(ctx)
	cancel()
	desired.ApplicationID = "cancelled"
	if _, err = publisher.CreateOrMatch(ctx, desired, "own", now); err == nil {
		t.Fatal("cancelled creation succeeded")
	}
	if _, found, _ := store.Get(context.Background(), "own", "cancelled"); found {
		t.Fatal("cancelled application saved")
	}
}

func TestCandidatePublicationFileRestartAndConcurrency(t *testing.T) {
	path := filepath.Join(t.TempDir(), "apps.json")
	reload := func() appcatalog.RuntimeStore {
		s := appcatalog.NewStore()
		if err := s.SetStatePath(path); err != nil {
			t.Fatal(err)
		}
		return s
	}
	checkCandidatePublicationStore(t, reload(), reload)
	seeded := appcatalog.NewStore()
	if _, err := seeded.Upsert(context.Background(), appcatalog.Entry{ApplicationID: "seed", ApplicationType: "private_app"}, "own", time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := seeded.SetStatePath(""); err != nil {
		t.Fatal(err)
	}
	if _, err := seeded.CreateOrMatch(context.Background(), appcatalog.Entry{ApplicationID: "seed", ApplicationType: "private_app"}, "own", time.Now()); !errors.Is(err, appcatalog.ErrCandidateApplicationConflict) {
		t.Fatal("seed adopted", err)
	}
	// A refused file save must not leave an application for a later matching retry.
	blocked := filepath.Join(t.TempDir(), "missing", "apps.json")
	failed := appcatalog.NewStore()
	if err := failed.SetStatePath(blocked); err != nil {
		t.Fatal(err)
	}
	entry := appcatalog.Entry{ApplicationID: "refused", ApplicationType: "private_app"}
	if _, err := failed.CreateOrMatch(context.Background(), entry, "own", time.Now()); err == nil {
		t.Fatal("invalid path accepted")
	}
	if _, found, _ := failed.Get(context.Background(), "own", "refused"); found {
		t.Fatal("failed save published live")
	}
}

func TestCandidatePublicationPostgresRestartAndConcurrency(t *testing.T) {
	dsn := os.Getenv("POSTGRES_QUEUE_E2E_DSN")
	if dsn == "" {
		t.Skip("POSTGRES_QUEUE_E2E_DSN is not set")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, q := range postgresApplicationCatalogSchemaSQL() {
		if _, err = db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = db.Exec("TRUNCATE application_catalog"); err != nil {
		t.Fatal(err)
	}
	defer db.Exec("DROP TABLE application_catalog")
	reload := func() appcatalog.RuntimeStore { return &postgresApplicationCatalogStore{db: db} }
	checkCandidatePublicationStore(t, reload(), reload)
	seeded := &postgresApplicationCatalogStore{db: db, seed: map[string]map[string]appcatalog.Entry{"own": {"seed": {ApplicationID: "seed"}}}}
	if _, err = seeded.CreateOrMatch(context.Background(), appcatalog.Entry{ApplicationID: "seed", ApplicationType: "private_app"}, "own", time.Now()); !errors.Is(err, appcatalog.ErrCandidateApplicationConflict) {
		t.Fatal("seed adopted", err)
	}
}
