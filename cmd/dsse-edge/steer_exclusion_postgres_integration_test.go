package main

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/steerexclusion"
)

func TestPostgresSteerExclusionOwnershipAndConcurrentWriters(t *testing.T) {
	fixture, _, _ := blobWriterPostgresFixture(t)
	migration, err := os.ReadFile("../../migrations/021_steer_exclusion_policies.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = fixture.db.Exec(string(migration)); err != nil {
		t.Fatal(err)
	}
	p := postgresSteerExclusionPersistence{db: fixture.db}
	ctx := context.Background()
	now := time.Now().UTC()
	first := steerexclusion.Policy{ID: "owned", TenantID: "tenant-a", ScopeType: "tenant", ExcludedAppSigningIDs: []string{"com.example.first"}, Status: "active", CreatedAt: now, UpdatedAt: now}
	if err := p.Upsert(ctx, &first); err != nil {
		t.Fatal(err)
	}
	intruder := first
	intruder.TenantID = "tenant-b"
	intruder.Note = "must not be saved"
	if err := p.Upsert(ctx, &intruder); !errors.Is(err, steerexclusion.ErrTenantConflict) {
		t.Fatalf("expected ownership refusal, got %v", err)
	}
	a, err := steerexclusion.NewStoreWithPersistence(p)
	if err != nil {
		t.Fatal(err)
	}
	b, err := steerexclusion.NewStoreWithPersistence(p)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for i, store := range []*steerexclusion.Store{a, b} {
		wg.Add(1)
		go func(i int, s *steerexclusion.Store) {
			defer wg.Done()
			row := first
			row.ID = []string{"cp-a", "cp-b"}[i]
			_, err := s.Upsert(row, now)
			errs <- err
		}(i, store)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	rows, err := p.LoadAll(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 {
		t.Fatalf("retained rows=%d want 3", len(rows))
	}
	for _, row := range rows {
		if row.TenantID != "tenant-a" || row.Note != "" {
			t.Fatalf("ownership was overwritten: %+v", row)
		}
	}
}
