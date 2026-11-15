package main

import (
	"context"
	"testing"
	"time"
)

// The Site catalogue's term in the bundle generation, read the way the bundle reads it, while the database's
// primary changes underneath. Measured on a three-region rolling upgrade: the primary moved a -> b -> c -> a,
// the counter read 52 while b led and 19 once a led again, and the generation stood still for every Site write
// that followed — so a created, rotated or deleted Site reached no Edge.
func TestASiteWriteAfterTheOldPrimaryLeadsAgainMovesTheGeneration(t *testing.T) {
	conn := &siteFailureConn{site: siteFailureSeed(), present: true, generation: 14}
	store := siteFailureStore(t, conn)
	read := func(what string) uint64 {
		t.Helper()
		g, err := store.ConfigGenerationChecked(context.Background())
		if err != nil {
			t.Fatalf("%s: %v", what, err)
		}
		return g
	}
	before := read("primary a")
	// A replica is promoted: it carries on from the value the sequence was logged at, ahead of the one in use.
	conn.generation = 46
	onB := read("primary b")
	if onB <= before {
		t.Fatalf("a promoted replica's counter did not move the generation: %d -> %d", before, onB)
	}
	if again := read("primary b, nothing written"); again != onB {
		t.Fatalf("an unchanged counter moved the generation: %d -> %d", onB, again)
	}
	// The old primary leads again, from the value it really had.
	conn.generation = 14
	backOnA := read("primary a again")
	if backOnA <= onB {
		t.Fatalf("a counter that went back froze the generation: %d -> %d", onB, backOnA)
	}
	// And from there every Site write moves it, which is the part that stood still.
	last := backOnA
	for i := 0; i < 5; i++ {
		if _, err := store.Upsert(context.Background(), adminSiteModel{TenantID: "tenant-a", SiteID: "site-a",
			Name: "After"}, time.Now()); err != nil {
			t.Fatal(err)
		}
		g := read("after a write")
		if g <= last {
			t.Fatalf("write %d after the primary returned did not move the generation: %d -> %d", i+1, last, g)
		}
		last = g
	}
	if fallback := store.ConfigGeneration(); fallback != last {
		t.Fatalf("the value a health reader falls back to is not the published one: %d, published %d", fallback, last)
	}
}

// Writers commit in any order, so the value a slower writer drew is smaller than one already read. That is not
// a change of primary and must not be counted as one.
func TestASlowerWriterIsNotAChangeOfPrimary(t *testing.T) {
	store := &postgresAdminSiteStore{}
	if g := store.observeReadGeneration(6); g != 6 {
		t.Fatalf("first read published %d, want 6", g)
	}
	store.observeWrittenGeneration(5)
	if g := store.observeReadGeneration(6); g != 6 {
		t.Fatalf("a slower writer's value moved the generation to %d", g)
	}
	store.observeWrittenGeneration(7)
	if g := store.lastGeneration.Load(); g != 7 {
		t.Fatalf("a committed write did not move the generation: %d", g)
	}
}
