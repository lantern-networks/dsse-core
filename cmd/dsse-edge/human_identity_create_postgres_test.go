package main

import (
	"context"
	"database/sql"
	"errors"
	"github.com/lantern-networks/dsse-core/humanidentity"
	"github.com/lantern-networks/dsse-core/model"
	"os"
	"reflect"
	"testing"
	"time"
)

func TestPostgresHumanIdentityCreatePreservesSyncedIdentityE2E(t *testing.T) {
	dsn := os.Getenv("POSTGRES_QUEUE_E2E_DSN")
	if dsn == "" {
		t.Skip("POSTGRES_QUEUE_E2E_DSN is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, stmt := range postgresHumanIdentityDirectorySchemaSQL() {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			t.Fatal(err)
		}
	}
	tenant := "create-check-" + time.Now().Format("150405.000000000")
	other := tenant + "-other"
	defer db.ExecContext(context.Background(), "DELETE FROM human_identities WHERE tenant_id IN ($1,$2)", tenant, other)
	var generation uint64
	store := postgresHumanIdentityDirectoryStore{DB: db, gen: &generation}
	now := time.Now().UTC().Truncate(time.Second)
	original, err := store.Upsert(ctx, model.HumanIdentity{ID: "alice", Subject: "synced", Source: "idp", Status: "suspended", Metadata: map[string]any{"keep": "yes"}}, tenant, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Create(ctx, model.HumanIdentity{ID: "alice", Subject: "replacement"}, tenant, now); !errors.Is(err, humanidentity.ErrIdentityExists) {
		t.Fatalf("conflict=%v", err)
	}
	users, err := store.List(ctx, tenant)
	if err != nil || !reflect.DeepEqual(users, []model.HumanIdentity{original}) || generation != 1 {
		t.Fatalf("conflict mutated state: %#v gen=%d err=%v", users, generation, err)
	}
	if _, err := store.Create(ctx, model.HumanIdentity{ID: "alice", Subject: "other"}, other, now); err != nil {
		t.Fatal(err)
	}
	created, err := store.Create(ctx, model.HumanIdentity{ID: "bob", Subject: "bob"}, tenant, now)
	if err != nil {
		t.Fatal(err)
	}
	fresh := postgresHumanIdentityDirectoryStore{DB: db}
	users, err = fresh.List(ctx, tenant)
	if err != nil || !reflect.DeepEqual(users, []model.HumanIdentity{original, created}) || generation != 3 {
		t.Fatalf("readback=%#v gen=%d err=%v", users, generation, err)
	}
	original.Status = "deleted"
	if _, err := store.Upsert(ctx, original, tenant, now); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Create(ctx, model.HumanIdentity{ID: "alice", Subject: "replacement"}, tenant, now); !errors.Is(err, humanidentity.ErrIdentityExists) {
		t.Fatalf("deleted conflict=%v", err)
	}
	users, err = fresh.List(ctx, tenant)
	if err != nil || users[0].Status != "deleted" || generation != 4 {
		t.Fatal("soft removal changed")
	}
}
