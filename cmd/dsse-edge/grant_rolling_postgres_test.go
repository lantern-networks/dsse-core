package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/grantstore"
	old "github.com/lantern-networks/dsse-core/grantstore/testdata/releasedv031"
	"os"
	"sync"
	"testing"
	"time"
)

// Run only against a dedicated, disposable database: this test owns the actual
// production key names. It never deletes rows in a pre-existing database.
func TestPostgresRollingGrantReleasedWriter(t *testing.T) {
	dsn := os.Getenv("DSSE_ROLLING_TEST_DSN")
	if dsn == "" {
		t.Skip("DSSE_ROLLING_TEST_DSN not set")
	}
	db, e := sql.Open("postgres", dsn)
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	if _, e = db.Exec(`CREATE TABLE cp_state_blobs (store_key TEXT PRIMARY KEY,payload BYTEA NOT NULL,updated_at TIMESTAMPTZ NOT NULL DEFAULT now())`); e != nil {
		t.Fatal("test requires a fresh database:", e)
	}
	defer db.Exec(`DROP TABLE cp_state_blobs`)
	p := postgresGrantPair{db}
	newer := grantstore.NewStore()
	released := old.NewStore()
	if e = newer.SetPersister(grantstore.RollingPersister{Backend: p}); e != nil {
		t.Fatal(e)
	}
	if e = released.SetPersister(postgresBlobPersister{db, "grants"}); e != nil {
		t.Fatal(e)
	}
	now := time.Now().UTC().Truncate(time.Second)
	base := grantstore.Grant{GrantID: "new", TenantID: "tenant", UserID: "user", IdPID: "idp", DeviceID: "device", Issuer: "https://idp.example", ProviderConfigSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Scope: "app:22", AuthTime: now.Format(time.RFC3339)}
	g, e := newer.Mint(base, time.Hour, now)
	if e != nil {
		t.Fatal(e)
	}
	if !released.Valid(g.GrantID, now) {
		t.Fatal("released reader rejected updated writer")
	}
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, e := released.Mint(old.Grant{GrantID: "old", TenantID: "tenant"}, time.Hour, now)
		errs <- e
	}()
	go func() {
		defer wg.Done()
		other := base
		other.GrantID = "new2"
		_, e := newer.Mint(other, time.Hour, now)
		errs <- e
	}()
	wg.Wait()
	close(errs)
	for e := range errs {
		if e != nil {
			t.Fatal(e)
		}
	}
	got, ok := newer.Get("new")
	if !ok || got.Issuer != base.Issuer || got.AuthTime != base.AuthTime || !newer.Valid("new", now) {
		t.Fatal("concurrent old writer erased evidence")
	}
	if _, ok := newer.Get("old"); !ok {
		t.Fatal("lost legacy concurrent write")
	}
	if _, _, e = released.RevokeForTenant("tenant", "new"); e != nil {
		t.Fatal(e)
	}
	if newer.Valid("new", now) {
		t.Fatal("legacy revocation not propagated")
	}
	if _, _, e = newer.RevokeForTenant("tenant", "old"); e != nil {
		t.Fatal(e)
	}
	if released.Valid("old", now) {
		t.Fatal("modern revocation not propagated")
	}
	single := base
	single.GrantID = "single"
	single.AuthenticationRequestID = "request"
	single.ReauthenticationStartedAt = now.Format(time.RFC3339)
	single, e = newer.Mint(single, time.Minute, now)
	if e != nil {
		t.Fatal(e)
	}
	if _, ok := released.Get("single"); ok {
		t.Fatal("single-use exposed to released writer")
	}
	if yes, e := newer.ConsumeAuthenticationRequest(context.Background(), single, now); e != nil || !yes {
		t.Fatalf("consume %v %v", yes, e)
	}
	// Failure after the two-key candidate is built must roll both keys back.
	beforeA, beforeB, e := p.LoadGrantPair(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	e = p.UpdateGrantPair(ctx, func(a, b []byte) ([]byte, []byte, error) { cancel(); return []byte(`{}`), []byte(`{}`), nil })
	if !errors.Is(e, context.Canceled) || !errors.Is(e, blobstore.ErrWriteNotCommitted) {
		t.Fatalf("cancellation classification: %v", e)
	}
	afterA, afterB, e := p.LoadGrantPair(context.Background())
	if e != nil || string(beforeA) != string(afterA) || string(beforeB) != string(afterB) {
		t.Fatal("partial commit")
	}
	var oldRows map[string]old.Grant
	if e = json.Unmarshal(afterA, &oldRows); e != nil {
		t.Fatal(e)
	}
	if _, ok := oldRows["single"]; ok {
		t.Fatal("single-use tombstone exposed")
	}
}
