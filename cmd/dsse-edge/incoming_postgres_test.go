package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/policy"
)

// Opt-in real PostgreSQL check. A private schema keeps this test away from a
// caller's existing admin_runtime_state row even when a test DB is reused.
func TestIncomingPostgresUnrelatedControlPlaneWriteKeepsConfirmedRule(t *testing.T) {
	dsn := os.Getenv("DSSE_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("set DSSE_TEST_POSTGRES_DSN for a real PostgreSQL check")
	}
	u, err := url.Parse(dsn)
	if err != nil || u.Scheme == "" {
		t.Skip("this isolated-schema test requires a PostgreSQL URL DSN")
	}
	admin, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	schema := fmt.Sprintf("incoming_%d_%d", os.Getpid(), time.Now().UnixNano())
	if _, err := admin.Exec(`CREATE SCHEMA "` + schema + `"`); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := admin.Exec(`DROP SCHEMA "` + schema + `" CASCADE`); err != nil {
			t.Errorf("cleanup test schema: %v", err)
		}
	}()
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	db, err := newCPStateBlobDB(u.String(), "../../migrations", true)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	p := postgresBlobPersister{db: db, key: "admin_runtime_state"}
	one, two := policy.NewStore(nil), policy.NewStore(nil)
	for _, store := range []*policy.Store{one, two} {
		if err := store.SetRuntimeStatePersister(p); err != nil {
			t.Fatal(err)
		}
	}
	tenant := testEvaluator().PolicyBundle.TenantID
	if err := one.SetServerInitiatedEnabledConfirmed(tenant, true); err != nil {
		t.Fatal(err)
	}
	if _, err := one.MutateLegacyExceptionConfirmed(tenant, "rule", func(row model.LegacyException) (model.LegacyException, error) {
		row.BusinessOwner, row.ExpiresAt, row.Status = "owner", "2030-01-01T00:00:00Z", "active"
		row.ServiceFamily, row.Protocol, row.Port = "tcp", "tcp", 8443
		return row, nil
	}); err != nil {
		t.Fatal(err)
	}
	// The second CP loaded before either incoming write. This ordinary, unrelated
	// setting change must not write its stale empty incoming maps over the first CP.
	two.SetEastWestEnabled(tenant, true)
	if err := two.RefreshSharedRuntime(); err != nil || !two.ServerInitiatedEnabledFor(tenant) || len(two.LegacyExceptionsFor(tenant)) != 1 {
		t.Fatalf("unrelated CP save erased incoming policy: %v", err)
	}
	fresh := policy.NewStore(nil)
	if err := fresh.SetRuntimeStatePersister(p); err != nil {
		t.Fatal(err)
	}
	if !fresh.ServerInitiatedEnabledFor(tenant) || len(fresh.LegacyExceptionsFor(tenant)) != 1 {
		t.Fatal("PostgreSQL reload lost incoming policy")
	}
	raw, err := p.Load()
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		EastWest map[string]bool `json:"east_west_enabled"`
	}
	if err := json.Unmarshal(raw, &document); err != nil || !document.EastWest[tenant] {
		t.Fatalf("unrelated CP write did not persist: %v", err)
	}
}
