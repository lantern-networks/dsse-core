package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/assetcatalog"
	"github.com/lantern-networks/dsse-core/connector"
	_ "github.com/lib/pq"
)

// Opt-in real Postgres check: CP A holds an older Store in one process while
// CP B commits an application destination from another process. CP A's next
// ordinary edit must preserve B's destination in the shared row.
func TestSharedApplicationCatalogAcrossPostgresProcesses(t *testing.T) {
	const tenant = "tenant_lab_001"
	dsn := os.Getenv("DSSE_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("set DSSE_TEST_POSTGRES_DSN for the separate-process PostgreSQL check")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Ping(); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS cp_state_blobs (
		store_key text PRIMARY KEY, payload bytea NOT NULL, updated_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		t.Fatal(err)
	}
	key := fmt.Sprintf("test_shared_application_%d", time.Now().UnixNano())
	defer db.Exec("DELETE FROM cp_state_blobs WHERE store_key=$1", key)
	viewer := assetcatalog.NewStore()
	if err := viewer.SetPersister(postgresBlobPersister{db: db, key: key}); err != nil {
		t.Fatal(err)
	}
	handler := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Registry: connector.NewRegistry(),
		AdminAuth: newAdminAuthStore(), OperatorTenantID: tenant, AssetStore: viewer})
	dir := t.TempDir()
	ready, resume := filepath.Join(dir, "ready"), filepath.Join(dir, "resume")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	child := func(stage string) *exec.Cmd {
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestSharedApplicationCatalogPostgresChild$", "-test.v")
		cmd.Env = append(os.Environ(), "DSSE_SHARED_ASSET_CHILD="+stage, "DSSE_SHARED_ASSET_KEY="+key,
			"DSSE_SHARED_ASSET_READY="+ready, "DSSE_SHARED_ASSET_RESUME="+resume)
		return cmd
	}
	first := child("first")
	if err := first.Start(); err != nil {
		t.Fatal(err)
	}
	defer func(cmd *exec.Cmd) { _ = cmd.Process.Kill(); _ = cmd.Wait() }(first)
	for {
		if _, err := os.Stat(ready); err == nil {
			break
		}
		if ctx.Err() != nil {
			t.Fatal("first CP did not save its destination before the deadline")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if out, err := child("second").CombinedOutput(); err != nil {
		t.Fatalf("second CP failed: %v; output=%s", err, out)
	}
	if err := os.WriteFile(resume, []byte("go"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := first.Wait(); err != nil {
		t.Fatalf("stale first CP edit failed: %v", err)
	}
	latest := assetcatalog.NewStore()
	if err := latest.SetPersister(postgresBlobPersister{db: db, key: key}); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"alpha", "beta"} {
		if _, found := latest.GetEndpoint(tenant, "app-"+id); !found {
			t.Fatalf("separate-process CP erased destination %s", id)
		}
	}
	if len(latest.ListGroups(tenant)) != 1 || latest.ConfigGeneration() != 3 {
		t.Fatalf("shared group/generation did not converge: groups=%d generation=%d", len(latest.ListGroups(tenant)), latest.ConfigGeneration())
	}
	var endpoints []assetcatalog.Endpoint
	read := doAdmin(t, handler, http.MethodGet, "/admin/assets/endpoints", "")
	if read.Code != http.StatusOK || json.Unmarshal(read.Body.Bytes(), &endpoints) != nil || len(endpoints) != 2 {
		t.Fatalf("stale CP admin read did not refresh from PostgreSQL: status=%d body=%s", read.Code, read.Body.String())
	}
	bundleRead := doAdmin(t, handler, http.MethodGet, "/admin/config-bundle", "")
	var bundle configBundlePayload
	if bundleRead.Code != http.StatusOK || json.Unmarshal(bundleRead.Body.Bytes(), &bundle) != nil ||
		bundle.Rules == nil || len(bundle.Rules.Endpoints) != 2 || bundle.Generation < 3 {
		t.Fatalf("stale CP Edge bundle did not refresh from PostgreSQL: status=%d body=%s", bundleRead.Code, bundleRead.Body.String())
	}
	if deleted, err := latest.DeleteApplicationEndpoint(tenant, "alpha", false); err != nil || !deleted {
		t.Fatalf("delete alpha: deleted=%v err=%v", deleted, err)
	}
	reloaded := assetcatalog.NewStore()
	if err := reloaded.SetPersister(postgresBlobPersister{db: db, key: key}); err != nil {
		t.Fatal(err)
	}
	_, alpha := reloaded.GetEndpoint(tenant, "app-alpha")
	_, beta := reloaded.GetEndpoint(tenant, "app-beta")
	if alpha || !beta || reloaded.ConfigGeneration() != 4 {
		t.Fatalf("delete/reload lost peer state: alpha=%v beta=%v generation=%d", alpha, beta, reloaded.ConfigGeneration())
	}
}

func TestSharedApplicationCatalogPostgresChild(t *testing.T) {
	stage := os.Getenv("DSSE_SHARED_ASSET_CHILD")
	if stage == "" {
		t.Skip("helper process")
	}
	db, err := sql.Open("postgres", os.Getenv("DSSE_TEST_POSTGRES_DSN"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store := assetcatalog.NewStore()
	if err := store.SetPersister(postgresBlobPersister{db: db, key: os.Getenv("DSSE_SHARED_ASSET_KEY")}); err != nil {
		t.Fatal(err)
	}
	id := "alpha"
	if stage == "second" {
		id = "beta"
	}
	if _, err := store.UpsertApplicationEndpoint(id, assetcatalog.Endpoint{
		TenantID: "tenant_lab_001", Alias: id, Kind: assetcatalog.KindNetwork, Address: id + ".example.test",
	}, false); err != nil {
		t.Fatal(err)
	}
	if stage != "first" {
		return
	}
	if err := os.WriteFile(os.Getenv("DSSE_SHARED_ASSET_READY"), []byte("ready"), 0o600); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat(os.Getenv("DSSE_SHARED_ASSET_RESUME")); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the first CP was not resumed")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, err := store.UpsertGroup(assetcatalog.Group{TenantID: "tenant_lab_001", Alias: "operators"}); err != nil {
		t.Fatal(err)
	}
}
