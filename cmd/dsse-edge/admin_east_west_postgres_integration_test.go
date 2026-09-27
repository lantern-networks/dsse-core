package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/eastwestobserve"
	"github.com/lantern-networks/dsse-core/policy"
	_ "github.com/lib/pq"
)

// This opt-in check uses the production PostgreSQL blob adapter. An older CP
// updates another tenant between ordinary Connector Access edits; the final
// edit must retain both tenants and must not persist an invalid request.
func TestEastWestConfirmedEditAcrossPostgresStores(t *testing.T) {
	dsn := os.Getenv("POSTGRES_QUEUE_E2E_DSN")
	if dsn == "" {
		t.Skip("set POSTGRES_QUEUE_E2E_DSN for the PostgreSQL check")
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
	key := fmt.Sprintf("test_east_west_confirmed_%d", time.Now().UnixNano())
	defer db.Exec("DELETE FROM cp_state_blobs WHERE store_key=$1", key)
	openStore := func() *policy.Store {
		t.Helper()
		store := policy.NewStore(nil)
		if err := store.SetRuntimeStatePersister(postgresBlobPersister{db: db, key: key}); err != nil {
			t.Fatal(err)
		}
		return store
	}
	current := openStore()
	stale := openStore()
	observer := openStore()
	observations := eastwestobserve.NewStore()
	observations.Observe("tenant_lab_001", eastwestobserve.SourceAny, "", "app.example.test", "ssh", 22, time.Now())
	handler := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Registry: connector.NewRegistry(),
		AdminAuth: newAdminAuthStore(), PolicyStore: current})
	peerHandler := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Registry: connector.NewRegistry(),
		AdminAuth: newAdminAuthStore(), PolicyStore: stale})
	observerHandler := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Registry: connector.NewRegistry(),
		AdminAuth: newAdminAuthStore(), PolicyStore: observer, EastWestObserveStore: observations})
	post := func(body string, want int) {
		t.Helper()
		rec := doAdmin(t, handler, http.MethodPost, "/admin/east-west", body)
		if rec.Code != want {
			t.Fatalf("POST status=%d want=%d body=%s", rec.Code, want, rec.Body.String())
		}
	}
	post(`{"mode":"partial","rules":[{"id":"old","mode":"deny","destinations":["old.example.test"],"protocols":["ssh"]}],"max_grant_ttl_seconds":60}`, http.StatusOK)

	// This CP was loaded before the first save. Its unrelated tenant edit must
	// merge into the latest shared row rather than replace the first edit.
	enabled, unmatched := true, false
	if err := stale.ApplyEastWestUpdateConfirmed("tenant_other", nil, nil, &enabled, &unmatched); err != nil {
		t.Fatal(err)
	}
	var before, after []byte
	if err := db.QueryRow("SELECT payload FROM cp_state_blobs WHERE store_key=$1", key).Scan(&before); err != nil {
		t.Fatal(err)
	}
	post(`{"mode":"invalid","rules":[{"id":"new","mode":"allow","protocols":["ssh"]}],"max_grant_ttl_seconds":120}`, http.StatusBadRequest)
	if err := db.QueryRow("SELECT payload FROM cp_state_blobs WHERE store_key=$1", key).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatal("invalid edit changed the PostgreSQL authority")
	}
	baselineBundle := doAdmin(t, handler, http.MethodGet, "/admin/config-bundle", "")
	var baseline configBundlePayload
	if baselineBundle.Code != http.StatusOK || json.Unmarshal(baselineBundle.Body.Bytes(), &baseline) != nil {
		t.Fatalf("baseline bundle status=%d body=%s", baselineBundle.Code, baselineBundle.Body.String())
	}
	peerEdit := doAdmin(t, peerHandler, http.MethodPost, "/admin/east-west",
		`{"mode":"full","rules":[{"id":"peer","mode":"deny","destinations":["app.example.test"],"protocols":["ssh"]}],"max_grant_ttl_seconds":90}`)
	if peerEdit.Code != http.StatusOK {
		t.Fatalf("peer edit status=%d body=%s", peerEdit.Code, peerEdit.Body.String())
	}
	observed := doAdmin(t, observerHandler, http.MethodGet, "/admin/east-west/observations", "")
	var inventory struct {
		Observations []struct {
			Covered bool `json:"covered"`
		} `json:"observations"`
	}
	if observed.Code != http.StatusOK || json.Unmarshal(observed.Body.Bytes(), &inventory) != nil ||
		len(inventory.Observations) != 1 || !inventory.Observations[0].Covered {
		t.Fatalf("stale CP observation coverage ignored peer rule: status=%d body=%s", observed.Code, observed.Body.String())
	}
	peerBundleRead := doAdmin(t, handler, http.MethodGet, "/admin/config-bundle", "")
	var peerBundle configBundlePayload
	if peerBundleRead.Code != http.StatusOK || json.Unmarshal(peerBundleRead.Body.Bytes(), &peerBundle) != nil ||
		peerBundle.Generation <= baseline.Generation || peerBundle.TenantConfig == nil ||
		!peerBundle.TenantConfig.EastWestEnabled || peerBundle.TenantConfig.EastWestAllowUnmatched ||
		len(peerBundle.TenantConfig.EastWestRules) != 1 || peerBundle.TenantConfig.EastWestRules[0].ID != "peer" {
		t.Fatalf("other CP bundle missed peer edit: status=%d body=%s", peerBundleRead.Code, peerBundleRead.Body.String())
	}
	peerRead := doAdmin(t, handler, http.MethodGet, "/admin/east-west", "")
	if peerRead.Code != http.StatusOK || !json.Valid(peerRead.Body.Bytes()) {
		t.Fatalf("other CP could not redisplay peer edit: status=%d body=%s", peerRead.Code, peerRead.Body.String())
	}
	var peerStatus struct {
		Mode  string `json:"mode"`
		Rules []struct {
			ID string `json:"id"`
		} `json:"rules"`
		TTL int `json:"max_grant_ttl_seconds"`
	}
	if err := json.Unmarshal(peerRead.Body.Bytes(), &peerStatus); err != nil || peerStatus.Mode != "full" ||
		len(peerStatus.Rules) != 1 || peerStatus.Rules[0].ID != "peer" || peerStatus.TTL != 90 {
		t.Fatalf("other CP displayed stale Connector Access: status=%d body=%s", peerRead.Code, peerRead.Body.String())
	}
	post(`{"mode":"full","rules":[{"id":"new","mode":"allow","protocols":["ssh"]}],"max_grant_ttl_seconds":120}`, http.StatusOK)
	var got struct {
		Mode  string `json:"mode"`
		Rules []struct {
			ID string `json:"id"`
		} `json:"rules"`
		TTL int `json:"max_grant_ttl_seconds"`
	}
	read := doAdmin(t, handler, http.MethodGet, "/admin/east-west", "")
	if read.Code != http.StatusOK || json.Unmarshal(read.Body.Bytes(), &got) != nil ||
		got.Mode != "full" || len(got.Rules) != 1 || got.Rules[0].ID != "new" || got.TTL != 120 {
		t.Fatalf("confirmed edit not redisplayed: status=%d body=%s", read.Code, read.Body.String())
	}
	reloaded := openStore()
	if !reloaded.EastWestIsEnabled("tenant_lab_001") || reloaded.EastWestAllowsUnmatched("tenant_lab_001") ||
		reloaded.EastWestMaxGrantTTL("tenant_lab_001") != 120 || len(reloaded.EastWestRulesFor("tenant_lab_001")) != 1 ||
		reloaded.EastWestRulesFor("tenant_lab_001")[0].ID != "new" || !reloaded.EastWestIsEnabled("tenant_other") ||
		reloaded.EastWestAllowsUnmatched("tenant_other") {
		t.Fatal("PostgreSQL reload lost the confirmed edit or the peer tenant")
	}
	if _, err := db.Exec("DELETE FROM cp_state_blobs WHERE store_key=$1", key); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if unavailable := doAdmin(t, handler, http.MethodGet, "/admin/east-west", ""); unavailable.Code != http.StatusServiceUnavailable {
		t.Fatalf("unreadable shared authority status=%d want=503", unavailable.Code)
	}
}
