package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

func trustDistributionPostgresFixture(t *testing.T) (*tenantTrustDistributor, *tenantTransportAuthority, *cpLeaderElector, *cpLeaderElector) {
	t.Helper()
	dsn := os.Getenv("POSTGRES_QUEUE_E2E_DSN")
	if dsn == "" {
		t.Skip("POSTGRES_QUEUE_E2E_DSN not set")
	}
	base, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { base.Close() })
	schema := fmt.Sprintf("distribution_term_%d", time.Now().UnixNano())
	if _, err := base.Exec("CREATE SCHEMA " + schema); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { base.Exec("DROP SCHEMA " + schema + " CASCADE") })
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	query := u.Query()
	query.Set("search_path", schema)
	u.RawQuery = query.Encode()
	t.Setenv("POSTGRES_QUEUE_E2E_DSN", u.String())
	a, b := postgresFailureElectors(t)
	db, err := sql.Open("postgres", os.Getenv("POSTGRES_QUEUE_E2E_DSN"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS cp_state_blobs(store_key text PRIMARY KEY,payload bytea NOT NULL,updated_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		t.Fatal(err)
	}
	for _, schema := range [][]string{postgresObservedExclusionSchemaSQL(), postgresObservedTrustTelemetrySchemaSQL(), postgresObservedRecoveryNameSchemaSQL(), postgresObservedRecoveryTargetSchemaSQL(), postgresObservedInterceptionRefusalsSchemaSQL(), postgresObservedAgentPolicyKeysSchemaSQL()} {
		for _, sql := range schema {
			if _, err := db.Exec(sql); err != nil {
				t.Fatal(err)
			}
		}
	}
	guard, err := os.ReadFile("../../migrations/047_pki_history_write_guard.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(string(guard)); err != nil {
		t.Fatal(err)
	}
	d, tr := trustDistributorFixture(t)
	if _, err := tr.EnsureCA("tenant_b", "b.dsse.invalid"); err != nil {
		t.Fatal(err)
	}
	authority := postgresBlobPersister{db: db, key: "tenant_transport_authorities"}
	if err := authority.Save(encodeAuthoritySnapshot(tr.cas)); err != nil {
		t.Fatal(err)
	}
	d.store = postgresBlobPersister{db: db, key: "tenant_trust_distributions"}
	d.config.ObservedExclusions = &postgresObservedExclusionStore{db: db}
	oldE, oldCP := cpLeaderElectorInstance, edgeIsControlPlane
	cpLeaderElectorInstance = a
	edgeIsControlPlane = true
	t.Cleanup(func() { cpLeaderElectorInstance = oldE; edgeIsControlPlane = oldCP })
	a.tick()
	if !a.IsLeader() {
		t.Fatal("initial leader absent")
	}
	return d, tr, a, b
}

func TestPostgresTrustDistributionMaterialRequestKeepsTerm(t *testing.T) {
	d, tr, a, b := trustDistributionPostgresFixture(t)
	publishTrustForTest(t, d, tr)
	before, err := d.store.Load()
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	registerTenantTransportMaterialRoute(mux, tr, nil, nil, "test", time.Hour, nil, true, d)
	req := httptest.NewRequest("POST", "/tenant-edge-material", nil)
	req.Header.Set("Authorization", "Bearer test")
	req.Body = &enrolmentTermBody{Reader: strings.NewReader(`{}`), before: func() {
		a.release()
		b.tick()
		if !b.IsLeader() {
			t.Fatal("no peer")
		}
		b.release()
		a.tick()
	}}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("previous term returned material: %d", rec.Code)
	}
	after, err := d.store.Load()
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("old request changed distribution", err)
	}
}

func TestPostgresTrustDistributionErasureKeepsTerm(t *testing.T) {
	d, tr, a, b := trustDistributionPostgresFixture(t)
	publishTrustForTest(t, d, tr)
	before, err := d.store.Load()
	if err != nil {
		t.Fatal(err)
	}
	stale := captureCPWriteLease(context.Background())
	a.release()
	b.tick()
	if !b.IsLeader() {
		t.Fatal("no peer")
	}
	b.release()
	a.tick()
	result := adminTenantPurgeResult{TenantID: "tenant_a"}
	(adminTenantExtraStores{TenantTrustDistributions: d}).eraseContext(stale, &result)
	if len(result.Failures) != 1 || len(result.Erased) != 0 {
		t.Fatalf("old request erased trust: %+v", result)
	}
	after, err := d.store.Load()
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("old erasure changed distribution", err)
	}
	result = adminTenantPurgeResult{TenantID: "tenant_a"}
	(adminTenantExtraStores{TenantTrustDistributions: d}).eraseContext(captureCPWriteLease(context.Background()), &result)
	if len(result.Failures) != 0 || len(result.Erased) != 1 {
		t.Fatal("current erasure failed", result)
	}
	after, err = d.store.Load()
	if err != nil {
		t.Fatal(err)
	}
	oldState, _ := decodeTenantTrustDistributions(before)
	state, err := decodeTenantTrustDistributions(after)
	if err != nil || state.SerialFloor != oldState.SerialFloor || len(state.Tenants) != 1 {
		t.Fatal("floor/peer lost", err)
	}
	if _, ok := state.Tenants["tenant_b"]; !ok {
		t.Fatal("foreign tenant removed")
	}
}

func TestPostgresTrustDistributionStandbyAbsentAndRestart(t *testing.T) {
	d, tr, a, b := trustDistributionPostgresFixture(t)
	if n, err := d.RemoveTenantContext(captureCPWriteLease(context.Background()), "missing"); err != nil || n != 0 {
		t.Fatal("absent erasure", n, err)
	}
	clock := d.now
	d.now = func() time.Time {
		var isolation string
		if err := a.conn.QueryRowContext(context.Background(), "SHOW transaction_isolation").Scan(&isolation); err != nil || isolation != "serializable" {
			t.Fatal("publication lost isolation", isolation, err)
		}
		return clock()
	}
	first := publishTrustForTest(t, d, tr)
	before, err := d.store.Load()
	if err != nil {
		t.Fatal(err)
	}
	a.release()
	b.tick()
	if !b.IsLeader() {
		t.Fatal("no peer")
	}
	if _, ok := d.For("tenant_a"); ok {
		t.Fatal("standby published signed trust")
	}
	after, err := d.store.Load()
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("standby changed distribution", err)
	}
	b.release()
	a.tick()
	restarted := &tenantTrustDistributor{store: d.store, config: d.config, now: func() time.Time { return time.Unix(1, 0) }}
	env, ok := restarted.For("tenant_b")
	if !ok {
		t.Fatal("restart unavailable")
	}
	want, _ := json.Marshal(first["tenant_b"].Envelope)
	got, _ := json.Marshal(env)
	if !bytes.Equal(want, got) {
		t.Fatal("restart re-signed unchanged trust")
	}
}

func TestCanonicalTrustUnavailableDoesNotFallBackOnAdminPage(t *testing.T) {
	d, tr := trustDistributorFixture(t)
	old, oldTrust := perTenantTrustBundlesForAdmin, transportTrust
	transportTrust = nil
	defer func() { perTenantTrustBundlesForAdmin = old; transportTrust = oldTrust }()
	config := serverConfig{AgentPolicySigner: d.config.AgentPolicySigner, TrustBundleCAPEM: tr.cas["tenant_a"].CACertPEM, TrustBundleSerial: 12, DistributedTenantTrust: &tenantTrustDistributionCache{}}
	perTenantTrustBundlesForAdmin = newPerTenantTrustBundles(config, "tenant_a")
	mux := http.NewServeMux()
	registerTransportTrustAnchorsEndpoint(mux, config, "tenant_a", func(_ string, h http.HandlerFunc) http.HandlerFunc { return h }, func(*http.Request, string, string, string, map[string]any) {})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest("GET", "/admin/transport-trust-anchors", nil))
	if rec.Code != 503 {
		t.Fatalf("screen substituted fallback anchors: %d", rec.Code)
	}
}
