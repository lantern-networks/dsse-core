package main

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/connector"
)

func TestPostgresSiteCheckedGenerationDoesNotHideReadFailure(t *testing.T) {
	db, err := sql.Open("postgres", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	sites := &postgresAdminSiteStore{db: db}
	sites.lastGeneration.Store(7)
	if cached := sites.ConfigGeneration(); cached != 7 {
		t.Fatalf("legacy health reader lost cached generation: %d", cached)
	}
	if _, err := sites.ConfigGenerationChecked(context.Background()); err == nil {
		t.Fatal("bundle issuer treated an unavailable database as cached generation 7")
	}
}

type failingCheckedSiteGeneration struct {
	adminSiteStore
	calls  atomic.Int32
	failAt atomic.Int32
}

func (s *failingCheckedSiteGeneration) ConfigGenerationChecked(context.Context) (uint64, error) {
	if call := s.calls.Add(1); call == s.failAt.Load() {
		return 0, errors.New("site generation authority unavailable")
	}
	return s.adminSiteStore.ConfigGeneration(), nil
}

func TestConfigBundleRefusesUnavailableSiteGenerationAndRecovers(t *testing.T) {
	const tenant = "operator"
	const token = "synthetic-site-generation-token"
	for _, tc := range []struct {
		name   string
		path   string
		failAt int32
	}{
		{name: "bundle initial generation", path: "/admin/config-bundle", failAt: 1},
		{name: "bundle final generation", path: "/admin/config-bundle", failAt: 2},
		{name: "fleet current generation", path: "/admin/fleet/config-status", failAt: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			auth := newAdminAuthStore()
			auth.UpsertPrincipal(adminPrincipal{ID: tenant, TenantID: tenant, Roles: []string{"admin"}, Status: "active"})
			auth.UpsertAPIToken(adminAPIToken{ID: tenant, TenantID: tenant, TokenHash: adminTokenHash(token),
				Roles: []string{"admin"}, Scopes: []string{"admin.policy.read"}, CreatedByAdminPrincipalID: tenant,
				Status: "active", ExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339)})
			sites := &failingCheckedSiteGeneration{adminSiteStore: newDurableAdminSiteStore(t.TempDir() + "/sites.json")}
			sites.failAt.Store(tc.failAt)
			handler := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Registry: connector.NewRegistry(),
				OperatorTenantID: tenant, AdminAuth: auth, SiteStore: sites,
				FleetConfigStatus: newFleetConfigStatusStore(time.Second)})
			get := func() *httptest.ResponseRecorder {
				t.Helper()
				req := httptest.NewRequest(http.MethodGet, tc.path, nil)
				req.Header.Set("Authorization", "Bearer "+token)
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, req)
				return rec
			}
			if got := get(); got.Code != http.StatusServiceUnavailable {
				t.Fatalf("site generation read failure published authority status %d", got.Code)
			}
			sites.failAt.Store(0)
			if got := get(); got.Code != http.StatusOK {
				t.Fatalf("site generation recovery did not restore the route: status %d", got.Code)
			}
		})
	}
}
