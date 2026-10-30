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
	"github.com/lantern-networks/dsse-core/humanidentity"
	"github.com/lantern-networks/dsse-core/model"
)

func TestPostgresTenantFleetHistoryCheckedReadReportsDatabaseFailure(t *testing.T) {
	db, err := sql.Open("postgres", "host=127.0.0.1 port=1 sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	store := &postgresAdminTenantModelStore{db: db}
	if _, err := store.DeletedTenantsChecked(context.Background()); err == nil {
		t.Fatal("database failure became empty tenant deletion history")
	}
	if _, err := store.PurgeOrdersChecked(context.Background()); err == nil {
		t.Fatal("database failure became empty tenant purge orders")
	}
}

type failingBundleTenantList struct{ *adminTenantModelStore }

func (*failingBundleTenantList) List(context.Context) ([]adminTenantModel, error) {
	return nil, errors.New("tenant authority unavailable")
}

type failingBundleFleetRead struct {
	*adminTenantModelStore
	failDeletions bool
	failOrders    bool
}

func (store *failingBundleFleetRead) DeletedTenantsChecked(context.Context) ([]tenantDeletion, error) {
	if store.failDeletions {
		return nil, errors.New("tenant deletion authority unavailable")
	}
	return store.adminTenantModelStore.DeletedTenants(), nil
}

func (store *failingBundleFleetRead) PurgeOrdersChecked(context.Context) ([]tenantPurgeOrder, error) {
	if store.failOrders {
		return nil, errors.New("tenant purge authority unavailable")
	}
	return store.adminTenantModelStore.PurgeOrders(), nil
}

type changingBundleTenantList struct {
	*adminTenantModelStore
	changeAfterList atomic.Bool
	extraGeneration atomic.Uint64
}

func (store *changingBundleTenantList) ConfigGeneration() uint64 {
	return store.adminTenantModelStore.ConfigGeneration() + store.extraGeneration.Load()
}

func (store *changingBundleTenantList) List(ctx context.Context) ([]adminTenantModel, error) {
	models, err := store.adminTenantModelStore.List(ctx)
	if store.changeAfterList.CompareAndSwap(true, false) {
		store.extraGeneration.Add(1)
	}
	return models, err
}

type changingBundleDirectoryList struct {
	*humanidentity.HumanIdentityDirectoryStore
	changeAfterList atomic.Bool
	extraGeneration atomic.Uint64
}

func (store *changingBundleDirectoryList) ConfigGeneration() uint64 {
	return store.HumanIdentityDirectoryStore.ConfigGeneration() + store.extraGeneration.Load()
}

func (store *changingBundleDirectoryList) List(ctx context.Context, tenant string, options ...humanidentity.HumanIdentityDirectoryListOptions) ([]model.HumanIdentity, error) {
	identities, err := store.HumanIdentityDirectoryStore.List(ctx, tenant, options...)
	if store.changeAfterList.CompareAndSwap(true, false) {
		store.extraGeneration.Add(1)
	}
	return identities, err
}

type failingBundleDirectoryList struct {
	*humanidentity.HumanIdentityDirectoryStore
	failPeople   bool
	failPolicies bool
}

func (store *failingBundleDirectoryList) List(ctx context.Context, tenant string, options ...humanidentity.HumanIdentityDirectoryListOptions) ([]model.HumanIdentity, error) {
	if store.failPeople {
		return nil, errors.New("people authority unavailable")
	}
	return store.HumanIdentityDirectoryStore.List(ctx, tenant, options...)
}

func (store *failingBundleDirectoryList) ListSourcePolicies(ctx context.Context, tenant string) ([]humanidentity.HumanIdentitySourcePolicy, error) {
	if store.failPolicies {
		return nil, errors.New("source-policy authority unavailable")
	}
	return store.HumanIdentityDirectoryStore.ListSourcePolicies(ctx, tenant)
}

func TestConfigBundleRefusesIncompleteAuthorityReads(t *testing.T) {
	const tenant = "operator"
	const token = "synthetic-config-bundle-authority-token"
	for _, tc := range []struct {
		name         string
		failTenants  bool
		failPeople   bool
		failPolicies bool
	}{
		{name: "tenant enumeration", failTenants: true},
		{name: "people directory", failPeople: true},
		{name: "directory source policies", failPolicies: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			auth := newAdminAuthStore()
			auth.UpsertPrincipal(adminPrincipal{ID: "operator", TenantID: tenant, Roles: []string{"admin"}, Status: "active"})
			auth.UpsertAPIToken(adminAPIToken{ID: "operator", TenantID: tenant, TokenHash: adminTokenHash(token),
				Roles: []string{"admin"}, Scopes: []string{"admin.policy.read"}, CreatedByAdminPrincipalID: "operator",
				Status: "active", ExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339)})
			var tenantStore adminTenantModelRuntimeStore = newAdminTenantModelStore(model.PolicyBundle{}, time.Now())
			if tc.failTenants {
				tenantStore = &failingBundleTenantList{tenantStore.(*adminTenantModelStore)}
			}
			directory := &failingBundleDirectoryList{
				HumanIdentityDirectoryStore: humanidentity.NewHumanIdentityDirectoryStore(),
				failPeople:                  tc.failPeople, failPolicies: tc.failPolicies,
			}
			handler := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Registry: connector.NewRegistry(),
				OperatorTenantID: tenant, AdminAuth: auth, TenantModelStore: tenantStore, HumanIdentities: directory})
			req := httptest.NewRequest(http.MethodGet, "/admin/config-bundle", nil)
			req.Header.Set("Authorization", "Bearer "+token)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != http.StatusServiceUnavailable {
				t.Fatalf("incomplete authority read published a bundle: status=%d body=%s", rec.Code, rec.Body.String())
			}
		})
	}
}

func TestConfigBundleRefusesConcurrentTenantAndDirectoryChange(t *testing.T) {
	const tenant = "operator"
	const token = "synthetic-config-bundle-concurrent-token"
	for _, source := range []string{"tenant catalog", "people directory"} {
		t.Run(source, func(t *testing.T) {
			auth := newAdminAuthStore()
			auth.UpsertPrincipal(adminPrincipal{ID: "operator", TenantID: tenant, Roles: []string{"admin"}, Status: "active"})
			auth.UpsertAPIToken(adminAPIToken{ID: "operator", TenantID: tenant, TokenHash: adminTokenHash(token),
				Roles: []string{"admin"}, Scopes: []string{"admin.policy.read"}, CreatedByAdminPrincipalID: "operator",
				Status: "active", ExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339)})
			tenants := &changingBundleTenantList{adminTenantModelStore: newAdminTenantModelStore(model.PolicyBundle{}, time.Now())}
			directory := &changingBundleDirectoryList{HumanIdentityDirectoryStore: humanidentity.NewHumanIdentityDirectoryStore()}
			handler := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Registry: connector.NewRegistry(),
				OperatorTenantID: tenant, AdminAuth: auth, TenantModelStore: tenants, HumanIdentities: directory})
			if source == "tenant catalog" {
				tenants.changeAfterList.Store(true)
			} else {
				directory.changeAfterList.Store(true)
			}
			get := func() *httptest.ResponseRecorder {
				t.Helper()
				req := httptest.NewRequest(http.MethodGet, "/admin/config-bundle", nil)
				req.Header.Set("Authorization", "Bearer "+token)
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, req)
				return rec
			}
			if got := get(); got.Code != http.StatusServiceUnavailable {
				t.Fatalf("concurrent %s change was published under a new generation: status=%d", source, got.Code)
			}
			if got := get(); got.Code != http.StatusOK {
				t.Fatalf("stable %s retry failed: status=%d", source, got.Code)
			}
		})
	}
}

func TestConfigBundleRefusesUnavailableTenantFleetHistory(t *testing.T) {
	const tenant = "operator"
	const token = "synthetic-config-bundle-fleet-history-token"
	for _, source := range []string{"deletions", "purge orders"} {
		t.Run(source, func(t *testing.T) {
			auth := newAdminAuthStore()
			auth.UpsertPrincipal(adminPrincipal{ID: "operator", TenantID: tenant, Roles: []string{"admin"}, Status: "active"})
			auth.UpsertAPIToken(adminAPIToken{ID: "operator", TenantID: tenant, TokenHash: adminTokenHash(token),
				Roles: []string{"admin"}, Scopes: []string{"admin.policy.read"}, CreatedByAdminPrincipalID: "operator",
				Status: "active", ExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339)})
			store := &failingBundleFleetRead{adminTenantModelStore: newAdminTenantModelStore(model.PolicyBundle{}, time.Now()),
				failDeletions: source == "deletions", failOrders: source == "purge orders"}
			handler := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Registry: connector.NewRegistry(),
				OperatorTenantID: tenant, AdminAuth: auth, TenantModelStore: store})
			req := httptest.NewRequest(http.MethodGet, "/admin/config-bundle", nil)
			req.Header.Set("Authorization", "Bearer "+token)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != http.StatusServiceUnavailable {
				t.Fatalf("%s unreadable but bundle published: status=%d", source, rec.Code)
			}
		})
	}
}
