package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/appcatalog"
	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/policy"
)

type policyStoreChangingDuringBundle struct {
	*policy.Store
	changeAfterSnapshot atomic.Bool
}

func (store *policyStoreChangingDuringBundle) SnapshotTenantConfig(tenant string) policy.TenantConfigBundle {
	cfg := store.Store.SnapshotTenantConfig(tenant)
	if store.changeAfterSnapshot.CompareAndSwap(true, false) {
		store.Store.SetEastWestAllowUnmatched(tenant, true)
	}
	return cfg
}

func TestPolicyBundleRejectsConcurrentEastWestPostureMutation(t *testing.T) {
	const tenant = "tenant_lab_001"
	const token = "synthetic-policy-generation-token"
	store := &policyStoreChangingDuringBundle{Store: policy.NewStore(nil)}
	store.SetEastWestEnabled(tenant, true)
	store.SetEastWestAllowUnmatched(tenant, false)
	auth := newAdminAuthStore()
	auth.UpsertPrincipal(adminPrincipal{ID: "operator", TenantID: tenant, Roles: []string{"admin"}, Status: "active"})
	auth.UpsertAPIToken(adminAPIToken{ID: "operator", TenantID: tenant, TokenHash: adminTokenHash(token),
		Roles: []string{"admin"}, Scopes: []string{"admin.policy.read"}, CreatedByAdminPrincipalID: "operator",
		Status: "active", ExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339)})
	handler := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Registry: connector.NewRegistry(),
		OperatorTenantID: tenant, AdminAuth: auth, ApplicationCatalogStore: appcatalog.NewStore(), PolicyStore: store})
	get := func() *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/admin/config-bundle", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}
	store.changeAfterSnapshot.Store(true)
	if got := get(); got.Code != http.StatusServiceUnavailable || !strings.Contains(got.Body.String(), "retry") {
		t.Fatalf("mixed-generation bundle status=%d body=%s", got.Code, got.Body.String())
	}
	got := get()
	if got.Code != http.StatusOK {
		t.Fatalf("stable bundle status=%d body=%s", got.Code, got.Body.String())
	}
	var bundle configBundlePayload
	if err := json.Unmarshal(got.Body.Bytes(), &bundle); err != nil {
		t.Fatal(err)
	}
	if bundle.TenantConfig == nil || !bundle.TenantConfig.EastWestEnabled || !bundle.TenantConfig.EastWestAllowUnmatched {
		t.Fatalf("stable bundle lost partial posture: %+v", bundle.TenantConfig)
	}
}
