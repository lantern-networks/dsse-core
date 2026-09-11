package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/logs"
)

// tenantModelStoreThatCannotCarry is a tenant-model store that can do everything a handler asks of it EXCEPT
// tell the fleet anything: no ConfigGeneration, no DeletedTenants, no OrderPurge, no PurgeOrders.
//
// It is not a hypothetical. It is the shape the Postgres backend had until 2026-08-18 — the backend the
// deployment documentation names for production — and it is deliberately NOT built by embedding the file store,
// because embedding would inherit the very methods whose absence is the subject.
type tenantModelStoreThatCannotCarry struct{ tenants []adminTenantModel }

func (s *tenantModelStoreThatCannotCarry) Get(context.Context, string) (adminTenantModel, error) {
	return adminTenantModel{}, nil
}

func (s *tenantModelStoreThatCannotCarry) Update(_ context.Context, tenant adminTenantModel, _ string, _ time.Time) (adminTenantModel, error) {
	return tenant, nil
}

func (s *tenantModelStoreThatCannotCarry) List(context.Context) ([]adminTenantModel, error) {
	return s.tenants, nil
}

func (s *tenantModelStoreThatCannotCarry) Put(_ context.Context, tenant adminTenantModel, _ time.Time) (adminTenantModel, error) {
	return tenant, nil
}

func (s *tenantModelStoreThatCannotCarry) Delete(context.Context, string) error { return nil }

// ★★★ ERASING LOCALLY WHILE THE FLEET IS NEVER TOLD IS WORSE THAN REFUSING (2026-08-18).
//
// POST /admin/tenants/{id}/purge recorded the erasure ORDER before acting, on purpose — the handler's own
// comment says "recorded first so that a failure here leaves an order standing rather than a partial erasure
// nobody is going to finish". But it recorded it through an anonymous type assertion whose `ok` was discarded:
//
//	if orderer, ok := tenantModelStore.(interface{ OrderPurge(string, time.Time) }); ok { orderer.OrderPurge(...) }
//
// The Postgres backend satisfied that assertion never. So on a Postgres control plane the order was recorded
// nowhere, the handler erased this node's own copy, and answered 200 with a footprint count — and every other
// node that ever served the tenant kept the customer's data with nothing to tell it otherwise. The operator
// read a successful erasure.
//
// The order is now read back after being placed, and a purge that cannot be carried is refused.
func TestAPurgeIsRefusedWhenTheErasureOrderCannotBeRecorded(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	auth := newAdminAuthStore()
	auth.UpsertPrincipal(adminPrincipal{
		ID: "adm_op", TenantID: "tenant_operator_001", Subject: "sub_op", Email: "op@lab.invalid",
		Roles: []string{"owner"}, IDPID: "keycloak_lab", Status: "active",
		CreatedAt: time.Now().Add(-time.Hour).UTC().Format(time.RFC3339),
	})
	auth.UpsertAPIToken(adminAPIToken{
		ID: "tok_op", TenantID: "tenant_operator_001", Name: "op",
		TokenHash: adminTokenHash(testPurgeOrderOperatorBearer), Roles: []string{"owner"}, Scopes: []string{"*"},
		CreatedByAdminPrincipalID: "adm_op",
		CreatedAt:                 time.Now().Add(-time.Hour).UTC().Format(time.RFC3339),
		ExpiresAt:                 time.Now().Add(time.Hour).UTC().Format(time.RFC3339), Status: "active",
	})

	purge := func(store adminTenantModelRuntimeStore) *httptest.ResponseRecorder {
		t.Helper()
		handler := newServerWithConfig(serverConfig{
			Evaluator:        testEvaluator(),
			Writer:           writer,
			Registry:         connector.NewRegistry(),
			AdminAuth:        auth,
			TenantModelStore: store,
			// ★ Without this the deployment has organizations and no operator, and NOBODY may act across
			// them — deliberate since 2026-08-22. The bearer below belongs to tenant_operator_001.
			OperatorTenantID: "tenant_operator_001",
		})
		req := httptest.NewRequest(http.MethodPost, "/admin/tenants/tenant_terminated/purge",
			strings.NewReader(`{"confirm_tenant_id":"tenant_terminated"}`))
		req.Header.Set("authorization", "Bearer "+testPurgeOrderOperatorBearer)
		req.Header.Set("content-type", "application/json")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}

	// The registry must be able to testify that the tenant is gone (a purge follows a termination), so it lists
	// somebody else.
	cannotCarry := &tenantModelStoreThatCannotCarry{tenants: []adminTenantModel{{TenantID: "tenant_someone_else", Status: "active"}}}
	rec := purge(cannotCarry)
	if rec.Code == http.StatusOK {
		t.Fatalf("a node that cannot record the erasure order erased its own copy and reported success: %s", rec.Body.String())
	}
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected a refusal naming the reason, got HTTP %d %s", rec.Code, rec.Body.String())
	}
	// The refusal has to say what is wrong, or an operator retries it forever.
	if body := rec.Body.String(); !strings.Contains(body, "erasure order") {
		t.Fatalf("the refusal does not name the erasure order, so nobody can act on it: %s", body)
	}

	// ★ THE CONTROL: a store that CAN carry the order must still erase, or this is a lockout rather than a
	// guard. The file store is the one that could carry it all along.
	now := time.Now().UTC()
	carrying := newDurableAdminTenantModelStore(testEvaluator().PolicyBundle, now, t.TempDir()+"/tenant_model.json")
	if _, err := carrying.Put(context.Background(), adminTenantModel{TenantID: "tenant_someone_else", Status: "active"}, now); err != nil {
		t.Fatalf("seed the control registry: %v", err)
	}
	if rec := purge(carrying); rec.Code != http.StatusOK {
		t.Fatalf("the control failed: a store that CAN record the order was refused too (HTTP %d %s) — "+
			"the test would then pass for the wrong reason", rec.Code, rec.Body.String())
	}
	// And the order stands afterwards, which is the whole point of recording it.
	if !tenantPurgeOrderStands(carrying, "tenant_terminated") {
		t.Fatalf("the erasure completed but no order was left standing, so a node that was offline is never told")
	}
}

// tenantModelStoreThatSwallowsTheOrder carries the contract in full and still records nothing: OrderPurge
// accepts and drops it. This is the Postgres store whose INSERT failed, or whose migration 041 never ran —
// and it is invisible to the caller, because OrderPurge returns nothing to check.
type tenantModelStoreThatSwallowsTheOrder struct {
	tenantModelStoreThatCannotCarry
}

func (s *tenantModelStoreThatSwallowsTheOrder) ConfigGeneration() uint64         { return 1 }
func (s *tenantModelStoreThatSwallowsTheOrder) DeletedTenants() []tenantDeletion { return nil }
func (s *tenantModelStoreThatSwallowsTheOrder) OrderPurge(string, time.Time)     {}
func (s *tenantModelStoreThatSwallowsTheOrder) PurgeOrders() []tenantPurgeOrder  { return nil }

// ★ AND THE SAME REFUSAL WHEN THE STORE ACCEPTS THE ORDER AND KEEPS NOTHING (2026-08-18).
//
// The first guard is a type assertion, which only catches a backend that never had the method. It cannot catch
// the case the method exists for: a failed INSERT, or migration 041 never applied. OrderPurge has no error
// return — the file store's signature has none and the two backends must be interchangeable — so the only way
// to know the order was recorded is to look for it afterwards.
func TestAPurgeIsRefusedWhenTheOrderIsAcceptedAndNotKept(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	auth := newAdminAuthStore()
	auth.UpsertPrincipal(adminPrincipal{
		ID: "adm_op2", TenantID: "tenant_operator_001", Subject: "sub_op2", Email: "op2@lab.invalid",
		Roles: []string{"owner"}, IDPID: "keycloak_lab", Status: "active",
		CreatedAt: time.Now().Add(-time.Hour).UTC().Format(time.RFC3339),
	})
	auth.UpsertAPIToken(adminAPIToken{
		ID: "tok_op2", TenantID: "tenant_operator_001", Name: "op2",
		TokenHash: adminTokenHash(testPurgeOrderSwallowedBearer), Roles: []string{"owner"}, Scopes: []string{"*"},
		CreatedByAdminPrincipalID: "adm_op2",
		CreatedAt:                 time.Now().Add(-time.Hour).UTC().Format(time.RFC3339),
		ExpiresAt:                 time.Now().Add(time.Hour).UTC().Format(time.RFC3339), Status: "active",
	})

	store := &tenantModelStoreThatSwallowsTheOrder{
		tenantModelStoreThatCannotCarry{tenants: []adminTenantModel{{TenantID: "tenant_someone_else", Status: "active"}}},
	}
	// It satisfies the contract, so the first guard lets it through — which is the point.
	if _, ok := tenantModelFleetCarrier(store); !ok {
		t.Fatal("this store must satisfy the carrier contract, or it tests the previous guard again rather than this one")
	}
	handler := newServerWithConfig(serverConfig{
		Evaluator: testEvaluator(), Writer: writer, Registry: connector.NewRegistry(),
		AdminAuth: auth, TenantModelStore: store,
		// ★ The bearer below belongs to tenant_operator_001; without this the deployment has organizations
		// and no operator, and erasing one is refused before this test's guard is reached (2026-08-22).
		OperatorTenantID: "tenant_operator_001",
	})
	req := httptest.NewRequest(http.MethodPost, "/admin/tenants/tenant_terminated/purge",
		strings.NewReader(`{"confirm_tenant_id":"tenant_terminated"}`))
	req.Header.Set("authorization", "Bearer "+testPurgeOrderSwallowedBearer)
	req.Header.Set("content-type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code == http.StatusOK {
		t.Fatalf("the order was dropped and the erasure went ahead anyway: %s", rec.Body.String())
	}
	if body := rec.Body.String(); !strings.Contains(body, "was not recorded") {
		t.Fatalf("the refusal must say the order was not recorded, or it is indistinguishable from the other guard: %s", body)
	}
}

const (
	testPurgeOrderOperatorBearer  = "raw-purge-order-operator"
	testPurgeOrderSwallowedBearer = "raw-purge-order-swallowed"
)
