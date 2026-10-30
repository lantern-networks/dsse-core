package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/lantern-networks/dsse-core/seatallocation"
)

func TestLicenseReadCannotSeeCaseDistinctTenantAllocation(t *testing.T) {
	declareOperatorTenantForTest(t, "operator")
	mux, _, _, allocations, deps := licenceAdminFixture(t)
	if _, err := allocations.Allocate(seatallocation.Policy{PoolSeats: 20}, "Acme", 7, "operator", "", "now"); err != nil {
		t.Fatal(err)
	}
	read := func(tenant string) []tenantSeatView {
		t.Helper()
		r := httptest.NewRequest(http.MethodGet, "/admin/license", nil)
		r = r.WithContext(context.WithValue(r.Context(), adminIdentityContextKey{}, adminIdentity{TenantID: tenant, Roles: []string{"admin"}, AuthMethod: "admin_session"}))
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("license read status: %d", w.Code)
		}
		var body struct {
			Tenants []tenantSeatView `json:"tenants"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		return body.Tenants
	}
	if rows := read("acme"); len(rows) != 0 {
		t.Fatalf("customer read another tenant's allocation: %#v", rows)
	}
	if _, err := allocations.Allocate(seatallocation.Policy{PoolSeats: 20}, "acme", 11, "operator", "", "now"); err != nil {
		t.Fatal(err)
	}
	if rows := deps.tenantViews(); len(rows) != 2 {
		t.Fatalf("operator view merged tenants: %#v", rows)
	}
	for tenant, seats := range map[string]int{"Acme": 7, "acme": 11} {
		rows := read(tenant)
		if len(rows) != 1 || rows[0].TenantID != tenant || rows[0].Allocated != seats {
			t.Fatalf("tenant %s got wrong allocation: %#v", tenant, rows)
		}
	}
}
