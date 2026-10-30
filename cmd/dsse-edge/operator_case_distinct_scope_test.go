package main

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestCaseDistinctOperatorCannotUndoCustomerDelegationOrApproval(t *testing.T) {
	declareOperatorTenantForTest(t, "Acme")
	store, handler := operatorAccessTestHandler(t)
	ctx := context.Background()
	if _, err := store.Put(ctx, adminTenantModel{
		TenantID: "acme", Status: "active", OperatorManaged: false,
		OperatorDelegationWithdrawnByCustomer: true, OperatorElevationRequiresApproval: true,
	}, time.Now()); err != nil {
		t.Fatal(err)
	}
	operator := adminIdentity{PrincipalID: "Adm", TenantID: "Acme", Roles: []string{"super_admin"}, AuthMethod: "admin_session"}
	call := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPut, "/admin/operator-delegation", bytes.NewBufferString(body))
		req.Header.Set("X-Operate-Tenant", "acme")
		req = req.WithContext(context.WithValue(req.Context(), adminIdentityContextKey{}, operator))
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}
	for _, body := range []string{`{"managed":true}`, `{"elevation_requires_approval":false}`} {
		if rec := call(body); rec.Code != http.StatusForbidden {
			t.Fatalf("operator from Acme changed distinct customer acme with %s: HTTP %d %s", body, rec.Code, rec.Body.String())
		}
	}
	got, err := store.Get(ctx, "acme")
	if err != nil {
		t.Fatal(err)
	}
	if got.OperatorManaged || !got.OperatorDelegationWithdrawnByCustomer || !got.OperatorElevationRequiresApproval {
		t.Fatalf("customer's delegation protections changed: %+v", got)
	}
	// The customer remains able to grant its own delegation after withdrawing it.
	self := httptest.NewRequest(http.MethodPut, "/admin/operator-delegation", strings.NewReader(`{"managed":true}`))
	self = self.WithContext(context.WithValue(self.Context(), adminIdentityContextKey{}, adminIdentity{
		PrincipalID: "customer-admin", TenantID: "acme", Roles: []string{"admin"}, AuthMethod: "admin_session",
	}))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, self)
	if rec.Code != http.StatusOK {
		t.Fatalf("customer cannot regrant its own delegation: HTTP %d %s", rec.Code, rec.Body.String())
	}
}

func TestCaseDistinctCustomerIsAnElevationTargetAndPrincipalIDsStayDistinct(t *testing.T) {
	declareOperatorTenantForTest(t, "Acme")
	store, handler := operatorAccessTestHandler(t)
	if _, err := store.Put(context.Background(), adminTenantModel{TenantID: "acme", Status: "active", OperatorManaged: true}, time.Now()); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/admin/operator-elevations", strings.NewReader(`{"minutes":5}`))
	req.Header.Set("X-Operate-Tenant", "acme")
	req = req.WithContext(context.WithValue(req.Context(), adminIdentityContextKey{}, adminIdentity{
		PrincipalID: "Adm", TenantID: "Acme", Roles: []string{"super_admin"}, AuthMethod: "admin_session",
	}))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("case-distinct customer was treated as operator's own tenant: HTTP %d %s", rec.Code, rec.Body.String())
	}
	tenant, err := store.Get(context.Background(), "acme")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if !operatorHasActiveElevation(tenant, "Adm", now) {
		t.Fatal("elevation did not authorize the exact principal")
	}
	if operatorHasActiveElevation(tenant, "adm", now) {
		t.Fatal("case-distinct principal borrowed another principal's elevation")
	}
}
