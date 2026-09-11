package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/model"
)

// ★★★ THE ROUTE ITSELF, IN BOTH DIRECTIONS (2026-08-20, the operator's decision).
//
// The rule lives in one function so the customer's screen and the write cannot disagree; this asserts the
// WRITE, because a rule proven only through its helper is the shape this repository has already paid for.
//
// Onboarding still works — an organization with no administrator of its own has no other way to be set up —
// and the reopen is refused. The asymmetry is between the directions, not between the parties, which is what
// makes this a delegation rather than a permission the holder can re-grant to itself.
func TestAnOperatorCannotReopenADelegationTheCustomerWithdrew(t *testing.T) {
	declareOperatorTenantForTest(t, "tenant_operator_001")
	store, handler := operatorAccessTestHandler(t)
	if _, err := store.Put(context.Background(), adminTenantModel{TenantID: "tenant_northwind",
		DisplayName: "Northwind", Status: "active"}, time.Now()); err != nil {
		t.Fatal(err)
	}

	put := func(as adminIdentity, operateTenant string, body map[string]any) *httptest.ResponseRecorder {
		blob, _ := json.Marshal(body)
		req := httptest.NewRequest(http.MethodPut, "/admin/operator-delegation", bytes.NewReader(blob))
		if operateTenant != "" {
			req.Header.Set("X-Operate-Tenant", operateTenant)
		}
		req = req.WithContext(context.WithValue(req.Context(), adminIdentityContextKey{}, as))
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}
	operator := adminIdentity{PrincipalID: "adm_operator", TenantID: "tenant_operator_001",
		Roles: []string{"super_admin"}, AuthMethod: "admin_session"}
	theirAdmin := adminIdentity{PrincipalID: "adm_nw", TenantID: "tenant_northwind",
		Roles: []string{"admin"}, AuthMethod: "admin_session"}

	// 1. Onboarding: the operator sets it for an organization that has never withdrawn anything.
	if rec := put(operator, "tenant_northwind", map[string]any{"managed": true}); rec.Code != http.StatusOK {
		t.Fatalf("the operator cannot set the delegation at onboarding (%d %s) — an organization with no "+
			"administrator of its own would have no path at all", rec.Code, rec.Body.String())
	}

	// 2. The organization withdraws it.
	if rec := put(theirAdmin, "", map[string]any{"managed": false}); rec.Code != http.StatusOK {
		t.Fatalf("the organization cannot withdraw its own delegation (%d %s)", rec.Code, rec.Body.String())
	}

	// 3. ★ The operator tries to turn it back on.
	rec := put(operator, "tenant_northwind", map[string]any{"managed": true})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("the operator reopened what the customer closed (HTTP %d %s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "withdrew this delegation itself") {
		t.Fatalf("the refusal does not say why, so nobody reading it knows what to do: %s", rec.Body.String())
	}

	// 4. And it is still off — a refusal that leaves the value changed is worse than one that fails.
	after, err := store.Get(context.Background(), "tenant_northwind")
	if err != nil {
		t.Fatalf("the organization vanished: %v", err)
	}
	if after.OperatorManaged {
		t.Fatal("the write was refused and the delegation is on anyway")
	}

	// 5. The customer can grant it again, and that clears the lock.
	if rec := put(theirAdmin, "", map[string]any{"managed": true}); rec.Code != http.StatusOK {
		t.Fatalf("the organization cannot re-grant its own delegation (%d %s)", rec.Code, rec.Body.String())
	}
	back, _ := store.Get(context.Background(), "tenant_northwind")
	if !back.OperatorManaged || back.OperatorDelegationWithdrawnByCustomer {
		t.Fatalf("re-granting did not return the organization to the ordinary shape: %+v", back)
	}
}

// ★ AND THE SAME ACT ONE FIELD OVER: clearing the approval requirement is reopening a door the customer shut.
func TestAnOperatorCannotClearTheCustomersApprovalRequirement(t *testing.T) {
	declareOperatorTenantForTest(t, "tenant_operator_001")
	store, handler := operatorAccessTestHandler(t)
	if _, err := store.Put(context.Background(), adminTenantModel{TenantID: "tenant_northwind", Status: "active",
		OperatorManaged: true, OperatorElevationRequiresApproval: true}, time.Now()); err != nil {
		t.Fatal(err)
	}

	blob, _ := json.Marshal(map[string]any{"elevation_requires_approval": false})
	req := httptest.NewRequest(http.MethodPut, "/admin/operator-delegation", bytes.NewReader(blob))
	req.Header.Set("X-Operate-Tenant", "tenant_northwind")
	req = req.WithContext(context.WithValue(req.Context(), adminIdentityContextKey{}, adminIdentity{
		PrincipalID: "adm_operator", TenantID: "tenant_operator_001",
		Roles: []string{"super_admin"}, AuthMethod: "admin_session"}))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("an operator switched off the approval that exists to be applied to them (HTTP %d %s)",
			rec.Code, rec.Body.String())
	}
	after, _ := store.Get(context.Background(), "tenant_northwind")
	if !after.OperatorElevationRequiresApproval {
		t.Fatal("the write was refused and the requirement is gone anyway")
	}
}

// operatorAccessTestHandler stands up just the envelope routes over a file-backed tenant model, with the admin
// wrapper passing straight through — the permission layer is asserted elsewhere and mixing the two here would
// hide which one refused.
func operatorAccessTestHandler(t *testing.T) (*adminTenantModelStore, http.Handler) {
	t.Helper()
	store := newAdminTenantModelStore(model.PolicyBundle{TenantID: "tenant_reference_lab"}, time.Now())
	mux := http.NewServeMux()
	registerOperatorAccessRoutes(mux, func(_ string, h http.HandlerFunc) http.HandlerFunc { return h },
		store, "", decision.Evaluator{PolicyBundle: model.PolicyBundle{TenantID: "tenant_reference_lab"}},
		nil, nil, "tenant_operator_001", func(id string) string { return id })
	return store, mux
}

// ★★★ AND THE READ THE SCREEN ACTUALLY CALLS MUST CARRY IT (2026-08-20, measured live).
//
// console/operatoraccess.js switches the customer's sentence on `data.operator_may_enable === false`, and the
// key lived only on the PUT response. So the strict comparison was never true and the organization was always
// shown the weaker sentence — including after a withdrawal, when the stronger one had just become true. The
// point of that field is that the screen asks the guard instead of keeping a sentence by hand; it was asking a
// guard that only answered when the customer wrote something.
func TestTheOperatorAccessReadCarriesWhatTheScreenSwitchesOn(t *testing.T) {
	store, handler := operatorAccessTestHandler(t)
	if _, err := store.Put(context.Background(), adminTenantModel{TenantID: "tenant_northwind", Status: "active",
		OperatorDelegationWithdrawnByCustomer: true}, time.Now()); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/admin/operator-access", nil)
	req = req.WithContext(context.WithValue(req.Context(), adminIdentityContextKey{}, adminIdentity{
		PrincipalID: "adm_nw", TenantID: "tenant_northwind", Roles: []string{"admin"},
		AuthMethod: "admin_session"}))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("the customer cannot read its own operator access record: %d %s", rec.Code, rec.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	value, present := body["operator_may_enable"]
	if !present {
		t.Fatal("the read does not carry operator_may_enable, so the screen's promise falls through to the " +
			"weaker sentence no matter what the guard says")
	}
	if value != false {
		t.Fatalf("the organization withdrew its delegation and the read says the operator may re-enable it: %v",
			value)
	}
}
