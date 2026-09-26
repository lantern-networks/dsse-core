package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/model"
)

func TestOrganizationNameEditPreservesCustomerWithdrawal(t *testing.T) {
	declareOperatorTenantForTest(t, "tenant_operator_001")
	path := filepath.Join(t.TempDir(), "tenants.json")
	store := newOperatorAwareAdminTenantModelStore(model.PolicyBundle{TenantID: "tenant_operator_001"}, time.Now(), path, "tenant_operator_001")
	seed := adminTenantModel{TenantID: "tenant_customer", DisplayName: "Customer", Status: "active", Timezone: "Asia/Tokyo", Region: "region-a", DataResidency: "legacy", PolicyBundleID: "bundle", PolicyBundleVersion: "v1", MetadataKeyCount: 4, OperatorElevationRequiresApproval: true}
	if _, err := store.Put(context.Background(), seed, time.Now()); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	endpoint := func(_ string, h http.HandlerFunc) http.HandlerFunc { return h }
	registerOperatorAccessRoutes(mux, endpoint, store, "", testEvaluator(), nil, nil, "tenant_operator_001", func(id string) string { return id })
	registerTenantAdminRoutes(mux, endpoint, serverConfig{}, testEvaluator(), nil, store, "tenant_operator_001", nil, nil, nil, nil, adminTenantExtraStores{}, "")
	op := adminIdentity{PrincipalID: "operator", TenantID: "tenant_operator_001", Roles: []string{"super_admin"}, AuthMethod: "admin_session"}
	customer := adminIdentity{PrincipalID: "customer", TenantID: "tenant_customer", Roles: []string{"admin"}, AuthMethod: "admin_session"}
	request := func(who adminIdentity, method, url, body string, operate bool, intended int) {
		t.Helper()
		r := httptest.NewRequest(method, url, bytes.NewBufferString(body))
		if operate {
			r.Header.Set("X-Operate-Tenant", "tenant_customer")
		}
		r = r.WithContext(context.WithValue(r.Context(), adminIdentityContextKey{}, who))
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		if w.Code != intended {
			t.Fatalf("%s %s: %d want %d: %s", method, url, w.Code, intended, w.Body.String())
		}
	}
	request(op, "PUT", "/admin/operator-delegation", `{"managed":true}`, true, 200)
	request(customer, "PUT", "/admin/operator-delegation", `{"managed":false}`, false, 200)
	request(op, "PUT", "/admin/operator-delegation", `{"managed":true}`, true, 403)
	before, _ := store.Get(context.Background(), "tenant_customer")
	request(op, "POST", "/admin/tenants", `{"tenant_id":"tenant_customer","display_name":"Renamed","status":"active","plan":"","home_region":"","allowed_regions":[]}`, false, 200)
	after, _ := store.Get(context.Background(), "tenant_customer")
	if !after.OperatorDelegationWithdrawnByCustomer || after.Timezone != "Asia/Tokyo" || after.Region != "region-a" || after.DataResidency != "legacy" || after.PolicyBundleID != "bundle" || after.PolicyBundleVersion != "v1" || after.MetadataKeyCount != 4 {
		t.Fatalf("ordinary edit erased stored fields: %+v", after)
	}
	if after.DisplayName != "Renamed" || !reflect.DeepEqual(after.OperatorDelegationChangedAt, before.OperatorDelegationChangedAt) || !reflect.DeepEqual(after.OperatorDelegationChangedBy, before.OperatorDelegationChangedBy) {
		t.Fatalf("edit/stamp mismatch: %+v", after)
	}
	request(op, "PUT", "/admin/operator-delegation", `{"managed":true}`, true, 403)
	for _, body := range []string{`{"tenant_id":"tenant_customer","operator_delegation_withdrawn_by_customer":false}`, `{"tenant_id":"tenant_customer","operator_managed":true}`, `{"tenant_id":"tenant_customer","operator_elevation_requires_approval":false}`} {
		request(op, "POST", "/admin/tenants", body, false, 403)
	}
	restored := newOperatorAwareAdminTenantModelStore(model.PolicyBundle{TenantID: "tenant_operator_001"}, time.Now(), path, "tenant_operator_001")
	saved, _ := restored.Get(context.Background(), "tenant_customer")
	if !saved.OperatorDelegationWithdrawnByCustomer || saved.Timezone != "Asia/Tokyo" {
		t.Fatalf("not persisted: %+v", saved)
	}
	request(customer, "PUT", "/admin/operator-delegation", `{"managed":true}`, false, 200)
	final, _ := store.Get(context.Background(), "tenant_customer")
	if !final.OperatorManaged || final.OperatorDelegationWithdrawnByCustomer {
		t.Fatalf("customer cannot reopen: %+v", final)
	}
}

func TestTenantEditPreservesOmittedSettingsAndAllowsExplicitClear(t *testing.T) {
	store := newAdminTenantModelStore(model.PolicyBundle{TenantID: "tenant_customer"}, time.Now())
	if _, err := store.Put(context.Background(), adminTenantModel{TenantID: "tenant_customer", DisplayName: "Customer", Timezone: "Asia/Tokyo", Plan: "standard", HomeRegion: "region-a", AllowedRegions: []string{"region-a"}}, time.Now()); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	registerTenantAdminRoutes(mux, func(_ string, h http.HandlerFunc) http.HandlerFunc { return h }, serverConfig{}, testEvaluator(), nil, store, "", nil, nil, nil, nil, adminTenantExtraStores{}, "")
	for _, tc := range []struct{ body, zone string }{{`{"display_name":"Renamed"}`, "Asia/Tokyo"}, {`{"timezone":"","allowed_regions":[],"plan":""}`, ""}} {
		r := httptest.NewRequest("POST", "/admin/tenant", bytes.NewBufferString(tc.body))
		r = r.WithContext(context.WithValue(r.Context(), adminIdentityContextKey{}, adminIdentity{TenantID: "tenant_customer", Roles: []string{"admin"}}))
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatalf("%d %s", w.Code, w.Body.String())
		}
		var got adminTenantModel
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		if got.Timezone != tc.zone || got.HomeRegion != "region-a" {
			t.Fatalf("omission/clear lost: %+v", got)
		}
	}
}
