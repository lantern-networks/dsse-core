package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/model"
)

func TestSharedFleetTenantSettingsRequireExplicitImpactConfirmation(t *testing.T) {
	t.Setenv("DSSE_TOPOLOGY_PROFILE", "three-regions-multi-edge")
	declareOperatorTenantForTest(t, "tenant_operator_001")
	store := newAdminTenantModelStore(model.PolicyBundle{TenantID: "tenant_customer"}, time.Now())
	cfg := serverConfig{RegionEndpoints: mustCatalog(t, "region-a=https://a.example;region-b=https://b.example;region-c=https://c.example"), EntrancePortalOrigins: `{"agents.example":"https://portal.example"}`}
	mux := http.NewServeMux()
	registerTenantAdminRoutes(mux, func(_ string, h http.HandlerFunc) http.HandlerFunc { return h }, cfg, testEvaluator(), nil, store, "tenant_operator_001", nil, nil, nil, nil, adminTenantExtraStores{}, "")
	request := func(method, path, body string, op bool, want int) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(method, path, bytes.NewBufferString(body))
		id := adminIdentity{TenantID: "tenant_customer", PrincipalID: "customer", Roles: []string{"admin"}}
		if op {
			id = adminIdentity{TenantID: "tenant_operator_001", PrincipalID: "operator", Roles: []string{"super_admin"}}
		}
		r = r.WithContext(context.WithValue(r.Context(), adminIdentityContextKey{}, id))
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		if w.Code != want {
			t.Fatalf("%s %s = %d want %d: %s", method, path, w.Code, want, w.Body.String())
		}
		return w
	}
	before, _ := store.Get(context.Background(), "tenant_customer")
	request("POST", "/admin/tenant", `{"allowed_regions":["region-a"]}`, false, 409)
	request("POST", "/admin/tenants", `{"tenant_id":"tenant_customer","allowed_regions":["region-a"]}`, true, 409)
	after, _ := store.Get(context.Background(), "tenant_customer")
	if !reflect.DeepEqual(before, after) {
		t.Fatal("unconfirmed change mutated tenant")
	}
	request("POST", "/admin/tenant", `{"allowed_regions":["region-a"],"acknowledge_shared_fleet_residency_impact":true}`, false, 200)
	after, _ = store.Get(context.Background(), "tenant_customer")
	if !reflect.DeepEqual(after.AllowedRegions, []string{"region-a"}) {
		t.Fatal("confirmation widened security boundary")
	}
	request("POST", "/admin/tenant", `{"display_name":"Renamed"}`, false, 200)
	if w := request("GET", "/admin/tenant", "", false, 200); !strings.Contains(w.Body.String(), "shared_fleet_warning") {
		t.Fatal("existing Region conflict invisible")
	}
	if w := request("GET", "/admin/tenants", "", true, 200); !strings.Contains(w.Body.String(), "shared_fleet_warning") {
		t.Fatal("organization list hides existing conflict")
	}
	request("POST", "/admin/tenants", `{"tenant_id":"tenant_customer","allowed_regions":["region-b"],"acknowledge_shared_fleet_residency_impact":false}`, true, 409)
	request("POST", "/admin/tenants", `{"tenant_id":"tenant_customer","allowed_regions":["region-b"],"acknowledge_shared_fleet_residency_impact":true}`, true, 200)
	request("POST", "/admin/tenant", `{"allowed_regions":["region-a","region-b","region-c"]}`, false, 200)
	request("POST", "/admin/tenant", `{"allowed_regions":[]}`, false, 200)
	rows, _ := store.List(context.Background())
	request("POST", "/admin/tenants", `{"display_name":"New narrow tenant","allowed_regions":["region-a"]}`, true, 409)
	next, _ := store.List(context.Background())
	if len(rows) != len(next) {
		t.Fatal("unconfirmed creation persisted tenant")
	}
	w := request("POST", "/admin/tenants", `{"display_name":"New narrow tenant","allowed_regions":["region-a"],"acknowledge_shared_fleet_residency_impact":true}`, true, 200)
	var created adminTenantModel
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if created.TenantID == "" || !reflect.DeepEqual(created.AllowedRegions, []string{"region-a"}) {
		t.Fatal("creation did not retain explicit boundary")
	}
}

func TestSharedFleetResidencyImpactDoesNotActivateOnOldOriginList(t *testing.T) {
	t.Setenv("DSSE_TOPOLOGY_PROFILE", "three-regions-multi-edge")
	store := newAdminTenantModelStore(model.PolicyBundle{TenantID: "tenant_customer"}, time.Now())
	tenant := adminTenantModel{TenantID: "tenant_customer", AllowedRegions: []string{"region-a"}}
	cfg := serverConfig{StepUpPortalOrigins: "https://a.example,https://b.example,https://c.example"}
	r := httptest.NewRequest("POST", "/admin/tenant", nil)
	w := httptest.NewRecorder()
	if !confirmSharedFleetTenantChange(w, r, cfg, store, tenant, nil, true) {
		t.Fatal("binary-only update changed legacy settings contract")
	}
	cfg.EntrancePortalOrigins = `{"agents.example":"https://a.example"}`
	w = httptest.NewRecorder()
	if confirmSharedFleetTenantChange(w, r, cfg, store, tenant, nil, true) || w.Code != 503 {
		t.Fatal("missing Region inventory silently accepted new restriction")
	}
}
