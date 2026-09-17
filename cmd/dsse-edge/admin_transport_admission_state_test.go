package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

func admissionStateRequest(h http.Handler, method, path, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+transportAuditBearer)
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestAdminTransportAdmissionRestoreReportsRemainingBlock(t *testing.T) {
	for _, layer := range []string{"local", "mesh", "synced"} {
		t.Run(layer, func(t *testing.T) {
			h, w, a, _ := transportAuditHandler(t)
			a.Revoke("owned-device", "local")
			a.Revoke("other-device", "foreign")
			if layer == "mesh" {
				a.RevokeFromMesh("owned-device", "peer")
			}
			if layer == "synced" {
				a.ReplaceSynced(map[string]string{"owned-device": "CP"})
			}
			r := transportAuditRequest(h, "restore", `{"identity":"owned-device"}`, transportAuditBearer)
			if r.Code != 200 {
				t.Fatalf("%d: %s", r.Code, r.Body)
			}
			var b map[string]any
			if err := json.Unmarshal(r.Body.Bytes(), &b); err != nil {
				t.Fatal(err)
			}
			blocked := layer != "local"
			if b["restored"] != true || b["transport_revoked"] != blocked || b["tenant_id"] != "tenant_lab_001" {
				t.Fatalf("%v", b)
			}
			if _, ok := a.Snapshot()["owned-device"]; ok {
				t.Fatal("local block not removed")
			}
			if _, ok := a.IsRevoked("other-device"); !ok {
				t.Fatal("foreign block removed")
			}
			if _, ok := a.IsRevoked("owned-device"); ok != blocked {
				t.Fatal("incorrect transport state")
			}
			count := 0
			for _, row := range readTransportAudits(t, w) {
				if row.EventType == "transport_admission_changed" {
					count++
					want := "success"
					if blocked {
						want = "partial"
					}
					if stringPtrValue(row.Result) != want || row.Metadata["transport_revoked"] != blocked || stringPtrValue(row.ActorUserID) != "transport-admin" {
						t.Fatalf("%+v", row)
					}
				}
			}
			if count != 1 {
				t.Fatal("missing domain audit")
			}
		})
	}
}

func TestAdminTransportAdmissionReadIncludesUnionAndTenant(t *testing.T) {
	h, _, a, _ := transportAuditHandler(t)
	a.RevokeFromMesh("owned-device", "peer")
	a.ReplaceSynced(map[string]string{"other-device": "foreign", "unplaced": "unknown"})
	r := admissionStateRequest(h, "GET", "/admin/transport-admission?expected_tenant_id=tenant_lab_001", "")
	if r.Code != 200 {
		t.Fatalf("%d: %s", r.Code, r.Body)
	}
	var b struct {
		Tenant   string   `json:"tenant_id"`
		Revoked  []string `json:"revoked_identities"`
		Withheld int      `json:"withheld_unattributable"`
	}
	if err := json.Unmarshal(r.Body.Bytes(), &b); err != nil {
		t.Fatal(err)
	}
	if b.Tenant != "tenant_lab_001" || !reflect.DeepEqual(b.Revoked, []string{"owned-device"}) || b.Withheld != 1 {
		t.Fatalf("%+v", b)
	}
}

func TestAdminDeviceAdmissionContextPrecondition(t *testing.T) {
	h, w, a, _ := transportAuditHandler(t)
	for _, route := range []struct{ method, path string }{{"GET", "/admin/enrolled-devices"}, {"GET", "/admin/transport-admission"}, {"POST", "/admin/transport-admission/revoke"}, {"POST", "/admin/transport-admission/restore"}, {"POST", "/admin/enrolled-devices/owned-device/enable"}, {"POST", "/admin/enrolled-devices/owned-device/disable"}} {
		r := admissionStateRequest(h, route.method, route.path+"?expected_tenant_id=tenant_other", `{"identity":"owned-device"}`)
		if r.Code != 409 {
			t.Fatalf("%s: %d %s", route.path, r.Code, r.Body)
		}
	}
	if len(a.List()) != 0 {
		t.Fatal("context failure changed transport")
	}
	r := admissionStateRequest(h, "GET", "/admin/enrolled-devices?expected_tenant_id=tenant_lab_001", "")
	if r.Code != 200 {
		t.Fatal(r.Code)
	}
	var b struct {
		Devices []struct {
			Enabled bool `json:"enabled"`
		}
	}
	if err := json.Unmarshal(r.Body.Bytes(), &b); err != nil {
		t.Fatal(err)
	}
	if len(b.Devices) != 1 || !b.Devices[0].Enabled {
		t.Fatal("inventory changed")
	}
	for _, row := range readTransportAudits(t, w) {
		if row.EventType == "transport_admission_changed" || row.EventType == "enrolled_inventory_updated" {
			t.Fatal("false domain success audit")
		}
		if stringPtrValue(row.Result) != "error" {
			t.Fatalf("non-error mutation audit: %+v", row)
		}
	}
}

func TestAdminTransportAdmissionUnconfiguredReadIsUnavailable(t *testing.T) {
	h := newServerWithConfig(serverConfig{Evaluator: testEvaluator()})
	r := httptest.NewRequest("GET", "/admin/transport-admission", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 503 {
		t.Fatalf("%d: %s", w.Code, w.Body)
	}
}
