package main

import (
	"encoding/json"
	"github.com/lantern-networks/dsse-core/revocation"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestRiskReadUnavailableReplacementAndRecovery(t *testing.T) {
	for _, mode := range []string{"zero-file", "duplicate", "read-error", "legacy"} {
		t.Run(mode, func(t *testing.T) {
			handler, writer, o, _, runtime, _ := deviceRiskAuditHandler(t)
			path := filepath.Join(t.TempDir(), "good.json")
			if err := o.SetStatePath(path); err != nil {
				t.Fatal(err)
			}
			o.Mark("owned-device", "high")
			o.Mark("other-device", "critical")
			if _, err := o.SetUserRisk(revocation.UserRisk{TenantID: "tenant_lab_001", ID: "alice", Severity: "medium"}); err != nil {
				t.Fatal(err)
			}
			if _, err := o.SetUserRisk(revocation.UserRisk{TenantID: "tenant_other", ID: "alice", Severity: "critical"}); err != nil {
				t.Fatal(err)
			}
			before := o.Snapshot()
			beforeRuntime := runtime.List()
			gen := o.ConfigGeneration()
			candidate := filepath.Join(t.TempDir(), "PRIVATE_SNAPSHOT_PATH")
			raw := ""
			if mode == "duplicate" {
				raw = `{"schema_version":"high_risk_overlay_state.v2","devices":{"owned-device":"high","owned-device":"medium"}}`
			}
			if mode == "legacy" {
				raw = `{"schema_version":"high_risk_overlay_state.v1","devices":{"legacy":"high"}}`
			}
			if mode == "read-error" {
				if err := os.Mkdir(candidate, 0700); err != nil {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(candidate, []byte(raw), 0600); err != nil {
				t.Fatal(err)
			}
			err := o.SetStatePath(candidate)
			if (err == nil) != (mode == "legacy") {
				t.Fatal(err)
			}
			read := func(query string, bearer string) *httptest.ResponseRecorder {
				r := httptest.NewRequest(http.MethodGet, "/admin/risk-signals"+query, nil)
				r.Header.Set("Authorization", "Bearer "+bearer)
				w := httptest.NewRecorder()
				handler.ServeHTTP(w, r)
				return w
			}
			for _, query := range []string{"", "?entity_type=user"} {
				w := read(query, transportAuditBearer)
				if w.Code != 503 || strings.Contains(w.Body.String(), "PRIVATE_") || strings.Contains(w.Body.String(), "high_risk") {
					t.Fatal(w.Code, w.Body.String())
				}
			}
			w := deviceRiskRequest(handler, `{"entity_type":"device","entity_id":"owned-device","severity":"none"}`, transportAuditBearer)
			if w.Code != 503 {
				t.Fatal(w.Code, w.Body.String())
			}
			if !reflect.DeepEqual(beforeRuntime, runtime.List()) {
				t.Fatal("unavailable write touched runtime")
			}
			if mode != "legacy" && (!reflect.DeepEqual(before, o.Snapshot()) || o.ConfigGeneration() != gen) {
				t.Fatal("invalid load lost live risk")
			}
			rows := readTransportAudits(t, writer)
			found := false
			for _, a := range rows {
				if a.EventType == "device_risk_change_failed" {
					found = true
					if stringPtrValue(a.Result) != "error" || stringPtrValue(a.TargetID) != "owned-device" || stringPtrValue(a.ActorUserID) != "transport-admin" {
						t.Fatal("wrong failure audit", a)
					}
				}
			}
			if !found {
				t.Fatal("failure audit missing")
			}
			if err := o.SetStatePath(path); err != nil {
				t.Fatal(err)
			}
			for _, query := range []string{"", "?entity_type=user"} {
				w := read(query, transportAuditBearer)
				if w.Code != 200 {
					t.Fatal(w.Code, w.Body.String())
				}
				var body struct {
					Tenant string            `json:"tenant_id"`
					Entity string            `json:"entity_type"`
					Risk   map[string]string `json:"high_risk"`
				}
				if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
					t.Fatal(err)
				}
				want := map[string]string{"owned-device": "high"}
				entity := "device"
				if query != "" {
					want = map[string]string{"alice": "medium"}
					entity = "user"
				}
				if body.Tenant != "tenant_lab_001" || body.Entity != entity || !reflect.DeepEqual(body.Risk, want) {
					t.Fatal("wrong restored namespace/scope", body)
				}
			}
			if w := read("", transportAuditReadBearer); w.Code != 403 {
				t.Fatal("unprivileged risk read accepted", w.Code)
			}
		})
	}
}
