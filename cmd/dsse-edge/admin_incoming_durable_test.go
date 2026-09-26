package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/lantern-networks/dsse-core/policy"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

type incomingFaultDisk struct {
	raw  []byte
	fail bool
}

func (p *incomingFaultDisk) Load() ([]byte, error) { return append([]byte(nil), p.raw...), nil }
func (p *incomingFaultDisk) Save(raw []byte) error {
	if p.fail {
		return errors.New("fixture storage path unavailable")
	}
	p.raw = append([]byte(nil), raw...)
	return nil
}
func TestIncomingHTTPWaitsForDurableSave(t *testing.T) {
	for _, action := range []string{"toggle", "create", "edit", "delete"} {
		t.Run(action, func(t *testing.T) {
			disk := &incomingFaultDisk{}
			store := policy.NewStore(nil)
			if err := store.SetRuntimeStatePersister(disk); err != nil {
				t.Fatal(err)
			}
			h := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), PolicyStore: store, AdminAuth: newAdminAuthStore()})
			call := func(method, path, body string) *httptest.ResponseRecorder {
				r := httptest.NewRecorder()
				h.ServeHTTP(r, httptest.NewRequest(method, path, strings.NewReader(body)))
				return r
			}
			ex := map[string]any{"id": "old", "business_owner": "secops", "source_server": "192.0.2.1", "expires_at": "2030-01-01T00:00:00Z", "protocol": "tcp", "port": 8443, "status": "active", "mode": "allow"}
			raw, _ := json.Marshal(ex)
			if r := call("POST", "/admin/legacy-exceptions", string(raw)); r.Code != 200 {
				t.Fatalf("seed %d", r.Code)
			}
			tenant := testEvaluator().PolicyBundle.TenantID
			before := append([]byte(nil), disk.raw...)
			rows := store.LegacyExceptionsFor(tenant)
			gen := store.ConfigGeneration()
			method, path, body := "POST", "/admin/server-initiated", `{"enabled":true}`
			if action != "toggle" {
				path = "/admin/legacy-exceptions"
				if action == "create" {
					ex["id"] = "new"
				}
				if action == "edit" {
					ex["business_owner"] = "changed"
				}
				raw, _ = json.Marshal(ex)
				body = string(raw)
				if action == "delete" {
					method = "DELETE"
					path += "/old"
					body = ""
				}
			}
			disk.fail = true
			r := call(method, path, body)
			if r.Code != 503 {
				t.Fatalf("save refusal returned %d want 503", r.Code)
			}
			if strings.Contains(r.Body.String(), "fixture storage path") {
				t.Fatal("storage detail exposed")
			}
			if !bytes.Equal(before, disk.raw) || !reflect.DeepEqual(rows, store.LegacyExceptionsFor(tenant)) || store.ConfigGeneration() != gen || store.ServerInitiatedEnabledFor(tenant) {
				t.Fatal("refused change altered live or durable state")
			}
			disk.fail = false
			if r = call(method, path, body); r.Code != 200 {
				t.Fatalf("retry %d: %s", r.Code, r.Body)
			}
			confirmed := store.LegacyExceptionsFor(tenant)
			switch action {
			case "toggle":
				if !store.ServerInitiatedEnabledFor(tenant) {
					t.Fatal("retry did not apply toggle")
				}
			case "create":
				if len(confirmed) != 2 {
					t.Fatal("retry did not create exception")
				}
			case "edit":
				if len(confirmed) != 1 || confirmed[0].BusinessOwner != "changed" {
					t.Fatal("retry did not edit exception")
				}
			case "delete":
				if len(confirmed) != 0 {
					t.Fatal("retry did not delete exception")
				}
			}
			fresh := policy.NewStore(nil)
			if err := fresh.SetRuntimeStatePersister(disk); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(fresh.LegacyExceptionsFor(tenant), store.LegacyExceptionsFor(tenant)) || fresh.ServerInitiatedEnabledFor(tenant) != store.ServerInitiatedEnabledFor(tenant) {
				t.Fatal("restarted store differs")
			}
		})
	}
}
