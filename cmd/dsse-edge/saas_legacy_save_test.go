package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/lantern-networks/dsse-core/configversion"
	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/policy"
)

type legacyToggleDisk struct {
	raw  []byte
	fail bool
}

func (d *legacyToggleDisk) Load() ([]byte, error) { return append([]byte(nil), d.raw...), nil }
func (d *legacyToggleDisk) Save(b []byte) error {
	if d.fail {
		return errors.New("synthetic private storage unavailable")
	}
	d.raw = append([]byte(nil), b...)
	return nil
}
func TestLegacySaaSToggleWaitsForSave(t *testing.T) {
	for _, operation := range []string{"toggle", "rollback"} {
		t.Run(operation, func(t *testing.T) {
			var shipped atomic.Int64
			cp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodGet {
					json.NewEncoder(w).Encode(configversion.Version{VersionNo: 1, Payload: json.RawMessage(`{"saas_enablement":{"app":false}}`)})
					return
				}
				shipped.Add(1)
				w.WriteHeader(http.StatusOK)
			}))
			defer cp.Close()
			path, body := "/admin/swg/tenant-restriction", `{"saas_enablement":{"app":false}}`
			if operation == "rollback" {
				path += "/rollback"
				body = `{"version_no":1}`
			}

			ev := testEvaluator()
			tenant := ev.PolicyBundle.TenantID
			ev.PolicyBundle.SWGTenantRestrictionRules = []model.SWGTenantRestrictionRule{{ID: "one", TenantID: tenant, SaaSApplicationID: "app", Status: "active"}, {ID: "two", TenantID: tenant, SaaSApplicationID: "app", Status: "active"}}
			s := policy.NewStore(nil)
			disk := &legacyToggleDisk{}
			if err := s.SetRuntimeStatePersister(disk); err != nil {
				t.Fatal(err)
			}
			h := newServerWithConfig(serverConfig{Evaluator: ev, PolicyStore: s, AdminAuth: newAdminAuthStore(), CPVersions: &cpConfigVersionClient{url: cp.URL, client: cp.Client()}})
			before := s.TenantRestrictionRuleStatusOverrides()
			gen := s.ConfigGeneration()
			rawBefore := append([]byte(nil), disk.raw...)
			disk.fail = true
			call := func(want int) {
				t.Helper()
				r := httptest.NewRecorder()
				h.ServeHTTP(r, httptest.NewRequest("POST", path, strings.NewReader(body)))
				if r.Code != want {
					t.Fatalf("status=%d want %d: %s", r.Code, want, r.Body)
				}
				if strings.Contains(r.Body.String(), "synthetic private") {
					t.Fatal("storage details exposed")
				}
			}
			call(503)
			if shipped.Load() != 0 {
				t.Fatal("failed change recorded a successful version")
			}
			if !reflect.DeepEqual(before, s.TenantRestrictionRuleStatusOverrides()) || s.ConfigGeneration() != gen || !bytes.Equal(rawBefore, disk.raw) {
				t.Fatalf("failed toggle changed state: statuses=%v/%v generation=%d/%d storedBytes=%d/%d", before, s.TenantRestrictionRuleStatusOverrides(), gen, s.ConfigGeneration(), len(rawBefore), len(disk.raw))
			}
			disk.fail = false
			call(200)
			if shipped.Load() != 1 {
				t.Fatal("successful change did not record one version")
			}
			raw := append([]byte(nil), disk.raw...)
			fresh := policy.NewStore(nil)
			if err := fresh.SetRuntimeStatePersister(disk); err != nil {
				t.Fatal(err)
			}
			want := map[string]string{"one": "inactive", "two": "inactive"}
			if !reflect.DeepEqual(fresh.TenantRestrictionRuleStatusOverrides(), want) || !bytes.Equal(raw, disk.raw) {
				t.Fatal("restart lost toggle")
			}

		})
	}
}
