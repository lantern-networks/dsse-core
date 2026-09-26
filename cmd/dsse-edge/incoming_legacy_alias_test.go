package main

import (
	"encoding/json"
	"github.com/lantern-networks/dsse-core/enrolledinventory"
	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/policy"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestIncomingLegacyTCPAliasesRemainUsable(t *testing.T) {
	for _, alias := range []string{"WinRM-HTTP", "PostgreSQL", "custom-db"} {
		for _, protocol := range []string{"", "tcp"} {
			t.Run(alias+"/"+protocol, func(t *testing.T) {
				tenant := testEvaluator().PolicyBundle.TenantID
				s := policy.NewStore(nil)
				ex := model.LegacyException{ID: "existing", TenantID: tenant, BusinessOwner: "owner", ServiceFamily: alias, Protocol: protocol, Port: 5985, Status: "active", Mode: "allow", ExpiresAt: time.Now().Add(time.Hour).Format(time.RFC3339)}
				s.UpsertLegacyException(tenant, ex)
				s.SetServerInitiatedEnabled(tenant, true)
				ledger := enrolledinventory.NewLedger()
				if _, err := ledger.Enroll("device", tenant, "", time.Now().Format(time.RFC3339)); err != nil {
					t.Fatal(err)
				}
				h := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), PolicyStore: s, AdminAuth: newAdminAuthStore(), EnrolledLedger: ledger})
				a := httptest.NewRecorder()
				h.ServeHTTP(a, httptest.NewRequest("GET", "/admin/legacy-exceptions/export", nil))
				d := asVerifiedDevice(t, h, "device", "/steer/server-initiated-export")
				for _, r := range []*httptest.ResponseRecorder{a, d} {
					var exp serverInitiatedExport
					if r.Code != 200 || json.Unmarshal(r.Body.Bytes(), &exp) != nil || len(exp.Rules) != 1 || exp.Rules[0].ServiceFamily != "tcp" || exp.Rules[0].Port != 5985 {
						t.Fatalf("legacy export %d: %s", r.Code, r.Body)
					}
				}
				ex.BusinessOwner = "new-owner"
				raw, _ := json.Marshal(ex)
				r := httptest.NewRecorder()
				h.ServeHTTP(r, httptest.NewRequest("POST", "/admin/legacy-exceptions", strings.NewReader(string(raw))))
				if r.Code != 200 {
					t.Fatalf("legacy edit %d %s", r.Code, r.Body)
				}
			})
		}
	}
}
