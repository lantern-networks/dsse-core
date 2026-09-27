package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/tenantca"
)

func TestOperatorExplicitTargetCannotBypassEnvelope(t *testing.T) {
	for _, single := range []bool{false, true} {
		t.Run(map[bool]string{false: "all", true: "one"}[single], func(t *testing.T) {
			out := &recordingAdminAuditOutboxDeadReader{}
			h, reg, trust, file := tenantCARoutesForTest(t, out)
			_, peerPEM := tenantCATestCA(t, "peer")
			if _, err := reg.Register("tenant_acme", peerPEM); err != nil {
				t.Fatal(err)
			}
			if err := reg.Save(file); err != nil {
				t.Fatal(err)
			}
			cert, pem := tenantCATestCA(t, "target boundary")
			if code, response := operatorEnvelopeCall(t, h, testTenantCANorthwindBearer, "POST", "/admin/tenant-cas", "", map[string]string{"ca_pem": string(pem)}); code != 201 {
				t.Fatal(code, response)
			}
			wantBefore, wantAfter := 1, 0
			if single {
				_, replacement := tenantCATestCA(t, "replacement")
				if code, response := operatorEnvelopeCall(t, h, testTenantCANorthwindBearer, "POST", "/admin/tenant-cas", "", map[string]string{"ca_pem": string(replacement)}); code != 201 {
					t.Fatal(code, response)
				}
				wantBefore, wantAfter = 2, 1
			}
			path := "/admin/tenant-cas/tenant_northwind"
			if single {
				path += "/" + tenantca.CAAnchorKey(cert)
			}
			before, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			delegate(t, tenantCAHarnessTenantStore, "tenant_acme", true, false)
			if code, response := operatorEnvelopeCall(t, h, testTenantCABearer, "POST", "/admin/operator-elevations", "tenant_acme", map[string]int{"minutes": 20}); code != 201 {
				t.Fatal(code, response)
			}
			for _, delegated := range []bool{false, true} {
				delegate(t, tenantCAHarnessTenantStore, "tenant_northwind", delegated, false)
				for _, header := range []string{"", "tenant_lab_001", "tenant_acme", "tenant_northwind"} {
					code, response := operatorEnvelopeCall(t, h, testTenantCABearer, http.MethodDelete, path, header, nil)
					if code != 403 {
						t.Errorf("delegated=%v header=%q: %d %s", delegated, header, code, response)
					}
					after, err := os.ReadFile(file)
					if err != nil {
						t.Fatal(err)
					}
					if !bytes.Equal(before, after) || reg.Registrations()["tenant_northwind"] != wantBefore || !trustStoreHolds(t, trust, cert) {
						t.Fatal("refused write changed authority")
					}
				}
			}
			if code, response := operatorEnvelopeCall(t, h, testTenantCABearer, "POST", "/admin/operator-elevations", "tenant_northwind", map[string]int{"minutes": 20}); code != 201 {
				t.Fatal(code, response)
			}
			if code, response := operatorEnvelopeCall(t, h, testTenantCABearer, "DELETE", path, "tenant_northwind", nil); code != 200 {
				t.Fatal(code, response)
			}
			fresh, err := tenantca.LoadTenantCARegistry(file)
			if err != nil {
				t.Fatal(err)
			}
			if fresh.Registrations()["tenant_northwind"] != wantAfter || len(reg.Facts(time.Now())) != wantAfter+1 || fresh.Registrations()["tenant_acme"] != 1 {
				t.Fatal("authorized withdrawal not persisted")
			}
			successes := 0
			for _, a := range out.insertedAudits {
				if a.Action != nil && strings.HasPrefix(*a.Action, "tenant_ca_") && strings.Contains(*a.Action, "withdraw") && stringPtrValue(a.Result) == "success" {
					successes++
				}
			}
			if successes != 1 {
				t.Fatalf("withdrawal success audits=%d", successes)
			}
		})
	}
}

// Exercise the shared guard across every classified PKI act. This supplements
// real-handler CA tests; it is not independent GUI acceptance of these routes.
func TestOperatorExplicitTargetGuardForClassifiedActs(t *testing.T) {
	declareOperatorTenantForTest(t, "operator")
	acts := append(append([]operatorElevatedAct{}, operatorElevatedActs...), operatorDailyWorkActs...)
	for _, act := range acts {
		t.Run(act.Method+act.Path, func(t *testing.T) {
			for _, selected := range []string{"", "operator", "other", "customer"} {
				r := httptest.NewRequest(act.Method, strings.ReplaceAll(act.Path, "*", "customer"), nil)
				r.Header.Set("X-Operate-Tenant", selected)
				r = requestWithAdminIdentity(r, adminIdentity{TenantID: "operator", Roles: []string{"owner"}, AuthMethod: "admin_api_token"})
				err := adminTenantPKITargetAllowed(r, "customer", "writing")
				_, bodyErr := adminTenantForWrite(r, "customer")
				if (err == nil) != (selected == "customer") || (bodyErr == nil) != (selected == "customer") {
					t.Fatalf("selected=%q: path=%v body=%v", selected, err, bodyErr)
				}
			}
		})
	}
}

func TestOperatorExplicitBodyTargetCannotBypassDelegation(t *testing.T) {
	h, reg, _, file := tenantCARoutesForTest(t)
	_, pem := tenantCATestCA(t, "body target")
	body := map[string]string{"tenant_id": "tenant_northwind", "ca_pem": string(pem)}
	delegate(t, tenantCAHarnessTenantStore, "tenant_acme", true, false)
	for _, header := range []string{"", "tenant_lab_001", "tenant_acme", "tenant_northwind"} {
		code, response := operatorEnvelopeCall(t, h, testTenantCABearer, "POST", "/admin/tenant-cas", header, body)
		if code != 403 {
			t.Fatalf("header=%q: %d %s", header, code, response)
		}
		if len(reg.Facts(time.Now())) != 0 {
			t.Fatal("refused body write changed registry")
		}
		if _, err := os.Stat(file); !os.IsNotExist(err) {
			t.Fatal("refused body write created file", err)
		}
	}
	delegate(t, tenantCAHarnessTenantStore, "tenant_northwind", true, false)
	if code, response := operatorEnvelopeCall(t, h, testTenantCABearer, "POST", "/admin/tenant-cas", "tenant_northwind", body); code != 201 {
		t.Fatal(code, response)
	}
}
