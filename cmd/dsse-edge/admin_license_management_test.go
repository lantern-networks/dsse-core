package main

import (
	"crypto/ecdsa"
	"errors"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/seatallocation"
	"github.com/lantern-networks/dsse-core/vendorlicense"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type licensingFaultStore struct {
	raw  []byte
	fail bool
}

func (p *licensingFaultStore) Load() ([]byte, error) { return p.raw, nil }
func (p *licensingFaultStore) Save(raw []byte) error {
	if p.fail {
		return errors.New("private storage detail")
	}
	p.raw = append([]byte(nil), raw...)
	return nil
}
func TestLicenseSaveFailureDoesNotConsumeSerial(t *testing.T) {
	mux, key, _, allocs, d := licenceAdminFixture(t)
	p := &licensingFaultStore{fail: true}
	d.licence.SetPersister(p)
	body := signedLicence(t, key, testLicence(20))
	code, out := adminCall(t, mux, "POST", "/admin/license", body)
	if code != 503 || strings.Contains(out["error"].(string), "private") {
		t.Fatalf("%d %+v", code, out)
	}
	if d.licence.LastAcceptedSerial() != 0 || d.licence.ConfigGeneration() != 0 {
		t.Fatal("failed save consumed serial")
	}
	if _, ok := d.licence.Current(d.acceptedKeys, d.msspID); ok {
		t.Fatal("failed save applied licence")
	}
	p.fail = false
	if code, _ := adminCall(t, mux, "POST", "/admin/license", body); code != 200 {
		t.Fatal(code)
	}
	restored := newLicenseStore()
	restored.SetPersister(p)
	if _, ok := restored.Current(d.acceptedKeys, d.msspID); !ok || restored.LastAcceptedSerial() != 1 {
		t.Fatal("retry not durable")
	}
	q := &licensingFaultStore{fail: true}
	allocs.SetPersister(q)
	if code, out := adminCall(t, mux, "POST", "/admin/seat-allocations", `{"tenant_id":"customer","seats":5}`); code != 503 || strings.Contains(out["error"].(string), "private") {
		t.Fatalf("%d %+v", code, out)
	}
	q.fail = false
	adminCall(t, mux, "POST", "/admin/seat-allocations", `{"tenant_id":"customer","seats":5}`)
	q.fail = true
	if code, _ := adminCall(t, mux, "DELETE", "/admin/seat-allocations/customer", ""); code != 503 {
		t.Fatal(code)
	}
	if allocs.SeatsFor("customer") != 5 {
		t.Fatal("failed removal changed allowance")
	}
}
func TestSeatManagementOperatorCanReleaseCustomerButCustomerCannot(t *testing.T) {
	_, key, _, _, _ := licenceAdminFixture(t)
	license := newLicenseStore()
	env, err := vendorlicense.Sign(testLicence(20), "review", key, licenceNow())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := license.Apply(env, []*ecdsa.PublicKey{&key.PublicKey}, "mssp_partner_a", "operator", licenceNow().Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	auth := newAdminAuthStore()
	now := time.Now()
	for _, who := range []struct {
		id, tenant string
		roles      []string
	}{{"operator", "tenant_lab_001", []string{"super_admin", "admin"}}, {"customer", "tenant_other", []string{"admin"}}} {
		auth.UpsertPrincipal(adminPrincipal{ID: who.id, TenantID: who.tenant, Roles: who.roles, Status: "active"})
		auth.UpsertAPIToken(adminAPIToken{ID: who.id, TenantID: who.tenant, TokenHash: adminTokenHash(who.id + "-test-token"), CreatedByAdminPrincipalID: who.id, Roles: who.roles, Scopes: []string{"*"}, Status: "active", CreatedAt: now.Add(-time.Minute).Format(time.RFC3339), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339)})
	}
	allocs := seatallocation.NewStore()
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	credentials := newLocalAdminCredentialStore("DSSE")
	h := newServerWithConfig(serverConfig{Writer: writer, LocalCredentials: credentials, Evaluator: testEvaluator(), OperatorTenantID: "tenant_lab_001", AdminAuth: auth, VendorLicense: license, SeatAllocations: allocs, LicenseAcceptedKeys: []*ecdsa.PublicKey{&key.PublicKey}, LicenseMSSPID: "mssp_partner_a"})
	call := func(who, method, path, body string) int {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+who+"-test-token")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w.Code
	}
	if code := call("operator", "POST", "/admin/seat-allocations", `{"tenant_id":"tenant_other","seats":5}`); code != 200 {
		t.Fatal(code)
	}
	for _, method := range []string{"POST", "DELETE"} {
		path := "/admin/seat-allocations"
		if method == "DELETE" {
			path += "/tenant_other"
		}
		if code := call("customer", method, path, `{"tenant_id":"tenant_other","seats":10}`); code != 403 {
			t.Fatalf("customer %s: %d", method, code)
		}
	}
	if allocs.SeatsFor("tenant_other") != 5 {
		t.Fatal("customer changed quota")
	}
	if code := call("operator", "DELETE", "/admin/seat-allocations/tenant_other", ""); code != 200 {
		t.Fatal(code)
	}
	if len(allocs.List()) != 0 {
		t.Fatal("operator did not release allocation")
	}
	if code := call("operator", "POST", "/admin/admins/invite", `{"email":"invited@example.invalid","roles":["super_admin","admin"]}`); code != 201 {
		t.Fatal(code)
	}
	changes, invites := 0, 0
	for _, a := range readTransportAudits(t, writer) {
		if a.EventType == "admin_seat_allocation_changed" {
			changes++
			if stringPtrValue(a.ActorUserID) != "operator" || a.TenantID != "tenant_lab_001" || stringPtrValue(a.TargetID) != "tenant_other" || a.Metadata["target_tenant_id"] != "tenant_other" || stringPtrValue(a.Result) != "success" {
				t.Fatalf("allocation audit: %+v", a)
			}
		}
		if a.EventType == "admin_account_invited" {
			invites++
			entries := credentials.List("tenant_lab_001")
			if len(entries) != 1 || stringPtrValue(a.ActorUserID) != "operator" || stringPtrValue(a.TargetID) != entries[0].PrincipalID || stringPtrValue(a.TargetType) != "admin_account" || a.TenantID != "tenant_lab_001" {
				t.Fatalf("invitation audit: %+v", a)
			}
		}
	}
	if changes != 2 || invites != 1 {
		t.Fatalf("audit counts: allocation=%d invitation=%d", changes, invites)
	}

}
