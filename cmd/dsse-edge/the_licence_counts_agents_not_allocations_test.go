package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/enrolledinventory"
	"github.com/lantern-networks/dsse-core/seatallocation"
)

type countingLedgerStub map[string]int

func (c countingLedgerStub) CountAdmitted(tenant string) int { return c[tenant] }

// A deployment's agent count is the whole deployment, including devices carrying no tenant. Written because the
// per-tenant rows read the same method with the opposite meaning, and reading the wrong one here would report a
// number that looks plausible and undercounts every untenanted device.
func TestDeploymentAgentsEnrolledCountsTheWholeDeployment(t *testing.T) {
	ledger := countingLedgerStub{"": 400, "tenant_a": 250, "tenant_b": 140}
	if got := deploymentAgentsEnrolled(ledger); got != 400 {
		t.Fatalf("the deployment has 400 agents enrolled; counted %d", got)
	}
	if got := deploymentAgentsEnrolled(nil); got != 0 {
		t.Fatalf("an absent ledger counts nothing; got %d", got)
	}
}

// ★ THE CASE THE OLD FIELDS COULD NOT SHOW. 500 licensed, 200 allocated, 400 enrolled: `unallocated` reported
// 300 and was correct about the plan, while the number the licence is billed on was 400 and appeared nowhere.
func TestUsageIsNotAllocation(t *testing.T) {
	const seats, allocated = 500, 200
	ledger := countingLedgerStub{"": 400}
	if unallocated := seats - allocated; unallocated != 300 {
		t.Fatalf("the plan says 300 unallocated; got %d", unallocated)
	}
	enrolled := deploymentAgentsEnrolled(ledger)
	if remaining := seats - enrolled; remaining != 100 {
		t.Fatalf("the contract has 100 seats left, not 300; got %d", remaining)
	}
	if note := licenceUsageNote(seats, enrolled); note != "" {
		t.Fatalf("inside the pool says nothing; got %q", note)
	}
}

// Over the pool is reported and refuses nothing — the sentence has to say so, because "over licence" alone
// leaves an operator deciding whether their fleet just stopped.
func TestOverThePoolIsReportedAndBreaksNothing(t *testing.T) {
	note := licenceUsageNote(200, 260)
	if note == "" {
		t.Fatal("260 agents against 200 licensed must be reported")
	}
	for _, want := range []string{"260", "200", "nothing is refused", "counted in agents"} {
		if !strings.Contains(note, want) {
			t.Fatalf("the note must carry %q; got %q", want, note)
		}
	}
	if licenceUsageNote(0, 260) != "" {
		t.Fatal("an unlicensed deployment has no pool to be over — OSS has no limit at all")
	}
}

// ★★ THE ROUTE, NOT THE HELPER. The two tests above prove the counter arithmetic, and a counter with no caller
// proves nothing about a screen — this product has lost a day to exactly that shape more than once. This drives
// GET /admin/license the way the Console does and asserts the number an operator actually reads.
func TestTheLicenceRouteReportsAgentsEnrolledNotSeatsAllocated(t *testing.T) {
	declareOperatorTenantForTest(t, "tenant_operator")
	mux, key, ledger, allocs, _ := licenceAdminFixture(t)

	// 400 agents across two customers and a handful that carry no tenant at all — the ones that appear in no
	// per-tenant row, so an operator adding the table by eye undercounts by exactly this many.
	for i := 0; i < 250; i++ {
		mustEnroll(t, ledger, fmt.Sprintf("a-%d", i), "tenant_a")
	}
	for i := 0; i < 145; i++ {
		mustEnroll(t, ledger, fmt.Sprintf("b-%d", i), "tenant_b")
	}
	for i := 0; i < 5; i++ {
		mustEnroll(t, ledger, fmt.Sprintf("seeded-%d", i), "")
	}
	if _, err := allocs.Allocate(seatallocation.Policy{PoolSeats: 500}, "tenant_a", 200, "adm", "", licenceNow().Format(time.RFC3339)); err != nil {
		t.Fatalf("allocate: %v", err)
	}
	if code, _ := adminCall(t, mux, http.MethodPost, "/admin/license", signedLicence(t, key, testLicence(500))); code != http.StatusOK {
		t.Fatalf("apply licence: HTTP %d", code)
	}

	read := func(id adminIdentity) map[string]any {
		t.Helper()
		r := httptest.NewRequest(http.MethodGet, "/admin/license", nil)
		r = r.WithContext(context.WithValue(r.Context(), adminIdentityContextKey{}, id))
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, r)
		if rec.Code != http.StatusOK {
			t.Fatalf("HTTP %d %s", rec.Code, rec.Body.String())
		}
		var body map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode: %v", err)
		}
		return body
	}
	num := func(body map[string]any, key string) int {
		t.Helper()
		v, ok := body[key].(float64)
		if !ok {
			t.Fatalf("the licence route did not answer %q; it said %v", key, body)
		}
		return int(v)
	}

	op := read(adminIdentity{PrincipalID: "adm_op", TenantID: "tenant_operator", Roles: []string{"owner"}, AuthMethod: "admin_session"})
	// The plan and the count are DIFFERENT NUMBERS, and this is the whole point: before this the route reported
	// only the first one, so a deployment 100 seats from its ceiling read as having 300 to give away.
	if got := num(op, "unallocated"); got != 300 {
		t.Fatalf("the operator has allocated 200 of 500, so 300 are unallocated; route said %d", got)
	}
	if got := num(op, "agents_enrolled"); got != 400 {
		t.Fatalf("400 agents are enrolled (250 + 145 + 5 untenanted); route said %d", got)
	}
	if got := num(op, "seats_remaining"); got != 100 {
		t.Fatalf("500 licensed minus 400 enrolled leaves 100; route said %d", got)
	}
	if _, present := op["usage_note"]; present {
		t.Fatalf("inside the licence there is nothing to settle; route said %v", op["usage_note"])
	}

	// ★ THE NEGATIVE, WITH THE RENDER PROVEN. A customer must not read a deployment-wide device count — holding
	// ten devices and reading 400 tells them 390 belong to organizations they cannot see. Asserting the absence
	// alone would pass against a route that answered nothing at all, so the fields a customer DOES get are
	// checked in the same body.
	cust := read(adminIdentity{PrincipalID: "adm_b", TenantID: "tenant_b", Roles: []string{"admin"}, AuthMethod: "admin_session"})
	for _, k := range []string{"agents_enrolled", "seats_remaining", "usage_note"} {
		if _, present := cust[k]; present {
			t.Fatalf("a customer administrator read %q — that is every organization's device count, not theirs", k)
		}
	}
	if got := num(cust, "seats"); got != 500 {
		t.Fatalf("the customer still reads the pool, which explains a refusal without naming anybody; got %d", got)
	}
}

// ★★★ A CONNECTOR IS AN AGENT FOR LICENSING (operator decision, 2026-08-27): count connectors as agents —
// they are already in the same ledger, so that is the simplest thing that can be true.
//
// It was ALREADY true, which is exactly why this test exists. A connector enrols through the same POST /enroll
// and lands in the same ledger, so CountAdmitted has always counted it — by construction rather than by
// decision, and a behaviour nothing asserts is a behaviour the next refactor is free to change. Measured on the
// standing lab before writing this: the ledger held conn-1af480bdb996 beside the walked device.
func TestAConnectorCountsAgainstTheLicence(t *testing.T) {
	ledger := enrolledinventory.NewLedger()
	now := licenceNow().Format(time.RFC3339)
	if _, err := ledger.EnrollDeviceForTenant("laptop-1", "tenant_a", "default", "enrolled via POST /enroll", now); err != nil {
		t.Fatalf("enrol device: %v", err)
	}
	if _, err := ledger.EnrollDeviceForTenant("conn-1af480bdb996", "tenant_a", "default",
		"enrolled with the bootstrap secret of Site hq", now); err != nil {
		t.Fatalf("enrol connector: %v", err)
	}
	if got := deploymentAgentsEnrolled(ledger); got != 2 {
		t.Fatalf("a connector counts as an agent, so this deployment has 2; counted %d", got)
	}
	if got := ledger.CountAdmitted("tenant_a"); got != 2 {
		t.Fatalf("the tenant's own seat usage counts its connector too; counted %d", got)
	}
}
