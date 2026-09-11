package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/enrolledinventory"
	"github.com/lantern-networks/dsse-core/logs"
)

// ★ ONE CUSTOMER'S ADMIN COULD READ — AND SILENCE — ANOTHER CUSTOMER'S DEVICE REPORTS (2026-08-16). Found in
// the sweep that started at /admin/device-runtime, and unscoped for the same reason: the list is keyed by
// device identity, a report carries no tenant, and with one tenant on the node a filtered read and an
// unfiltered one are the same answer.
//
// A concern is a sharper disclosure than presence. It names a device AND says what is wrong with it — "failing
// attestation", "gone quiet" — which is a sentence about another customer's security posture. And the DELETE
// beside it took the identity straight from the path, so the read handed over the names and the write let an
// unrelated account dismiss the notification a customer was meant to act on. Nothing was enforced either way,
// which is exactly why it would have gone unnoticed: no device stops working, a report just quietly is not
// there any more.
func TestDeviceConcernsAreOneTenantsAndCannotBeDismissedByAnother(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	ledger := enrolledinventory.NewLedger()
	stamp := time.Now().UTC().Format(time.RFC3339)
	// tenant_lab_001 is the node's own tenant (testEvaluator), which is what an admin resolves to here.
	if _, err := ledger.Enroll("mine-dev-1", "tenant_lab_001", "", stamp); err != nil {
		t.Fatalf("enroll: %v", err)
	}
	if _, err := ledger.Enroll("theirs-dev-1", "tenant_someone_else", "", stamp); err != nil {
		t.Fatalf("enroll: %v", err)
	}
	handler := newServerWithConfig(serverConfig{
		Evaluator:      testEvaluator(),
		EnrolledLedger: ledger,
		Writer:         writer,
		Registry:       connector.NewRegistry(),
		AdminAuth:      newAdminAuthStore(),
	})
	do := func(method, path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}

	now := time.Now().UTC()
	reportedDeviceConcerns.record("mine-dev-1", "attestation_failed", now)
	reportedDeviceConcerns.record("theirs-dev-1", "attestation_failed", now)
	t.Cleanup(func() {
		reportedDeviceConcerns.clear("mine-dev-1")
		reportedDeviceConcerns.clear("theirs-dev-1")
	})

	// The read: the other tenant's device is absent, and the caller's own is PRESENT in the same response —
	// otherwise this passes just as well when the whole list is empty.
	rec := do(http.MethodGet, "/admin/device-concerns")
	if rec.Code != http.StatusOK {
		t.Fatalf("device-concerns status=%d body=%s", rec.Code, rec.Body.String())
	}
	if body := rec.Body.String(); strings.Contains(body, "theirs-dev-1") {
		t.Fatalf("another tenant's device — and what is wrong with it — was handed to this caller: %s", body)
	} else if !strings.Contains(body, "mine-dev-1") {
		t.Fatalf("the caller lost its OWN reported device: %s", body)
	}

	// The write: dismissing another tenant's report is refused, and — the part that matters — the report is
	// STILL THERE afterwards. A 404 that silently deleted it anyway would be the same defect wearing a status
	// code.
	if rec := do(http.MethodDelete, "/admin/device-concerns/theirs-dev-1"); rec.Code != http.StatusNotFound {
		t.Fatalf("dismissing another tenant's report must be 404; got %d body=%s", rec.Code, rec.Body.String())
	}
	found := false
	for _, c := range reportedDeviceConcerns.snapshot() {
		if c.Identity == "theirs-dev-1" {
			found = true
		}
	}
	if !found {
		t.Fatal("the other tenant's report was dismissed anyway — the refusal was cosmetic")
	}

	// And the caller can still dismiss its own, which is the capability this must not cost.
	if rec := do(http.MethodDelete, "/admin/device-concerns/mine-dev-1"); rec.Code != http.StatusOK {
		t.Fatalf("dismissing the caller's OWN report must work; got %d body=%s", rec.Code, rec.Body.String())
	}
}

// ★★★ THE WRITE THAT FILLS THE LIST (2026-08-22, measured on the reference deployment).
//
// The 2026-08-17 sweep scoped the two neighbours — the LIST withholds a report about somebody else's device,
// and the REVOKE refuses to cut one off. It left POST /admin/revocations/report, which fills the list.
// Northwind's own administrator, holding no cross-organization permission, posted a concern naming the lab
// organization's mac-dev-1 and got 202 on both nodes; the lab's administrator then read it as a finding about
// their own laptop, with Northwind's free text as the reason.
func TestReportingAConcernAboutAnotherOrganizationsDeviceIsRefused(t *testing.T) {
	src, err := os.ReadFile("admin_device_admission_routes.go")
	if err != nil {
		t.Fatalf("read the routes: %v", err)
	}
	body := string(src)
	start := strings.Index(body, `mux.HandleFunc("POST /admin/revocations/report"`)
	if start < 0 {
		t.Fatal("the report route is gone — this gate is reading the wrong file and would pass for anything")
	}
	end := strings.Index(body[start+10:], "mux.HandleFunc(")
	handler := body[start:]
	if end > 0 {
		handler = body[start : start+10+end]
	}
	// It must resolve the caller's organization and place the identity in it — the same pair the revoke path
	// beside it uses. Checking only for the word "tenant" would pass for a handler that logs one.
	for _, want := range []string{"adminTenantIDFromRequest(r)", "identityBelongsToTenant(config.EnrolledLedger"} {
		if !strings.Contains(handler, want) {
			t.Fatalf("the report route does not %s, so a customer can still write a concern about another "+
				"organization's device", want)
		}
	}
	// ★ AND IT REFUSES THE WAY ITS NEIGHBOUR DOES: 404, because whether an identity exists here is itself the
	// answer being withheld. A 403 confirms the device.
	if !strings.Contains(handler, "http.StatusNotFound") {
		t.Fatal("the refusal is not a 404, so it confirms whether another organization's device exists here")
	}
	// ★ THE CONTROL. An operator answering for the whole deployment must still be able to report, or this
	// closed the route rather than scoping it.
	if !strings.Contains(handler, "adminAnswerScope(r)") {
		t.Fatal("the scope check has no whole-deployment escape, so an operator can no longer report a concern")
	}
}
