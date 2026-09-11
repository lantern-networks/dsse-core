package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/enrolledinventory"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/revocation"
)

// ★★ THE RISK OVERLAY NAMED EVERY ORGANIZATION'S DEVICES (2026-08-18, found by listing the reads a customer
// can reach whose handler never mentions a tenant).
//
// GET /admin/risk-signals returns the entities the deployment currently considers high risk, with the
// severity — and it handed the whole map to any caller holding admin.risk.read, which every tenant
// administrator has. "win-dev-1: critical" is a statement about another customer's incident when it is not
// the caller's: exactly the sentence GET /admin/transport-admission was scoped for in the August per-device
// sweep. This route was three files away and was missed.
//
// The test runs with real credentials because the middleware REPLACES an identity put in the request context,
// and resolves a request with none to an UNSCOPED caller for whom everything is theirs — the state in which
// this boundary cannot be observed at all.
func TestTheRiskOverlayIsScopedToTheOrganizationAsking(t *testing.T) {
	declareOperatorTenantForTest(t, "tenant_operator_001")
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	ledger := enrolledinventory.NewLedger()
	stamp := time.Now().UTC().Format(time.RFC3339)
	if _, err := ledger.Enroll("lab-dev-1", "tenant_lab_001", "", stamp); err != nil {
		t.Fatalf("enroll: %v", err)
	}
	if _, err := ledger.Enroll("other-dev-1", "tenant_someone_else", "", stamp); err != nil {
		t.Fatalf("enroll: %v", err)
	}
	overlay := revocation.NewHighRiskOverlay()
	overlay.Mark("lab-dev-1", "high")
	overlay.Mark("other-dev-1", "critical")
	// An entity the ledger cannot place — marked, then deleted. An ordinary end state, and the reason the
	// answer carries a count rather than quietly dropping it.
	overlay.Mark("ghost-dev-1", "medium")

	auth := newAdminAuthStore()
	for _, who := range []struct {
		id, tenant, bearer string
		roles              []string
	}{
		{"adm_lab", "tenant_lab_001", testRiskLabBearer, []string{"admin"}},
		{"adm_other", "tenant_someone_else", testRiskOtherBearer, []string{"admin"}},
		// Answering for the deployment. `owner` rather than `super_admin` deliberately: super_admin holds no
		// admin.risk.read at all, so it cannot reach this route to be a control for it — which is a separate
		// question about who should see a deployment's risk picture, noted rather than decided here.
		{"adm_op", "tenant_operator_001", testRiskOperatorBearer, []string{"owner"}},
	} {
		auth.UpsertPrincipal(adminPrincipal{
			ID: who.id, TenantID: who.tenant, Subject: "sub_" + who.id, Email: who.id + "@lab.invalid",
			Roles: who.roles, IDPID: "keycloak_lab", Status: "active",
			CreatedAt: time.Now().Add(-time.Hour).UTC().Format(time.RFC3339),
		})
		auth.UpsertAPIToken(adminAPIToken{
			ID: "tok_" + who.id, TenantID: who.tenant, Name: who.id,
			TokenHash: adminTokenHash(who.bearer), Roles: who.roles, Scopes: []string{"*"},
			CreatedByAdminPrincipalID: who.id,
			CreatedAt:                 time.Now().Add(-time.Hour).UTC().Format(time.RFC3339),
			ExpiresAt:                 time.Now().Add(time.Hour).UTC().Format(time.RFC3339), Status: "active",
		})
	}
	handler := newServerWithConfig(serverConfig{
		Evaluator:       testEvaluator(),
		HighRiskOverlay: overlay,
		EnrolledLedger:  ledger,
		Writer:          writer,
		Registry:        connector.NewRegistry(),
		AdminAuth:       auth,
		// The organization that operates this deployment — see operator_is_an_organization_not_a_role.go.
		// Without it the caller below holds super_admin in a CUSTOMER organization, which is no longer enough.
		OperatorTenantID: "tenant_operator_001",
	})

	read := func(bearer string) (map[string]string, int) {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/admin/risk-signals", nil)
		if bearer != "" {
			req.Header.Set("authorization", "Bearer "+bearer)
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("HTTP %d %s", rec.Code, rec.Body.String())
		}
		var body struct {
			HighRisk map[string]string `json:"high_risk"`
			Withheld int               `json:"withheld_unattributable"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode: %v", err)
		}
		return body.HighRisk, body.Withheld
	}

	mine, withheld := read(testRiskLabBearer)
	if _, ok := mine["other-dev-1"]; ok {
		t.Fatalf("a customer read another organization's high-risk device: %v", mine)
	}
	if mine["lab-dev-1"] != "high" {
		t.Fatalf("a customer must still see its OWN risk — this is a boundary, not a blinding: %v", mine)
	}
	// ghost-dev-1 cannot be placed, so it is counted rather than shown or silently dropped.
	if withheld != 1 {
		t.Fatalf("entities the ledger cannot place must be counted, got withheld=%d", withheld)
	}

	// The other organization sees its own, and not the first one's — the boundary is not "everything except
	// the first caller".
	theirs, _ := read(testRiskOtherBearer)
	if theirs["other-dev-1"] != "critical" {
		t.Fatalf("the other organization lost its own device: %v", theirs)
	}
	if _, ok := theirs["lab-dev-1"]; ok {
		t.Fatalf("the boundary leaks the other way too: %v", theirs)
	}

	// The control: a caller answering for the DEPLOYMENT still sees everything, or this is a lockout rather
	// than scoping. (An unauthenticated request is not the control — with an auth store present the middleware
	// answers 401, which measures nothing about the boundary.)
	all, withheldAll := read(testRiskOperatorBearer)
	for _, id := range []string{"lab-dev-1", "other-dev-1", "ghost-dev-1"} {
		if _, ok := all[id]; !ok {
			t.Fatalf("a deployment-scoped caller lost %q: %v", id, all)
		}
	}
	if withheldAll != 0 {
		t.Fatalf("a deployment-scoped caller withholds nothing, got %d", withheldAll)
	}
	if strings.TrimSpace(all["ghost-dev-1"]) != "medium" {
		t.Fatalf("severities must survive the scoping: %v", all)
	}
}

const (
	testRiskLabBearer      = "raw-risk-lab-admin"
	testRiskOtherBearer    = "raw-risk-other-admin"
	testRiskOperatorBearer = "raw-risk-operator"
)

// ★★ AND THE READINESS ANSWER WAS ABOUT THE NODE'S ORGANIZATION, WHATEVER YOU ASKED (2026-08-18).
//
// GET /admin/transport-ca-readiness tells you whether your fleet has picked up a CA. It read the tenant from
// evaluator.PolicyBundle.TenantID — the NODE's own organization — and built the device list from the whole
// enrolled inventory, so a customer's answer was computed over every organization on the Edge WITH THE NAMES
// IN IT: Ready, NotReady, Silent and NeverReportedAnything are all lists of device identities.
//
// Two defects in one line: the readiness was about somebody else's fleet, and the identities came with it.
func TestTransportCAReadinessAnswersForTheOrganizationAsking(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	ledger := enrolledinventory.NewLedger()
	stamp := time.Now().UTC().Format(time.RFC3339)
	for _, d := range []struct{ id, tenant string }{
		{"lab-dev-1", "tenant_lab_001"},
		{"other-dev-1", "tenant_someone_else"},
	} {
		if _, err := ledger.Enroll(d.id, d.tenant, "", stamp); err != nil {
			t.Fatalf("enroll %s: %v", d.id, err)
		}
	}

	auth := newAdminAuthStore()
	auth.UpsertPrincipal(adminPrincipal{
		ID: "adm_lab", TenantID: "tenant_lab_001", Subject: "sub_lab", Email: "lab@lab.invalid",
		Roles: []string{"admin"}, IDPID: "keycloak_lab", Status: "active",
		CreatedAt: time.Now().Add(-time.Hour).UTC().Format(time.RFC3339),
	})
	auth.UpsertAPIToken(adminAPIToken{
		ID: "tok_lab_ready", TenantID: "tenant_lab_001", Name: "lab",
		TokenHash: adminTokenHash(testReadinessLabBearer), Roles: []string{"admin"}, Scopes: []string{"*"},
		CreatedByAdminPrincipalID: "adm_lab",
		CreatedAt:                 time.Now().Add(-time.Hour).UTC().Format(time.RFC3339),
		ExpiresAt:                 time.Now().Add(time.Hour).UTC().Format(time.RFC3339), Status: "active",
	})

	handler := newServerWithConfig(serverConfig{
		Evaluator:          testEvaluator(),
		EnrolledLedger:     ledger,
		ObservedExclusions: newObservedExclusionStore(64),
		Writer:             writer,
		Registry:           connector.NewRegistry(),
		AdminAuth:          auth,
		OperatorTenantID:   "tenant_operator_001",
	})

	req := httptest.NewRequest(http.MethodGet, "/admin/transport-ca-readiness?sha256=deadbeef", nil)
	req.Header.Set("authorization", "Bearer "+testReadinessLabBearer)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("HTTP %d %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if strings.Contains(body, "other-dev-1") {
		t.Fatalf("a customer's readiness answer named another organization's device: %s", body)
	}
	// Its own device is still counted, or the scoping blinded the fleet view it exists to give.
	if !strings.Contains(body, "lab-dev-1") {
		t.Fatalf("the caller's own device vanished from its own readiness answer: %s", body)
	}
}

const testReadinessLabBearer = "raw-readiness-lab-admin"
