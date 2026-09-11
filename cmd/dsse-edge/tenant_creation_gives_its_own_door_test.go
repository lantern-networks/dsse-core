package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/policyrule"
)

// ★★★ THE ONE MOMENT AN ORGANIZATION CAN BE GIVEN ITS OWN DOOR NAME FOR FREE (2026-08-28).
//
// The Edge picks an organization's transport certificate by the name a device sends; a device that sends none
// is served the deployment's shared one. Doing this LATER is a movement — announce the name, wait for every
// device to adopt it, serve both meanwhile. At creation there are no devices, so none of that applies, and it
// is the only time that is true. Before this, an operator had to know to visit a second screen, take a
// time-boxed elevation, and press a button that until today did not exist.
func TestCreatingAnOrganizationCanGiveItItsOwnDoorName(t *testing.T) {
	now := time.Now().UTC()
	declareOperatorTenantForTest(t, "tenant_lab")
	declareDeploymentNameSuffix("dsse.test", "")
	authority := newTenantTransportAuthority(nil, func([]byte) error { return nil }, func() time.Time { return now })
	store := newOperatorAwareAdminTenantModelStore(model.PolicyBundle{TenantID: "tenant_lab"}, now, "", "")
	rules := policyrule.NewStore()
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("writer: %v", err)
	}
	t.Cleanup(func() { _ = writer.Close() })

	mux := http.NewServeMux()
	registerTenantAdminRoutes(mux, func(_ string, h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			h(w, requestWithAdminIdentity(r, adminIdentity{
				PrincipalID: "adm_operator", TenantID: "tenant_lab", AuthMethod: "admin_session",
				Roles: []string{"super_admin"},
			}))
		}
	}, serverConfig{TenantTransportAuthority: authority}, decision.Evaluator{}, writer, store,
		"tenant_lab", nil, nil, rules, nil, adminTenantExtraStores{}, "")

	create := func(body string) map[string]any {
		t.Helper()
		r := httptest.NewRequest(http.MethodPost, "/admin/tenants", strings.NewReader(body))
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, r)
		if rec.Code != http.StatusOK {
			t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
		}
		var out map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode: %v (%s)", err, rec.Body.String())
		}
		return out
	}

	asked := create(`{"display_name":"Kaede Logistics","status":"active","transport_authority":true}`)
	id, _ := asked["tenant_id"].(string)
	if strings.TrimSpace(id) == "" {
		t.Fatal("the created organization has no id")
	}
	name, _ := asked["transport_server_name"].(string)
	if strings.TrimSpace(name) == "" {
		t.Fatalf("the organization was created without its own door name, and the answer did not say why: %v", asked)
	}
	// ★ THE NAME IS THE ISSUED ID, NEVER THE COMPANY'S. SNI is plaintext and this deployment strips ECH, so a
	// name derived from "Kaede Logistics" would answer "is this customer here" to anybody who can reach the port.
	if strings.Contains(strings.ToLower(name), "kaede") {
		t.Fatalf("the door name carries the company's own name (%q) — an SNI probe then enumerates the "+
			"customer list", name)
	}
	if serverName, inForce, _, _, known := authority.StateFor(id); !known || serverName != name || inForce == "" {
		t.Fatalf("the authority is not in force for the name the answer gave: known=%v name=%q since=%q",
			known, serverName, inForce)
	}

	// ★ AND AN API CALLER THAT SAYS NOTHING GETS EXACTLY WHAT IT GOT BEFORE. Creating an authority makes every
	// Edge in the fleet fetch material for a new organization; that is not something to start doing to callers
	// who never asked.
	silent := create(`{"display_name":"Quiet Corp","status":"active"}`)
	if name, _ := silent["transport_server_name"].(string); strings.TrimSpace(name) != "" {
		t.Fatalf("a caller that asked for nothing was given an authority anyway: %q", name)
	}
	quietID, _ := silent["tenant_id"].(string)
	if _, _, _, _, known := authority.StateFor(quietID); known {
		t.Fatal("an authority was created for an organization nobody asked to give one to")
	}
}

// ★★★ A NEW ORGANIZATION CARRIES WHAT ITS OWN SCREEN SAYS IT CARRIES (2026-08-28, measured by creating one and
// running a flow as one of its devices).
//
// An organization created before this had no policy at all. Its Internet Access screen said, in these words,
// "Everything your people reach on the internet is allowed and inspected", and the deployment answered every
// flow of every one of its devices with
//
//	steer_mux_denied … decision=deny reason="No active policy matched the request."
//
// A customer handed a freshly created organization got a fleet that carries nothing, from a screen promising
// the opposite. The deployment's own organization has had this posture since installation; only the ones
// created afterwards went without — which is every customer.
func TestANewOrganizationCarriesThePostureItsScreenDescribes(t *testing.T) {
	now := time.Now().UTC()
	declareOperatorTenantForTest(t, "tenant_lab")
	declareDeploymentNameSuffix("dsse.test", "")
	rules := policyrule.NewStore()
	store := newOperatorAwareAdminTenantModelStore(model.PolicyBundle{TenantID: "tenant_lab"}, now, "", "")
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("writer: %v", err)
	}
	t.Cleanup(func() { _ = writer.Close() })

	mux := http.NewServeMux()
	registerTenantAdminRoutes(mux, func(_ string, h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			h(w, requestWithAdminIdentity(r, adminIdentity{
				PrincipalID: "adm_operator", TenantID: "tenant_lab", AuthMethod: "admin_session",
				Roles: []string{"super_admin"},
			}))
		}
	}, serverConfig{}, decision.Evaluator{}, writer, store, "tenant_lab", nil, nil, rules, nil,
		adminTenantExtraStores{}, "")

	r := httptest.NewRequest(http.MethodPost, "/admin/tenants",
		strings.NewReader(`{"display_name":"Suzuran Foods","status":"active"}`))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, r)
	if rec.Code != http.StatusOK {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	id, _ := out["tenant_id"].(string)
	if note, _ := out["starting_posture_note"].(string); note != "" {
		t.Fatalf("the organization was created carrying nothing: %s", note)
	}

	carried := rules.List(id, policyrule.PlaneEgress)
	if len(carried) != 1 {
		t.Fatalf("a new organization holds %d rule(s); with none, every flow of every one of its devices is "+
			"denied while its own screen says everything is allowed and inspected", len(carried))
	}
	rule := carried[0]
	if rule.Action.Access != policyrule.AccessAllow || rule.Action.Inspection != policyrule.InspectionInspect {
		t.Fatalf("the starting posture is %q/%q, not the allowed-and-inspected the screen describes",
			rule.Action.Access, rule.Action.Inspection)
	}
	if rule.Status != policyrule.StatusActive {
		t.Fatalf("the starting rule is %q, so it decides nothing", rule.Status)
	}
	// ★ IT IS THE CUSTOMER'S OWN RULE. A starting posture the Console cannot edit or remove would be
	// configuration nobody can narrow — the shape this deployment has paid for before.
	if _, ok := rules.Get(id, rule.ID); !ok {
		t.Fatal("the starting rule is not in this organization's own list, so it cannot be narrowed or removed")
	}
	if removed, err := rules.Delete(id, rule.ID); err != nil || !removed {
		t.Fatalf("the starting rule cannot be deleted (%v/%v)", removed, err)
	}
	// And it belongs to THAT organization and nobody else.
	if len(rules.List("tenant_lab", policyrule.PlaneEgress)) != 0 {
		t.Fatal("creating an organization authored a rule in another one")
	}
}
