package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/model"
)

// operatorEnvelopeCall issues an admin request as one of the harness identities, optionally acting within
// another organization.
func operatorEnvelopeCall(t *testing.T, handler http.Handler, bearer, method, path, operateTenant string, body any) (int, string) {
	t.Helper()
	var reader *bytes.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		reader = bytes.NewReader(raw)
	} else {
		reader = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, reader)
	req.Header.Set("authorization", "Bearer "+bearer)
	if operateTenant != "" {
		req.Header.Set("X-Operate-Tenant", operateTenant)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec.Code, rec.Body.String()
}

// delegate turns the standing delegation on (or off) for an organization, the way the route does.
func delegate(t *testing.T, store adminTenantModelAdminStore, tenantID string, managed, requiresApproval bool) {
	t.Helper()
	tenant, err := store.Get(context.Background(), tenantID)
	if err != nil {
		t.Fatalf("read %s: %v", tenantID, err)
	}
	tenant.TenantID = tenantID
	tenant.OperatorManaged = managed
	tenant.OperatorElevationRequiresApproval = requiresApproval
	if _, err := store.Put(context.Background(), tenant, time.Now()); err != nil {
		t.Fatalf("write %s: %v", tenantID, err)
	}
}

// ★ THE OPERATOR COULD ENTER A CUSTOMER AND CHANGE NOTHING (the customer-write rule, measured). super_admin holds none of the
// customer-side write permissions, so "operate within" was implemented, tested, and useless. The standing
// delegation is the answer chosen in the envelope design: inside an organization that has asked the operator to run it, the
// operator does that organization's ordinary work with that organization's ordinary permissions.
//
// The control and the assertion are the SAME request against two organizations, one delegated and one not —
// so this cannot pass because the route is broken for everybody.
func TestTheDelegationIsWhatLetsAnOperatorDoTheDailyWork(t *testing.T) {
	handler, _, _, _ := tenantCARoutesForTest(t)
	store := tenantCAHarnessTenantStore
	delegate(t, store, "tenant_northwind", true, false)
	delegate(t, store, "tenant_acme", false, false)

	_, caPEM := tenantCATestCA(t, "Daily Work CA")
	body := map[string]string{"tenant_id": "tenant_northwind", "ca_pem": string(caPEM)}
	code, response := operatorEnvelopeCall(t, handler, testTenantCABearer, http.MethodPost, "/admin/tenant-cas", "tenant_northwind", body)
	if code != http.StatusCreated {
		t.Fatalf("the operator could not do ordinary work inside a DELEGATED organization: HTTP %d %s", code, response)
	}

	_, acmePEM := tenantCATestCA(t, "Undelegated CA")
	body = map[string]string{"tenant_id": "tenant_acme", "ca_pem": string(acmePEM)}
	code, response = operatorEnvelopeCall(t, handler, testTenantCABearer, http.MethodPost, "/admin/tenant-cas", "tenant_acme", body)
	if code != http.StatusForbidden {
		t.Fatalf("an organization that delegated NOTHING was written to anyway: HTTP %d %s", code, response)
	}
	if !strings.Contains(response, "has not delegated") {
		t.Fatalf("the refusal does not say which of the two things is missing: %s", response)
	}
}

// ★ AND THE DELEGATION STOPS AT WHAT A TENANT ADMINISTRATOR HOLDS. The customer is saying "run my
// organization", not "here are the keys to the installation". A delegation that reached admin.platform.write
// would mean one customer's signature widened what the operator can do to every other customer's Edge.
func TestTheDelegationDoesNotReachTheDeploymentsOwnPowers(t *testing.T) {
	tenantAdmin := adminPermissionsByRole["admin"]
	for _, permission := range []string{"admin.platform.write", "admin.quota.write", "admin.tenant.admin"} {
		if tenantAdmin[permission] {
			t.Fatalf("%s is held by an ordinary tenant admin; the ceiling this test relies on does not exist", permission)
		}
		if operatorDelegationGrants(permission) {
			t.Fatalf("the standing delegation grants %s — that is the operator's own power, not the customer's", permission)
		}
	}
	// The control: it DOES grant the ordinary tenant-side work, or the delegation would be decorative.
	for _, permission := range []string{"admin.policy.write", "admin.enrollment.write", "admin.config.write"} {
		if !operatorDelegationGrants(permission) {
			t.Fatalf("the delegation does not grant %s, so it cannot cover the daily work", permission)
		}
	}
	// And either-of gates count if ANY alternative is a tenant-side permission.
	if !operatorDelegationGrants("admin.policy.write|admin.tenant.admin") {
		t.Fatal("an either-of gate whose tenant half is delegated was refused")
	}
}

// ★ THE ELEVATION IS NOT A FALLBACK, AND THAT DISTINCTION IS THE WHOLE GATE. Several destructive routes are
// gated "tenant permission OR operator permission" — a workaround added while the envelope design was open — so an operator
// satisfies the permission check outright. A first version hung the elevation check off the branch taken when
// the permission check FAILED, which left exactly the acts elevation exists for ungated for the only caller
// it was written to bound.
func TestADestructiveActNeedsAnElevationEvenWhenThePermissionCheckPasses(t *testing.T) {
	handler, registry, _, _ := tenantCARoutesForTest(t)
	store := tenantCAHarnessTenantStore
	delegate(t, store, "tenant_northwind", true, false)

	// Two CAs, so withdrawing one is a rotation rather than the end of the organization's identity basis.
	_, outgoingPEM := tenantCATestCA(t, "Outgoing CA")
	_, replacementPEM := tenantCATestCA(t, "Replacement CA")
	for _, caPEM := range [][]byte{outgoingPEM, replacementPEM} {
		body := map[string]string{"tenant_id": "tenant_northwind", "ca_pem": string(caPEM)}
		if code, response := operatorEnvelopeCall(t, handler, testTenantCABearer, http.MethodPost, "/admin/tenant-cas", "tenant_northwind", body); code != http.StatusCreated {
			t.Fatalf("register: HTTP %d %s", code, response)
		}
	}
	outgoing := tenantCAFingerprint(t, outgoingPEM)
	withdraw := func() (int, string) {
		return operatorEnvelopeCall(t, handler, testTenantCABearer, http.MethodDelete,
			"/admin/tenant-cas/tenant_northwind/"+outgoing, "tenant_northwind", nil)
	}

	code, response := withdraw()
	if code != http.StatusForbidden {
		t.Fatalf("an operator withdrew a customer's device CA with no elevation: HTTP %d %s", code, response)
	}
	// ★ A FIELD, NOT A SENTENCE (2026-08-21). The refusal used to be matched on its prose, and its prose used
	// to end with "Grant one with POST /admin/operator-elevations" — an API call shown to an operator on a
	// screen as the way forward. The answer now carries elevation_required so a screen can offer the act, and
	// this asserts the machine-readable half: prose can be rewritten for its readers, a contract cannot.
	if !strings.Contains(response, `"elevation_required"`) ||
		!strings.Contains(response, `"tenant_id":"tenant_northwind"`) {
		t.Fatalf("the refusal does not name the elevation a screen would have to offer: %s", response)
	}
	// The registration above is the control: the SAME caller, the SAME organization, ordinary work, allowed.
	// Without it, "the destructive act was refused" is also what a broken delegation looks like.

	code, response = operatorEnvelopeCall(t, handler, testTenantCABearer, http.MethodPost,
		"/admin/operator-elevations", "tenant_northwind", map[string]int{"minutes": 30})
	if code != http.StatusCreated {
		t.Fatalf("the operator could not take an elevation: HTTP %d %s", code, response)
	}

	if code, response = withdraw(); code != http.StatusOK {
		t.Fatalf("the elevated act was still refused with an elevation active: HTTP %d %s", code, response)
	}
	for _, fact := range registry.Facts(time.Now()) {
		if strings.EqualFold(fact.SHA256, outgoing) {
			t.Fatal("the route answered 200 and withdrew nothing")
		}
	}
}

// An elevation that ends only on a screen is the defect this repository knows best. It ends against the
// clock, and the act it authorised is refused again the moment it does.
func TestAnElevationStopsAuthorisingWhenItExpires(t *testing.T) {
	now := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	tenant := adminTenantModel{TenantID: "tenant_northwind", OperatorManaged: true}
	tenant.OperatorElevations = []operatorElevation{{
		ID: "elev_1", GrantedTo: "adm_operator",
		StartedAt: now.Format(time.RFC3339),
		ExpiresAt: now.Add(30 * time.Minute).Format(time.RFC3339),
	}}

	if !operatorHasActiveElevation(tenant, "adm_operator", now.Add(29*time.Minute)) {
		t.Fatal("the control failed: an elevation inside its window did not authorise")
	}
	if operatorHasActiveElevation(tenant, "adm_operator", now.Add(31*time.Minute)) {
		t.Fatal("an elevation kept authorising after it expired")
	}
	// And it belongs to the operator who took it. Two people sharing one window means the record cannot say
	// who acted, which is the only thing the customer is being shown.
	if operatorHasActiveElevation(tenant, "adm_someone_else", now.Add(5*time.Minute)) {
		t.Fatal("another operator rode somebody else's elevation")
	}
	// A corrupt end is not an open-ended one.
	tenant.OperatorElevations[0].ExpiresAt = "not a timestamp"
	if operatorHasActiveElevation(tenant, "adm_operator", now) {
		t.Fatal("an unparseable expiry authorised — the worst record in the store became the most powerful")
	}
}

// An organization that asked to be asked is asked. A pending elevation authorises nothing, and the operator
// cannot approve its own.
func TestAnElevationAwaitingApprovalAuthorisesNothing(t *testing.T) {
	now := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	tenant := adminTenantModel{TenantID: "tenant_northwind", OperatorManaged: true, OperatorElevationRequiresApproval: true}
	pending := operatorElevation{
		ID: "elev_1", GrantedTo: "adm_operator",
		StartedAt: now.Format(time.RFC3339), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339),
		ApprovalRequired: true,
	}
	tenant.OperatorElevations = []operatorElevation{pending}

	if operatorHasActiveElevation(tenant, "adm_operator", now) {
		t.Fatal("an elevation the organization has not approved authorised an act")
	}
	if got := pending.state(now); got != "pending_approval" {
		t.Fatalf("state = %q; the organization cannot see that it is being asked", got)
	}

	approved := now.Add(time.Minute).Format(time.RFC3339)
	tenant.OperatorElevations[0].ApprovedAt = &approved
	if !operatorHasActiveElevation(tenant, "adm_operator", now.Add(2*time.Minute)) {
		t.Fatal("the control failed: an approved elevation still authorised nothing")
	}

	// Ending it beats approval: either side may stop it, at any time.
	ended := now.Add(3 * time.Minute).Format(time.RFC3339)
	tenant.OperatorElevations[0].EndedAt = &ended
	if operatorHasActiveElevation(tenant, "adm_operator", now.Add(4*time.Minute)) {
		t.Fatal("an elevation that was ended kept authorising")
	}
}

// ★ THE ORGANIZATION CAN SEE WHAT WAS DONE TO IT WITHOUT ASKING THE OPERATOR. This is the half of the envelope design the
// user agreed with before the reason field was dropped, and it is the part that carries the accountability a
// free-text justification only appeared to.
//
// Scoped like every per-organization read in this codebase: its own and no other's. The sweep that fixed four
// device-facing reads found each of them answering for everybody, so a new read that names organizations
// starts with the boundary rather than acquiring one later.
func TestAnOrganizationSeesTheElevationsOverItAndNobodyElses(t *testing.T) {
	handler, _, _, _ := tenantCARoutesForTest(t)
	store := tenantCAHarnessTenantStore
	delegate(t, store, "tenant_northwind", true, false)
	delegate(t, store, "tenant_acme", true, false)

	for _, tenant := range []string{"tenant_northwind", "tenant_acme"} {
		if code, response := operatorEnvelopeCall(t, handler, testTenantCABearer, http.MethodPost,
			"/admin/operator-elevations", tenant, map[string]int{"minutes": 15}); code != http.StatusCreated {
			t.Fatalf("elevate over %s: HTTP %d %s", tenant, code, response)
		}
	}

	// northwind's OWN administrator, holding no cross-tenant permission at all.
	code, response := operatorEnvelopeCall(t, handler, testTenantCANorthwindBearer, http.MethodGet, "/admin/operator-access", "", nil)
	if code != http.StatusOK {
		t.Fatalf("an organization could not read the operator's access to it: HTTP %d %s", code, response)
	}
	var body map[string]any
	if err := json.Unmarshal([]byte(response), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["tenant_id"] != "tenant_northwind" {
		t.Fatalf("the record answered for %v", body["tenant_id"])
	}
	if body["managed"] != true {
		t.Fatal("the organization cannot see that it has delegated its management")
	}
	elevations, _ := body["elevations"].([]any)
	if len(elevations) != 1 {
		t.Fatalf("northwind sees %d elevations; it should see exactly its own one", len(elevations))
	}
	first, _ := elevations[0].(map[string]any)
	if first["state"] != "active" || strings.TrimSpace(first["granted_by"].(string)) == "" {
		t.Fatalf("the record does not say who took it or whether it is open: %v", first)
	}
	if _, hasReason := first["reason"]; hasReason {
		t.Fatal("a reason field came back — the envelope design decided against one, and a field nothing verifies is " +
			"bookkeeping that looks like accountability")
	}

	// And it cannot read the other organization's, header or no header.
	code, response = operatorEnvelopeCall(t, handler, testTenantCANorthwindBearer, http.MethodGet, "/admin/operator-access", "tenant_acme", nil)
	if code == http.StatusOK && strings.Contains(response, "tenant_acme") {
		t.Fatalf("a tenant administrator read another organization's operator-access record: %s", response)
	}
}

// A customer cannot grant itself an elevation, and cannot grant one over anybody else. Elevation is the
// operator's act, bounded by the customer — inverting that would make the whole envelope decorative.
func TestACustomerCannotElevateItself(t *testing.T) {
	handler, _, _, _ := tenantCARoutesForTest(t)
	delegate(t, tenantCAHarnessTenantStore, "tenant_northwind", true, false)

	for _, target := range []string{"", "tenant_northwind", "tenant_acme"} {
		code, response := operatorEnvelopeCall(t, handler, testTenantCANorthwindBearer, http.MethodPost,
			"/admin/operator-elevations", target, map[string]int{"minutes": 15})
		if code == http.StatusCreated {
			t.Fatalf("a tenant administrator granted itself an elevation (target %q): %s", target, response)
		}
	}
	// The control: the operator can, over a delegated organization.
	if code, response := operatorEnvelopeCall(t, handler, testTenantCABearer, http.MethodPost,
		"/admin/operator-elevations", "tenant_northwind", map[string]int{"minutes": 15}); code != http.StatusCreated {
		t.Fatalf("the control failed: the operator could not elevate over a delegated organization: HTTP %d %s", code, response)
	}
}

// An elevation over an organization that has delegated nothing is refused: elevation ADDS to a delegation, it
// does not replace one. Otherwise an operator could reach into an organization that never asked, simply by
// taking a window first.
func TestAnElevationCannotSubstituteForTheDelegation(t *testing.T) {
	handler, _, _, _ := tenantCARoutesForTest(t)
	delegate(t, tenantCAHarnessTenantStore, "tenant_acme", false, false)

	code, response := operatorEnvelopeCall(t, handler, testTenantCABearer, http.MethodPost,
		"/admin/operator-elevations", "tenant_acme", map[string]int{"minutes": 15})
	if code != http.StatusConflict {
		t.Fatalf("an elevation was granted over an organization that delegated nothing: HTTP %d %s", code, response)
	}
	if !strings.Contains(response, "does not replace one") {
		t.Fatalf("the refusal does not explain the order of the two: %s", response)
	}
}

// A window without a short end is the standing permission the design exists to avoid.
func TestAnElevationMustBeShort(t *testing.T) {
	handler, _, _, _ := tenantCARoutesForTest(t)
	delegate(t, tenantCAHarnessTenantStore, "tenant_northwind", true, false)

	for _, minutes := range []int{0, -1, operatorElevationMaxMinutes + 1} {
		code, response := operatorEnvelopeCall(t, handler, testTenantCABearer, http.MethodPost,
			"/admin/operator-elevations", "tenant_northwind", map[string]int{"minutes": minutes})
		if code != http.StatusBadRequest {
			t.Fatalf("minutes=%d was accepted: HTTP %d %s", minutes, code, response)
		}
	}
	if code, _ := operatorEnvelopeCall(t, handler, testTenantCABearer, http.MethodPost,
		"/admin/operator-elevations", "tenant_northwind", map[string]int{"minutes": operatorElevationMaxMinutes}); code != http.StatusCreated {
		t.Fatal("the control failed: the longest permitted window was refused")
	}
}

// ★ AN ELEVATION THAT IS TRUE ON ONE NODE IS NOT AN ELEVATION (the envelope design). The operator reaches whichever Edge the
// load balancer picked; the act lands wherever the route goes. A window enforced per node is the per-Edge
// shape this repository has already paid for twice — authored rules that were per-Edge while every screen
// said "applied", and a Console steer exclusion that vanished fifteen seconds later.
//
// So this is measured through the CHANNEL, not asserted from the struct. The delegation and the elevations
// ride the config bundle's tenant section, and the thing that would silently break that is a receiving side
// which rebuilds the row field by field — the "read path stops carrying" family, three of which turned up in
// one day. A round trip is the only check that notices.
func TestTheDelegationAndItsElevationsReachAnotherEdgeThroughTheBundle(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	authority := newAdminTenantModelStore(model.PolicyBundle{}, now)
	edge := newAdminTenantModelStore(model.PolicyBundle{}, now)

	elevation := operatorElevation{
		ID: "elev_carried", GrantedTo: "adm_operator", GrantedBy: "ops@example.invalid",
		StartedAt: now.Format(time.RFC3339), ExpiresAt: now.Add(30 * time.Minute).Format(time.RFC3339),
	}
	if _, err := authority.Put(ctx, adminTenantModel{
		TenantID: "tenant_northwind", DisplayName: "Northwind", Status: "active",
		OperatorManaged: true, OperatorElevationRequiresApproval: true,
		OperatorElevations: []operatorElevation{elevation},
	}, now); err != nil {
		t.Fatalf("author: %v", err)
	}

	// The control: before the sync the other Edge knows nothing, so a pass below cannot come from a store
	// that happened to be seeded with the same thing.
	if before, _ := edge.List(ctx); len(before) != 0 {
		t.Fatalf("the control failed: the receiving Edge already held %d organization(s)", len(before))
	}
	syncTenantSection(t, authority, edge, now)

	received, err := edge.Get(ctx, "tenant_northwind")
	if err != nil {
		t.Fatalf("read on the receiving Edge: %v", err)
	}
	if !received.OperatorManaged {
		t.Fatal("the delegation did not reach the other Edge — the operator would be refused there and " +
			"allowed here, for the same organization, at the same moment")
	}
	if !received.OperatorElevationRequiresApproval {
		t.Fatal("the organization's requirement to be asked did not travel")
	}
	if len(received.OperatorElevations) != 1 || received.OperatorElevations[0].ID != elevation.ID {
		t.Fatalf("the elevation did not travel: %+v", received.OperatorElevations)
	}
	if !operatorHasActiveElevation(received, "adm_operator", now.Add(time.Minute)) {
		t.Fatal("the elevation arrived but does not authorise on the receiving Edge")
	}
	// And it ends there by the same clock, with no further bundle needed — which is why the end is an
	// absolute timestamp rather than a countdown the node would have to be told about.
	if operatorHasActiveElevation(received, "adm_operator", now.Add(31*time.Minute)) {
		t.Fatal("the receiving Edge kept authorising after the window closed")
	}
}

// ★ A RULE THAT HIDES ITS OWN STATE MAKES EVERY REFUSAL UNDER IT UNACTIONABLE (found live, first run). The
// route that reports whether an organization has delegated is gated on a permission a tenant administrator
// holds, so the delegation rule fired on it: the operator was refused with a message telling them to obtain
// the thing they were trying to find out about, and given no way to look.
func TestTheOperatorCanReadTheEnvelopeOfAnOrganizationThatHasDelegatedNothing(t *testing.T) {
	handler, _, _, _ := tenantCARoutesForTest(t)
	delegate(t, tenantCAHarnessTenantStore, "tenant_acme", false, false)

	code, response := operatorEnvelopeCall(t, handler, testTenantCABearer, http.MethodGet, "/admin/operator-access", "tenant_acme", nil)
	if code != http.StatusOK {
		t.Fatalf("the operator could not read the delegation state of an undelegated organization: HTTP %d %s", code, response)
	}
	if !strings.Contains(response, `"managed":false`) {
		t.Fatalf("the answer does not state the delegation is absent: %s", response)
	}
	// The control: this exemption is for READING the envelope only. Ordinary work in the same organization is
	// still refused, or the exemption would be a hole rather than a window.
	_, caPEM := tenantCATestCA(t, "Should Not Land")
	code, response = operatorEnvelopeCall(t, handler, testTenantCABearer, http.MethodPost, "/admin/tenant-cas",
		"tenant_acme", map[string]string{"tenant_id": "tenant_acme", "ca_pem": string(caPEM)})
	if code != http.StatusForbidden {
		t.Fatalf("the exemption widened past the route it names: HTTP %d %s", code, response)
	}
}

// ★ WITHDRAWING THE DELEGATION MUST NOT STRAND AN OPEN ELEVATION (found live, 2026-08-16). Ending one is
// gated "admin.tenant.admin|admin.config.write", and admin.config.write is tenant-side — so the delegation
// rule fired on it, and the moment an organization withdrew its delegation the operator lost the ability to
// close a window that was still open. That is the exact moment somebody wants every window shut. On the lab
// five elevations reported active that no run could close, and a later check passed for the wrong reason
// because one of them was still standing.
func TestAnOpenElevationCanStillBeEndedAfterTheDelegationIsWithdrawn(t *testing.T) {
	handler, _, _, _ := tenantCARoutesForTest(t)
	store := tenantCAHarnessTenantStore
	delegate(t, store, "tenant_northwind", true, false)

	code, response := operatorEnvelopeCall(t, handler, testTenantCABearer, http.MethodPost,
		"/admin/operator-elevations", "tenant_northwind", map[string]int{"minutes": 30})
	if code != http.StatusCreated {
		t.Fatalf("elevate: HTTP %d %s", code, response)
	}
	var granted map[string]any
	if err := json.Unmarshal([]byte(response), &granted); err != nil {
		t.Fatalf("decode: %v", err)
	}
	id, _ := granted["elevation"].(map[string]any)["id"].(string)

	// The organization changes its mind about the whole arrangement.
	delegate(t, store, "tenant_northwind", false, false)

	code, response = operatorEnvelopeCall(t, handler, testTenantCABearer, http.MethodDelete,
		"/admin/operator-elevations/"+id, "tenant_northwind", nil)
	if code != http.StatusOK {
		t.Fatalf("the operator could not end an open elevation after the delegation was withdrawn: HTTP %d %s",
			code, response)
	}
	// And it is really shut, not merely reported shut.
	tenant, err := store.Get(context.Background(), "tenant_northwind")
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if operatorHasActiveElevation(tenant, "adm_operator", time.Now()) {
		t.Fatal("the elevation still authorises after being ended")
	}

	// The control: ordinary work in that organization IS refused now — the exemption covers the envelope's
	// own controls and nothing else.
	_, caPEM := tenantCATestCA(t, "Should Not Land After Withdrawal")
	code, response = operatorEnvelopeCall(t, handler, testTenantCABearer, http.MethodPost, "/admin/tenant-cas",
		"tenant_northwind", map[string]string{"tenant_id": "tenant_northwind", "ca_pem": string(caPEM)})
	if code != http.StatusForbidden {
		t.Fatalf("the exemption widened past the envelope's own controls: HTTP %d %s", code, response)
	}
}

// ★ THE OPERATOR'S OWN ORGANIZATION HAS NOBODY TO DELEGATE FROM (found live, 2026-08-16). The delegation
// route refuses to set a delegation on the operator's own tenant — correct, it does not delegate to itself —
// and the enforcement rule then demanded one anyway. The result was an organization no one could act inside,
// with no act available that would have changed it. Found while trying to mint the operator's first named
// credential, which is the exact work that exists to end the shared break-glass token.
func TestTheOperatorsOwnOrganizationDoesNotNeedADelegation(t *testing.T) {
	now := time.Now().UTC()
	auth := newAdminAuthStore()
	auth.UpsertPrincipal(adminPrincipal{
		ID: "adm_operator", TenantID: "tenant_operator_001", Subject: "sub_operator",
		Email: "operator@example.invalid", Roles: []string{"admin", "super_admin"}, IDPID: "keycloak_lab",
		Status: "active", CreatedAt: now.Add(-time.Hour).Format(time.RFC3339),
	})
	auth.UpsertAPIToken(adminAPIToken{
		ID: "tok_operator", TenantID: "tenant_operator_001", Name: "operator",
		TokenHash: adminTokenHash(testTenantCABearer), Roles: []string{"admin", "super_admin"},
		Scopes: []string{"*"}, CreatedByAdminPrincipalID: "adm_operator",
		CreatedAt: now.Add(-time.Hour).Format(time.RFC3339),
		ExpiresAt: now.Add(time.Hour).Format(time.RFC3339), Status: "active",
	})
	// A registry that knows which organization is the operator's, the way a node with -operator-tenant-id does.
	tenants := newOperatorAwareAdminTenantModelStore(model.PolicyBundle{}, now, "", "tenant_operator_001")
	for _, id := range []string{"tenant_operator_001", "tenant_northwind"} {
		if _, err := tenants.Put(context.Background(), adminTenantModel{TenantID: id, DisplayName: id, Status: "active"}, now); err != nil {
			t.Fatalf("seed %s: %v", id, err)
		}
	}
	handler := newServerWithConfig(serverConfig{
		Evaluator: testEvaluator(), AdminAuth: auth, TenantModelStore: tenants,
		OperatorTenantID: "tenant_operator_001",
	})

	code, response := operatorEnvelopeCall(t, handler, testTenantCABearer, http.MethodGet,
		"/admin/enrolled-devices", "tenant_operator_001", nil)
	if code == http.StatusForbidden && strings.Contains(response, "has not delegated") {
		t.Fatalf("acting inside the operator's own organization demanded a delegation it cannot be given: %s", response)
	}

	// The control: a CUSTOMER organization in the same registry still demands one, so the exemption is about
	// the operator tenant and not about the rule having stopped working.
	code, response = operatorEnvelopeCall(t, handler, testTenantCABearer, http.MethodGet,
		"/admin/enrolled-devices", "tenant_northwind", nil)
	if code != http.StatusForbidden || !strings.Contains(response, "has not delegated") {
		t.Fatalf("the control failed: a customer organization no longer requires a delegation: HTTP %d %s", code, response)
	}
}

// ★ A HEADER YOU MAY NOT USE MUST NOT SILENTLY REDIRECT YOUR WRITE (2026-08-16, measured live on the lab).
// X-Operate-Tenant is ignored for callers without admin.tenant.admin. For a READ that is right — you see your
// own organization and never another's. For a WRITE it means the act lands somewhere the caller did not name:
// an API token holding only the tenant admin role sent X-Operate-Tenant: tenant_northwind with
// POST /admin/admins/invite and got 201, with the administrator seated in its OWN organization, and nothing
// in the answer contradicted the request.
//
// This is the header twin of the defect already fixed for the same choice carried in the BODY, which is a
// 400 for exactly this reason.
func TestAWriteNamingAnOrganizationYouMayNotActInIsRefused(t *testing.T) {
	handler, _, _, _ := tenantCARoutesForTest(t)

	// The customer's own administrator: no cross-tenant permission at all.
	code, response := operatorEnvelopeCall(t, handler, testTenantCANorthwindBearer, http.MethodPost,
		"/admin/tenant-cas", "tenant_acme", map[string]string{"tenant_id": "tenant_acme", "ca_pem": "x"})
	if code != http.StatusForbidden {
		t.Fatalf("a write naming another organization was not refused: HTTP %d %s", code, response)
	}
	if !strings.Contains(response, "may only act in") {
		t.Fatalf("the refusal does not say which organization the caller may act in: %s", response)
	}

	// ★★ AND SO IS A READ (2026-08-22). This control used to assert the OPPOSITE — that a read carrying the
	// same header still answered for the caller's own organization — on the grounds that a read discloses
	// nothing. True about disclosure, false about the answer: the caller asked about tenant_acme and was
	// handed tenant_northwind's numbers under tenant_acme's name, with nothing saying so. Measured on the
	// reference fleet, where one Edge runs without -operator-tenant-id: the operator asked that node for an
	// organization's devices and got HTTP 200 and an empty list, while the other Edge of the same fleet
	// returned three.
	code, response = operatorEnvelopeCall(t, handler, testTenantCANorthwindBearer, http.MethodGet,
		"/admin/operator-access", "tenant_acme", nil)
	if code != http.StatusForbidden {
		t.Fatalf("a read naming another organization was answered instead of refused: HTTP %d %s", code, response)
	}
	if !strings.Contains(response, "answered for") {
		t.Fatalf("the refusal reads as if a write had been attempted: %s", response)
	}

	// ★ THE CONTROL THAT MATTERS, and it must not be the one above. Without it this passes for a build that
	// refuses every read carrying the header, including the caller's own organization — which would take a
	// customer's own console away from them to close an operator-side hole.
	code, response = operatorEnvelopeCall(t, handler, testTenantCANorthwindBearer, http.MethodGet,
		"/admin/operator-access", "tenant_northwind", nil)
	if code != http.StatusOK || !strings.Contains(response, "tenant_northwind") {
		t.Fatalf("a read naming the caller's OWN organization was refused: HTTP %d %s", code, response)
	}

	// And the operator, who may use it, still can.
	code, response = operatorEnvelopeCall(t, handler, testTenantCABearer, http.MethodPost,
		"/admin/operator-elevations", "tenant_northwind", map[string]int{"minutes": 5})
	if code == http.StatusForbidden && strings.Contains(response, "may only act in") {
		t.Fatalf("the refusal caught the operator too, who is exactly who the header is for: %s", response)
	}
}

// ★ THE SETUP CHECKLIST OF AN ORGANIZATION THAT HAS DELEGATED NOTHING IS EXACTLY WHAT AN OPERATOR NEEDS
// (2026-08-16, found in the Console). The route is gated "admin.tenant.read|admin.tenant.admin", and
// admin.tenant.read is tenant-side, so the delegation rule refused it — for every organization that has just
// been created, which is when the checklist matters. The Organizations list showed "unknown" for the one
// undelegated organization and a full answer for the two that had delegated.
func TestAnOperatorCanReadTheSetupOfAnOrganizationThatHasDelegatedNothing(t *testing.T) {
	handler, _, _, _ := tenantCARoutesForTest(t)
	delegate(t, tenantCAHarnessTenantStore, "tenant_acme", false, false)

	code, response := operatorEnvelopeCall(t, handler, testTenantCABearer, http.MethodGet,
		"/admin/organization-setup", "tenant_acme", nil)
	if code != http.StatusOK {
		t.Fatalf("the operator could not read the setup state of an undelegated organization: HTTP %d %s", code, response)
	}
	if !strings.Contains(response, "tenant_acme") {
		t.Fatalf("the answer is not about that organization: %s", response)
	}

	// The control: the exemption is for READING the state. Acting inside that organization is still refused,
	// or it would be a hole rather than a window.
	_, caPEM := tenantCATestCA(t, "Should Not Land Undelegated")
	code, response = operatorEnvelopeCall(t, handler, testTenantCABearer, http.MethodPost, "/admin/tenant-cas",
		"tenant_acme", map[string]string{"tenant_id": "tenant_acme", "ca_pem": string(caPEM)})
	if code != http.StatusForbidden {
		t.Fatalf("the exemption widened past reading: HTTP %d %s", code, response)
	}

	// And a tenant administrator still cannot read another organization's.
	code, response = operatorEnvelopeCall(t, handler, testTenantCANorthwindBearer, http.MethodGet,
		"/admin/organization-setup", "tenant_acme", nil)
	if code == http.StatusOK && strings.Contains(response, "tenant_acme") {
		t.Fatalf("a tenant administrator read another organization's setup state: %s", response)
	}
}

// ★★ AN ELEVATION THAT IS OVER CANNOT BE RESTATED (2026-08-16, found by calling both routes on a finished
// record on the live lab). Approving and ending guarded only on EndedAt, so an elevation that had LAPSED —
// EndedAt nil, ApprovedAt nil — was still writable. An elevation that expired at 12:22 took an approval
// stamped 13:55 and an end stamped 13:55, its state flipped from "expired" to "ended", and both calls returned
// 200 saying approved:true / ended:true.
//
// The elevation record is the evidence of what an operator was allowed to do and for how long. Evidence that
// can be written after the fact is not evidence.
func TestAFinishedElevationCannotBeApprovedOrEndedAfterwards(t *testing.T) {
	handler, _, _, _ := tenantCARoutesForTest(t)
	store := tenantCAHarnessTenantStore
	delegate(t, store, "tenant_northwind", true, false)

	code, response := operatorEnvelopeCall(t, handler, testTenantCABearer, http.MethodPost,
		"/admin/operator-elevations", "tenant_northwind", map[string]int{"minutes": 30})
	if code != http.StatusCreated {
		t.Fatalf("elevate: HTTP %d %s", code, response)
	}
	var granted map[string]any
	if err := json.Unmarshal([]byte(response), &granted); err != nil {
		t.Fatalf("decode: %v", err)
	}
	id, _ := granted["elevation"].(map[string]any)["id"].(string)

	// Make it lapse the way the clock does: nothing ended it, its window simply closed.
	tenant, err := store.Get(context.Background(), "tenant_northwind")
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	lapsed := time.Now().UTC().Add(-time.Minute).Format(time.RFC3339)
	for i := range tenant.OperatorElevations {
		if strings.EqualFold(tenant.OperatorElevations[i].ID, id) {
			tenant.OperatorElevations[i].ExpiresAt = lapsed
		}
	}
	if _, err := store.Put(context.Background(), tenant, time.Now().UTC()); err != nil {
		t.Fatalf("write: %v", err)
	}

	// Ending it again must be refused, and must not restate when or by whom it ended.
	code, response = operatorEnvelopeCall(t, handler, testTenantCABearer, http.MethodDelete,
		"/admin/operator-elevations/"+id, "tenant_northwind", nil)
	if code != http.StatusConflict {
		t.Fatalf("ending a lapsed elevation must be refused as a conflict, got HTTP %d %s", code, response)
	}

	// Approving it must be refused too: an approval stamped after the window closed says somebody allowed
	// access that had already gone away.
	code, response = operatorEnvelopeCall(t, handler, testTenantCABearer, http.MethodPost,
		"/admin/operator-elevations/"+id+"/approve", "tenant_northwind", map[string]any{})
	if code == http.StatusOK {
		t.Fatalf("approving a lapsed elevation must not succeed, got HTTP %d %s", code, response)
	}

	// And the record still says what actually happened.
	tenant, err = store.Get(context.Background(), "tenant_northwind")
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	for _, e := range tenant.OperatorElevations {
		if !strings.EqualFold(e.ID, id) {
			continue
		}
		if e.EndedAt != nil {
			t.Fatalf("a lapsed elevation was given an end time it never had: %+v", e)
		}
		if e.ApprovedAt != nil {
			t.Fatalf("a lapsed elevation was given an approval it never had: %+v", e)
		}
	}
}
