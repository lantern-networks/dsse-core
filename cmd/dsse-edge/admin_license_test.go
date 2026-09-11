package main

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/enrolledinventory"
	"github.com/lantern-networks/dsse-core/seatallocation"
	"github.com/lantern-networks/dsse-core/vendorlicense"
)

func licenceAdminFixture(t *testing.T) (*http.ServeMux, *ecdsa.PrivateKey, *enrolledinventory.Ledger, *seatallocation.Store, adminLicenseDeps) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	ledger := enrolledinventory.NewLedger()
	allocs := seatallocation.NewStore()
	gate := newEnrolmentLicensing(allocs, ledger, true, quotaEnforcing)
	gate.now = licenceNow
	d := adminLicenseDeps{
		licence:      newLicenseStore(),
		allocations:  allocs,
		licensing:    gate,
		ledger:       ledger,
		acceptedKeys: []*ecdsa.PublicKey{&key.PublicKey},
		msspID:       "mssp_partner_a",
		now:          licenceNow,
	}
	mux := http.NewServeMux()
	registerAdminLicenseEndpoints(mux, d, func(_ string, h http.HandlerFunc) http.HandlerFunc { return h })
	return mux, key, ledger, allocs, d
}

func adminCall(t *testing.T, mux *http.ServeMux, method, path, body string) (int, map[string]any) {
	return adminCallAs(t, mux, method, path, body, "")
}

// adminCallAs makes the same call while OPERATING AS another tenant, the way a cross-tenant operator does.
func adminCallAs(t *testing.T, mux *http.ServeMux, method, path, body, operateAs string) (int, map[string]any) {
	t.Helper()
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, path, nil)
	} else {
		r = httptest.NewRequest(method, path, strings.NewReader(body))
	}
	// ★ AUTHENTICATED, like every admin request in production (2026-08-14). This helper built a bare request
	// with no identity, which meant the seat-allocation routes were exercised in a state the deployment never
	// reaches — and that is how they came to read the tenant from the request BODY instead of from the caller.
	// A tenant-scoped route tested without a tenant is a route whose scoping is not tested.
	//
	// The identity is the MSSP OPERATOR (owner), and the tenant being operated on travels in X-Operate-Tenant —
	// which is what the Console already sends on every admin call (console/app.js:408). Allocating for several
	// tenants is done by operating as each of them, not by naming them in a body.
	r = r.WithContext(context.WithValue(r.Context(), adminIdentityContextKey{},
		adminIdentity{PrincipalID: "adm_test", TenantID: "tenant_a", Roles: []string{"owner"}, AuthMethod: "admin_session"}))
	if operateAs != "" {
		r.Header.Set("X-Operate-Tenant", operateAs)
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, r)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

func signedLicence(t *testing.T, k *ecdsa.PrivateKey, p vendorlicense.Payload) string {
	t.Helper()
	env, err := vendorlicense.Sign(p, "jv-1", k, licenceNow())
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	raw, _ := json.Marshal(env)
	return string(raw)
}

func TestApplyingALicenceMakesItTheOneInForce(t *testing.T) {
	mux, key, _, _, _ := licenceAdminFixture(t)

	code, body := adminCall(t, mux, http.MethodGet, "/admin/license", "")
	if code != http.StatusOK || body["licensed"] != false || body["state"] != "no_licence_installed" {
		t.Fatalf("before any licence: %d %+v", code, body)
	}

	code, body = adminCall(t, mux, http.MethodPost, "/admin/license", signedLicence(t, key, testLicence(1000)))
	if code != http.StatusOK || body["seats"].(float64) != 1000 {
		t.Fatalf("apply: %d %+v", code, body)
	}
	_, body = adminCall(t, mux, http.MethodGet, "/admin/license", "")
	if body["licensed"] != true || body["seats"].(float64) != 1000 || body["state"] != "active" {
		t.Fatalf("after apply: %+v", body)
	}
}

// An older file with more seats on it is the only realistic attack, and the endpoint is where it would arrive.
func TestAnOlderLicenceIsRefusedByTheEndpoint(t *testing.T) {
	mux, key, _, _, _ := licenceAdminFixture(t)
	second := testLicence(1000)
	second.Serial = 2
	if code, _ := adminCall(t, mux, http.MethodPost, "/admin/license", signedLicence(t, key, second)); code != http.StatusOK {
		t.Fatalf("apply serial 2: %d", code)
	}
	older := testLicence(999999)
	older.Serial = 1
	code, body := adminCall(t, mux, http.MethodPost, "/admin/license", signedLicence(t, key, older))
	if code == http.StatusOK {
		t.Fatalf("an older serial must be refused however many seats it claims: %+v", body)
	}
}

func TestALicenceForAnotherMSSPIsRefused(t *testing.T) {
	mux, key, _, _, _ := licenceAdminFixture(t)
	p := testLicence(1000)
	p.MSSPID = "mssp_somebody_else"
	if code, _ := adminCall(t, mux, http.MethodPost, "/admin/license", signedLicence(t, key, p)); code == http.StatusOK {
		t.Fatalf("a licence addressed elsewhere must be refused")
	}
}

// ★ A dry run tells an operator what applying WOULD do. Shrinking the pool below what is already allocated is
// legitimate but means redistribution work, and finding that out afterwards is how a customer's enrolment breaks
// with nobody realising why.
func TestADryRunShowsTheConsequenceBeforeApplying(t *testing.T) {
	mux, key, _, allocs, _ := licenceAdminFixture(t)
	adminCall(t, mux, http.MethodPost, "/admin/license", signedLicence(t, key, testLicence(1000)))
	allocs.Allocate(seatallocation.Policy{PoolSeats: 1000}, "tenant_a", 800, "adm", "", "t0")

	smaller := testLicence(500)
	smaller.Serial = 2
	code, body := adminCall(t, mux, http.MethodPost, "/admin/license?dry_run=true", signedLicence(t, key, smaller))
	if code != http.StatusOK {
		t.Fatalf("dry run: %d %+v", code, body)
	}
	change := body["change"].(map[string]any)
	if change["seats_after"].(float64) != 500 || change["seats_delta"].(float64) != -500 {
		t.Fatalf("the change must be stated: %+v", change)
	}
	if change["over_allocated_after"].(float64) != 300 {
		t.Fatalf("the operator must be told they would be 300 over: %+v", change)
	}
	// And nothing changed: a dry run that applied would be worse than no dry run at all.
	_, after := adminCall(t, mux, http.MethodGet, "/admin/license", "")
	if after["seats"].(float64) != 1000 {
		t.Fatalf("a dry run must not apply anything: %+v", after)
	}
}

// ★★ The support answer. "Customer X cannot enrol a device" is the call an MSSP operator actually gets, and the
// reason comes from the SAME function the enrolment path uses — a reason re-derived in a browser would
// eventually disagree with the one the device was given.
func TestTheTenantViewSaysWhoIsBlockedAndWhy(t *testing.T) {
	declareOperatorTenantForTest(t, "tenant_a")
	mux, key, ledger, allocs, _ := licenceAdminFixture(t)
	adminCall(t, mux, http.MethodPost, "/admin/license", signedLicence(t, key, testLicence(1000)))

	allocs.Allocate(seatallocation.Policy{PoolSeats: 1000}, "tenant_full", 2, "adm", "", "t0")
	allocs.Allocate(seatallocation.Policy{PoolSeats: 1000}, "tenant_room", 50, "adm", "", "t0")
	enrol(t, ledger, "tenant_full", 2)
	enrol(t, ledger, "tenant_room", 1)
	// A tenant with devices and NO allocation: the case an operator gets called about, and the one a view built
	// only from the allocation table would never show.
	enrol(t, ledger, "tenant_unallocated", 1)

	_, body := adminCall(t, mux, http.MethodGet, "/admin/license", "")
	rows := map[string]map[string]any{}
	for _, raw := range body["tenants"].([]any) {
		r := raw.(map[string]any)
		rows[r["tenant_id"].(string)] = r
	}
	if len(rows) != 3 {
		t.Fatalf("every tenant with devices or an allocation must appear: %+v", rows)
	}
	if rows["tenant_full"]["blocked"] != true || rows["tenant_full"]["reason"] == "" {
		t.Fatalf("a full tenant must be shown as blocked WITH a reason: %+v", rows["tenant_full"])
	}
	if rows["tenant_room"]["blocked"] != false {
		t.Fatalf("a tenant with room is not blocked: %+v", rows["tenant_room"])
	}
	// ★ UPDATED WITH THE BEHAVIOUR (2026-08-14). A tenant nobody has given a quota to is no longer BLOCKED —
	// that was the flip where allocating seats to one customer silently stopped enrolment for every other one.
	// The row must still SAY so, though: the original intent of this assertion was that the condition is
	// visible, and only the verdict attached to it has changed.
	if rows["tenant_unallocated"]["blocked"] != false {
		t.Fatalf("a tenant with no quota must no longer be blocked by another tenant's allocation: %+v",
			rows["tenant_unallocated"])
	}
	if !strings.Contains(rows["tenant_unallocated"]["reason"].(string), "no quota set") {
		t.Fatalf("an unallocated tenant must still be visible and named as such: %+v", rows["tenant_unallocated"])
	}
}

// A seat block lapsing shrinks the pool on a date nobody watches. The first symptom would otherwise be an
// enrolment failing.
func TestTheViewWarnsWhenThePoolIsAboutToChange(t *testing.T) {
	mux, key, _, _, _ := licenceAdminFixture(t)
	n := licenceNow()
	p := testLicence(0)
	p.Grants = []vendorlicense.Grant{
		{Seats: 10, EndsAt: n.AddDate(0, 13, 0).Format(time.RFC3339)},
		{Seats: 5, EndsAt: n.AddDate(0, 3, 0).Format(time.RFC3339)},
	}
	adminCall(t, mux, http.MethodPost, "/admin/license", signedLicence(t, key, p))

	_, body := adminCall(t, mux, http.MethodGet, "/admin/license", "")
	if body["seats"].(float64) != 15 {
		t.Fatalf("both blocks are live now: %+v", body["seats"])
	}
	if body["next_pool_change_at"] == nil || body["next_pool_seats"].(float64) != 10 {
		t.Fatalf("the operator must be told the pool drops to 10, and when: %+v", body)
	}
}

func TestAllocationsAreSetAndRemovedThroughTheAPI(t *testing.T) {
	mux, key, ledger, _, _ := licenceAdminFixture(t)
	adminCall(t, mux, http.MethodPost, "/admin/license", signedLicence(t, key, testLicence(100)))

	code, body := adminCallAs(t, mux, http.MethodPost, "/admin/seat-allocations", `{"tenant_id":"tenant_a","seats":60}`, "tenant_a")
	if code != http.StatusOK || body["unallocated"].(float64) != 40 {
		t.Fatalf("allocate: %d %+v", code, body)
	}
	// Past the pool is a conflict, not a bad request: the operator's input is well formed, there simply is not
	// room, and the number they need is in the message.
	if code, _ := adminCallAs(t, mux, http.MethodPost, "/admin/seat-allocations", `{"tenant_id":"tenant_b","seats":50}`, "tenant_b"); code != http.StatusConflict {
		t.Fatalf("over the pool must be a conflict, got %d", code)
	}
	// Reducing below current use is allowed and reported, not refused.
	enrol(t, ledger, "tenant_a", 5)
	_, body = adminCall(t, mux, http.MethodPost, "/admin/seat-allocations", `{"tenant_id":"tenant_a","seats":2}`)
	if body["below_current_use"] != true {
		t.Fatalf("the operator must be told this is below current use: %+v", body)
	}
	if code, _ := adminCall(t, mux, http.MethodDelete, "/admin/seat-allocations/tenant_a", ""); code != http.StatusOK {
		t.Fatalf("remove: %d", code)
	}
	_, body = adminCall(t, mux, http.MethodGet, "/admin/license", "")
	if body["unallocated"].(float64) != 100 {
		t.Fatalf("removing an allocation returns its seats: %+v", body)
	}
}

// A licence that no longer verifies — a withdrawn vendor key — must read differently from one that was never
// installed. They look identical in a table and need opposite responses.
func TestAWithdrawnVendorKeyIsDistinguishableFromNeverLicensed(t *testing.T) {
	mux, key, _, _, d := licenceAdminFixture(t)
	adminCall(t, mux, http.MethodPost, "/admin/license", signedLicence(t, key, testLicence(1000)))

	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	d.acceptedKeys = []*ecdsa.PublicKey{&other.PublicKey}
	mux2 := http.NewServeMux()
	registerAdminLicenseEndpoints(mux2, d, func(_ string, h http.HandlerFunc) http.HandlerFunc { return h })

	_, body := adminCall(t, mux2, http.MethodGet, "/admin/license", "")
	if body["licensed"] != false || body["state"] != "licence_no_longer_verifies" {
		t.Fatalf("a licence under a withdrawn key must say so: %+v", body)
	}
}

func TestGarbageIsRejectedWithAMessageAnOperatorCanAct(t *testing.T) {
	mux, _, _, _, _ := licenceAdminFixture(t)
	for _, body := range []string{`not json at all`, `{}`, `{"type":"x"}`} {
		code, out := adminCall(t, mux, http.MethodPost, "/admin/license", body)
		if code != http.StatusBadRequest {
			t.Fatalf("%q: want 400, got %d", body, code)
		}
		if msg, _ := out["error"].(string); !strings.Contains(msg, "licence file") {
			t.Fatalf("%q: the message must say what was wrong with the FILE, got %q", body, msg)
		}
	}
}

// A sealed licence goes through the same admin route as a plain one. Both shapes are accepted because a
// deployment not yet issued a recipient key still receives plain envelopes, and making an operator pick the
// right menu item — with the wrong pick producing a mystifying error — would be a way to fail for no reason.
func TestASealedLicenceIsAppliedThroughTheSameEndpoint(t *testing.T) {
	mux, key, _, _, d := licenceAdminFixture(t)
	recipient, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("recipient key: %v", err)
	}
	d.recipientKey = recipient
	mux = http.NewServeMux()
	registerAdminLicenseEndpoints(mux, d, func(_ string, h http.HandlerFunc) http.HandlerFunc { return h })

	env, err := vendorlicense.Sign(testLicence(2500), "jv-1", key, licenceNow())
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	sealed, err := vendorlicense.Seal(env, recipient.PublicKey(), "mssp_partner_a-key-1")
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	raw, _ := json.Marshal(sealed)

	code, body := adminCall(t, mux, http.MethodPost, "/admin/license", string(raw))
	if code != http.StatusOK || body["seats"].(float64) != 2500 {
		t.Fatalf("a sealed licence must apply: %d %+v", code, body)
	}
	// And the plain form still works on the same route.
	plain := testLicence(3000)
	plain.Serial = 2
	if code, _ := adminCall(t, mux, http.MethodPost, "/admin/license", signedLicence(t, key, plain)); code != http.StatusOK {
		t.Fatalf("a plain envelope must still apply: %d", code)
	}
}

// Without a recipient key the message must name what is missing, not fail as unparseable — the operator's next
// action is to configure the key, and a decode error would send them looking at the file instead.
func TestASealedLicenceWithNoRecipientKeySaysSo(t *testing.T) {
	mux, key, _, _, _ := licenceAdminFixture(t)
	recipient, _ := ecdh.X25519().GenerateKey(rand.Reader)
	env, _ := vendorlicense.Sign(testLicence(100), "jv-1", key, licenceNow())
	sealed, _ := vendorlicense.Seal(env, recipient.PublicKey(), "")
	raw, _ := json.Marshal(sealed)

	code, body := adminCall(t, mux, http.MethodPost, "/admin/license", string(raw))
	if code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", code)
	}
	if msg, _ := body["error"].(string); !strings.Contains(msg, "no recipient key is configured") {
		t.Fatalf("the message must name the missing configuration, got %q", msg)
	}
}

// ★ EVERY ORGANIZATION'S DEVICE COUNT WAS READABLE BY EVERY ORGANIZATION (2026-08-16, found by an adversarial
// pass over the operator screens, not by a test). GET /admin/license is gated on admin.state.read — which
// every tenant role holds, correctly, since a customer must see its own allowance — and it answered with the
// per-tenant table for the WHOLE deployment. Measured with a customer's own administrator holding no
// cross-tenant permission: it read the other organization's id, allocation and usage.
//
// Capacity ACROSS organizations is the operator's business; one organization's usage is not another's.
func TestACustomerSeesOnlyItsOwnRowInTheLicence(t *testing.T) {
	declareOperatorTenantForTest(t, "tenant_operator")
	mux, _, ledger, _, _ := licenceAdminFixture(t)
	// Two organizations with devices, so there is something to leak.
	mustEnroll(t, ledger, "a-1", "tenant_a")
	mustEnroll(t, ledger, "b-1", "tenant_b")
	mustEnroll(t, ledger, "b-2", "tenant_b")
	// No allocation is needed to make the point: an organization with devices and NO allowance is exactly the
	// row the view exists to show, and it is equally somebody else's business.

	rowsFor := func(identity adminIdentity) []string {
		t.Helper()
		r := httptest.NewRequest(http.MethodGet, "/admin/license", nil)
		r = r.WithContext(context.WithValue(r.Context(), adminIdentityContextKey{}, identity))
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, r)
		if rec.Code != http.StatusOK {
			t.Fatalf("HTTP %d %s", rec.Code, rec.Body.String())
		}
		var body map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode: %v", err)
		}
		ids := []string{}
		for _, row := range body["tenants"].([]any) {
			ids = append(ids, row.(map[string]any)["tenant_id"].(string))
		}
		return ids
	}

	// A customer's own administrator: no cross-tenant permission anywhere.
	customer := rowsFor(adminIdentity{PrincipalID: "adm_b", TenantID: "tenant_b", Roles: []string{"admin"}, AuthMethod: "admin_session"})
	for _, id := range customer {
		if id != "tenant_b" {
			t.Fatalf("a customer administrator read organization %q's capacity (saw %v)", id, customer)
		}
	}
	if len(customer) != 1 {
		t.Fatalf("the customer sees %v; it should see exactly its own row", customer)
	}

	// The control: the operator still sees the whole deployment, or the scoping took away the answer the
	// capacity block exists to give.
	operator := rowsFor(adminIdentity{PrincipalID: "adm_op", TenantID: "tenant_operator", Roles: []string{"owner"}, AuthMethod: "admin_session"})
	if len(operator) < 2 {
		t.Fatalf("the operator sees %v — the scoping cut the operator's view too", operator)
	}
}

// ★★ AND THE FIELDS AROUND THAT TABLE ARE THE OPERATOR'S CONTRACT (2026-08-17, read as the first
// administrator of a self-run organization).
//
// The test above scoped the per-tenant TABLE and stopped there, so the same response went on handing every
// customer the licence's addressee (mssp_id — the operator's own tenant id), its serial, whether the
// deployment is on an evaluation, when the operator's service contract ends, and the grant schedule: how many
// seats they bought and until when. A principal with no cross-tenant permission read all of it.
//
// The pool totals deliberately stay for everyone — "the pool has room" explains a refusal without naming
// anybody. What a customer needs here is whether their devices can enrol and how many seats they hold.
func TestACustomerDoesNotSeeTheOperatorsCommercialTerms(t *testing.T) {
	declareOperatorTenantForTest(t, "tenant_operator")
	mux, key, ledger, _, _ := licenceAdminFixture(t)
	mustEnroll(t, ledger, "b-1", "tenant_b")
	// A licence has to be IN FORCE, or the route answers "no_licence_installed" and returns before it reaches
	// any of the fields this test is about — which is how the first version of it passed for the wrong reason.
	if code, _ := adminCall(t, mux, http.MethodPost, "/admin/license", signedLicence(t, key, testLicence(1000))); code != http.StatusOK {
		t.Fatalf("apply licence: HTTP %d", code)
	}

	bodyFor := func(identity adminIdentity) map[string]any {
		t.Helper()
		r := httptest.NewRequest(http.MethodGet, "/admin/license", nil)
		r = r.WithContext(context.WithValue(r.Context(), adminIdentityContextKey{}, identity))
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

	commercial := []string{"mssp_id", "serial", "is_evaluation", "service_ends_at", "grants"}
	customer := bodyFor(adminIdentity{PrincipalID: "adm_b", TenantID: "tenant_b", Roles: []string{"admin"}, AuthMethod: "admin_session"})
	for _, key := range commercial {
		if _, present := customer[key]; present {
			t.Fatalf("a customer administrator read %q from the licence — that is the record between the "+
				"operator and their vendor, and no customer asked for it", key)
		}
	}

	// What the customer DOES need is still there: can my devices enrol, and how big is the pool.
	for _, key := range []string{"licensed", "enforced", "state", "seats", "unallocated", "tenants"} {
		if _, present := customer[key]; !present {
			t.Fatalf("the scoping removed %q, which is how a customer learns whether its devices can enrol", key)
		}
	}

	// The control: every one of those fields is still answered for the operator, or this is not scoping — it
	// is deletion, and the screen that exists to show a licence would have nothing to show.
	operator := bodyFor(adminIdentity{PrincipalID: "adm_op", TenantID: "tenant_operator", Roles: []string{"owner"}, AuthMethod: "admin_session"})
	for _, key := range commercial {
		if _, present := operator[key]; !present {
			t.Fatalf("the operator can no longer read %q — the licence screen is theirs and it needs it", key)
		}
	}
}
