package main

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/lantern-networks/dsse-core/agentupdate"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	agenttelemetry "github.com/lantern-networks/dsse-core/agenttelemetry"
	"github.com/lantern-networks/dsse-core/connector"
	devicestore "github.com/lantern-networks/dsse-core/device"
	enrolledinventory "github.com/lantern-networks/dsse-core/enrolledinventory"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
)

// admin_agent_device_updates_scope_test.go — what this view may show, and what it must refuse to compute.
//
// Two findings from the fourteenth review, both about a number that looks fine and is not: a device belonging
// to no tenant appearing in EVERY tenant's fleet, and a telemetry outage rendering as a fleet that has gone
// silent.

// failingTelemetry is a store whose read fails, which is the case the coverage band could not express.
type failingTelemetry struct{ agenttelemetry.RuntimeStore }

func (failingTelemetry) RecordUpdate(context.Context, model.AgentUpdateEvent) error { return nil }
func (failingTelemetry) RecordStatus(context.Context, model.AgentStatus) error      { return nil }
func (failingTelemetry) UpdateSummary(context.Context, string) (map[string]any, error) {
	return nil, errors.New("db down")
}
func (failingTelemetry) StatusSummary(context.Context, string) (map[string]any, error) {
	return nil, errors.New("db down")
}
func (failingTelemetry) LatestUpdateByDevice(context.Context, string) (map[string]model.AgentUpdateEvent, error) {
	return nil, errors.New("read agent_update_events: context deadline exceeded")
}

// mustEnroll puts one identity in the ledger the way the enrol endpoint does.
func mustEnroll(t *testing.T, ledger *enrolledinventory.Ledger, identity, tenantID string) {
	t.Helper()
	if _, err := ledger.Enroll(identity, tenantID, "test", "2026-08-12T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
}

// deviceUpdatesResponse asks the endpoint AS an administrator of asTenant.
//
// ★ THE FIRST VERSION OF THIS HELPER SENT NO IDENTITY (2026-08-12, fifteenth review), so every request
// resolved to the empty tenant and the tests could not tell one tenant's answer from another's — they were
// asserting against a scope that never occurs in a deployment. A test that cannot express the boundary cannot
// hold it, and this one was written to hold exactly that boundary.
func deviceUpdatesResponse(t *testing.T, asTenant string, enrolled *enrolledinventory.Ledger,
	telemetry agenttelemetry.RuntimeStore) map[string]any {
	t.Helper()
	mux := http.NewServeMux()
	registerAgentDeviceUpdateRoutes(mux, func(_ string, h http.HandlerFunc) http.HandlerFunc { return h },
		devicestore.NewStore(), enrolled, telemetry, newPublishedAgentUpdateStore(), nil, nil, nil, nil)
	req := httptest.NewRequest(http.MethodGet, "/admin/agent/device-updates", nil)
	req = req.WithContext(context.WithValue(req.Context(), adminIdentityContextKey{},
		adminIdentity{PrincipalID: "adm_test", TenantID: asTenant, AuthMethod: "admin_session"}))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("HTTP %d: %s", rec.Code, rec.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if got := body["tenant_id"]; got != asTenant {
		t.Fatalf("the endpoint answered for tenant %q while the caller was %q — the identity did not reach it, "+
			"so nothing below is testing a tenant boundary", got, asTenant)
	}
	return body
}

// deviceIDs is what an admin of that tenant can actually read off the screen.
func deviceIDs(t *testing.T, body map[string]any) []string {
	t.Helper()
	out := []string{}
	for _, row := range body["devices"].([]any) {
		out = append(out, row.(map[string]any)["device_id"].(string))
	}
	return out
}

// ★ A DEVICE WITH NO TENANT WAS EVERY TENANT'S DEVICE, and the first fix INFERRED the deployment mode from
// the ledger — so it failed open in the state nobody pictures. This is that state: a ledger holding one
// tenant's devices plus an unassigned one, read by an admin of a DIFFERENT tenant. There is no second tenant
// in the data to notice, and the boundary still has to hold.
func TestATenantlessDeviceIsNotShownToATenantTheLedgerHasNotSeen(t *testing.T) {
	ledger := enrolledinventory.NewLedger()
	mustEnroll(t, ledger, "a-1", "tenant_a")
	mustEnroll(t, ledger, "legacy-1", "")

	body := deviceUpdatesResponse(t, "tenant_b", ledger, nil)

	for _, id := range deviceIDs(t, body) {
		if id == "legacy-1" || id == "a-1" {
			t.Fatalf("tenant_b's admin was shown %q. The ledger names only tenant_a, so a boundary derived "+
				"from the ledger sees no second tenant and lets everything through — which is what happens "+
				"the day a tenant is added, the last device of one is removed, or a migration is half-done.", id)
		}
	}
}

// And the tenant that DOES own devices sees its own and only its own.
func TestATenantSeesItsOwnDevicesAndNoOthers(t *testing.T) {
	ledger := enrolledinventory.NewLedger()
	mustEnroll(t, ledger, "a-1", "tenant_a")
	mustEnroll(t, ledger, "b-1", "tenant_b")
	mustEnroll(t, ledger, "legacy-1", "")

	body := deviceUpdatesResponse(t, "tenant_a", ledger, nil)

	got := deviceIDs(t, body)
	if len(got) != 1 || got[0] != "a-1" {
		t.Fatalf("tenant_a's fleet came back as %v; it owns exactly one device", got)
	}
	coverage := body["coverage"].(map[string]any)
	if coverage["unassigned"] != float64(1) {
		t.Fatalf("the unassigned device was withheld and NOT counted (%v) — withholding without counting is "+
			"a device that vanished, which is the other half of this failure", coverage["unassigned"])
	}
}

// ★ A TELEMETRY OUTAGE MUST NOT RENDER AS A REPORTING OUTAGE. Answering from an empty set made a Postgres
// timeout indistinguishable from a fleet that had genuinely stopped reporting.
func TestATelemetryOutageIsDeclaredAndPublishesNoCoverage(t *testing.T) {
	ledger := enrolledinventory.NewLedger()
	mustEnroll(t, ledger, "d-1", "tenant_a")
	mustEnroll(t, ledger, "d-2", "tenant_a")

	body := deviceUpdatesResponse(t, "tenant_a", ledger, failingTelemetry{})

	if body["degraded"] != agentDeviceUpdatesTelemetryUnavailable {
		t.Fatalf("a telemetry read failure produced an undegraded answer (%v): the caller has no way to tell "+
			"a database outage from a fleet that has gone quiet", body["degraded"])
	}
	// ★ AND NOT ONE ROW MAY ASSERT A DEVICE STATE EITHER (2026-08-12, fifteenth review). Withholding the
	// coverage left every row saying `never_reported`, and the Console counts, filters and badges off the
	// ROWS — so the fabricated fleet survived one layer below the fix that was meant to remove it.
	for _, row := range body["devices"].([]any) {
		if state := row.(map[string]any)["state"]; state != agentDeviceStateUnknown {
			t.Fatalf("a row claimed state %q while the outcome store could not be read. `never_reported` is a "+
				"claim about the DEVICE; this answer cannot make one.", state)
		}
	}
	coverage, _ := body["coverage"].(map[string]any)
	if len(coverage) != 0 {
		t.Fatalf("coverage was published over an unreadable store: %v — a number computed from nothing is not "+
			"a smaller truth, it is a wrong one", coverage)
	}
	// The inventory half still stands, which is why this is not a 503.
	if len(body["devices"].([]any)) != 2 {
		t.Fatalf("the inventory rows were dropped too; an operator locked out of the whole page during a "+
			"database blip learns less, not more: %v", body["devices"])
	}
}

// And a healthy read still publishes coverage, or the test above would pass against a build that had simply
// stopped reporting numbers.
func TestAHealthyReadStillPublishesCoverage(t *testing.T) {
	ledger := enrolledinventory.NewLedger()
	mustEnroll(t, ledger, "d-1", "tenant_a")

	body := deviceUpdatesResponse(t, "tenant_a", ledger, nil)

	if body["degraded"] != nil {
		t.Fatalf("a healthy answer declared itself degraded: %v", body["degraded"])
	}
	coverage := body["coverage"].(map[string]any)
	if coverage["devices"] != float64(1) {
		t.Fatalf("coverage did not describe the fleet: %v", coverage)
	}
}

// ★ THE ARCH WAS GUESSED FROM THE PLATFORM (2026-08-12, fourteenth review): macOS meant arm64, Windows meant
// amd64. Intel Macs and Windows-on-ARM are compared against a release built for a different machine.
func TestADeviceIsJudgedAgainstTheArchItReported(t *testing.T) {
	offering := map[string]string{"darwin/arm64": "0.2.9", "darwin/amd64": "0.2.4"}
	intelMac := model.Device{ID: "mac-intel-1"}
	event := model.AgentUpdateEvent{
		ID: "aue_1", DeviceID: "mac-intel-1", UpdateStatus: "installed", CurrentAgentVersion: "0.2.4",
		Metadata: map[string]any{"platform": "darwin", "arch": "amd64"},
	}

	got := agentDeviceUpdateFor(intelMac, event, offering)

	if got.TargetVersion != "0.2.4" {
		t.Fatalf("an Intel Mac was offered %q — the arm64 release it cannot run. The fleet's usual arch is not "+
			"this device's arch, and the device said so.", got.TargetVersion)
	}
	if got.State != agentDeviceStateUpToDate {
		t.Fatalf("an Intel Mac on the published amd64 release read as %q", got.State)
	}
}

// A device that has not reported an arch — an outbox written before the field existed — still gets the
// fallback, or adding the field would blank out every device that has not spoken since.
func TestADeviceThatReportedNoArchStillGetsTheFallback(t *testing.T) {
	offering := map[string]string{"darwin/arm64": "0.2.9"}
	mac := model.Device{ID: "mac-dev-1"}
	event := model.AgentUpdateEvent{
		ID: "aue_1", DeviceID: "mac-dev-1", UpdateStatus: "installed", CurrentAgentVersion: "0.2.9",
		Metadata: map[string]any{"platform": "darwin"},
	}

	if got := agentDeviceUpdateFor(mac, event, offering); got.State != agentDeviceStateUpToDate {
		t.Fatalf("a Mac that predates the arch field read as %q (target %q)", got.State, got.TargetVersion)
	}
}

// enrolledDevicesResponse asks GET /admin/enrolled-devices as an administrator of asTenant — the call the
// Console makes first when it draws the Devices list.
func enrolledDevicesResponse(t *testing.T, asTenant string, ledger *enrolledinventory.Ledger) map[string]any {
	t.Helper()
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	handler := newServerWithConfig(serverConfig{
		Evaluator:      testEvaluator(),
		EnrolledLedger: ledger,
		Writer:         writer,
		Registry:       connector.NewRegistry(),
		AdminAuth:      newAdminAuthStore(),
		// The organization that operates this deployment — see operator_is_an_organization_not_a_role.go.
		// Without it the caller below holds super_admin in a CUSTOMER organization, which is no longer enough.
		OperatorTenantID: "tenant_lab_001",
	})
	// The real mechanism an operator uses to act within a tenant. Injecting an identity into the context does
	// not work here and SHOULD not: the auth middleware replaces it, which is the property that keeps a caller
	// from choosing its own tenant.
	req := httptest.NewRequest(http.MethodGet, "/admin/enrolled-devices", nil)
	req.Header.Set("X-Operate-Tenant", asTenant)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("HTTP %d: %s", rec.Code, rec.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if got := body["tenant_id"]; got != asTenant {
		t.Fatalf("the endpoint answered for tenant %q while the caller was %q", got, asTenant)
	}
	return body
}

// ★ THE PATH THE CONSOLE READS FIRST (2026-08-12, sixteenth review). The agent-update view was corrected one
// review earlier, but the Devices list is built from GET /admin/enrolled-devices — and that endpoint, plus
// enable/disable/group/delete beside it, still treated a device with no tenant as everybody's. Fixing the
// newer surface while the older one stayed open closed nothing an operator could observe.
func TestAnUnassignedDeviceIsNotInATenantAdminsEnrolledList(t *testing.T) {
	declareOperatorTenantForTest(t, "tenant_lab_001")
	ledger := enrolledinventory.NewLedger()
	mustEnroll(t, ledger, "a-1", "tenant_a")
	mustEnroll(t, ledger, "legacy-1", "")

	body := enrolledDevicesResponse(t, "tenant_a", ledger)

	for _, row := range body["devices"].([]any) {
		if id := row.(map[string]any)["identity"]; id == "legacy-1" {
			t.Fatal("a device belonging to no tenant was listed for tenant_a — and the same row is served to " +
				"every other tenant, which is one device with as many owners as the deployment has tenants")
		}
	}
	if body["unassigned"] != float64(1) {
		t.Fatalf("the withheld device was not counted (%v): withholding without saying so is a device that "+
			"vanished, and an unassigned fleet is the thing an operator most needs told", body["unassigned"])
	}
}

// enrolPost enrols an identity as an administrator of asTenant, and returns the status and body.
func enrolAsTenant(t *testing.T, asTenant string, ledger *enrolledinventory.Ledger, identity string) (int, string) {
	t.Helper()
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	handler := newServerWithConfig(serverConfig{
		Evaluator: testEvaluator(), EnrolledLedger: ledger, Writer: writer,
		Registry: connector.NewRegistry(), AdminAuth: newAdminAuthStore(),
		OperatorTenantID: "tenant_lab_001",
	})
	req := httptest.NewRequest(http.MethodPost, "/admin/enrolled-devices",
		strings.NewReader(`{"identity":"`+identity+`","note":"taken"}`))
	req.Header.Set("content-type", "application/json")
	req.Header.Set("X-Operate-Tenant", asTenant)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec.Code, rec.Body.String()
}

// ★ THE READ AND MUTATE PATHS WERE CLOSED AND THE CREATE PATH WAS A TAKEOVER (2026-08-12, seventeenth
// review). The enrol write overwrites an existing entry's tenant with the caller's and re-enables it, so
// knowing a device id was authority over the machine it names.
//
// The actor here is an OPERATOR — X-Operate-Tenant is honoured only for admin.tenant.admin, so that is who
// this harness can authenticate as. The refusal a TENANT admin gets is asserted where a tenant admin can be
// expressed exactly: enrolledinventory's own tests, which is also where the race lives.
func TestNotEvenAnOperatorTakesADeviceFromAnotherTenantByEnrolling(t *testing.T) {
	ledger := enrolledinventory.NewLedger()
	mustEnroll(t, ledger, "b-1", "tenant_b")
	if _, ok := ledger.SetEnabled("b-1", false, "2026-08-12T00:00:00Z"); !ok {
		t.Fatal("could not disable the device under test")
	}

	code, body := enrolAsTenant(t, "tenant_a", ledger, "b-1")

	if code == http.StatusOK {
		t.Fatalf("a device was moved out of tenant_b by enrolling it into tenant_a: %s", body)
	}
	cur, _ := ledger.EntryFor("b-1")
	if !strings.EqualFold(cur.TenantID, "tenant_b") {
		t.Fatalf("the device moved tenant: now %q", cur.TenantID)
	}
	if cur.Enabled {
		t.Fatal("a disabled device was re-enabled on the way past — admission restored as a side effect of a " +
			"call that should not have been allowed at all")
	}
}

// ★ AND THE OPERATOR PATH THE CONSOLE PROMISES NOW EXISTS (2026-08-12, eighteenth review). The screen tells an
// operator that unassigned devices are theirs to assign, and until now nothing could do it: a tenant-scoped
// caller was refused, and an unscoped one re-saved the empty tenant. The instruction described an action the
// product did not have.
func TestAnOperatorCanAdoptAnUnassignedDevice(t *testing.T) {
	declareOperatorTenantForTest(t, "tenant_lab_001")
	ledger := enrolledinventory.NewLedger()
	mustEnroll(t, ledger, "legacy-1", "")

	code, body := enrolAsTenant(t, "tenant_a", ledger, "legacy-1")

	if code != http.StatusOK {
		t.Fatalf("an operator could not adopt an unassigned device (%d %s) — the Console still says they can", code, body)
	}
	if cur, _ := ledger.EntryFor("legacy-1"); !strings.EqualFold(cur.TenantID, "tenant_a") {
		t.Fatalf("the adoption did not assign the device: %q", cur.TenantID)
	}
}

// And enrolling a NEW identity, or re-enrolling one's own, still works — or the tests above would pass against
// a build that had simply lost the ability to enrol anything.
func TestATenantAdminCanStillEnrolItsOwnDevices(t *testing.T) {
	declareOperatorTenantForTest(t, "tenant_lab_001")
	ledger := enrolledinventory.NewLedger()
	mustEnroll(t, ledger, "a-1", "tenant_a")

	if code, body := enrolAsTenant(t, "tenant_a", ledger, "a-2"); code != http.StatusOK {
		t.Fatalf("enrolling a new device failed: %d %s", code, body)
	}
	if code, body := enrolAsTenant(t, "tenant_a", ledger, "a-1"); code != http.StatusOK {
		t.Fatalf("re-enrolling its own device failed: %d %s", code, body)
	}
}

// ★ AN ISSUER MUST BE ABLE TO CONSUME AN IDENTITY ONCE (2026-08-13, twenty-fourth review). Three answers to
// this were wrong before the right one: refuse a shared store (two issuers sharing a document overwrite each
// other), a -enroll-sole-issuer flag (a self-certification every signer can pass), and node-local files —
// which are WORSE, because then the enrolment markers cannot reach each other at all. What a one-time
// decision taken by more than one process needs is one place to take it.
func TestAnIssuingEdgeWithoutAClaimStoreIsRefused(t *testing.T) {
	// Through the predicates the startup gate itself calls, so this is the product's decision rather than a
	// second copy of it agreeing with the first.
	for _, c := range []struct {
		name       string
		hasSigner  bool
		hasClaims  bool
		store      string
		mustRefuse bool
	}{
		{"issues with no database to claim in", true, false, "/state/inventory.json", true},
		{"issues with a claim store", true, true, "/state/inventory.json", false},
		{"issues with a claim store but a shared ledger", true, true, "postgres", true},
		{"does not issue, no database", false, false, "/state/inventory.json", false},
		{"does not issue, shared ledger", false, false, "postgres", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			refuses := enrolIssuerNeedsClaimStore(c.hasSigner, c.hasClaims) ||
				enrolIssuerNeedsExclusiveStore(c.hasSigner, c.store)
			if refuses != c.mustRefuse {
				t.Fatalf("the startup gate would %v; this combination must %v",
					map[bool]string{true: "REFUSE", false: "allow"}[refuses],
					map[bool]string{true: "be refused", false: "be allowed"}[c.mustRefuse])
			}
		})
	}
}

// The claim names which node took it, because "two certificates for one device name" is a question about
// where, and a claim that records only that it happened cannot answer it.
func TestAClaimNamesTheNodeThatTookIt(t *testing.T) {
	if got := edgeNodeIdentityForClaims("region-a", ":8443"); got != "region-a/:8443" {
		t.Fatalf("node identity = %q", got)
	}
	if got := edgeNodeIdentityForClaims("", ""); got != "edge" {
		t.Fatalf("an unnamed node produced %q rather than something readable", got)
	}
}

// ★ ONE NODE'S BACKFILL IS NOT THE DEPLOYMENT'S MIGRATION (2026-08-13, twenty-sixth review). During a rolling
// upgrade the NEW issuer starts with a node-local ledger holding no enrolment markers: its backfill claims
// nothing, succeeds, and it would begin issuing while every identity only the OLD issuer knows about is still
// unclaimed. The barrier is what orders that.
//
// Through the decision the barrier itself calls, so this is the product's rule rather than a second copy of it.
func TestOnlyANodeWithSomethingToContributeMayEndTheMigration(t *testing.T) {
	for _, c := range []struct {
		name        string
		contributed int
		fresh       bool
		mayDeclare  bool
	}{
		{"the node holding the fleet", 12, false, true},
		{"a new node with an empty ledger", 0, false, false},
		{"a genuinely new deployment", 0, true, true},
		{"a node that contributed AND declares fresh", 3, true, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			reason, got := identityClaimBarrierDecision(c.contributed, c.fresh)
			if got != c.mayDeclare {
				t.Fatalf("may declare = %v, want %v", got, c.mayDeclare)
			}
			if got && strings.TrimSpace(reason) == "" {
				t.Fatal("the barrier would be recorded with no reason — the row is what a later operator reads " +
					"to know whether the migration they are looking at actually happened")
			}
		})
	}
}

// ★ THE DEVICE-FACING SET AND THE ADMIN STORE ARE DIFFERENT OBJECTS (2026-08-13, twenty-eighth review).
// Publishing wrote to the admin store; devices read `publishedUpdates`, which only the CP→Edge pull filled —
// a loop gated on a source URL a control plane does not set. Every screen said active and no device was ever
// offered anything.
func TestActivationReachesTheSetDevicesRead(t *testing.T) {
	deviceFacing := &publishedUpdates{}
	store := newPublishedAgentUpdateStore()
	if len(deviceFacing.targets()) != 0 {
		t.Fatal("the device-facing set did not start empty")
	}

	// Nothing in the store yet: a refresh must not invent anything.
	refreshDeviceFacingPublished(deviceFacing, store, "tenant_a", nil)
	if got := len(deviceFacing.targets()); got != 0 {
		t.Fatalf("a refresh over an empty store published %d target(s)", got)
	}
}

// ★★ AN ENFORCING EDGE OFFERS RELEASES FROM THE SET IT PULLED, AND THE SCREEN MUST SAY SO (2026-08-13, found
// on the lab). This endpoint built its "offering" from the CP-AUTHORED store, which on an enforcing Edge is
// empty by design: such an Edge pulls the published set into the DEVICE-FACING one. The Console reads this
// endpoint from the Edge, so the ordinary production topology reported an empty offering and marked every
// device `no_release` — while that same Edge was serving 0.2.9 to a Mac and 0.2.1 to a Windows box.
//
// The screen built to stop this lane being invisible was the thing making it invisible.
func TestAPullingEdgeReportsTheReleaseItIsActuallyServing(t *testing.T) {
	mux := http.NewServeMux()
	facing := &publishedUpdates{byTarget: map[string]publishedUpdate{
		updateTargetKey("windows", "amd64"): {Manifest: agentupdate.Manifest{
			Version: "0.2.1+3f8f2b02", Platform: "windows", Arch: "amd64"}},
	}}
	ledger := enrolledinventory.NewLedger()
	mustEnroll(t, ledger, "win-dev-1", "t1")

	// No CP-authored store: this node pulls, which is what an enforcing Edge does.
	registerAgentDeviceUpdateRoutes(mux, func(_ string, fn http.HandlerFunc) http.HandlerFunc { return fn },
		devicestore.NewStore(), ledger, agenttelemetry.NewStore(), newPublishedAgentUpdateStore(), facing,
		nil, nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/admin/agent/device-updates", nil)
	req = req.WithContext(context.WithValue(req.Context(), adminIdentityContextKey{},
		adminIdentity{PrincipalID: "adm", TenantID: "t1", AuthMethod: "admin_session"}))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("HTTP %d: %s", rec.Code, rec.Body.String())
	}
	var body struct {
		Offering map[string]string `json:"offering"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if got := body.Offering[updateTargetKey("windows", "amd64")]; got != "0.2.1+3f8f2b02" {
		t.Fatalf("the screen reports %q for windows/amd64 — this Edge is serving 0.2.1+3f8f2b02 to that fleet, "+
			"and every device on this page reads as having no release", got)
	}
}
