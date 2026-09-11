package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	agentrollout "github.com/lantern-networks/dsse-core/agentrollout"

	"github.com/lantern-networks/dsse-core/agentupdate"
	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/logs"
	"os"
	"path/filepath"
)

// the rollout decision honors the admin plan, supports rollback (converge to a known-good
// version) and freeze (halt all movement), and falls back to the static target when no plan is set.
func TestAgentRolloutDecision(t *testing.T) {
	// No plan, no static target -> target is current, no update.
	if tgt, _, req := agentrollout.AgentRolloutDecision(agentrollout.AgentRolloutPlan{}, "1.0.0", "", "lab"); tgt != "1.0.0" || req {
		t.Fatalf("no plan/no static: target=%q req=%v", tgt, req)
	}
	// No plan, static target ahead -> follow the static flag (back-compat).
	if tgt, ch, req := agentrollout.AgentRolloutDecision(agentrollout.AgentRolloutPlan{}, "1.0.0", "1.2.0", "lab"); tgt != "1.2.0" || ch != "lab" || !req {
		t.Fatalf("static fallback: target=%q ch=%q req=%v", tgt, ch, req)
	}
	// Rollout plan ahead of the device -> update required to the desired version (overrides static).
	rollout := agentrollout.AgentRolloutPlan{DesiredVersion: "2.0.0", ReleaseChannel: "stable", Intent: agentrollout.AgentRolloutIntentRollout}
	if tgt, ch, req := agentrollout.AgentRolloutDecision(rollout, "1.0.0", "1.2.0", "lab"); tgt != "2.0.0" || ch != "stable" || !req {
		t.Fatalf("rollout: target=%q ch=%q req=%v", tgt, ch, req)
	}
	// Rollback: a device on the bad version is told to converge back to the known-good one.
	rollback := agentrollout.AgentRolloutPlan{DesiredVersion: "1.0.0", Intent: agentrollout.AgentRolloutIntentRollback}
	if tgt, _, req := agentrollout.AgentRolloutDecision(rollback, "2.0.0", "2.0.0", "lab"); tgt != "1.0.0" || !req {
		t.Fatalf("rollback: target=%q req=%v", tgt, req)
	}
	// Already on the desired version -> no update.
	if _, _, req := agentrollout.AgentRolloutDecision(rollout, "2.0.0", "1.2.0", "lab"); req {
		t.Fatal("device already on desired version must not require update")
	}
	// Freeze: halt all movement even though the device is behind the target.
	freeze := agentrollout.AgentRolloutPlan{DesiredVersion: "2.0.0", Frozen: true, Intent: agentrollout.AgentRolloutIntentFreeze}
	if _, _, req := agentrollout.AgentRolloutDecision(freeze, "1.0.0", "1.2.0", "lab"); req {
		t.Fatal("freeze must not require any update")
	}
}

// admin rollout update validation (intent + desired_version rules).
func TestValidateAgentRolloutUpdate(t *testing.T) {
	if p, err := agentrollout.ValidateAgentRolloutUpdate(agentrollout.AgentRolloutUpdateRequest{DesiredVersion: "2.0.0"}); err != nil || p.Intent != agentrollout.AgentRolloutIntentRollout {
		t.Fatalf("default intent should be rollout: %+v err=%v", p, err)
	}
	if p, err := agentrollout.ValidateAgentRolloutUpdate(agentrollout.AgentRolloutUpdateRequest{Intent: "freeze", Reason: "0.2.6 bricked the pilot ring"}); err != nil || !p.Frozen {
		t.Fatalf("freeze should not require a version and must set Frozen: %+v err=%v", p, err)
	}
	if _, err := agentrollout.ValidateAgentRolloutUpdate(agentrollout.AgentRolloutUpdateRequest{Intent: "rollout"}); err == nil {
		t.Fatal("rollout without desired_version must be rejected")
	}
	if _, err := agentrollout.ValidateAgentRolloutUpdate(agentrollout.AgentRolloutUpdateRequest{Intent: "rollback"}); err == nil {
		t.Fatal("rollback without desired_version must be rejected")
	}
	if _, err := agentrollout.ValidateAgentRolloutUpdate(agentrollout.AgentRolloutUpdateRequest{Intent: "sideways", DesiredVersion: "2.0.0"}); err == nil {
		t.Fatal("invalid intent must be rejected")
	}
}

// ★ THIS TEST HAS PINNED THREE DIFFERENT BEHAVIOURS IN ONE DAY, and the sequence is the point.
//
// It began by asserting 200 and that GET reflected the stored plan — both true, both meaningless: the store was
// an in-process map no device read, while devices took their plan from a file on each Edge. A green test
// certified that an operator could halt a bad release while every endpoint carried on installing.
//
// It then asserted a refusal, which was honest and fixed nothing.
//
// It now asserts the rule that makes the write mean something: this endpoint IS the authority on a control
// plane (edges pull from it) and is NOT on an enforcing edge (which pulls, so a local write would be
// overwritten and would reach nobody meanwhile). The same request is accepted in one process and refused in
// the other, and that is what is checked.
func TestTheRolloutHaltIsWritableOnlyWhereItIsTheAuthority(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	newEdge := func(cache *agentRolloutCache) http.Handler {
		return newServerWithConfig(serverConfig{
			Evaluator:         testEvaluator(),
			Writer:            writer,
			Registry:          connector.NewRegistry(),
			AdminAuth:         newAdminAuthStore(),
			AgentRolloutCache: cache,
		})
	}
	put := func(h http.Handler, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPut, "/admin/agent-rollout", strings.NewReader(body))
		req.Header.Set("content-type", "application/json")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	// The halt is the only intent wired to devices; see the handler for why the other two are refused.
	const halt = `{"intent":"freeze","frozen":true,"reason":"bad build 1.5.0"}`

	cp := newEdge(nil)
	got := put(cp, halt)
	if got.Code != http.StatusOK || !strings.Contains(got.Body.String(), "bad build 1.5.0") {
		t.Fatalf("the control plane must accept the halt: code=%d body=%s", got.Code, got.Body.String())
	}
	// ★ And it must not imply the halt is already everywhere: edges poll, and devices poll them.
	if !strings.Contains(got.Body.String(), "next poll") {
		t.Error("the answer must say when this reaches devices rather than implying it already has")
	}

	edge := newEdge(&agentRolloutCache{})
	got = put(edge, halt)
	if got.Code != http.StatusConflict {
		t.Fatalf("an enforcing edge must refuse the write: code=%d body=%s", got.Code, got.Body.String())
	}
	if !strings.Contains(got.Body.String(), "control plane") {
		t.Errorf("the refusal must say where to author it instead, got %s", got.Body.String())
	}
}

// The device-facing plan holds the fleet until an edge that pulls has actually pulled: "I have not been told
// whether this fleet is halted" and "this fleet is not halted" must not render the same.
func TestAnEdgeThatHasNotPulledYetServesFrozen(t *testing.T) {
	rc, err := resolveRolloutControl(serverConfig{AgentRolloutCache: &agentRolloutCache{}}, "tenant_lab")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if !rc.Frozen {
		t.Fatal("an edge with no answer yet must hold the fleet, not release it")
	}
	if !strings.Contains(rc.FrozenReason, "has not managed to read one yet") {
		t.Errorf("the reason must say it is ignorance rather than a halt somebody ordered: %q", rc.FrozenReason)
	}

	cache := &agentRolloutCache{}
	cache.setForTenant("tenant_lab", agentrollout.AgentRolloutPlan{Frozen: true, Reason: "0.2.6 bricked the pilot ring"})
	rc, _ = resolveRolloutControl(serverConfig{AgentRolloutCache: cache}, "tenant_lab")
	if !rc.Frozen || !strings.Contains(rc.FrozenReason, "pilot ring") {
		t.Fatalf("the control plane's halt did not reach the device-facing plan: %+v", rc)
	}
}

// ★ An intent nothing consumes was refused rather than stored with a 200: `rollout`/`rollback` name a desired
// version, and which release a fleet was offered came from the signed manifest alone, so accepting one would
// have been the same silent lie as the endpoint that reached no device at all, moved into a field.
//
// ★★★ ON 2026-08-28 THE FIELD ACQUIRED ITS READER, and the refusal became the untrue half. The device-facing
// manifest route resolves the requesting device's ORGANIZATION from its certificate and serves what that
// organization runs — which is what makes this the customer's own control over its fleet's version.
//
// So the assertion is inverted, and what it now pins is that the answer is stored and readable back: a control
// an administrator sets and cannot see is the shape both halves of this history were about.
func TestTheVersionAnOrganizationRunsIsStoredAndReadableBack(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	plans := agentrollout.NewAgentRolloutStore()
	h := newServerWithConfig(serverConfig{
		Evaluator: testEvaluator(), Writer: writer, Registry: connector.NewRegistry(), AdminAuth: newAdminAuthStore(),
		AgentRolloutPlans: plans,
	})
	req := httptest.NewRequest(http.MethodPut, "/admin/agent-rollout",
		strings.NewReader(`{"intent":"rollback","desired_version":"1.4.2","reason":"bad build"}`))
	req.Header.Set("content-type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200: an organization naming the version it runs is the half of release "+
			"management that is its own — %s", rec.Code, rec.Body.String())
	}
	if got := plans.Get(testEvaluator().PolicyBundle.TenantID).DesiredVersion; got != "1.4.2" {
		t.Fatalf("the version this organization says it runs was not stored: %q", got)
	}
}

func TestAdminAgentRolloutRejectsMalformedRequests(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	handler := newServerWithConfig(serverConfig{
		Evaluator: testEvaluator(),
		Writer:    writer,
		Registry:  connector.NewRegistry(),
		AdminAuth: newAdminAuthStore(),
	})
	do := func(method, path, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("content-type", "application/json")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}
	if bad := do(http.MethodPut, "/admin/agent-rollout", `{"intent":"rollout"}`); bad.Code != http.StatusBadRequest {
		t.Fatalf("rollout without version must be 400; got %d", bad.Code)
	}
}

// ★ CP AUTHORITY IS THE WHOLE DOCUMENT, NOT JUST THE HALT. Leaving the waves and the window in a file on each
// edge meant a fleet had as many schedules as it had edges, and a screen reading one of them reported
// "applied" for all — the per-edge authored-rules defect this codebase has already paid for once.
func TestTheControlPlaneOwnsTheScheduleNotJustTheHalt(t *testing.T) {
	dir := t.TempDir()
	local := filepath.Join(dir, "rollout.json")
	// A file that disagrees with the control plane about everything.
	if err := os.WriteFile(local, []byte(`{"frozen":false,"waves":{"waves":[{"group":"default","delay_days":9}]},`+
		`"window":{"local_start":"01:00","local_end":"02:00","require_idle_minutes":0,"require_unattended":true,`+
		`"require_ac_power":true,"deadline_days":1}}`), 0o600); err != nil {
		t.Fatal(err)
	}

	cache := &agentRolloutCache{}
	cache.setForTenant("tenant_lab", agentrollout.AgentRolloutPlan{
		Frozen: false,
		Waves:  &agentrollout.WaveSchedule{Waves: []agentrollout.RolloutWave{{Group: "pilot", DelayDays: 0}}},
		Window: &agentupdate.PlanWindow{LocalStart: "22:00", LocalEnd: "23:00", DeadlineDays: 7},
	})

	rc, err := resolveRolloutControl(serverConfig{AgentRolloutCache: cache, RolloutControlPath: local}, "tenant_lab")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if len(rc.Waves.Waves) != 1 || rc.Waves.Waves[0].Group != "pilot" {
		t.Fatalf("the file's wave schedule won over the control plane's: %+v", rc.Waves)
	}
	if rc.Window == nil || rc.Window.LocalStart != "22:00" {
		t.Fatalf("the file's window won over the control plane's: %+v", rc.Window)
	}

	// ★ But the file can still HALT. Two ways to stop a fleet, neither able to un-stop the other.
	if err := os.WriteFile(local, []byte(`{"frozen":true,"frozen_reason":"halted on this edge by hand"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	rc, _ = resolveRolloutControl(serverConfig{AgentRolloutCache: cache, RolloutControlPath: local}, "tenant_lab")
	if !rc.Frozen || !strings.Contains(rc.FrozenReason, "by hand") {
		t.Fatalf("a local halt must still hold this edge's devices: %+v", rc)
	}
}

// With nothing authored centrally, the file is all there is — a deployment with no control plane must keep
// working exactly as it did.
func TestWithNoCentralScheduleTheFileStillAnswers(t *testing.T) {
	dir := t.TempDir()
	local := filepath.Join(dir, "rollout.json")
	if err := os.WriteFile(local, []byte(`{"frozen":false,"waves":{"waves":[{"group":"default","delay_days":3}]}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cache := &agentRolloutCache{}
	cache.setForTenant("tenant_lab", agentrollout.AgentRolloutPlan{Frozen: false}) // pulled, but says nothing about the schedule

	rc, err := resolveRolloutControl(serverConfig{AgentRolloutCache: cache, RolloutControlPath: local}, "tenant_lab")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if len(rc.Waves.Waves) != 1 || rc.Waves.Waves[0].DelayDays != 3 {
		t.Fatalf("the file's schedule must still apply when nothing is authored centrally: %+v", rc.Waves)
	}
}

// ★ A BROKEN LOCAL HALT FILE MUST STILL HALT (2026-08-12, fourth review). loadRolloutControl answers a damaged
// file with Frozen=true AND an error — that pairing is the point of it — and the CP-sourced path used the
// result only when the error was nil, discarding the halt. A JSON typo during an incident would have let
// updates continue on the one path built to stop them.
func TestABrokenLocalHaltStillHoldsEvenWhenTheControlPlaneSaysGo(t *testing.T) {
	dir := t.TempDir()
	local := filepath.Join(dir, "rollout.json")
	if err := os.WriteFile(local, []byte(`{"frozen":true, "frozen_reason":"halting 0.2.6" oops`), 0o600); err != nil {
		t.Fatal(err)
	}
	cache := &agentRolloutCache{}
	cache.setForTenant("tenant_lab", agentrollout.AgentRolloutPlan{Frozen: false}) // the control plane is not halted

	rc, err := resolveRolloutControl(serverConfig{AgentRolloutCache: cache, RolloutControlPath: local}, "tenant_lab")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if !rc.Frozen {
		t.Fatal("★ a damaged local halt file let the fleet keep moving")
	}
	if !strings.Contains(rc.FrozenReason, "held until") {
		t.Errorf("the reason must say it is holding because it cannot read the file: %q", rc.FrozenReason)
	}
}

// ★ EDITING THE SCHEDULE MUST NOT TOUCH THE HALT (2026-08-12, fourth review). With rollout/rollback refused,
// the only way to save waves or a window was to piggyback on intent=freeze — which also decides whether the
// fleet is halted, so moving a maintenance window at 10:00 could lift an incident halt somebody set at 03:00.
//
// Driven through the HTTP path deliberately: the previous test filled the cache directly and proved nothing
// about the write path an operator actually uses.
func TestAScheduleChangeGoesThroughHTTPAndLeavesTheHaltAlone(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	store := agentrollout.NewAgentRolloutStore()
	h := newServerWithConfig(serverConfig{
		Evaluator: testEvaluator(), Writer: writer, Registry: connector.NewRegistry(),
		AdminAuth: newAdminAuthStore(), AgentRolloutPlans: store,
	})
	put := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPut, "/admin/agent-rollout", strings.NewReader(body))
		req.Header.Set("content-type", "application/json")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	// An incident halt.
	if got := put(`{"intent":"freeze","frozen":true,"reason":"0.2.6 bricked the pilot ring"}`); got.Code != http.StatusOK {
		t.Fatalf("halt: %d %s", got.Code, got.Body.String())
	}
	// Then, hours later, somebody moves the maintenance window.
	got := put(`{"intent":"schedule","window":{"local_start":"23:00","local_end":"04:00","require_idle_minutes":0,` +
		`"require_unattended":true,"require_ac_power":true,"deadline_days":14}}`)
	if got.Code != http.StatusOK {
		t.Fatalf("schedule: %d %s", got.Code, got.Body.String())
	}

	after := store.Get(testEvaluator().PolicyBundle.TenantID)
	if !after.Frozen {
		t.Fatal("★ a schedule change lifted an incident halt")
	}
	if after.Window == nil || after.Window.LocalStart != "23:00" {
		t.Fatalf("the schedule did not take: %+v", after.Window)
	}
	if !strings.Contains(after.Reason, "pilot ring") {
		t.Errorf("the halt's reason must survive too, got %q", after.Reason)
	}

	// And a schedule request that changes nothing is refused rather than stored as an empty edit.
	if got := put(`{"intent":"schedule"}`); got.Code != http.StatusBadRequest {
		t.Errorf("an empty schedule change must be refused, got %d", got.Code)
	}
	// A window that would silently remove a condition is refused where it is authored.
	if got := put(`{"intent":"schedule","window":{"local_start":"23:00","local_end":"04:00",` +
		`"require_idle_minutes":-1,"require_unattended":true,"require_ac_power":true,"deadline_days":14}}`); got.Code != http.StatusBadRequest {
		t.Errorf("a negative idle requirement must be refused, got %d %s", got.Code, got.Body.String())
	}
}

// ★★ A COMBINED CONTROL PLANE MUST SERVE THE WHOLE AUTHORED PLAN, NOT JUST THE HALT (2026-08-13, thirtieth
// review). The twenty-ninth review fixed "a freeze authored here never reaches devices" by reading the store —
// but only when the plan was FROZEN, and it dropped the Waves on the way out. So an operator's wave schedule
// was accepted with 200, audited, and shown on the admin screen, while every device was served the empty
// schedule from a file that PUT does not write. Same defect as the freeze, one field over.
func TestAWaveScheduleAuthoredOnACombinedControlPlaneReachesDevices(t *testing.T) {
	store := agentrollout.NewAgentRolloutStore()
	waves := agentrollout.WaveSchedule{Waves: []agentrollout.RolloutWave{
		{Group: "pilot", DelayDays: 0},
		{Group: "rest", DelayDays: 2},
	}}
	if err := store.Set("tenant_lab", agentrollout.AgentRolloutPlan{Waves: &waves}); err != nil {
		t.Fatal(err)
	}

	// No cache: this IS the control plane, so there is nothing to pull from.
	rc, err := resolveRolloutControl(serverConfig{AgentRolloutPlans: store}, "tenant_lab")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if rc.Frozen {
		t.Fatal("an unfrozen plan came back frozen")
	}
	if len(rc.Waves.Waves) != 2 || rc.Waves.Waves[0].Group != "pilot" {
		t.Fatalf("the authored wave schedule did not reach the device-facing plan: %+v — every device gets the "+
			"empty schedule while the screen shows the operator's", rc.Waves)
	}
}

// ★ AND IT MUST ANSWER FOR THE DEVICE'S TENANT (#11, same round). Fetching the plan for this Edge's own bundle
// tenant means, on a multi-tenant control plane, that tenant B's freeze reaches nobody while the bundle
// tenant's freeze stops every fleet on the box.
func TestTheHaltComesFromTheDevicesOwnTenant(t *testing.T) {
	store := agentrollout.NewAgentRolloutStore()
	if err := store.Set("tenant_b", agentrollout.AgentRolloutPlan{Frozen: true, Reason: "B's pilot ring is bricked"}); err != nil {
		t.Fatal(err)
	}

	rc, _ := resolveRolloutControl(serverConfig{AgentRolloutPlans: store}, "tenant_b")
	if !rc.Frozen || !strings.Contains(rc.FrozenReason, "pilot ring") {
		t.Fatalf("tenant B's own halt did not reach its devices: %+v", rc)
	}
	// And it must not leak the other way: a tenant with no halt is not stopped by someone else's.
	rc, _ = resolveRolloutControl(serverConfig{AgentRolloutPlans: store}, "tenant_a")
	if rc.Frozen {
		t.Fatalf("tenant A was frozen by tenant B's halt: %+v", rc)
	}
}

// ★★ A PULLING EDGE SERVES ONE TENANT'S PLAN, AND MUST NOT HAND IT TO ANOTHER TENANT'S DEVICES (2026-08-13,
// thirty-first review #6). The previous round fixed this for a combined control plane and left the pulling
// topology exactly as it was: the cache holds a single plan, pulled for this Edge's own tenant, while the route
// stamps the document it signs with the DEVICE's tenant from its client certificate. A tenant-B device
// therefore received a plan labelled tenant B carrying tenant A's freeze — so B's halt reached nobody and A's
// halt stopped everybody, with a document that looked correct.
func TestAPullingEdgeHoldsADeviceWhoseTenantItHasNoPlanFor(t *testing.T) {
	cache := &agentRolloutCache{}
	cache.setForTenant("tenant_a", agentrollout.AgentRolloutPlan{Frozen: true, Reason: "A's pilot ring is bricked"})

	// A device of tenant A gets tenant A's answer.
	rc, err := resolveRolloutControl(serverConfig{AgentRolloutCache: cache}, "tenant_a")
	if err != nil {
		t.Fatal(err)
	}
	if !rc.Frozen || !strings.Contains(rc.FrozenReason, "pilot ring") {
		t.Fatalf("tenant A's own halt did not reach its devices: %+v", rc)
	}

	// A device of tenant B must NOT be given it — and must not be told it is free either.
	rc, err = resolveRolloutControl(serverConfig{AgentRolloutCache: cache}, "tenant_b")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(rc.FrozenReason, "pilot ring") {
		t.Fatalf("tenant B was served tenant A's halt: %+v", rc)
	}
	if !rc.Frozen {
		t.Fatal("tenant B was told it is not halted by an edge that has never been told whether it is — " +
			"'I have not heard' and 'not halted' must not render the same")
	}
	if !strings.Contains(rc.FrozenReason, "tenant_b") {
		t.Fatalf("the reason must name the tenant nobody answered for: %q", rc.FrozenReason)
	}
}
