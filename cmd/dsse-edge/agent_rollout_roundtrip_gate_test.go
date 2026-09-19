package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/agentrollout"
	"github.com/lantern-networks/dsse-core/agentupdate"
	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/logs"
)

// agent_rollout_roundtrip_gate_test.go — GATE 1 of the four the convergence plan asks for: what an
// administrator writes must arrive at the endpoint a DEVICE reads.
//
// ★★ WHY THIS SHAPE AND NOT A UNIT TEST (2026-08-13, thirty-first review #10). Every existing test of this
// lane calls resolveRolloutControl directly, and three separate defects in three consecutive rounds lived in
// the wiring BETWEEN the admin write and the device route — a freeze stored where the device path never read
// it, a wave schedule dropped on the way out, a plan answered for the wrong tenant. A function tested in
// isolation was correct in every one of them.
//
// So this drives both ends: PUT /admin/agent-rollout, then GET /steer/agent-update-plan as a device with a
// verified client certificate, and asserts the device is served what the operator authored. It is deliberately
// blind to how the two are connected, because that is the part that keeps breaking.

// planGateHarness wires the admin write route and the device read route over ONE store, the way a combined
// control plane does.
type planGateHarness struct {
	mux       *http.ServeMux
	plans     *agentrollout.AgentRolloutStore
	published *publishedUpdates
}

func newPlanGateHarness(t *testing.T) *planGateHarness {
	t.Helper()
	return newPlanGateHarnessAt(t, "")
}

// newPlanGateHarnessAt backs the store with a file, so a "restart" is a second harness over the same path.
func newPlanGateHarnessAt(t *testing.T, storePath string) *planGateHarness {
	t.Helper()
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	h := &planGateHarness{mux: http.NewServeMux(), plans: agentrollout.NewAgentRolloutStore(),
		published: &publishedUpdates{byTarget: map[string]publishedUpdate{}}}
	if storePath != "" {
		if err := h.plans.LoadFrom(storePath); err != nil {
			t.Fatalf("load the rollout store: %v", err)
		}
	}
	evaluator := decision.Evaluator{}
	config := serverConfig{
		AgentRolloutPlans:  h.plans,
		PublishedUpdates:   h.published,
		RolloutControlPath: t.TempDir() + "/rollout.json", // absent: the store is the authority
		Evaluator:          evaluator,
	}
	registerAgentQualityRoutes(h.mux, func(_ string, fn http.HandlerFunc) http.HandlerFunc { return fn },
		evaluator, writer, nil, nil, h.plans, "0.3.0", "stable", nil, nil, nil)
	registerSteerAgentUpdatePlanRoutes(h.mux, config, agentUpdatePlanTenant{id: ""})
	return h
}

// authorAs performs the admin write an operator performs.
func (h *planGateHarness) authorAs(t *testing.T, tenant string, body string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPut, "/admin/agent-rollout", strings.NewReader(body))
	req = req.WithContext(context.WithValue(req.Context(), adminIdentityContextKey{},
		adminIdentity{PrincipalID: "adm_gate", TenantID: tenant, AuthMethod: "admin_session"}))
	rec := httptest.NewRecorder()
	h.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("the admin write failed: %d %s", rec.Code, rec.Body.String())
	}
}

// asDevice reads the plan the way an agent does: a verified client certificate, no admin session.
func (h *planGateHarness) asDevice(t *testing.T, identity string) map[string]any {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/steer/agent-update-plan?platform=windows&arch=amd64", nil)
	leaf := &x509.Certificate{Subject: pkix.Name{CommonName: identity}}
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{leaf},
		VerifiedChains:   [][]*x509.Certificate{{leaf}},
	}
	rec := httptest.NewRecorder()
	h.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("the device could not read its plan: %d %s", rec.Code, rec.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("the plan is not JSON: %v", err)
	}
	return out
}

// planPayload digs the signed-or-bare plan document out of whatever the route returned.
func planPayload(t *testing.T, body map[string]any) map[string]any {
	t.Helper()
	if _, ok := body["frozen"]; ok {
		return body
	}
	if raw, ok := body["payload_b64"].(string); ok {
		t.Fatalf("the plan came back as a signed envelope (%d chars) and this harness signs nothing — the "+
			"assertions below need the payload", len(raw))
	}
	return body
}

// ★ A FREEZE AN OPERATOR AUTHORS MUST REACH THE DEVICE ENDPOINT. This is review 29 #1 and review 30 #3 in one
// assertion: the freeze was stored where the device path did not read it, and then the fix carried the freeze
// and dropped everything else.
func TestGateOneAnAuthoredHaltReachesTheDeviceEndpoint(t *testing.T) {
	h := newPlanGateHarness(t)
	h.authorAs(t, "", `{"intent":"freeze","reason":"0.3.0 bricked the pilot ring"}`)

	got := planPayload(t, h.asDevice(t, "win-dev-1"))
	frozen, _ := got["frozen"].(bool)
	if !frozen {
		t.Fatalf("the device was NOT told the fleet is halted: %v", got)
	}
	if reason, _ := got["frozen_reason"].(string); !strings.Contains(reason, "pilot ring") {
		t.Fatalf("the operator's reason did not travel: %q", reason)
	}
}

// ★ AND SO MUST THE SCHEDULE — as the effect it has on THIS device (2026-08-13). Review 30 #3: the combined
// control plane returned the store's answer only when it was FROZEN, so a wave schedule was accepted, audited
// and displayed while every device got an empty one.
//
// The device is not sent the fleet's schedule, and should not be: it is sent the moment ITS wave opens,
// computed here from the authored delays and the release instant. So the assertion is on eligible_since, which
// is the only part of a schedule a device can act on — and the first version of this test looked for a "waves"
// field the plan deliberately does not carry. The gate caught the test.
func TestGateOneAnAuthoredWaveScheduleMovesThisDevicesEligibility(t *testing.T) {
	h := newPlanGateHarness(t)
	released := time.Now().UTC().Add(-time.Hour)
	h.published.replace(map[string]publishedUpdate{
		updateTargetKey("windows", "amd64"): {Manifest: agentupdate.Manifest{
			Version: "0.3.0", Platform: "windows", Arch: "amd64",
			ReleasedAt: released.Format(time.RFC3339),
		}},
	})

	// No groups for this device, so it takes the SLOWEST wave — the rule that stops an unscheduled group
	// becoming a same-day fleet-wide rollout by omission.
	h.authorAs(t, "", `{"intent":"freeze","frozen":false,"reason":"scheduling the ring order",
		"waves":{"waves":[{"group":"pilot","delay_days":0},{"group":"rest","delay_days":3}]}}`)

	got := planPayload(t, h.asDevice(t, "win-dev-1"))
	eligible, _ := got["eligible_since"].(string)
	if eligible == "" {
		t.Fatalf("the device was given no wave start, so the authored schedule reached nothing: %v", got)
	}
	at, err := time.Parse(time.RFC3339, eligible)
	if err != nil {
		t.Fatal(err)
	}
	if delay := at.Sub(released).Round(time.Hour); delay != 72*time.Hour {
		t.Fatalf("this device's wave opens %s after the release; the authored slowest wave is 3 days, so the "+
			"schedule an operator wrote is not the one being applied", delay)
	}
}

// ★★ GATE 2: WHAT SURVIVED THE RESTART IS WHAT THE DEVICE READS (2026-08-13, thirty-first review #10).
//
// Restart survival was tested in pieces and never through the device-facing route, which is where this lane's
// defects live: a value can persist perfectly and still not reach an endpoint, and this product has shipped
// exactly that — a published release restored to the admin screen while devices got 404, and a halt stored
// where the device path never looked.
//
// So the assertion is end to end across a process boundary: author through the admin route, throw the process
// away, build a new one over the same file, and ask AS A DEVICE.
func TestGateTwoAHaltSurvivesARestartAllTheWayToTheDevice(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent_rollout.json")

	first := newPlanGateHarnessAt(t, path)
	first.authorAs(t, "", `{"intent":"freeze","reason":"0.3.0 bricked the pilot ring"}`)
	if frozen, _ := planPayload(t, first.asDevice(t, "win-dev-1"))["frozen"].(bool); !frozen {
		t.Fatal("the halt did not reach the device before the restart, so this test proves nothing about after")
	}

	// The restart: nothing of the first process survives except the file.
	//
	// ★ VERIFIED BY POINTING THE SECOND HARNESS SOMEWHERE ELSE, which answers frozen:false — so this assertion
	// is about the file and not about a value that survived in memory. (Changing the path for BOTH harnesses
	// proves nothing: the first one writes wherever it is told, and the second then reads it.)
	second := newPlanGateHarnessAt(t, path)
	got := planPayload(t, second.asDevice(t, "win-dev-1"))
	frozen, _ := got["frozen"].(bool)
	if !frozen {
		t.Fatalf("after a restart the device is told the fleet is NOT halted: %v — an operator who stopped a bad "+
			"release would have to stop it again, without being told the first one lapsed", got)
	}
	if reason, _ := got["frozen_reason"].(string); !strings.Contains(reason, "pilot ring") {
		t.Fatalf("the halt survived without its reason: %q", reason)
	}
}
