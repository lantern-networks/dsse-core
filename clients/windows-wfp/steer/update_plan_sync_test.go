package main

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/agentupdate"
)

func (r *manifestCourierRec) planSync(baseURL string) *signedDocCourier {
	return newPlanCourier(&signedDocCourier{
		client:   &http.Client{Timeout: 5 * time.Second},
		baseURL:  baseURL,
		interval: time.Hour,
		write:    func(b []byte) error { r.written = append(r.written, append([]byte(nil), b...)); return nil },
		logf:     func(f string, a ...any) { r.logs = append(r.logs, f) },
	})
}

// TestThePlanAcceptsAnUnsignedBody is the one place the plan courier deliberately differs from the manifest,
// and the difference was found by reading the Edge rather than assumed.
//
// An Edge with no agent-policy signer serves the plan payload as a bare JSON object — not an envelope. That is
// a supported deployment. Requiring an envelope type here would break every one of them, and break it in the
// worst direction: the previous plan would stay on disk, and if that plan said frozen the fleet would remain
// halted while the courier reported nothing but a transport error.
// ★ THE FIXTURE USED TO BE A BODY THE EDGE NEVER SERVES (corrected 2026-08-13). It carried no
// `schema_version`, and so proved acceptance of something that could not have worked end to end anyway:
// DecodeRolloutPlan refuses a plan whose schema is absent. The real unsigned branch
// (steer_agent_update_plan_routes.go) writes an agentupdate.RolloutPlan, which always stamps the schema — so
// what the courier must accept is THIS shape, and requiring the name costs a legitimate deployment nothing.
func TestThePlanAcceptsAnUnsignedBody(t *testing.T) {
	r := &manifestCourierRec{}
	srv := serve(t, http.StatusOK, []byte(`{"schema_version":"`+agentupdate.RolloutPlanSchema+
		`","frozen":false,"eligible_since":"2026-08-10T00:00:00Z"}`))

	if err := r.planSync(srv.URL).refreshOnce(context.Background()); err != nil {
		t.Fatalf("the plan courier refused an unsigned payload the Edge legitimately serves: %v", err)
	}
	if len(r.written) != 1 {
		t.Fatalf("wrote %d times, want 1", len(r.written))
	}
}

// TestThePlanAcceptsItsOwnEnvelopeType: the signed shape, now that the plan has a type of its own.
func TestThePlanAcceptsItsOwnEnvelopeType(t *testing.T) {
	r := &manifestCourierRec{}
	srv := serve(t, http.StatusOK, envelopeBytes(t, agentupdate.RolloutPlanEnvelopeType))

	if err := r.planSync(srv.URL).refreshOnce(context.Background()); err != nil {
		t.Fatalf("the plan courier refused a correctly-typed signed plan: %v", err)
	}
	if len(r.written) != 1 {
		t.Fatalf("wrote %d times, want 1", len(r.written))
	}
}

// TestThePlanRefusesAnotherDocumentsType is the reason the plan getting its own type was worth doing, and it
// is the expensive refusal to get right.
//
// The plan and the steer-exclusion policy are signed by the SAME key, so a signature check cannot tell them
// apart — only the type can. An exclusion policy served on the plan path would reach the updater, fail to
// verify as a plan, and under the rule that an unverifiable plan is a FREEZE it would HALT THE FLEET. A
// routing mistake must not be able to do that.
func TestThePlanRefusesAnotherDocumentsType(t *testing.T) {
	for _, wrong := range []string{"dsse_agent_steer_policy.v1", agentupdate.EnvelopeType} {
		r := &manifestCourierRec{}
		srv := serve(t, http.StatusOK, envelopeBytes(t, wrong))
		err := r.planSync(srv.URL).refreshOnce(context.Background())
		if err == nil {
			t.Fatalf("the plan courier accepted a %q envelope; that would reach the updater as a FREEZE", wrong)
		}
		if !strings.Contains(err.Error(), agentupdate.RolloutPlanEnvelopeType) {
			t.Fatalf("the error does not say which type was expected: %v", err)
		}
		if len(r.written) != 0 {
			t.Fatalf("wrote a %q envelope to the plan file", wrong)
		}
	}
}

// TestThePlanStillRefusesNonJSON is what the relaxed check must NOT give up.
//
// This matters more for the plan than for the manifest: an unverifiable plan means FREEZE, so a captive-portal
// page reaching the updater would halt the fleet. Keeping "is it JSON at all" is what stops a transport fault
// from becoming a halt.
func TestThePlanStillRefusesNonJSON(t *testing.T) {
	for _, b := range [][]byte{
		[]byte("<html><body>Sign in to the WiFi</body></html>"),
		[]byte("{"),
		[]byte(""),
	} {
		r := &manifestCourierRec{}
		srv := serve(t, http.StatusOK, b)
		if err := r.planSync(srv.URL).refreshOnce(context.Background()); err == nil {
			t.Fatalf("the plan courier accepted a non-JSON body, which would reach the updater as a FREEZE: %q", b)
		}
		if len(r.written) != 0 {
			t.Fatalf("wrote a non-JSON body: %q", b)
		}
	}
}

// TestThePlanKeepsWhatIsOnDiskWhenUncertain is the property the shared type exists to guarantee, asserted
// separately for the plan because the consequence differs.
//
// For the manifest, losing it means not updating. For the plan, losing it means losing the FREEZE — the only
// way to stop a release on devices that already hold its manifest. A courier that dropped the plan on a 5xx
// would turn an Edge hiccup into a resumed bad rollout.
func TestThePlanKeepsWhatIsOnDiskWhenUncertain(t *testing.T) {
	for _, status := range []int{
		http.StatusInternalServerError, http.StatusBadGateway, http.StatusUnauthorized, http.StatusNotFound,
	} {
		r := &manifestCourierRec{}
		srv := serve(t, status, []byte("boom"))
		_ = r.planSync(srv.URL).refreshOnce(context.Background())
		if len(r.written) != 0 {
			t.Fatalf("status %d caused a write; an uncertain answer must leave the plan alone", status)
		}
	}
}

// TestThePlanIsQuietWhenNothingIsPublished: a fleet that never configured a rollout must not be halted by the
// feature arriving, so an absent plan is the ordinary state and says so quietly.
func TestThePlanIsQuietWhenNothingIsPublished(t *testing.T) {
	r := &manifestCourierRec{}
	srv := serve(t, http.StatusNotFound, nil)
	if err := r.planSync(srv.URL).refreshOnce(context.Background()); !errors.Is(err, errNotPublished) {
		t.Fatalf("err = %v, want errNotPublished", err)
	}
}

// TestBothCouriersShareTheSameMachinery pins the reason there is one type rather than two.
//
// The two differ in exactly three fields. If a later change gives one of them a behaviour the other lacks —
// most dangerously a delete path, which for the plan would mean a misdirected Edge path could lift a freeze —
// it has to be done by adding a field here, which is visible, rather than by editing one of two files that
// happen to look alike.
func TestBothCouriersShareTheSameMachinery(t *testing.T) {
	r := &manifestCourierRec{}
	m := r.sync("https://edge.test")
	p := r.planSync("https://edge.test")

	if m.name == p.name {
		t.Fatalf("both couriers log as %q; their lines would be indistinguishable", m.name)
	}
	if m.path == p.path {
		t.Fatalf("both couriers fetch %q; one of them is pointed at the wrong endpoint", m.path)
	}
	if m.envelopeType == "" || p.envelopeType == "" {
		t.Fatal("both couriers must name the type they expect")
	}
	if m.envelopeType == p.envelopeType {
		t.Fatalf("both expect %q; the plan and the manifest are different documents and one of them would be "+
			"accepted on the other's path", m.envelopeType)
	}
	// Only the plan tolerates an ABSENT type, and only because the Edge still serves it unsigned. The manifest
	// endpoint always signs, so the same tolerance there would accept a bare JSON object as an update manifest.
	if m.unsignedSchema != "" {
		t.Fatal("the manifest courier must not accept an untyped body; that endpoint always signs")
	}
	if p.unsignedSchema != agentupdate.RolloutPlanSchema {
		t.Fatalf("the plan courier accepts an untyped body only when it names itself %q, got %q — an Edge with "+
			"no agent-policy signer serves the plan unsigned, but any JSON object at all decodes to an empty "+
			"envelope, so the schema name is the only thing separating the two",
			agentupdate.RolloutPlanSchema, p.unsignedSchema)
	}
	// Neither has any way to delete. Asserted by construction: the struct has no such field, so this test
	// stops compiling if one is added without thought.
	if m.write == nil || p.write == nil {
		t.Fatal("both couriers must have a write function and nothing else that touches the file")
	}
}

// ★ THE DEFECT THIS EXISTS FOR (2026-08-13, found by the macOS side in its own courier — review 30 #13 — and
// present here in the same shape). `json.Unmarshal` into a struct does not mind missing fields, so EVERY JSON
// object decodes to an envelope with `Type == ""`. While the untyped body was accepted on a bool alone, a
// proxy or captive portal answering 200 with JSON was indistinguishable from the unsigned plan, and its body
// was written over a verified one.
//
// The cost is not a bad plan, it is a STOPPED DEVICE: under signed operation the updater refuses what it
// cannot verify as ErrPlanUnverifiable, and an unverifiable plan is a FREEZE. One misrouted response and that
// machine stops updating until somebody notices — and the thing that notices is the fleet view showing a
// device that is behind, which looks like a hundred ordinary ones.
func TestThePlanRefusesJSONThatNeverClaimedToBeAPlan(t *testing.T) {
	for _, body := range []string{
		`{"error":"gateway timeout","code":504}`,          // a proxy answering in JSON
		`{"message":"sign in to continue","portal":true}`, // a captive portal that speaks JSON
		`{}`, // the emptiest thing that still parses
		`{"schema_version":"dsse.agent-update-plan.v2"}`, // a schema this build does not serve
		`{"schema_version":"dsse.exclusion-policy.v1"}`,  // another document of ours, untyped
	} {
		r := &manifestCourierRec{}
		srv := serve(t, http.StatusOK, []byte(body))
		err := r.planSync(srv.URL).refreshOnce(context.Background())
		if err == nil {
			t.Fatalf("%s was accepted as the unsigned plan", body)
		}
		if len(r.written) != 0 {
			t.Fatalf("%s was WRITTEN over the plan on disk — under signed operation the updater then freezes "+
				"this device", body)
		}
	}
}

// And the refusal keeps what is on disk rather than clearing it, which is the same rule the rest of this
// courier follows: a transport fault must not be able to disarm or freeze anything by itself.
func TestRefusingAnImpostorLeavesTheExistingPlanAlone(t *testing.T) {
	r := &manifestCourierRec{}
	srv := serve(t, http.StatusOK, []byte(`{"error":"bad gateway"}`))
	err := r.planSync(srv.URL).refreshOnce(context.Background())
	if err == nil {
		t.Fatal("the impostor was accepted")
	}
	if !strings.Contains(err.Error(), "keeping what is already on disk") {
		t.Fatalf("the refusal does not say the existing plan is kept: %v", err)
	}
}
