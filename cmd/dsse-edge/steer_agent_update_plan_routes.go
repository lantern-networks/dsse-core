package main

// steer_agent_update_plan_routes.go — WHEN a device may install, as opposed to WHAT.
//
// The manifest says what to install and is immutable per release, signed by a key no Edge holds. This says
// when, changes independently of any release, and is minted here per request with the agent-policy key — the
// same key and the same shape as the steering posture and the tuning policy, because this is configuration.
//
// ★ THE KEY SPLIT IS THE POINT AND IT IS EASY TO ERODE. An Edge cannot mint the authority to RUN CODE; it can
// mint the authority to decide WHEN. Those are different powers and they sit behind different keys, so a
// compromised traffic node can delay a fleet, halt it, or update it at noon — and cannot make it run anything.
// If these two documents ever end up under one key, that property is gone and nothing will notice.
//
// TWO FACTS THE DEVICE CANNOT WORK OUT FOR ITSELF:
//
//   - frozen — the halt, and the WITHDRAWAL mechanism. A release found bad after it shipped has to be stopped
//     on devices that already hold its manifest, so un-publishing cannot be the answer: those devices would
//     never hear about it. It is also why the courier must not delete a manifest on a 404 — see the Windows
//     side's own correction. Withdrawal is a signed document that says stop, not the absence of one.
//   - eligible_since — this device's wave start. Only the control plane can compute it: it needs the release
//     time, the device's group memberships and the wave schedule together, and the device has none of those.
//
// eligible_since being PER DEVICE while everything else is tenant-wide is why this endpoint is
// device-identified rather than a static document.

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/agentrollout"
	"github.com/lantern-networks/dsse-core/agentupdate"
)

// rolloutControl is the operator-authored file behind this endpoint: the wave schedule, and the halt.
//
// One file rather than two because they are edited in the same moment for the same reason — "stagger this
// release" and "stop this release" are the same operator answering the same question about the same rollout.
type rolloutControl struct {
	// Frozen halts every device in the tenant. It is here rather than in a flag because a halt an operator has
	// to restart an Edge to apply is not a halt.
	Frozen bool `json:"frozen"`
	// FrozenReason travels to the device and into its log, because "waiting: rollout is frozen" without a
	// reason sends someone to look for a fault that is actually a decision.
	FrozenReason string                    `json:"frozen_reason,omitempty"`
	Waves        agentrollout.WaveSchedule `json:"waves"`
	// Window is the tenant's maintenance window, in the device's LOCAL time. The type is the SHARED one that
	// the device decodes, not a copy: both ends have to agree field for field, they live in different modules,
	// and a field one side writes and the other ignores is a control an operator believes is in effect and is
	// not. On this document that could be the freeze.
	Window *agentupdate.PlanWindow `json:"window,omitempty"`
}

// loadRolloutControl reads the file fresh on every request.
//
// Per request, not at startup, and that is the whole design of the halt: an operator edits the file and the
// fleet stops within one plan poll. Re-reading a small JSON document costs nothing at this call rate, and the
// alternative — caching with a reload signal — would mean the halt depends on a mechanism that can itself fail
// at the moment it is needed.
//
// The three outcomes are deliberately not two:
//
//   - ABSENT: no schedule and no freeze. The ordinary deployment that never configured waves must not be
//     halted by the absence of a file it was never told to write.
//   - PRESENT and readable: as written.
//   - PRESENT and BROKEN: FROZEN, loudly. An operator editing this file is plausibly halting a bad release
//     right now, and a JSON typo must not be the thing that lets the release keep going. Failing open here
//     would make the halt least reliable exactly when it is being used.
func loadRolloutControl(path string) (rolloutControl, error) {
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return rolloutControl{}, nil
	}
	if err != nil {
		return rolloutControl{Frozen: true, FrozenReason: fmt.Sprintf(
			"the rollout control file could not be read (%v), so this fleet is held until it can be", err)}, err
	}
	var rc rolloutControl
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if derr := dec.Decode(&rc); derr != nil {
		return rolloutControl{Frozen: true, FrozenReason: fmt.Sprintf(
			"the rollout control file is unreadable (%v), so this fleet is held until it is corrected", derr)}, derr
	}
	if verr := rc.Waves.Validate(); verr != nil {
		return rolloutControl{Frozen: true, FrozenReason: fmt.Sprintf(
			"the rollout wave schedule is invalid (%v), so this fleet is held until it is corrected", verr)}, verr
	}
	return rc, nil
}

// resolveRolloutControl answers where this Edge gets the halt and the wave schedule from.
//
// ★ AND WHAT IT DOES BEFORE IT HAS AN ANSWER. An Edge configured to pull from a control plane serves FROZEN
// until its first successful pull. "I have not been told whether the fleet is halted" and "the fleet is not
// halted" must not render the same: of the two ways to be wrong, holding a release for one poll interval is
// the recoverable one, and the other is the release an operator believes they stopped.
func resolveRolloutControl(config serverConfig, tenantID string) (rolloutControl, error) {
	cache := config.AgentRolloutCache
	if cache == nil {
		// ★ THE HALT AN OPERATOR AUTHORS IS IN THE STORE, NOT IN THAT FILE (2026-08-13, twenty-ninth review).
		// On a combined control plane (no cache, because there is nothing to pull FROM) this read only the
		// local rollout-control file, which PUT /admin/agent-rollout does not write. So a freeze was accepted
		// with 200, audited, and shown as frozen on the admin screen — which reads the store — while every
		// device was served frozen=false from a file that usually does not exist, and went on installing the
		// release the operator believes they stopped.
		//
		// This is the sister of "publish never reaches devices", and the more dangerous direction: that one
		// fails to start something, this one fails to STOP it. The store is consulted first and the file
		// remains the fallback for a deployment that has no store.
		// ★★ AND IT CARRIED ONLY THE HALT (2026-08-13, thirtieth review). The branch above returned the store's
		// answer ONLY when the plan was frozen, and dropped its Waves on the way. So on a combined control plane
		// an operator's WAVE SCHEDULE was accepted, audited and displayed — and every device was served the
		// empty schedule from a file that PUT does not write. The same defect as the freeze, one field over: the
		// half of the fix that was not written.
		//
		// ★ AND IT ANSWERED FOR THE WRONG TENANT (#11, same round). The plan was fetched for this Edge's own
		// bundle tenant, so on a multi-tenant control plane tenant B's freeze reached nobody while the bundle
		// tenant's freeze stopped everybody. The caller already resolves the DEVICE's tenant from its client
		// certificate for the plan it signs; the halt has to come from the same place, or a device is told it is
		// frozen by an authority it does not belong to.
		if config.AgentRolloutPlans != nil {
			// The file first, so it remains the fallback for fields the store does not set — a deployment whose
			// schedule has always lived on disk keeps working — and the store is then overlaid on top of it.
			rc, ferr := loadRolloutControl(config.RolloutControlPath)
			if ferr != nil && !os.IsNotExist(ferr) {
				// loadRolloutControl answers a damaged file with Frozen=true AND an error; that pairing is the
				// point of it, so the halt is kept rather than discarded by the code that asked for it.
				log.Printf("agent_update_plan: the local rollout control file %s is unusable (%v) — holding this "+
					"control plane's devices", config.RolloutControlPath, ferr)
			}
			plan := config.AgentRolloutPlans.Get(tenantID)
			if plan.Waves != nil {
				rc.Waves = *plan.Waves
			}
			if plan.Window != nil {
				rc.Window = plan.Window
			}
			// Two ways to stop and neither can un-stop the other: whichever of the two says halt, halts.
			if plan.Frozen {
				rc.Frozen = true
				rc.FrozenReason = strings.TrimSpace(plan.Reason)
				if rc.FrozenReason == "" {
					rc.FrozenReason = "halted by an administrator on this control plane"
				}
			}
			return rc, nil
		}
		return loadRolloutControl(config.RolloutControlPath)
	}
	// ★★ AND THE CACHE'S PLAN IS FOR ONE TENANT (2026-08-13, thirty-first review #6). An enforcing Edge pulls a
	// single plan, for its own enforcement tenant, and can serve devices of ANOTHER tenant when several Tenant
	// CAs are registered. Serving that plan to them means tenant B's freeze reaches nobody while the pulling
	// Edge's tenant halts everyone — and the route would stamp it with tenant B's name, so the document would
	// even look right.
	//
	// Held, not guessed, and for the reason this whole function is built on: "I have not been told whether this
	// fleet is halted" and "this fleet is not halted" must not render the same. Of the two ways to be wrong,
	// holding a tenant's updates until its plan can be pulled is the recoverable one.
	// ★★★ AND IT NOW ASKS FOR THAT ORGANIZATION (2026-08-28). The hold above was right and permanent: an Edge
	// told about one organization held every other one's fleet for ever, because it was never told anything
	// about them. It asks the control plane for the SET now, so an organization it has been told about is
	// answered from its own plan and only a genuinely unknown one is held.
	plan, known := cache.planFor(tenantID)
	if !known && strings.TrimSpace(tenantID) != "" {
		_, fetched, lastErr := cache.Get()
		why := fmt.Sprintf("this edge has not been told whether %s's fleet is halted", tenantID)
		if !fetched {
			why = "this edge takes its rollout plan from the control plane and has not managed to read one yet"
		}
		if lastErr != "" {
			why += " (" + lastErr + ")"
		}
		return rolloutControl{Frozen: true, FrozenReason: why + ", so the fleet is held until it is"}, nil
	}
	_, fetched, lastErr := cache.Get()
	if !fetched {
		why := "this edge takes its rollout plan from the control plane and has not managed to read one yet"
		if lastErr != "" {
			why += " (" + lastErr + ")"
		}
		return rolloutControl{Frozen: true, FrozenReason: why + ", so the fleet is held until it can"}, nil
	}
	rc := rolloutControl{Frozen: plan.Frozen, FrozenReason: plan.Reason}
	if plan.Frozen && strings.TrimSpace(rc.FrozenReason) == "" {
		rc.FrozenReason = "halted from the control plane"
	}
	// ★ THE WHOLE DOCUMENT COMES FROM THE CONTROL PLANE, not just the halt (2026-08-11). Leaving the waves and
	// the window in a file on each edge meant a fleet had as many schedules as it had edges, and a screen
	// reading one of them would report "applied" for all of them — the per-edge authored-rules defect this
	// codebase has already paid for once. One authority, or none.
	if plan.Waves != nil {
		rc.Waves = *plan.Waves
	}
	rc.Window = plan.Window

	// The local file can still HALT — two ways to stop, neither able to un-stop the other — and its schedule is
	// deliberately ignored while a control plane is answering. Ignoring it silently would leave an operator
	// editing a file that does nothing, so it is reported.
	// ★ THE LOCAL HALT APPLIES EVEN WHEN THE FILE IS BROKEN (2026-08-12, fourth review). loadRolloutControl
	// answers a damaged file with Frozen=true AND an error — that pairing is the whole point of it — and this
	// used the result only when the error was nil, throwing the halt away. A JSON typo during an incident would
	// have let updates continue, silently, on the one path built to stop them. The safe answer must not be
	// discarded by the code that asked for it.
	file, ferr := loadRolloutControl(config.RolloutControlPath)
	if ferr != nil && !os.IsNotExist(ferr) {
		log.Printf("agent_update_plan: the local rollout control file %s is unusable (%v) — holding this edge's "+
			"devices, whatever the control plane says", config.RolloutControlPath, ferr)
	}
	{
		if !rc.Frozen && file.Frozen {
			rc.Frozen, rc.FrozenReason = true, file.FrozenReason
		}
		if plan.Waves == nil && len(file.Waves.Waves) > 0 {
			rc.Waves = file.Waves // nothing authored centrally yet: the file is all there is
		} else if len(file.Waves.Waves) > 0 {
			log.Printf("agent_update_plan: the control plane authors this tenant's wave schedule; the local file "+
				"%s is IGNORED for waves (its freeze still applies)", config.RolloutControlPath)
		}
		if plan.Window == nil && file.Window != nil {
			rc.Window = file.Window
		} else if file.Window != nil {
			log.Printf("agent_update_plan: the control plane authors this tenant's maintenance window; the local "+
				"file %s is IGNORED for the window", config.RolloutControlPath)
		}
	}
	return rc, nil
}

// registerSteerAgentUpdatePlanRoutes serves the device-facing rollout plan.
func registerSteerAgentUpdatePlanRoutes(mux *http.ServeMux, config serverConfig, evaluator decisionEvaluatorForPlan) {
	// GET /steer/agent-update-plan?platform=windows&arch=amd64
	//
	// platform/arch for the same reason the manifest endpoint takes them, and one more: the wave is measured
	// from the RELEASE time, which is a property of the manifest this device would install. A plan computed
	// against the wrong release would hand a device a wave start for a build it is not being offered.
	mux.HandleFunc("GET /steer/agent-update-plan", func(w http.ResponseWriter, r *http.Request) {
		identity, verified := transportDeviceIdentityFromRequest(r)
		if !verified || strings.TrimSpace(identity) == "" {
			writeError(w, http.StatusUnauthorized, fmt.Errorf("a verified device transport identity is required"))
			return
		}
		platform := strings.TrimSpace(r.URL.Query().Get("platform"))
		arch := strings.TrimSpace(r.URL.Query().Get("arch"))
		if platform == "" || arch == "" {
			writeError(w, http.StatusBadRequest, fmt.Errorf("platform and arch query parameters are required"))
			return
		}

		// ★ THE CONTROL PLANE OUTRANKS THE FILE when this Edge pulls from one. The file remains the answer for
		// a deployment with no control plane (the lab, and a single-node install), which is why it is a fallback
		// rather than a removal — but where a CP exists, a per-Edge file is exactly the state that made
		// "authored rules" mean something different on every node.
		// ★ RESOLVED BEFORE THE HALT IS READ (2026-08-13, thirtieth review, #11). The plan this route signs is
		// stamped with the DEVICE's tenant, from its client certificate; the halt has to be fetched for the same
		// tenant or a multi-tenant control plane serves everybody the bundle tenant's freeze — tenant B's halt
		// reaching nobody, and the bundle tenant's stopping every fleet on the box.
		planTenant := evaluator.tenantID()
		if bound, terr := authoritativeTenantForRequest(r, "", config.TenantCARegistry); terr == nil &&
			strings.TrimSpace(bound) != "" {
			planTenant = bound
		}

		rc, rerr := resolveRolloutControl(config, planTenant)
		if rerr != nil && !os.IsNotExist(rerr) {
			// Logged as well as served: the device learns it is held, and the operator needs to know WHY the
			// fleet stopped, on the machine where the file is.
			log.Printf("agent_update_plan control file unusable path=%s err=%v — serving FROZEN to every device",
				config.RolloutControlPath, rerr)
		}

		// CP-AUTHORITATIVE group, from the enrolment ledger — never a device-reported one. The group selects
		// which wave speaks for this device, so a self-asserted group would let a machine put itself in the
		// pilot ring, which is the one place a bad build is supposed to be caught before the fleet takes it.
		group := cpAuthoritativeGroup(config.EnrolledLedger, identity)
		var groups []string
		if strings.TrimSpace(group) != "" {
			groups = []string{group}
		}

		// The plan is stamped with the DEVICE's tenant, not this Edge's (2026-08-13, twenty-eighth review): an
		// Edge with several Tenant CAs registered used to sign every plan with its own bundle tenant, so a
		// tenant-B device held its wave for the mismatch and never updated. Resolved above, because the halt is
		// read for the same tenant and the two must not be able to disagree.
		payload := agentupdate.RolloutPlan{
			SchemaVersion:  agentupdate.RolloutPlanSchema,
			TenantID:       planTenant,
			DeviceIdentity: identity,
			Frozen:         rc.Frozen,
			FrozenReason:   rc.FrozenReason,
			Window:         rc.Window,
			GeneratedAt:    time.Now().UTC().Format(time.RFC3339),
		}

		// The wave start needs the release instant, which lives on the manifest this device would be offered.
		// With nothing published there is no wave to be in, and the field is omitted rather than zeroed — the
		// device reads an absent eligible_since as "no schedule", which is not the same as "your wave opened at
		// the zero time".
		if u, ok := config.PublishedUpdates.forTarget(platform, arch); ok {
			if released, perr := time.Parse(time.RFC3339, u.Manifest.ReleasedAt); perr == nil {
				start, assignment := rc.Waves.WaveStart(groups, released)
				if !start.IsZero() {
					payload.EligibleSince = start.UTC().Format(time.RFC3339)
				}
				// The assignment's reasoning travels with the answer. "Why is this machine still on the old
				// build" is the question this feature generates, and "day 5" without "because it is in finance,
				// which outranks its membership in pilot" sends an admin to the wrong place.
				payload.WaveReason = assignment.Reason
				payload.TargetVersion = u.Manifest.Version
			}
		}

		// Logged per fetch, at INFO, for a sharper reason than the manifest's. This document carries the FREEZE,
		// and after a halt the question is "which devices have actually been told to stop" — a question nothing
		// else can answer, because the device's own record is on the device and a device that took a bad update
		// may be the one that cannot report. A halt whose reach is unknowable is a halt an operator cannot act on.
		log.Printf("agent_update_plan_served device=%s platform=%s arch=%s frozen=%t eligible_since=%q target=%q",
			identity, platform, arch, payload.Frozen, payload.EligibleSince, payload.TargetVersion)

		if config.AgentPolicySigner == nil {
			// Unsigned, like the sibling endpoints without a signer. The device decides what to do with that:
			// an updater with a pinned plan key refuses it, which is the deployment that wanted withdrawal to
			// be tamper-evident getting what it asked for.
			writeJSON(w, http.StatusOK, payload)
			return
		}
		// SignTyped, not Sign: the plan gets its own envelope type so it cannot be confused with the exclusion
		// policy the same key also signs. See agentupdate.RolloutPlanEnvelopeType.
		env, serr := config.AgentPolicySigner.SignTyped(agentupdate.RolloutPlanEnvelopeType, payload, time.Now())
		if serr != nil {
			writeError(w, http.StatusInternalServerError, fmt.Errorf("sign the rollout plan: %w", serr))
			return
		}
		writeJSON(w, http.StatusOK, env)
	})
}

// decisionEvaluatorForPlan is the one thing this surface needs from the evaluator. Narrow on purpose: the plan
// route has no business reading policy, and a narrow dependency says so in a way a comment cannot.
type decisionEvaluatorForPlan interface{ tenantID() string }

// rolloutControlFlags is this surface's flag, defined here rather than in main.go — the Phase 0 ratchet freezes
// main.go's flag count and a new surface adding to it is the regression the ratchet exists to catch.
type rolloutControlFlags struct {
	path *string
	// sourceURL makes this Edge an ENFORCING edge that pulls the halt from a control plane instead of owning
	// it. Empty keeps the file as the authority, which is the single-node and lab shape.
	sourceURL *string
	poll      *time.Duration
}

func registerRolloutControlFlags() *rolloutControlFlags {
	return &rolloutControlFlags{
		sourceURL: flag.String("agent-rollout-source-url", "",
			"CP→Edge sync: control-plane admin base (e.g. https://controlplane:9443) this enforcing Edge PULLS the "+
				"agent rollout halt from. Set it and the control plane owns the freeze — this edge serves FROZEN "+
				"until its first successful pull, because \"I have not been told\" and \"not halted\" must not read "+
				"the same. Empty = the local -agent-update-rollout-control file is the authority."),
		poll: flag.Duration("agent-rollout-source-poll", 30*time.Second,
			"how often to pull the rollout halt from the control plane"),
		path: flag.String("agent-update-rollout-control", "",
			"path to the rollout control JSON (wave schedule + freeze) served at GET /steer/agent-update-plan. "+
				"Read fresh on every request, so editing it halts or staggers the fleet within one device poll "+
				"without restarting this edge. Absent = no waves and no freeze; PRESENT BUT BROKEN = frozen, "+
				"because a typo must not be what lets a release an operator is halting keep going."),
	}
}

// agentUpdatePlanTenant adapts the evaluator without widening what this file can reach.
type agentUpdatePlanTenant struct{ id string }

func (t agentUpdatePlanTenant) tenantID() string { return t.id }
