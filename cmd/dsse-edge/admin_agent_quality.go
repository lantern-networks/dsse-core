package main

import (
	"fmt"
	"github.com/lantern-networks/dsse-core/hotstore"
	"log"
	"net/http"
	_ "net/http/pprof" // DIAGNOSTIC: registers /debug/pprof on http.DefaultServeMux; served only when -pprof-listen is set
	"strings"
	"time"

	agentrollout "github.com/lantern-networks/dsse-core/agentrollout"
	agenttelemetry "github.com/lantern-networks/dsse-core/agenttelemetry"
	"github.com/lantern-networks/dsse-core/decision"

	// The IANA timezone database, compiled in. The runtime image is FROM scratch, so there is no
	// /usr/share/zoneinfo and time.LoadLocation would fail for EVERY zone — including the ones an operator
	// just typed into the Console. Validation that passes on a developer's machine and rejects everything in
	// the container is worse than no validation, because it looks like the operator's mistake.
	_ "time/tzdata"

	"github.com/lantern-networks/dsse-core/logs"
)

func adminAgentQualitySummary(tenantID string, deviceStore deviceRuntimeStore, writer *logs.Writer, agentTelemetry agenttelemetry.RuntimeStore, targetVersion string, now time.Time) (map[string]any, error) {
	return adminAgentQualitySummaryFrom(nil, tenantID, deviceStore, writer, agentTelemetry, targetVersion, now)
}

// adminAgentQualitySummaryFrom answers from the hot store when the process has one — the fleet-wide view —
// falling back to this process's own telemetry when it does not. See adminAgentUpdateEventSummaryFrom.
func adminAgentQualitySummaryFrom(hot hotstore.Store, tenantID string, deviceStore deviceRuntimeStore, writer *logs.Writer, agentTelemetry agenttelemetry.RuntimeStore, targetVersion string, now time.Time) (map[string]any, error) {
	statusCounts := map[string]int{
		"registered": 0,
		"healthy":    0,
		"degraded":   0,
		"offline":    0,
		"revoked":    0,
	}
	versionCounts := map[string]int{}
	total := 0
	stale := 0
	onTarget := 0
	staleCutoff := now.UTC().Add(-agentQualityStaleAfter)

	devices, err := devicesForTenant(deviceStore, tenantID)
	if err != nil {
		return nil, err
	}

	for _, dev := range devices {
		total++
		status := strings.TrimSpace(dev.Status)
		if status == "" {
			status = "unknown"
		}
		statusCounts[status]++
		if dev.AgentVersion != "" {
			versionCounts[dev.AgentVersion]++
		}
		if targetVersion != "" && dev.AgentVersion == targetVersion {
			onTarget++
		}
		if seenAt, err := time.Parse(time.RFC3339, dev.LastSeenAt); err == nil && seenAt.Before(staleCutoff) {
			stale++
		}
	}

	updateEvents, err := adminAgentUpdateEventSummaryFrom(hot, writer, agentTelemetry, tenantID)
	if err != nil {
		return nil, err
	}
	accessDecisions, err := adminAgentAccessDecisionSummary(writer, tenantID)
	if err != nil {
		return nil, err
	}
	agentStatusEvents, err := adminAgentStatusEventSummary(writer, agentTelemetry, tenantID)
	if err != nil {
		return nil, err
	}
	qualityStatus, qualityReasons := adminAgentQualityStatus(total, stale, updateEvents, agentStatusEvents)

	return map[string]any{
		"tenant_id":            tenantID,
		"generated_at":         now.UTC().Format(time.RFC3339),
		"stale_after_seconds":  int(agentQualityStaleAfter.Seconds()),
		"target_agent_version": targetVersion,
		"quality_status":       qualityStatus,
		"quality_reasons":      qualityReasons,
		"devices": map[string]any{
			"total":             total,
			"status_counts":     statusCounts,
			"version_counts":    versionCounts,
			"stale":             stale,
			"on_target_version": onTarget,
		},
		"agent_update_events": updateEvents,
		"agent_status_events": agentStatusEvents,
		"access_decisions":    accessDecisions,
	}, nil
}

func adminAgentQualityStatus(deviceTotal, staleDevices int, updateEvents, agentStatusEvents map[string]any) (string, []string) {
	reasons := []string{}
	if deviceTotal == 0 {
		return "unknown", []string{"no_devices"}
	}
	if staleDevices > 0 {
		reasons = append(reasons, "stale_devices")
	}
	if intMapValue(agentStatusEvents, "crash_events") > 0 {
		reasons = append(reasons, "agent_crash_events")
	}
	if intMapValue(agentStatusEvents, "steering_failed") > 0 {
		reasons = append(reasons, "steering_failures")
	}
	terminalUpdates := intMapValue(updateEvents, "terminal_events")
	if terminalUpdates > 0 && intMapValue(updateEvents, "installed_events") < terminalUpdates {
		reasons = append(reasons, "agent_update_failures")
	}
	if len(reasons) > 0 {
		return "warn", reasons
	}
	return "ok", reasons
}

// Agent quality/rollout admin routes, moved verbatim out of newServerWithConfig
// (Phase 2 route-registration split). Parameter names match the constructor's locals.
func registerAgentQualityRoutes(mux *http.ServeMux, adminEndpoint func(string, http.HandlerFunc) http.HandlerFunc, evaluator decision.Evaluator, writer *logs.Writer, deviceStore deviceRuntimeStore, agentTelemetry agenttelemetry.RuntimeStore, agentRolloutPlans *agentrollout.AgentRolloutStore, agentTargetVersion string, agentReleaseChannel string, rolloutCache *agentRolloutCache, hot hotstore.Store) {
	mux.HandleFunc("GET /admin/agent/quality", adminEndpoint("admin.usage.read", func(w http.ResponseWriter, r *http.Request) {
		summary, err := adminAgentQualitySummaryFrom(hot, adminTenantIDFromRequest(r), deviceStore, writer, agentTelemetry, agentTargetVersion, time.Now().UTC())
		if err != nil {
			log.Printf("admin agent quality summary failed: %v", err)
			writeError(w, http.StatusInternalServerError, fmt.Errorf("agent quality summary is unavailable"))
			return
		}
		writeJSON(w, http.StatusOK, summary)
	}))
	// agent lifecycle: read + drive the tenant's agent rollout/rollback plan. GET returns the
	// current plan + the fleet adoption summary (who has moved); PUT drives a rollout, a rollback to a
	// known-good version, or an incident freeze — hot-applied (the runtime rollout endpoint consults it).
	mux.HandleFunc("GET /admin/agent-rollout", adminEndpoint("admin.agents.read", func(w http.ResponseWriter, r *http.Request) {
		tenantID := adminTenantIDFromRequest(r)
		var fleet map[string]any
		if agentTelemetry != nil {
			if summary, err := adminAgentUpdateEventSummaryFrom(hot, writer, agentTelemetry, tenantID); err == nil {
				fleet = summary
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"schema_version":        "admin_agent_rollout.v1",
			"tenant_id":             tenantID,
			"plan":                  agentRolloutPlans.Get(tenantID),
			"static_target":         agentTargetVersion,
			"fleet_update_summary":  fleet,
			"no_secret_attestation": true,
		})
	}))
	// ★★★ EVERY ORGANIZATION'S PLAN, FOR A NODE THAT SERVES EVERY ORGANIZATION (2026-08-28). An Edge pulled
	// GET /admin/agent-rollout and was answered ONE plan — its own enforcement tenant's — and did the honest
	// thing with it: a device of any other organization was HELD, because "I have not been told whether that
	// fleet is halted" must not read like "it is not halted". Safe, and it means every customer's fleet behind
	// a pulling Edge is held for ever: never told anything, so never moving.
	//
	// The singular route stays exactly as it is, for an Edge of an older build and for a screen asking about
	// one organization. This one is what a fleet Edge asks.
	mux.HandleFunc("GET /admin/agent-rollouts", adminEndpoint("admin.agents.read", func(w http.ResponseWriter, r *http.Request) {
		if agentRolloutPlans == nil {
			writeJSON(w, http.StatusOK, map[string]any{"schema_version": "admin_agent_rollouts.v1", "tenants": map[string]any{}})
			return
		}
		// ★ THE PREDICATE IS "DOES THIS CREDENTIAL BELONG TO THE DEPLOYMENT", NOT "IS SOMEBODY SIGNED IN OUTSIDE
		// AN ORGANIZATION" (2026-08-28, measured: the Edge asked and was answered its own organization's plan
		// and nobody else's, so every customer's fleet stayed held). adminAnsweringForTheDeployment describes an
		// operator's SESSION; an Edge presents the fleet credential, which is an API token of the operator
		// organization and is never "signed in outside an organization". Asking the session question of a
		// machine credential answers false for ever — the same wrong predicate that hid the Publish button from
		// an operator standing inside an organization this morning.
		//
		// A customer's credential belongs to the customer organization and still gets its own and nobody else's.
		operatorOrg := operatorTenantConfigured()
		callerOrg := strings.TrimSpace(adminTenantIDFromRequest(r))
		forTheDeployment := adminAnsweringForTheDeployment(r) ||
			(operatorOrg != "" && strings.EqualFold(callerOrg, operatorOrg))
		out := map[string]agentrollout.AgentRolloutPlan{}
		if forTheDeployment {
			for _, tenant := range agentRolloutPlans.Tenants() {
				out[tenant] = agentRolloutPlans.Get(tenant)
			}
		} else {
			// A customer asking gets its own and nobody else's — the same rule every read on this surface has.
			tenant := strings.TrimSpace(adminTenantIDFromRequest(r))
			if tenant != "" {
				out[tenant] = agentRolloutPlans.Get(tenant)
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"schema_version": "admin_agent_rollouts.v1",
			"tenant_id":      adminTenantIDFromRequest(r),
			"tenants":        out,
		})
	}))
	mux.HandleFunc("PUT /admin/agent-rollout", adminEndpoint("admin.agents.write", func(w http.ResponseWriter, r *http.Request) {
		tenantID := adminTenantIDFromRequest(r)
		var req agentrollout.AgentRolloutUpdateRequest
		if err := decodeLimitedJSONBody(w, r, &req, maxEdgeRuntimeJSONBodyBytes); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("decode agent rollout update: %w", err))
			return
		}
		plan, err := agentrollout.ValidateAgentRolloutUpdate(req)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		// ★ ACCEPTED ONLY WHERE IT IS THE AUTHORITY (2026-08-11).
		//
		// This process is an enforcing Edge when it PULLS its rollout plan from a control plane. Writing here
		// would then update a map the device route no longer consults, which is the defect this whole change
		// exists to end — so it refuses and names where to author instead. On the control plane itself (nothing
		// to pull from) this store IS the authority: edges fetch it, and the write is honoured.
		if rolloutCache != nil {
			refused, why := "refused", "refused: this edge pulls its rollout plan from the control plane; author "+
				"the halt there"
			rec := agentRolloutAuditLog(tenantID, plan, evaluator, sourceIPFromRequest(r))
			rec.Result, rec.Reason = &refused, &why
			if err := writer.Append("audit.log.jsonl", rec); err != nil {
				writeError(w, http.StatusInternalServerError, err)
				return
			}
			writeError(w, http.StatusConflict, fmt.Errorf("this edge is not the authority for the rollout plan: it "+
				"pulls one from the control plane every poll, so a plan written here would be overwritten and would "+
				"reach no device in the meantime. Author the halt on the control plane"))
			return
		}
		// ★ HISTORICAL, AND THE REASON THIS ENDPOINT WAS BRIEFLY 501 (2026-08-11).
		//
		// This handler validated the request, stored the plan in an in-process map, wrote an audit entry and
		// answered 200. Devices get their rollout plan from GET /steer/agent-update-plan, which reads the
		// operator-authored file named by -agent-update-rollout-control and has never consulted this store. The
		// device-facing GET /devices/{id}/agent-rollout that exposes it is called by no client in this tree —
		// not the macOS agent, not the Windows one. Two dead ends, an audit trail, and a success code.
		//
		// So an operator could halt a bad release here, watch it succeed, see it recorded, and every endpoint
		// would carry on installing. A freeze that cannot be trusted is worse than no freeze, because the
		// operator stops looking for another way to stop the release.
		//
		// REFUSING IS THE HONEST INTERIM. It does not fix anything — the fix is the control plane owning this
		// state and the edges fetching it (,) — but it converts a
		// silent lie into a stated gap, today, in the one place an operator would otherwise be misled. The
		// message names the path that does work, so nobody is left without a way to halt a release.
		//
		// ★ ONLY THE HALF THAT REACHES DEVICES IS ACCEPTED (2026-08-11, second review). The plan carries three
		// intents; only `freeze` was wired to the device-facing plan, so `rollout` and `rollback` named a
		// DESIRED VERSION that nothing consumed — an instruction stored and answered 200 with no reader, which
		// is the shape this endpoint was refusing an hour earlier in a different field. It was refused rather
		// than silently dropped, and the message named what did work.
		//
		// ★★★ AND ON 2026-08-28 IT ACQUIRED ITS READER, so the refusal became the untrue half. The
		// device-facing manifest route now resolves the requesting device's ORGANIZATION from its certificate
		// and serves what that organization runs — which is what makes this field the customer's own control
		// over its fleet's version, the half of release management that was never theirs to hold.
		//
		// ★ WHAT IT CAN DO IS HOLD, NOT REWIND. An Edge carries one version per target — the release the
		// catalogue currently distributes — so naming another keeps a fleet where it is and is refused by name
		// at the device, out loud. Going back to a version this deployment no longer publishes needs the Edge
		// to hold more than one, and that is not built. The refusal that remains is the honest one; the one
		// removed here had stopped being true.

		// This store used to reach nobody at all: devices read a file on each Edge and nothing copied one into
		// the other, so an operator could halt a bad release, watch it succeed, and every endpoint carried on
		// installing. The edges now PULL this, which is what makes the write mean something — see
		// agent_rollout_sync.go.
		// The merge — carry the schedule through a halt, carry the halt through a schedule change — happens
		// inside the store under ONE lock. Read-then-write here let two concurrent admins each read the same
		// previous state, and the later writer silently undid the earlier one.
		previous := agentRolloutPlans.Get(tenantID)
		// ★ PERSISTED BEFORE IT IS ACKNOWLEDGED. Edges pull this store as the authority; a halt that lives only
		// in RAM is un-withdrawn by the next control-plane restart, and a 200 that outlives its own storage is
		// the same lie this endpoint was refusing an hour ago.
		// ★ THE RECORD IS WRITTEN BEFORE THE CHANGE (2026-08-11, third review). Applying first and auditing
		// second meant an audit failure answered 500 with the plan already live and already pulled by edges —
		// and for an unfreeze that is the dangerous direction: an operator watching a failure while every
		// device resumes. The journal in the updater has followed this rule from the start ("an unrecorded step
		// is a step nobody can recover from"); this endpoint had it backwards.
		//
		// The cost of this order is an audit entry for a change that then fails to store, which is the
		// harmless way round: a record of something that did not happen is a question, while an unrecorded
		// change is a fleet nobody can account for.
		// ★ TWO RECORDS, AND THE FIRST DOES NOT CLAIM SUCCESS (2026-08-12, fourth review). Writing the audit
		// first was right; writing it with Result="success" was not — a store failure then left the trail
		// asserting both that it worked and that it did not. There is no transaction to be had here (the audit
		// is an append-only file, the store is another file), so the honest shape is an ATTEMPT record before
		// and an OUTCOME record after. A reader who finds an attempt with no outcome knows exactly what to go
		// and check, which is more than either record alone could tell them.
		// ★ THE ATTEMPT MUST CARRY WHAT WAS BEING ATTEMPTED (2026-08-12, fifth review). An attempt with no
		// outcome is the record a reader is most likely to be staring at — the store failed, or the process
		// died between the two writes — and it was the one record that said nothing about the schedule. So it
		// gets the same before/after the outcome gets, minus the claim that anything was applied.
		attempted := agentRolloutScheduleAuditLog(tenantID, previous, plan, evaluator, sourceIPFromRequest(r))
		attempted.EventType = "agent_rollout_plan_attempted"
		// REQUESTED, not "after": this is the plan as the operator sent it, before Apply merges it with what
		// is already stored. Calling it "after" in a record written BEFORE the store is touched would be the
		// kind of small lie an incident reader builds a wrong timeline on.
		attempted.Metadata["schedule_requested"] = attempted.Metadata["schedule_after"]
		attempted.Metadata["frozen_requested"] = attempted.Metadata["frozen_after"]
		delete(attempted.Metadata, "schedule_after")
		delete(attempted.Metadata, "frozen_after")
		attemptedResult := "attempted"
		attempted.Result = &attemptedResult
		if err := writer.Append("audit.log.jsonl", attempted); err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Errorf("the change was NOT applied because it could "+
				"not be recorded (%w): a halt nobody can account for afterwards is not one this system will make", err))
			return
		}
		merged, serr := agentRolloutPlans.Apply(tenantID, plan, time.Now())
		if serr != nil {
			failed, why := "failed", "the plan could not be stored durably: "+serr.Error()
			rec := agentRolloutAuditLog(tenantID, plan, evaluator, sourceIPFromRequest(r))
			rec.Result, rec.Reason = &failed, &why
			if aerr := writer.Append("audit.log.jsonl", rec); aerr != nil {
				log.Printf("agent_rollout_audit_outcome_lost tenant=%s err=%v (the attempt IS recorded and this "+
					"failure is not — treat the attempt as unresolved)", tenantID, aerr)
			}
			writeError(w, http.StatusInternalServerError, fmt.Errorf("the halt could not be stored durably (%w), so "+
				"it has NOT been accepted: a freeze that a restart would forget is worse than one that failed "+
				"loudly", serr))
			return
		}
		plan = merged
		// The outcome, carrying WHAT CHANGED — including the schedule, which the old record could not express,
		// so nobody could tell from the trail who moved the pilot ring or the maintenance window.
		if err := writer.Append("audit.log.jsonl", agentRolloutScheduleAuditLog(tenantID, previous, merged, evaluator,
			sourceIPFromRequest(r))); err != nil {
			log.Printf("agent_rollout_audit_outcome_lost tenant=%s err=%v", tenantID, err)
		}
		writeJSON(w, http.StatusOK, map[string]any{"schema_version": "admin_agent_rollout.v1", "tenant_id": tenantID,
			"plan": plan,
			// ★ Reach is not instant and the screen must not imply it is: edges poll, and devices poll them.
			"reaches_devices": "edges pull this plan on their next poll, and devices ask their edge on theirs; a " +
				"halt is in force fleet-wide within both intervals"})
	}))
}
