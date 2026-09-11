package main

import (
	"log"
	"net/http"
	"strings"
	"time"

	"sort"

	agentrollout "github.com/lantern-networks/dsse-core/agentrollout"
	agenttelemetry "github.com/lantern-networks/dsse-core/agenttelemetry"
	agentupdate "github.com/lantern-networks/dsse-core/agentupdate"
	enrolledinventory "github.com/lantern-networks/dsse-core/enrolledinventory"
	"github.com/lantern-networks/dsse-core/model"
)

// admin_agent_device_updates.go — what the fleet number looks like when you open it.
//
// ★ EVERYTHING THIS LANE DOES HAS BEEN INVISIBLE (2026-08-12). The updates, the rollbacks, the refusals and
// the halt all work and are reachable by `curl` and by nothing else. A summary that cannot be opened is a
// number to be believed rather than acted on: "42 installed" does not say WHICH machine is still on the old
// build, which one refused, or why — and the answers are the same data, grouped differently.
//
// ★ AND IT DECLARES WHAT IT CANNOT SEE. The count of devices that have never reported an outcome is part of
// the answer, not a rounding error: a fleet where nine machines are silent and one failed is not "one
// problem". Every number here carries the population it was computed over.

// agentDeviceUpdate is one device's update state, as the control plane knows it.
type agentDeviceUpdate struct {
	DeviceID string `json:"device_id"`
	// ReportedVersion is what the device said it was RUNNING when it last reported an outcome. Distinct from
	// the inventory's agent_version, which is what it said at its last heartbeat — the two answer different
	// questions and a device that stopped reporting keeps the older one.
	ReportedVersion string `json:"reported_version,omitempty"`
	TargetVersion   string `json:"target_version,omitempty"`
	// State is the ONE word an operator reads: up_to_date | pending | failed | refused | never_reported.
	State string `json:"state"`
	// Reason is the device's own sentence, unedited. The endpoint wrote it knowing why; summarising it here
	// would replace what happened with what this file guessed it meant.
	Reason     string `json:"reason,omitempty"`
	ReportedAt string `json:"reported_at,omitempty"`
	// RejectedManifestSHA256 identifies a document that would not verify. A refusal of one names no version, so
	// this is the only thing that distinguishes a second substituted manifest from a repeat of the first.
	RejectedManifestSHA256 string `json:"rejected_manifest_sha256,omitempty"`
}

// agentDeviceUpdatesResponse is the whole answer: the release being offered, the rows, and the coverage.
type agentDeviceUpdatesResponse struct {
	SchemaVersion string              `json:"schema_version"`
	TenantID      string              `json:"tenant_id"`
	Offering      map[string]string   `json:"offering"`
	Frozen        bool                `json:"frozen"`
	FrozenReason  string              `json:"frozen_reason,omitempty"`
	Devices       []agentDeviceUpdate `json:"devices"`
	// Degraded names a part of this answer that could not be computed, empty when the whole answer stands.
	// Its one value today is `telemetry_unavailable`: the rows still carry the inventory, and no coverage is
	// published, because a number computed over an unreadable store is not a smaller truth but a wrong one.
	Degraded string         `json:"degraded,omitempty"`
	Coverage map[string]any `json:"coverage"`
}

// agentDeviceUpdatesTelemetryUnavailable is the one degraded reason this view can report.
const agentDeviceUpdatesTelemetryUnavailable = "telemetry_unavailable"

// registerAgentDeviceUpdateRoutes serves the per-device view the Devices list folds in.
func registerAgentDeviceUpdateRoutes(mux *http.ServeMux, adminEndpoint func(string, http.HandlerFunc) http.HandlerFunc,
	deviceStore deviceRuntimeStore, enrolled *enrolledinventory.Ledger, telemetry agenttelemetry.RuntimeStore,
	published *publishedAgentUpdateStore, deviceFacing *publishedUpdates,
	plans *agentrollout.AgentRolloutStore, rolloutCache *agentRolloutCache,
	trustedKeys []string) {
	mux.HandleFunc("GET /admin/agent/device-updates", adminEndpoint("admin.agents.read", func(w http.ResponseWriter, r *http.Request) {
		tenantID := adminTenantIDFromRequest(r)
		now := time.Now().UTC()

		// ★★ WHAT THIS NODE WOULD ACTUALLY HAND A DEVICE (2026-08-13, found on the lab: the Devices page said
		// "no release" for every device while the Edge was serving 0.2.9 and 0.2.1).
		//
		// This read only the CP-AUTHORED store, which on an ENFORCING EDGE is empty by design — such an Edge
		// pulls the published set into the device-facing one. Since the Console reads this endpoint from the
		// Edge, the ordinary production topology showed an empty offering and marked every device `no_release`,
		// on the screen whose comment two paragraphs down says this lane had been invisible.
		//
		// The CP store first, because on a control plane it is the authority an operator writes to; the
		// device-facing set fills anything it does not cover, because that is what a device is handed.
		offering := map[string]string{}
		for target, envelope := range published.ForTenant(tenantID) {
			if m, err := agentupdate.Open(envelope, trustedKeys, now); err == nil {
				offering[target] = m.Version
			}
		}
		if deviceFacing != nil {
			for target, u := range deviceFacing.targets() {
				if _, ok := offering[target]; !ok {
					offering[target] = u.Manifest.Version
				}
			}
		}

		plan, frozen, frozenReason := agentRolloutForTenant(plans, rolloutCache, tenantID)
		_ = plan

		// ★ A TELEMETRY OUTAGE USED TO RENDER AS A REPORTING OUTAGE (2026-08-12, fourteenth review). The read
		// failure was logged and then answered from an EMPTY set — so every device came back
		// `never_reported`, the coverage band read 0/N, and a Postgres timeout was indistinguishable from a
		// fleet that had genuinely gone silent. That is this lane's own defect: a value that means "nothing"
		// and "cannot tell" at the same time, in the screen built to stop exactly that.
		//
		// It is not a 503, because the inventory half of this answer is still true and an operator locked out
		// of the whole page during a database blip learns less, not more. The response says it is degraded and
		// WITHHOLDS the coverage numbers rather than publishing wrong ones.
		latest := map[string]model.AgentUpdateEvent{}
		telemetryErr := error(nil)
		if telemetry != nil {
			byDevice, err := telemetry.LatestUpdateByDevice(r.Context(), tenantID)
			if err == nil {
				latest = updateEventsByIdentity(byDevice)
			} else {
				telemetryErr = err
				log.Printf("agent device updates: telemetry could not be read (%v) — the answer is marked "+
					"degraded and carries no coverage; the inventory half still stands", err)
			}
		}

		// ★ THE FLEET IS THE ENROLMENT LEDGER, NOT THE DEVICE STORE (2026-08-12). A control plane holds the
		// ledger and an enforcing Edge holds the runtime store, so keying this on the store answered an EMPTY
		// list from the one process the Console reads. The two are joined: the ledger says who exists, the
		// store adds what it knows, and a device that reported an outcome is included even if neither has it
		// yet — silence about a machine that just spoke would be its own kind of wrong.
		byID := map[string]model.Device{}
		if devices, derr := devicesForTenant(deviceStore, tenantID); derr == nil {
			byID = runtimeDevicesByIdentity(devices, tenantID)
		}
		// ★ A DEVICE WITH NO TENANT WAS EVERY TENANT'S DEVICE (2026-08-12, fourteenth review). An entry whose
		// TenantID is empty — a legacy or seeded one — was folded into EVERY tenant's answer, which put one
		// fleet's device identifiers in front of another's admin and counted the same machine once per tenant.
		//
		// ★ AND THE FIRST FIX INFERRED THE DEPLOYMENT MODE, WHICH FAILS OPEN (2026-08-12, fifteenth review).
		// It kept the old behaviour on an Edge whose LEDGER named at most one tenant — so a deployment holding
		// tenant_a's devices plus an unassigned one answered tenant_b's admin with those identifiers, because
		// the ledger had not yet been given a second tenant to notice. Every boundary that fails open does it
		// in the state nobody pictures: a tenant just added, the last device of one removed, a migration
		// half-done. A security boundary derived from the data it is protecting is not a boundary.
		//
		// So there is no mode to get wrong. A tenant-less entry belongs to no tenant, therefore it is in NO
		// tenant's rows — and it is COUNTED, which is what keeps this from being a device that vanishes.
		// `coverage.unassigned` is a number every admin sees without seeing anyone's device ids, and it says
		// the true thing: there are machines here that no tenant owns and nobody can act on.
		unassigned := 0
		identities := []string{}
		seen := map[string]bool{}
		if enrolled != nil {
			for _, entry := range enrolled.List() {
				entryTenant := strings.TrimSpace(entry.TenantID)
				if entryTenant == "" {
					unassigned++
					continue
				}
				if !strings.EqualFold(entryTenant, strings.TrimSpace(tenantID)) {
					continue
				}
				if id := enrolledinventory.NormalizeIdentity(entry.Identity); id != "" && !seen[id] {
					seen[id] = true
					identities = append(identities, id)
				}
			}
		}
		for id := range byID {
			if !seen[id] {
				seen[id] = true
				identities = append(identities, id)
			}
		}
		for id := range latest {
			if !seen[id] {
				seen[id] = true
				identities = append(identities, id)
			}
		}
		sort.Strings(identities)

		// ★ WITHHOLDING THE COVERAGE WAS NOT ENOUGH (2026-08-12, fifteenth review). The rows were still built
		// from the empty event set, so every device came back `never_reported` — and the Console counts,
		// filters and badges off the ROWS, not off the coverage block. The fabricated fleet state survived the
		// fix that was supposed to remove it, one layer down.
		//
		// `unknown` is the honest word: this control plane cannot say what this device last did. It is a state
		// of its own, deliberately not one of the four an operator acts on.
		rows := make([]agentDeviceUpdate, 0, len(identities))
		counts := map[string]int{}
		for _, id := range identities {
			device, ok := byID[id]
			if !ok {
				device = model.Device{ID: id, OS: agentDeviceOSFrom(latest[id])}
			}
			var row agentDeviceUpdate
			if telemetryErr != nil {
				row = agentDeviceUpdate{DeviceID: id, State: agentDeviceStateUnknown,
					ReportedVersion: device.AgentVersion}
			} else {
				row = agentDeviceUpdateFor(device, latest[id], offering)
			}
			counts[row.State]++
			rows = append(rows, row)
		}
		fleetSize := len(identities)

		degraded := ""
		coverage := map[string]any{}
		if telemetryErr != nil {
			degraded = agentDeviceUpdatesTelemetryUnavailable
		} else {
			coverage = map[string]any{
				"devices":        fleetSize,
				"reported":       fleetSize - counts[agentDeviceStateNeverReported],
				"never_reported": counts[agentDeviceStateNeverReported],
				"by_state":       counts,
			}
			if unassigned > 0 {
				coverage["unassigned"] = unassigned
			}
		}

		writeJSON(w, http.StatusOK, agentDeviceUpdatesResponse{
			SchemaVersion: "admin_agent_device_updates.v1",
			TenantID:      tenantID,
			Offering:      offering,
			Frozen:        frozen,
			FrozenReason:  frozenReason,
			Devices:       rows,
			Degraded:      degraded,
			// ★ THE POPULATION IS PART OF THE ANSWER. A fleet where nine machines are silent and one failed is
			// not "one problem", and a screen that shows the one is describing a different fleet.
			//
			// And when the telemetry could not be read there IS no population to state, so the numbers are
			// absent rather than zero. A caller that renders coverage must check `degraded` first; one that
			// does not gets no numbers to render, which is the failure mode this whole file exists to avoid.
			Coverage: coverage,
		})
	}))
}

// Device update states. One word each, because the row has room for one.
const (
	agentDeviceStateUpToDate      = "up_to_date"
	agentDeviceStatePending       = "pending"
	agentDeviceStateFailed        = "failed"
	agentDeviceStateRefused       = "refused"
	agentDeviceStateNeverReported = "never_reported"
	// agentDeviceStateNoRelease is a device this control plane offers nothing to — an unpublished platform, or
	// one whose platform it cannot resolve.
	//
	// ★ IT IS NOT "UP TO DATE" (2026-08-12). The first version treated an unknown target as current, so a
	// device the fleet publishes nothing for read as fine — the same "absence rendered as success" this whole
	// lane keeps producing, arriving in the screen built to expose it.
	agentDeviceStateNoRelease = "no_release"
	// agentDeviceStateUnknown is what this control plane says when it could not READ the outcome store. It is
	// not a state of the device — it is a statement about this answer, and it exists so that a store outage
	// cannot be rendered as a fleet that has gone quiet.
	agentDeviceStateUnknown = "unknown"
)

// agentDeviceUpdateFor decides the one word, from what the device actually said.
//
// ★ "NEVER REPORTED" IS NOT "UP TO DATE" (2026-08-12). The inventory carries an agent_version from the
// heartbeat, so a device that has never completed an update still LOOKS current — and on a fleet where the
// reporting lane is broken, every machine would read as fine. Silence is its own state and is counted as one.
func agentDeviceUpdateFor(device model.Device, event model.AgentUpdateEvent, offering map[string]string) agentDeviceUpdate {
	row := agentDeviceUpdate{DeviceID: device.ID}
	// The platform the DEVICE reported wins over the inventory's: the inventory may carry a display string
	// ("macOS 26") while the manifest is keyed by what the endpoint calls itself.
	platform := strings.ToLower(strings.TrimSpace(agentDeviceOSFrom(event)))
	if platform == "" {
		platform = agentDevicePlatformFromOS(device.OS)
	}
	// Same rule as the platform above, for the same reason: the device is the only thing that knows.
	arch := agentDeviceArchFrom(event)
	if arch == "" {
		arch = agentDeviceArch(platform)
	}
	target := ""
	if platform != "" && arch != "" {
		target = offering[updateTargetKey(platform, arch)]
	}
	row.TargetVersion = target

	if strings.TrimSpace(event.ID) == "" {
		row.State = agentDeviceStateNeverReported
		row.ReportedVersion = device.AgentVersion
		return row
	}
	row.ReportedVersion = event.CurrentAgentVersion
	row.ReportedAt = event.Timestamp
	if event.FailureReason != nil {
		row.Reason = *event.FailureReason
	}
	if meta := event.Metadata; meta != nil {
		if digest := stringValue(meta["rejected_manifest_sha256"]); digest != "" {
			row.RejectedManifestSHA256 = digest
		}
		if refused, _ := meta["refused"].(bool); refused {
			row.State = agentDeviceStateRefused
			return row
		}
	}
	switch strings.TrimSpace(event.UpdateStatus) {
	case "failed":
		row.State = agentDeviceStateFailed
	case "installed", "rolled_back":
		switch {
		case target == "":
			row.State = agentDeviceStateNoRelease
			row.Reason = bl_noRelease(device)
		case agentupdate.SameVersion(event.CurrentAgentVersion, target):
			row.State = agentDeviceStateUpToDate
		default:
			row.State = agentDeviceStatePending
		}
	default:
		row.State = agentDeviceStatePending
	}
	return row
}

// bl_noRelease says WHY nothing is offered, because the two reasons need different actions: publish a release,
// or find out what this device is.
func bl_noRelease(device model.Device) string {
	if strings.TrimSpace(device.OS) == "" {
		return "this control plane does not know this device's platform, so it cannot tell which release " +
			"applies to it"
	}
	return "no release is published for " + strings.TrimSpace(device.OS)
}

// agentDeviceOSFrom recovers the platform from what a device reported, for one the runtime store has never
// seen. Empty when nothing said — which shows as "no release offered for this device" rather than a guess.
func agentDeviceOSFrom(event model.AgentUpdateEvent) string {
	if event.Metadata == nil {
		return ""
	}
	return stringValue(event.Metadata["platform"])
}

// agentDevicePlatformFromOS maps an inventory OS string onto the name a manifest is keyed by. Unknown stays
// unknown: a guess here shows a device as current against a release that was never meant for it.
func agentDevicePlatformFromOS(os string) string {
	os = strings.ToLower(strings.TrimSpace(os))
	switch {
	case strings.Contains(os, "mac") || strings.Contains(os, "darwin"):
		return "darwin"
	case strings.Contains(os, "win"):
		return "windows"
	default:
		return ""
	}
}

// agentDeviceArch is the architecture a device's manifest target is keyed by. The inventory does not carry it
// today, so this answers the one the fleet actually runs and says so where it is used: a wrong arch shows a
// device as "no release offered" rather than inventing one.
// agentDeviceArchFrom is the architecture the DEVICE reported, which is the only source that can be right for
// an Intel Mac or a Windows-on-ARM box. Empty when the device has not said — an outbox written by an updater
// that predates the field, or a device that has never reported at all — and the caller falls back to the
// guess below rather than treating "" as an architecture.
func agentDeviceArchFrom(event model.AgentUpdateEvent) string {
	if event.Metadata == nil {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(stringValue(event.Metadata["arch"])))
}

// agentDeviceArch is the FALLBACK: the architecture the fleet mostly runs, for a device that has not reported
// one. It is a guess and it is wrong for real hardware — see the note below — so it is only reached when the
// device itself has said nothing.
func agentDeviceArch(platform string) string {
	// ★ "darwin" CONTAINS "win" (2026-08-12, and this cost an hour of looking at the wrong end). A substring
	// test for the platform name matched every Mac as Windows, so the row looked up darwin/amd64, found
	// nothing, and reported "no release is published for darwin" — while darwin/arm64 was sitting in the
	// offering it had just printed. The name is a whole token; it is compared as one.
	//
	// ★ AND IT IS A GUESS THAT IS WRONG FOR HARDWARE PEOPLE OWN (2026-08-12, fourteenth review). Intel Macs
	// and Windows-on-ARM read as arm64/amd64 here, so those devices were compared against a release built for
	// a different machine — "no release is published" for one that is, or "up to date" against a version that
	// cannot run. The device knows; agentDeviceArchFrom asks it first, and this stands in only until a device
	// has reported once.
	switch strings.ToLower(strings.TrimSpace(platform)) {
	case "windows":
		return "amd64"
	case "darwin":
		return "arm64"
	default:
		return ""
	}
}

func agentRolloutForTenant(plans *agentrollout.AgentRolloutStore, cache *agentRolloutCache,
	tenantID string) (agentrollout.AgentRolloutPlan, bool, string) {
	if cache != nil {
		plan, fetched, _ := cache.Get()
		if !fetched {
			// Serving FROZEN until the first pull is the enforcing Edge's rule, and the screen must say the
			// same thing the devices are being told.
			return plan, true, "this edge has not yet pulled the halt from the control plane"
		}
		return plan, plan.Frozen, plan.Reason
	}
	if plans == nil {
		return agentrollout.AgentRolloutPlan{}, false, ""
	}
	plan := plans.Get(tenantID)
	return plan, plan.Frozen, plan.Reason
}
