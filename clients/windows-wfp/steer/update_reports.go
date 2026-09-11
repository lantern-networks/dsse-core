//go:build windows

// update_reports.go — the agent sends what the UPDATER could not.
//
// ★ WHY THE TWO ARE SPLIT (2026-08-12). DsseUpdater runs as LocalSystem and launches msiexec; it deliberately
// holds no network identity, because giving the process most likely to be replaced mid-execution the
// certificate that proves this machine's identity is not a trade worth making. So it writes each terminal
// outcome to a directory beside its journal, and this agent — which already holds that certificate and already
// beats on a timer — sends them.
//
// ★ AND WHY IT MATTERS AT ALL. Until this existed the ingest route (`POST /devices/{id}/agent-updates`) had no
// caller on either platform. Every update, rollback and failure this product performed was invisible to the
// control plane: the fleet view read `total: 0` whether a fleet had updated cleanly or the updater had never
// run once. "Nothing to report" and "nothing is reporting" rendered identically on the one screen an operator
// would actually look at.
package main

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"github.com/lantern-networks/dsse-core/agentupdate"
)

// updateReportsDir is where DsseUpdater leaves them: beside its journal, under %ProgramData%.
func updateReportsDir() string {
	root := os.Getenv("ProgramData")
	if root == "" {
		root = "DSSE"
		return agentupdate.ReportsDir(filepath.Join(root, "update", "journal.json"))
	}
	return agentupdate.ReportsDir(filepath.Join(root, "DSSE", "update", "journal.json"))
}

// agentUpdateEventBody is the ingest route's shape. Built here rather than imported so the agent does not take
// a dependency on the Edge's model package for four fields.
//
// device_id and tenant_id come from THIS process's verified identity, not from the report: the updater records
// what it could read from the runstate file, and the authoritative answer is the certificate the Edge checked.
// A device that mis-identifies itself in a fleet report is worse than one that does not report.
func agentUpdateEventBody(cfg heartbeatConfig, r agentupdate.Report) map[string]any {
	// ★ rolled_back GOES OUT AS ITSELF (2026-08-12, sixth review). It used to be rewritten to `installed` on
	// the grounds that the Edge has one word for a completed install — but the Edge's own aggregation counts
	// rolled_back SEPARATELY, so flattening it counted every rollback as a successful update and inflated the
	// rollout success rate with the events that most contradict it.
	meta := map[string]any{
		// The control plane cannot tell which release applies to a device without knowing what it is; its
		// enrolment ledger carries no platform.
		"platform": r.Platform,
		// ★ AND THE ARCH BESIDE IT (2026-08-12, fourteenth review). A release target is keyed by platform AND
		// arch; sending only the platform left the Edge to guess the other half, and it guessed a constant per
		// OS — so a Windows-on-ARM box was compared against the amd64 release.
		"arch":            r.Arch,
		"kind":            r.Kind,
		"reported_by":     "dsse-steer",
		"device_recorded": r.DeviceID,
	}
	if r.DroppedBefore > 0 {
		// ★ SAID OUT LOUD. A device offline long enough to overflow its outbox must not come back with a tidy
		// history that silently begins in the middle.
		meta["dropped_before"] = r.DroppedBefore
	}
	body := map[string]any{
		// ★ THE ID GOES ON THE WIRE (2026-08-12, sixth review). The stored report already has a stable one, and
		// dropping it meant every RETRY — a lost response, or a crash between "accepted" and "removed" — became
		// a NEW event at the Edge: counted twice in the success rate and audited twice. The Edge treats a
		// repeated id as the same event.
		"id":                    r.ID,
		"device_id":             cfg.deviceID,
		"tenant_id":             cfg.tenantID,
		"current_agent_version": r.RunningVersion,
		"target_agent_version":  r.TargetVersion,
		"update_status":         edgeUpdateStatus(r.Status),
		// ★ NOT "dsse" (2026-08-12, sixth review, found by reading the schema this lands in). The Edge's
		// agent_update_events table CHECKs update_source IN ('mdm','control_plane','manual'), so the value the
		// first version of this file sent would have been REJECTED on every insert — the fleet view would have
		// stayed empty for a third reason. The release came from the control plane, which is what this means.
		"update_source": "control_plane",
		"timestamp":     r.At,
		"metadata":      meta,
	}
	if r.Reason != "" {
		body["failure_reason"] = r.Reason
	}
	if r.FromVersion != "" {
		meta["from_version"] = r.FromVersion
	}
	if r.Status == agentupdate.ReportRolledBack {
		meta["rolled_back"] = true
	}
	if r.Status == agentupdate.ReportRefused {
		meta["refused"] = true
	}
	if r.RejectedDigest != "" {
		// ★ IT IS THE ONLY THING THAT IDENTIFIES THIS REFUSAL (2026-08-12, ninth review). A manifest that does
		// not verify supplies no version this box may believe, so the refusal has none — and without the digest
		// the fleet sees "no version, generic signature error" and cannot tell a SECOND substituted document
		// from a repeat of the first. It was stored in the report on the device and dropped on the way out.
		meta["rejected_manifest_sha256"] = r.RejectedDigest
	}
	return body
}

// edgeUpdateStatus maps a device-side status to one the Edge's schema accepts.
//
// ★ THE SCHEMA IS A CHECK CONSTRAINT, NOT A SUGGESTION. agent_update_events allows
// available|downloaded|installing|installed|failed|rolled_back. A REFUSAL — a device told to update that
// cannot, which is the state an operator most needs to see — has no value of its own there, and inventing one
// would have every such row rejected at insert.
//
// So it goes as `failed`, which is true from the fleet's point of view (this device is not on the target), and
// the metadata carries `refused: true` with the reason so the two are still distinguishable to anyone reading
// the event rather than the counter.
func edgeUpdateStatus(status string) string {
	if status == agentupdate.ReportRefused {
		return "failed"
	}
	return status
}

// drainUpdateReports sends everything the updater has queued, oldest first, and stops at the first refusal.
//
// Called only AFTER a heartbeat has succeeded, which is why there is no backoff here: a successful beat has
// just proved the route and the certificate work, so a failure in the drain is about THIS request rather than
// about the device being offline. A device with no route never reaches this line.
//
// Quiet when there is nothing to send — this runs on every beat — and loud on both interesting outcomes: a
// report that went out, and a report that could not. Silence here would recreate the exact defect the file
// exists to fix, one layer up.
func drainUpdateReports(cfg heartbeatConfig, client *http.Client) {
	dir := updateReportsDir()
	if agentupdate.PendingReports(dir) == 0 {
		return
	}
	url := cfg.baseURL() + "/devices/" + cfg.deviceID + "/agent-updates"
	sent, corrupt, err := agentupdate.DrainReports(dir, func(r agentupdate.Report) error {
		return postJSON(client, url, agentUpdateEventBody(cfg, r), http.StatusAccepted, http.StatusOK)
	})
	if sent > 0 {
		fmt.Printf("update reports: %d outcome(s) delivered to the Edge for device %s\n", sent, cfg.deviceID)
	}
	if corrupt > 0 {
		fmt.Fprintf(os.Stderr, "update reports: %d unreadable report(s) were discarded — that many update "+
			"outcomes will never appear in the fleet view\n", corrupt)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "update reports: %d still waiting (kept, in order): %v\n",
			agentupdate.PendingReports(dir), err)
	}
}
