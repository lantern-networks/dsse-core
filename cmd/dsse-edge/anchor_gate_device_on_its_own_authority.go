package main

import (
	"strings"
	"time"
)

// anchor_gate_device_on_its_own_authority.go — a device that has moved to its organization's own transport
// authority does not depend on the shared anchor store at all.
//
// ★★★ AFTER ROADMAP D, NO ANCHOR IN THE SHARED STORE COULD EVER BE WITHDRAWN AGAIN (2026-08-20, measured).
//
// The withdrawal gate asks whether some certificate REMAINING IN THIS STORE is trusted by every enrolled
// device. That was the right question while every device verified the Edge against the deployment-wide
// anchor. Roadmap D gave each organization its own transport certificate, delivered per organization and not
// through this store, so both real devices now report pinning e9ad1954… — their organization's CA — and
// neither pins the shared MSSP anchor.
//
// So the gate found nothing that "every device trusts", and refused: twenty-two attempts over eighteen
// minutes, every one "unconfirmed: mac-dev-1, win-dev-1", while both devices were healthy and had reported
// adopting the CURRENT serial minutes earlier. The store had become append-only, and the last step of the
// roadmap — retiring the shared anchor — was unreachable through the door an administrator uses.
//
// A device is counted as covered here only on its OWN evidence and only against what THIS NODE SERVES:
//   - the device's report is fresh (the same shelf life the readiness rule uses — a six-month-old report says
//     nothing about a machine that has since been re-imaged),
//   - it reports the fingerprint of the transport CA this Edge is serving for that device's organization, and
//   - the withdrawal target is not that CA.
//
// It never widens to a device that reports nothing, reports something stale, or reports a fingerprint this
// node does not serve — those stay in the denominator, where a straggler belongs.
func devicesOnTheirOwnOrganizationsAuthority(config serverConfig, tenantID, targetSHA string,
	known []string) map[string]bool {
	covered := map[string]bool{}
	if config.ObservedExclusions == nil || transportTenantCertificates == nil {
		return covered
	}
	target := strings.ToLower(strings.TrimSpace(targetSHA))
	// Asked one device at a time, by exact identity. A single paged listing would silently leave whoever fell
	// off the last page OUT of the covered set — which reads as "this device has not confirmed" and is the
	// safe direction, but it also makes the answer depend on page size, and this file is about a denominator
	// that stopped matching reality once already.
	for _, device := range known {
		id := strings.ToLower(strings.TrimSpace(device))
		if id == "" {
			continue
		}
		page := config.ObservedExclusions.Query(tenantID, observedQueryFilter{Device: device, Limit: 1})
		if len(page.Entries) == 0 {
			continue
		}
		entry := page.Entries[0]
		if !strings.EqualFold(strings.TrimSpace(entry.DeviceIdentity), device) || len(entry.PinnedTransportCASHA256) == 0 {
			continue
		}
		if entry.ReportedAt.IsZero() || time.Since(entry.ReportedAt) > transportCAReportShelfLife {
			continue
		}
		own, ok := transportTenantCertificates.AnchorFingerprintFor(strings.TrimSpace(entry.TenantID))
		own = strings.ToLower(strings.TrimSpace(own))
		if !ok || own == "" || own == target {
			continue
		}
		if entry.pinsTransportCA(own) {
			covered[id] = true
		}
	}
	return covered
}
