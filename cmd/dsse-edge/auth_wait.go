package main

import (
	"context"
	"time"

	"github.com/lantern-networks/dsse-core/edgeplane"
)

// steerMuxStepUpGrantWait bounds how long a held native flow is parked waiting for the OOB step-up ceremony to
// mint a grant before we give up and drop it (the client then retries). Long enough for a human to complete an
// interactive IdP login; short enough not to pin a native client past its own connect patience.
const steerMuxStepUpGrantWait = 120 * time.Second
const steerMuxStepUpPollInterval = 500 * time.Millisecond

// waitForStepUpGrant parks a held steer-mux flow until the device earns a live step-up grant (the OOB browser
// ceremony completed) or the bound elapses / the client gives up. Returns true only if a grant appeared, so the
// caller can resume forwarding on the same held connection (auto-release, task #5). It never blocks the mux
// demux: handleOpen runs per-flow in its own goroutine, and peer CLOSE still routes to vc via the demux loop.
func waitForStepUpGrant(ctx context.Context, gate *federatedAuthGate, tenantID, deviceID string, requirements federatedRequirements, vc *edgeplane.MuxVirtualConn, maxWait time.Duration, portalURL ...string) bool {
	link := ""
	if len(portalURL) == 1 {
		link = portalURL[0]
	}
	// The compatibility helper has no current-policy re-evaluation callback, so
	// it must not announce a confirmed resumed result to the endpoint UI.
	return waitForStepUpGrantInternal(ctx, gate, tenantID, deviceID, requirements, vc, maxWait, link, func() bool { return true }, false)
}

// Keep both the quota slot and the small buffer until current policy has been
// checked. Failure closes the flow; only successful authorization restores it.
func waitForStepUpGrantChecked(ctx context.Context, gate *federatedAuthGate, tenantID, deviceID string, requirements federatedRequirements, vc *edgeplane.MuxVirtualConn, maxWait time.Duration, portalURL string, authorize func() bool, notify ...func(string)) bool {
	result := func(outcome string) { _ = vc.SendAuthResult(requirements.RequestID, outcome) }
	if len(notify) == 1 && notify[0] != nil {
		result = notify[0]
	}
	return waitForStepUpGrantInternal(ctx, gate, tenantID, deviceID, requirements, vc, maxWait, portalURL, authorize, true, result)
}

func waitForStepUpGrantInternal(ctx context.Context, gate *federatedAuthGate, tenantID, deviceID string, requirements federatedRequirements, vc *edgeplane.MuxVirtualConn, maxWait time.Duration, portalURL string, authorize func() bool, reportResult bool, report ...func(string)) bool {
	if gate == nil || vc == nil || maxWait <= 0 || (gate.draining != nil && gate.draining.Load()) {
		return false
	}
	release, ok := gate.waitBudget.acquire(tenantID, deviceID)
	if !ok {
		return false
	}
	defer release()
	if !vc.BeginAuthWait() {
		return false
	}
	resumed := false
	defer func() {
		// A successful wait only releases the hold. The caller reports "resumed"
		// after it has established the upstream connection; a dial can still fail.
		if reportResult && !resumed && portalURL != "" && requirements.RequestID != "" {
			if len(report) == 1 && report[0] != nil {
				report[0]("not_resumed")
			}
		}
		if !resumed {
			_ = vc.Close()
		}
	}()
	if portalURL != "" && vc.SendStepUp(portalURL) != nil {
		return false
	}
	deadline := time.Now().Add(maxWait)
	t := time.NewTicker(steerMuxStepUpPollInterval)
	defer t.Stop()
	for {
		select {
		case <-vc.Closed():
			return false
		case <-ctx.Done():
			return false
		default:
		}
		if !time.Now().Before(deadline) {
			return false
		}
		if gate.hasLiveGrantWithRequirements(tenantID, deviceID, requirements) {
			if authorize == nil || !authorize() || ctx.Err() != nil || !time.Now().Before(deadline) {
				return false
			}
			resumed = vc.EndAuthWait()
			return resumed
		}
		select {
		case <-vc.Closed():
			return false // client/agent gave up (peer CLOSE) or the mux tore down
		case <-ctx.Done():
			return false
		case <-t.C:
			if !time.Now().Before(deadline) {
				return false
			}
		}
	}
}
