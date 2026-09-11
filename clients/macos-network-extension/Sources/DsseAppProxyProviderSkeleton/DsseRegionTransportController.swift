import Foundation
import OSLog
import DsseNetworkExtensionContract

// Same subsystem as the rest of the NE provider so the operator's existing
// `log stream --predicate 'subsystem == "<the app's bundle id>"'` picks these up — the name is
// derived, never a literal; see DsseRuntimeLogSubsystem.
private let dsseRegionFailoverLogger = Logger(subsystem: DsseRuntimeLogSubsystem.name, category: "region-failover")

// DsseRegionTransportController is the agent-side ORCHESTRATION that ties the signed region list, the selector,
// and a health probe into one control loop, emitting a Decision the provider acts on (steer through the current
// region / deny when fail-closed). It is the last piece before the live transport wiring: the provider only has
// to (1) feed the verified list from the poller via updateList(), and (2) act on each Decision — rebuild the
// runtime-copy transport for dec.current.endpoint on a region change, or deny on .failClosed / .denied.
//
// Everything here is unit-testable with an injected probe; the real probe (out-of-band resolve + TCP + (T) mTLS)
// and the transport rebuild live in the provider, behind these two seams.
public final class DsseRegionTransportController: @unchecked Sendable {
    private let selector: DsseRegionSelector
    private let probe: (DsseRegionEndpoint) -> DsseRegionHealth
    // onDecision(decision, regionChanged): the provider steers through decision.current (rebuilding the transport
    // when regionChanged is true) or denies on .failClosed / .denied.
    private let onDecision: (DsseRegionDecision, Bool) -> Void
    private let queue = DispatchQueue(label: "dsse.region-transport-controller")
    private var timer: DispatchSourceTimer?
    private var lastCurrentRegion: String = ""
    private var heldLogKey: String = "" // dedup: (region|kind) of the last-logged hold; a change (region OR benign->admission-deny) re-logs

    public init(selector: DsseRegionSelector,
                probe: @escaping (DsseRegionEndpoint) -> DsseRegionHealth,
                onDecision: @escaping (DsseRegionDecision, Bool) -> Void) {
        self.selector = selector
        self.probe = probe
        self.onDecision = onDecision
    }

    /// Feed a freshly-verified region list (wire this to DsseRegionEndpointPoller.start's onUpdate). A residency
    /// shrink that removes the current region drops it inside the selector.
    public func updateList(_ verified: DsseVerifiedRegionEndpoints) {
        queue.async { [weak self] in
            self?.selector.updateList(allowed: verified.endpoints, home: verified.homeRegion)
        }
    }

    /// Run one probe+select round and emit the decision. Returns the decision (also delivered via onDecision).
    @discardableResult
    public func evaluateOnce() -> DsseRegionDecision {
        let dec = selector.evaluate(probe: probe)
        // Observability for the accepted-risk hysteresis window (does NOT change behavior): the hold is
        // otherwise silent. Log it once per entry — loudly when it is an admission-deny (a revoked/not-enrolled
        // device kept steering through this region until the kill-switch takes effect). Mirrors the Windows
        // agent's act(). See docs/2026-07-26_region_failover_hysteresis_accepted_risk.ja.md.
        if dec.held {
            // Dedup on (region|kind): log once per entry, but ALWAYS re-log when the region changes or a benign
            // unreachable hold ESCALATES to an admission-deny (revocation) — a single bool would swallow that.
            let region = dec.current?.region ?? "?"
            let key = region + "|" + (dec.heldAdmissionDenied ? "denied" : "unreach")
            if key != heldLogKey {
                if dec.heldAdmissionDenied {
                    dsseRegionFailoverLogger.warning("HOLDING admission-denied region \(region, privacy: .public) under hysteresis (revoked/not-enrolled) — failover suppressed for stability; client-side deny in <=\(dec.heldRoundsRemaining, privacy: .public) more round(s). The Edge still denies this device independently per connection.")
                } else {
                    dsseRegionFailoverLogger.notice("holding degraded (unreachable) region \(region, privacy: .public) under hysteresis — tolerating a transient blip; failover in <=\(dec.heldRoundsRemaining, privacy: .public) more round(s).")
                }
                heldLogKey = key
            }
        } else {
            heldLogKey = ""
        }
        let changedRegion = (dec.current?.region ?? "") != lastCurrentRegion
        lastCurrentRegion = dec.current?.region ?? ""
        // Always deliver so the provider can act on fail-closed/denied too; it rebuilds the transport only when
        // the current region actually changed (regionChanged).
        onDecision(dec, changedRegion)
        return dec
    }

    /// Returns true if the most recent evaluation changed the current region (the provider's signal to rebuild
    /// the transport).
    public func currentRegion() -> String { lastCurrentRegion }

    public func start(interval: TimeInterval) {
        queue.async { [weak self] in
            guard let self else { return }
            _ = self.evaluateOnceLocked()
            let t = DispatchSource.makeTimerSource(queue: self.queue)
            t.schedule(deadline: .now() + interval, repeating: interval)
            t.setEventHandler { [weak self] in _ = self?.evaluateOnceLocked() }
            t.resume()
            self.timer = t
        }
    }

    public func stop() {
        queue.async { [weak self] in
            self?.timer?.cancel()
            self?.timer = nil
        }
    }

    private func evaluateOnceLocked() -> DsseRegionDecision { evaluateOnce() }
}
