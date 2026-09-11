import Foundation
import Network
import DsseNetworkExtensionContract

// DsseRegionTCPProbe is the health probe for the region selector.
//
// ★★★ IT MAKES THE CONNECTION THE TUNNEL MAKES, OR IT IS MEASURING A DIFFERENT QUESTION (2026-08-31).
//
// Until today this opened a bare TCP socket and reported `admitted: reachable` — the two fields of
// DsseRegionHealth collapsed into one, on a probe that could not tell them apart. The contract it fills in
// says what they mean: "reachable = the (T) transport answered (TCP + mTLS handshake completed)" and
// "admitted = this device was admitted (NOT a revoked / not-enrolled handshake rejection)". A TCP connect
// answers neither.
//
// The cost was measured on 2026-08-30. Both regions' Edges stopped serving any certificate for half an hour
// — every SNI got `no peer certificate available` — and 443 stayed open the whole time, so this probe called
// both regions healthy and the device had nowhere to fail over TO. A region that listens and refuses is the
// exact failure this selector exists for, and it was the one shape the probe could not see.
//
// So the parameters come from makeTunnelParameters, the same call the tunnel uses: the same announced server
// name, the same anchors resolved live, the same client identity. Not a re-derivation of them — the Windows
// side found the mirror of this on their own probe, where it handshook under a DIFFERENT name than the real
// connection and failed x509 against a healthy region. A probe that builds its own parameters is a second
// implementation of the thing it is supposed to be testing.
public enum DsseRegionTCPProbe {
    // Lock-protected result holder so the @Sendable NWConnection state handler can publish back to the caller
    // under Swift 6 strict concurrency.
    private final class Result: @unchecked Sendable {
        private let lock = NSLock()
        private var reachable = false
        private var admitted = false
        private var rttMillis = 0
        private var detail = ""
        func admit(rtt: Int) { lock.lock(); reachable = true; admitted = true; rttMillis = rtt; lock.unlock() }
        /// The transport answered and then refused this device: TCP is open, TLS did not complete.
        func refused(rtt: Int, why: String) {
            lock.lock(); reachable = true; admitted = false; rttMillis = rtt; detail = why; lock.unlock()
        }
        func down(why: String) { lock.lock(); detail = why; lock.unlock() }
        func snapshot() -> (Bool, Bool, Int, String) {
            lock.lock(); defer { lock.unlock() }; return (reachable, admitted, rttMillis, detail)
        }
    }

    /// probe dials a region's (T) endpoint exactly as the tunnel would. `parameters` must come from the
    /// caller's live transport security so that what is measured is what would be used; the parameterless
    /// form is for tests and for the case where no transport has been built yet, and says so in the result.
    public static func probe(endpoint: String, timeout: TimeInterval = 2.0,
                             parameters: @autoclosure () -> NWParameters? = nil) -> DsseRegionHealth {
        guard let (host, port) = hostPort(endpoint) else {
            return DsseRegionHealth(reachable: false, admitted: false, rttMillis: 0)
        }
        // ★ NO TRANSPORT YET IS NOT "HEALTHY". Before this device has a transport there is nothing to
        // handshake with, and the honest answer about admission is "not established" — which, for a selector
        // that must not hunt for a region that admits a revoked device, is reported as reachable-but-not-
        // admitted rather than as a healthy region.
        guard let params = parameters() else {
            let tcp = probeTCPOnly(host: host, port: port, timeout: timeout)
            return DsseRegionHealth(reachable: tcp.0, admitted: false, rttMillis: tcp.1)
        }
        let conn = NWConnection(host: host, port: port, using: params)
        let sem = DispatchSemaphore(value: 0)
        let start = DispatchTime.now()
        let result = Result()
        conn.stateUpdateHandler = { (state: NWConnection.State) in
            switch state {
            case .ready:
                result.admit(rtt: Int(Double(DispatchTime.now().uptimeNanoseconds - start.uptimeNanoseconds) / 1_000_000.0))
                sem.signal()
            case .failed(let error):
                // ★★★ NOT EVERY TLS FAILURE IS A REFUSAL OF THIS DEVICE, AND THE DIFFERENCE IS A KILL SWITCH.
                //
                // The caller arms setDenyOnAdmissionDeny and setInstantRevokeOnAdmissionDeny, so
                // admitted=false on the current region makes this device stop carrying traffic at the first
                // probe. If every TLS error were read as "denied", an Edge restarting mid-handshake, a
                // certificate rotation, or the half hour on 2026-08-30 when both Edges served no certificate
                // at all would each have taken this Mac dark on their own — and this deployment's rule is
                // that a device is blocked when an ADMINISTRATOR blocks it, never because a probe had a bad
                // second.
                //
                // A refusal OF THIS DEVICE is a fatal alert the peer sent about the certificate we presented.
                // Those, and only those, are admission denials. Everything else — our own trust evaluation
                // failing, the peer serving nothing, an aborted handshake — means the region is unhealthy,
                // which is what failover is for.
                switch error {
                case .tls(let status) where Self.isAdmissionDenial(status):
                    result.refused(rtt: Int(Double(DispatchTime.now().uptimeNanoseconds - start.uptimeNanoseconds) / 1_000_000.0), why: "tls/\(status) \(Self.denialName(status))")
                default:
                    result.down(why: "\(error)")
                }
                sem.signal()
            case .cancelled:
                sem.signal()
            default:
                break
            }
        }
        conn.start(queue: DispatchQueue(label: "dsse.region-probe"))
        _ = sem.wait(timeout: .now() + timeout)
        conn.cancel()
        let (reachable, admitted, rttMillis, detail) = result.snapshot()
        if reachable && !admitted {
            dsseRuntimeLog("region_probe endpoint=\(endpoint) REFUSED this device (\(detail)) — the region is "
                + "up and did not admit this device. Failing over would only look for a region that says yes "
                + "to a device this deployment has declined, so it is reported and not fled from")
        }
        return DsseRegionHealth(reachable: reachable, admitted: admitted, rttMillis: rttMillis)
    }


    /// isAdmissionDenial reports whether an OSStatus is a fatal alert the PEER sent about the certificate this
    /// device presented — the only shape that means "this deployment declined this device" rather than "this
    /// region is having a bad minute". Anything absent from this list makes the region unhealthy instead, and
    /// unhealthy is recoverable; denied is not.
    static func isAdmissionDenial(_ status: OSStatus) -> Bool {
        denialNames[status] != nil
    }

    static func denialName(_ status: OSStatus) -> String {
        denialNames[status] ?? "unknown"
    }

    private static let denialNames: [OSStatus: String] = [
        -9825: "peer rejected our certificate (bad_certificate)",
        -9832: "peer says our certificate is revoked",
        -9833: "peer says our certificate is expired",
        -9834: "peer does not recognise our certificate (certificate_unknown)",
        -9835: "peer does not trust the authority that issued our certificate (unknown_ca)",
        -9836: "peer refused this device (access_denied)",
    ]

    private static func probeTCPOnly(host: NWEndpoint.Host, port: NWEndpoint.Port,
                                     timeout: TimeInterval) -> (Bool, Int) {
        let conn = NWConnection(host: host, port: port, using: .tcp)
        let sem = DispatchSemaphore(value: 0)
        let start = DispatchTime.now()
        let result = Result()
        conn.stateUpdateHandler = { (state: NWConnection.State) in
            switch state {
            case .ready:
                result.admit(rtt: Int(Double(DispatchTime.now().uptimeNanoseconds - start.uptimeNanoseconds) / 1_000_000.0))
                sem.signal()
            case .failed, .cancelled:
                sem.signal()
            default:
                break
            }
        }
        conn.start(queue: DispatchQueue(label: "dsse.region-probe.tcp"))
        _ = sem.wait(timeout: .now() + timeout)
        conn.cancel()
        let (reachable, _, rtt, _) = result.snapshot()
        return (reachable, rtt)
    }

    /// Parse host + port from a region endpoint URL (https://host:port).
    static func hostPort(_ urlString: String) -> (NWEndpoint.Host, NWEndpoint.Port)? {
        guard let url = URL(string: urlString.trimmingCharacters(in: .whitespacesAndNewlines)),
              let host = url.host, !host.isEmpty else { return nil }
        let rawPort = url.port ?? (url.scheme == "https" ? 443 : 80)
        guard rawPort > 0, rawPort <= 65535, let port = NWEndpoint.Port(rawValue: UInt16(rawPort)) else { return nil }
        return (NWEndpoint.Host(host), port)
    }
}
