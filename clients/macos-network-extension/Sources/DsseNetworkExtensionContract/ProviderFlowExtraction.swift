import Foundation

public enum ProviderFlowTransport: String, Codable, Equatable {
    case tcp
    case udp
    case unknown
}

public enum ProviderFlowExtractionStatus: String, Codable, Equatable {
    case ok
    case denied
}

// Drops un-interceptable QUIC (UDP/443) for steer-target flows and forces a fallback to TCP/TLS.
// Closes the ZTNA hole where QUIC escapes steering and passes through, handled by the NE itself
// (the product-mechanism version of the host pf hack). Not applied to excluded/passthrough flows
// (e.g. self-excluded apps); evaluated after the passthrough decision in handleNewFlow.
public enum ProviderQUICFallbackPolicy {
    public static let quicUDPPort = 443

    public static func shouldDropForcingTCPFallback(transport: ProviderFlowTransport, remotePort: Int) -> Bool {
        transport == .udp && remotePort == quicUDPPort
    }
}

public enum ProviderFlowExtractionReason: String, Codable, Equatable {
    case extracted = "extracted_tcp_host_port"
    case unsupportedTransport = "unsupported_transport"
    case invalidFlowAuthority = "invalid_flow_authority"
}

public struct ProviderFlowAuthorityInput: Equatable {
    public let transport: ProviderFlowTransport
    public let remoteHost: String
    public let remotePort: Int
    public let sourceBundleID: String?

    public init(transport: ProviderFlowTransport, remoteHost: String, remotePort: Int, sourceBundleID: String? = nil) {
        self.transport = transport
        self.remoteHost = remoteHost
        self.remotePort = remotePort
        self.sourceBundleID = sourceBundleID
    }
}

public struct ProviderFlowExtractionResult: Codable, Equatable {
    public let status: ProviderFlowExtractionStatus
    public let reason: ProviderFlowExtractionReason
    public let flowTransport: ProviderFlowTransport
    public let sourceBundleIDPresent: Bool
    public let sourceBundleIDTrusted: Bool
    public let providerFlowRequest: ProviderFlowRequest?

    enum CodingKeys: String, CodingKey {
        case status
        case reason
        case flowTransport = "flow_transport"
        case sourceBundleIDPresent = "source_bundle_id_present"
        case sourceBundleIDTrusted = "source_bundle_id_trusted"
        case providerFlowRequest = "provider_flow_request"
    }
}

public enum ProviderFlowExtractor {
    public static func extract(_ input: ProviderFlowAuthorityInput) -> ProviderFlowExtractionResult {
        guard input.transport == .tcp else {
            return denied(input, reason: .unsupportedTransport)
        }
        guard let host = normalizeFlowAuthorityHost(input.remoteHost), validPort(input.remotePort) else {
            return denied(input, reason: .invalidFlowAuthority)
        }
        return ProviderFlowExtractionResult(
            status: .ok,
            reason: .extracted,
            flowTransport: input.transport,
            sourceBundleIDPresent: sourceBundleIDPresent(input.sourceBundleID),
            sourceBundleIDTrusted: false,
            providerFlowRequest: ProviderFlowRequest(host: host, port: input.remotePort, sourceBundleID: nil)
        )
    }

    private static func denied(_ input: ProviderFlowAuthorityInput, reason: ProviderFlowExtractionReason) -> ProviderFlowExtractionResult {
        ProviderFlowExtractionResult(
            status: .denied,
            reason: reason,
            flowTransport: input.transport,
            sourceBundleIDPresent: sourceBundleIDPresent(input.sourceBundleID),
            sourceBundleIDTrusted: false,
            providerFlowRequest: nil
        )
    }

    private static func sourceBundleIDPresent(_ value: String?) -> Bool {
        guard let value else {
            return false
        }
        return !value.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }
}
