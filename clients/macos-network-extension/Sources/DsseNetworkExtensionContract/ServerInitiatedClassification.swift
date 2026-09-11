import Foundation

//  (Mac S3): server-initiated (inbound) flow classification.
//
// A server->client connection is an INBOUND connection to this managed endpoint: a remote server opened it,
// the local device is the destination. The macOS NETransparentProxyProvider can claim such flows via an
// `.inbound` NENetworkRule; this pure module turns a claimed inbound flow's metadata into the 
// DecisionRequest fields the Edge expects (connection_initiator=server, source_server, device_group,
// service_family, ...), so the Edge can apply server-initiated access control (default-deny + Legacy
// Exception). It is PURE (no NetworkExtension dependency) and unit-tested — the brain; the provider wires
// the claimed inbound flow into it and enforces the Edge's decision (next, device-bound slice).
//
// Mirrors the Windows WFP inbound path: the
// classification keys are identical so a tenant's Legacy Exceptions match the same way on both platforms.

public struct ServerInitiatedClassification: Equatable {
    /// Always "server": this is what triggers the Edge's server-initiated branch (isServerInitiated).
    public let connectionInitiator: String
    /// The remote endpoint that initiated the inbound connection — the server identity. Legacy Exception
    /// match key + audit key. An IP literal (the usual inbound case) or a normalized hostname.
    public let sourceServer: String
    /// This endpoint's device group (matched against a Legacy Exception's device_group). Empty = wildcard.
    public let deviceGroup: String
    /// Derived from the LOCAL port the server connected to (e.g. 3389->rdp, 445->smb).
    public let serviceFamily: String
    /// "tcp" / "udp".
    public let networkProtocol: String
    /// The local port the server connected to (Legacy Exception port match).
    public let destinationPort: Int

    public init(
        connectionInitiator: String,
        sourceServer: String,
        deviceGroup: String,
        serviceFamily: String,
        networkProtocol: String,
        destinationPort: Int
    ) {
        self.connectionInitiator = connectionInitiator
        self.sourceServer = sourceServer
        self.deviceGroup = deviceGroup
        self.serviceFamily = serviceFamily
        self.networkProtocol = networkProtocol
        self.destinationPort = destinationPort
    }
}

/// Classify an inbound (server->client) flow. Returns nil when the flow must NOT be treated as
/// server-initiated — a loopback/invalid remote (local traffic, not lateral) or an invalid local port — so
/// the provider leaves those alone. `remoteHost` is the connecting server's address (IP literal or host);
/// `localPort` is the port on THIS device the server connected to.
public func classifyServerInitiatedInboundFlow(
    remoteHost: String,
    localPort: Int,
    networkProtocol: String = "tcp",
    deviceGroup: String
) -> ServerInitiatedClassification? {
    // The remote must be a real, non-loopback address/host. normalizeFlowAuthorityHost rejects loopback IPs,
    // wildcards, and malformed input — exactly the flows that are not server-initiated lateral movement.
    guard let server = normalizeFlowAuthorityHost(remoteHost) else {
        return nil
    }
    guard validPort(localPort) else {
        return nil
    }
    let proto = normalizeNetworkProtocol(networkProtocol)
    return ServerInitiatedClassification(
        connectionInitiator: "server",
        sourceServer: server,
        deviceGroup: deviceGroup.trimmingCharacters(in: .whitespacesAndNewlines),
        serviceFamily: serverInitiatedServiceFamily(localPort),
        networkProtocol: proto,
        destinationPort: localPort
    )
}

/// Service family for a server-initiated inbound flow, keyed by the LOCAL listening port. Covers the
/// lateral-movement / remote-management protocols  and  care about; falls back to the generic
/// HTTP(S)/tcp mapping otherwise. Kept in lockstep with the Windows side's port->family mapping.
public func serverInitiatedServiceFamily(_ port: Int) -> String {
    switch port {
    case 3389:
        return "rdp"
    case 445, 139:
        return "smb"
    case 5985, 5986:
        return "winrm"
    case 22:
        return "ssh"
    case 135:
        return "rpc"
    case 5900:
        return "vnc"
    case 1433:
        return "mssql"
    case 443:
        return "https"
    case 80:
        return "http"
    default:
        return "tcp"
    }
}

private func normalizeNetworkProtocol(_ proto: String) -> String {
    let p = proto.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
    return p == "udp" ? "udp" : "tcp"
}
