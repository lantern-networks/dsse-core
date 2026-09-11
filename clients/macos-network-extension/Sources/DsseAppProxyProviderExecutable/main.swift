import Dispatch
import DsseAppProxyProviderSkeleton
import DsseNetworkExtensionContract
import Foundation
import NetworkExtension
import OSLog

private let providerLogger = Logger(
    subsystem: DsseRuntimeLogSubsystem.name,
    category: "app-proxy-provider"
)

private func log(_ message: String) {
    providerLogger.notice("\(message, privacy: .public)")
    NSLog("DsseAppProxyProvider: %@", message)
    FileHandle.standardError.write(Data("DsseAppProxyProvider: \(message)\n".utf8))
}

private let providerPrincipalClassName = NSStringFromClass(DsseAppProxyProvider.self)

log("starting Network Extension System Extension provider mode for \(providerPrincipalClassName)")
NEProvider.startSystemExtensionMode()
dispatchMain()
