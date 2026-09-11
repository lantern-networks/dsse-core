// swift-tools-version: 6.0

import PackageDescription

let package = Package(
    name: "DsseNetworkExtensionContract",
    platforms: [
        .macOS(.v13)
    ],
    products: [
        .library(
            name: "DsseNetworkExtensionContract",
            targets: ["DsseNetworkExtensionContract"]
        ),
        .library(
            name: "DsseAppProxyProviderSkeleton",
            targets: ["DsseAppProxyProviderSkeleton"]
        ),
        .executable(
            name: "DsseAgent",
            targets: ["DsseAgentAppExecutable"]
        ),
        .executable(
            name: "DsseAppProxyProvider",
            targets: ["DsseAppProxyProviderExecutable"]
        )
    ],
    targets: [
        .target(
            name: "DsseNetworkExtensionContract"
        ),
        .target(
            name: "DsseAppProxyProviderSkeleton",
            dependencies: ["DsseNetworkExtensionContract"]
        ),
        .executableTarget(
            name: "DsseAgentAppExecutable",
            dependencies: [
                "DsseNetworkExtensionContract",
                "DsseAppProxyProviderSkeleton"
            ]
        ),
        .executableTarget(
            name: "DsseAppProxyProviderExecutable",
            dependencies: [
                "DsseNetworkExtensionContract",
                "DsseAppProxyProviderSkeleton"
            ]
        ),
        .testTarget(
            name: "DsseAppProxyProviderSkeletonTests",
            dependencies: [
                "DsseNetworkExtensionContract",
                "DsseAppProxyProviderSkeleton"
            ]
        )
    ]
)
