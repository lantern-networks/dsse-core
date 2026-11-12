# Changes since 0.4.1

The baseline is the published `v0.4.1-experimental` source and its artifacts. See
[Acceptance](verification.md) for what was installed and checked.

## Installation

| Area | 0.4.2 |
|---|---|
| One command per machine | `dsse-install -up` runs the steps `-order` prints, in the same order, for every published layout. A single machine is installed with one command and no plan file; a plan with several machines takes one command on the first machine and one on each other machine, or one command in all with `-ssh`. Completed steps are kept, so the same command continues after a failure. See [Deployment](../../deployment.md#run-the-order-with--up) |
| Installer binaries | The release publishes `dsse-install` built for Linux x86-64 and arm64, so the first machine needs Docker and no Go toolchain or source clone |
| Release manifest | `-release-manifest release-manifest.json` takes the image references, the packages' publisher and the PostgreSQL major from the published manifest; a plan does not have to carry them |
| Names | `-up` lists the names that do not resolve before it creates anything, and `-print-names` prints the lines for a hosts file |
| First administrator | `-up` writes the first administrator's credentials to `admin-credentials.txt`, readable only by its owner, and prints where it is |

## Scale

| Area | 0.4.2 |
|---|---|
| Device heartbeats | An Edge no longer writes its whole device inventory for every heartbeat. A heartbeat that only renews the time is answered at once and saved within five seconds; one that changes what the Edge knows about the device is saved before it is answered, and changes that arrive together share one write |
| Entrance | The generated entrance (HAProxy) uses the whole local port range for its connections to the Edges, so a fleet reconnecting at once does not run out of source ports |
| Audit shipping | An Edge whose audit spool is full no longer rewrites the spool for every record |

## Security and dependencies

| Area | 0.4.2 |
|---|---|
| Go | Every binary is built with Go 1.27.4, which fixes GO-2026-6859 (CVE-2026-97054) in `net/http` |
| Go modules | `golang.org/x/sys` 0.50.0, `golang.org/x/text` 0.44.0, `klauspost/compress` 1.20.4, `andybalholm/brotli` 1.3.0 |
| Images | Alpine 3.24.4 bases for the product, Console and tools images, PostgreSQL 18.6 on Alpine 3.24 for the tools image, and the current HAProxy 3.4.7 digest. See [Dependency versions](../../dependency-versions.md) |

## Endpoints

The Windows and macOS agents have no functional change. Both packages are rebuilt from
the 0.4.2 source with Go 1.27.4 and the modules above. The Windows driver is the
Microsoft-signed file shipped since 0.4.0.
