# Windows agent packaging

Build the user-mode programs and MSI from the public source tree. For endpoint installation,
use the [Windows agent guide](../../../docs/windows-agent.md). This page is for package builders.

## Prerequisites

- Windows, Go 1.25 or newer, PowerShell, and a .NET SDK.
- WiX 5 (`dotnet tool install --global wix --version 5.0.2`) and the Windows SDK signing tools.
- A driver matching the target architecture and accepted by the target's Windows security policy.
- Your own signing identity for a distributed MSI. The `test` backend is for development only.

The [driver build guide](../driver/BUILD.md) produces a development driver. For the
attestation path, Microsoft's [signing requirements](https://learn.microsoft.com/en-us/windows-hardware/drivers/dashboard/code-signing-reqs)
include an EV certificate associated with the Hardware Dev Center account. Follow the
provider's current instructions for obtaining and protecting that identity.

## Build a package

Start from a clean checkout of the release revision. From the repository root:

```powershell
cd clients\windows-wfp\packaging
.\build-msi.ps1 -DriverSys 'C:\build-inputs\dsse-wfp.sys' -DriverAttested `
  -Sign -SignBackend evtoken
```

Configure the signing backend below before using `-Sign`. The version comes from the
repository's `VERSION`; use `-Version` only when deliberately building a selected version.
Output is `<repository>\outputs\windows\DsseAgent.msi`, not a subdirectory of `packaging`.

`-DriverSys` selects the actual driver file. `-DriverAttested` selects the compatibility
gate for a Microsoft attestation-signed driver and validates the supplied signature.
Use both together. Neither option signs a driver. An attestation signature does not
establish compatibility with every Windows security policy; test the packaged driver
under the target's Secure Boot and memory-integrity settings.

For ARM64, pass `-Arch arm64` and a native ARM64 `-DriverSys`. The driver source build is
x64-oriented, so an ARM64 Go cross-build alone is not a complete ARM64 installer.

## Provisioning inputs

Distributable MSI and bootstrapper builds must be generic: the same signed artifact and
SHA256 serve independent deployments and every tenant, for a given release and platform/architecture.
Deployment operators distribute the original signed file; changing the deployment must not
require rebuilding, repacking, editing MSI tables, or signing the artifact again. Supply the Console's profile, independent verification pin,
and enrolment token at installation; see [Install it](../../../docs/windows-agent.md#install-it).

Do not use build-time `-Profile`, `-Pin`, `-TenantBundle`, `-TransportCA`, `-UpdatePin`,
`-PlanPin`, or `-BypassDest` to prepare a public release. These deployment-specific values
belong in verified external provisioning inputs and the device's protected runtime state.
Legacy provisioned-build options are not a release distribution path.

The Authenticode publisher is the product's code-signing identity and may be fixed in the
generic package with `-UpdatePublisher`. It is distinct from a tenant's profile, manifest,
and rollout-plan signing keys. Verify the actual Windows signer; do not substitute an
Apple Team ID. See [Agent updates](../../../docs/agent-updates.md).

Inspect both the MSI/Bootstrapper tables (including Properties and CustomActions) and
extracted payload before distribution. No DSSE deployment or tenant profile, CA, token,
identity, verification key, region configuration, or connection/recovery address may be
embedded, including linker constants in executables. Test the same MSI hash with external
provisioning inputs from two independent deployments with different domains, CAs, and
profile-signing keys, and verify that a routine upgrade preserves the
existing identity and adopted trust instead of replacing them with build-time defaults.

A signed profile's `region_priority` reorders only the regions the deployment permits.
Lower values are preferred (`1` is highest); a missing region ranks last. It cannot add
a region outside the signed allowed set.

## Signing backends

Run from this directory. Secrets such as token PINs stay in the signing provider's
prompt or secret store, not in scripts or build logs.

```powershell
# Development only: creates/uses a self-signed test identity.
.\sign.ps1 -Files .\example.exe

# Azure Trusted Signing: configure your approved account and metadata.
$env:DSSE_SIGN_BACKEND='trustedsigning'
$env:DSSE_TS_DLIB='C:\signing\Azure.CodeSigning.Dlib.dll'
$env:DSSE_TS_METADATA='C:\signing\metadata.json'
.\sign.ps1 -Files .\example.exe -Verify

# EV token: use your own certificate's store thumbprint.
$env:DSSE_SIGN_BACKEND='evtoken'
$env:DSSE_EV_THUMBPRINT='<your-signing-certificate-SHA1-thumbprint>'
.\sign.ps1 -Files .\example.exe -Verify
```

The token backend may prompt interactively. Permit access to the configured timestamp
service (`DSSE_EV_TSA` overrides its default) and verify the resulting timestamp. Use
the token provider's documented activation/recovery procedure; do not guess a PIN.
`sign.ps1` signs user-mode artifacts; it does not replace Microsoft driver signing.

## Optional bootstrapper

After the MSI build:

```powershell
.\build-bundle.ps1 -Sign -SignBackend evtoken
```

This produces `DsseAgentSetup.exe` using WiX Burn. `-WithWebView2` can include the WebView2
runtime. Build prerequisites include `WixToolset.BootstrapperApplications.wixext` and
`WixToolset.Util.wixext`. Run the bundle from an ordinary build/output directory, not
under the Windows system directories.

## Verify what will be distributed

Check the package signature and extract it into a new temporary directory with an
administrative MSI extraction (`msiexec /a`) to inspect the actual payload. All required
executables must have the expected publisher, and the staged `.sys` must retain its
Microsoft signature for the attestation build. The current MSI installs the WFP callout
as a kernel service and relies on the `.sys` embedded signature; retain the signing
submission's other artifacts with your release records.

For a signed Burn bundle, verify both the bundle and the publisher shown when its engine
requests elevation. The window's product title is not signature evidence. Test install,
enrolment, restart, steering, and uninstall on a dedicated target machine; run
[verify-windows-install.ps1](verify-windows-install.ps1) and its `-AfterUninstall` mode.
A successful signing command or an MSI exit code alone is insufficient.

## Runtime and removal

`DsseSteer` reads a verified profile from `HKLM\SOFTWARE\DSSE\Agent`; the signed envelope
is stored there and verified on read. A missing or invalid profile cannot authorize a
new transport. Installation must establish the intended service start mode and enrolment.

The uninstall runs `dsse-steer --mode recover` before removing the network components.
Recovery failures do not necessarily fail the entire uninstall, so verify restored
connectivity and inspect remaining trust and identity material afterwards. See the
[Windows removal limitations](../../../docs/windows-agent.md#removing-it).

## Migrating a manually registered service

An agent registered with `--service-install` keeps configuration in its service arguments;
the MSI's `--config-store` service uses a signed profile instead. Do not install over a
manual service without preparing an equivalent signed profile and a recovery path.
The MSI has a guard against an unmanaged existing `DsseSteer` service.

**This migration path is not validated as an end-to-end Windows procedure.** Use a
separate lab to verify it before relying on it: record the original configuration,
prepare and verify the replacement material, restore native networking, remove the
manual service, install the provisioned MSI, and verify steering and reboot persistence.
Keep the original enrolment material protected and check that the service can use it.
