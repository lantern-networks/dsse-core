# Windows agent

The Windows agent combines the `DsseWfp` kernel callout driver, `DsseSteer` service,
watchdog, and updater in an MSI. It captures outbound TCP and carries it to the deployment.
Use an isolated lab for this experimental release.

For user-facing authentication during internal access, see the
[Windows and macOS OOB windows](east-west-policy.md#windows-and-macos-authentication-windows).
The Windows helper uses WebView2 and needs its Runtime; that section explains
launch behavior, browser fallback, and returning to the original connection.

## Prerequisites

- An administrator account on the Windows device and a working network connection.
- A running deployment and [customer organization](organizations.md) with its authorities configured.
- A package for the device's architecture with signatures accepted by its Windows security policy.
  For Secure Boot systems, use a suitable Microsoft-signed driver; signing an MSI does not sign its driver.
- DNS resolution for the regional transport and recovery URLs in the signed profile.

The driver source build is x64-oriented. An ARM64 MSI requires a native ARM64 driver
supplied to the build; cross-compiling the Go services alone is insufficient. See
[Packaging](../clients/windows-wfp/packaging/README.md) and
[Driver build](../clients/windows-wfp/driver/BUILD.md).

## What a device is placed by

The MSI is a generic product package shared by independently operated deployments and
all their customer organizations. For a given release and supported platform/architecture,
its contents, signature, and SHA256 do not change with the deployment or tenant.
A deployment operator distributes the original signed file without rebuilding, modifying,
or signing it again. Obtain the other three files separately
from the administrator for the organization this device will join:

| File | Purpose |
|---|---|
| `DsseAgent.msi` | Signed installer for the device's architecture |
| `install_profile.json` | Signed configuration and trust material |
| `enrolment_token.txt` | One-time authorization for this device to join |
| `profile_signing_key.txt` | Public key used to verify the profile |

Keep DSSE deployment and organization CAs, profile/policy/update verification keys,
endpoint and recovery addresses, region configuration, device identities, and enrolment
tokens outside the MSI. Apply the verified external configuration at
installation. A routine software upgrade preserves the enrolled device's protected state;
moving it to another organization requires an explicit migration and fresh enrolment.

A newly created deployment may offer only the last three files: the operator must
[publish a signed package](agent-updates.md) or provide it separately. Do not assume
that the archive contains an installer until you check it.

Extract into an **empty directory**. Numbered browser downloads such as
`install_profile (1).json` are not substitutes for the filenames above. Check the
package signature against the expected publisher:

```powershell
Get-AuthenticodeSignature .\DsseAgent.msi | Format-List Status,SignerCertificate
```

`Valid` must refer to the publisher your administrator designated. Obtain the profile
pin through a trusted handoff and verify the profile with
[dsse-profileverify](operator-tools.md):

```powershell
dsse-profileverify -profile install_profile.json -pin profile_signing_key.txt
```

Confirm the customer organization, transport names, posture, device CA pin, and expected
interception root. A profile's date alone cannot establish authenticity or freshness;
check the intended deployment and validity as well as its signature. A failed signature
check must be resolved before installation.

Generating a device archive also creates an enrolment approval. If a download fails or
the token is lost, revoke the unused approval in **Enrolment Tokens** and issue a replacement.
One token is for one device; do not duplicate it across a fleet.

## The deployment's names have to resolve first

Devices dial the regional URLs in the profile. Configure DNS, or for an isolated lab,
the Windows hosts file at `C:\Windows\System32\drivers\etc\hosts`, using the addresses
provided by the deployment operator. Include the recovery names the profile actually names.

`organization.transport_server_name` and `organization.enrolment_server_name` select
organization-specific TLS identities. They are SNI names: the agent can send them while
dialling a regional endpoint. They do not necessarily require a separate DNS lookup by
the agent. Tools that connect directly to those names do need them to resolve.

Do not infer the server's identity from its certificate issuer name. To diagnose a
regional address with OpenSSL, use the [anchor and hostname verification command](after-verify.md#1-trust-the-deployment-and-sign-in).

## Install it

The following PowerShell commands start in the empty directory containing the four files.
Run with administrator privileges. Absolute paths avoid ambiguity in MSI custom actions:

```powershell
$msi = (Resolve-Path .\DsseAgent.msi).Path
$config = (Resolve-Path .\install_profile.json).Path
$token = (Resolve-Path .\enrolment_token.txt).Path
$pin = (Resolve-Path .\profile_signing_key.txt).Path
$log = Join-Path $PWD 'install.log'
$p = Start-Process msiexec.exe -Wait -PassThru -ArgumentList "/i `"$msi`" /qn /l*v `"$log`" CONFIG=`"$config`" TOKEN=`"$token`" PIN=`"$pin`""
$p.ExitCode
```

Inspect nonzero exit codes and `install.log`; 3010 requests a reboot. Installer success
alone does not prove enrolment or steering. The device identity is created on first
service start as SYSTEM, so its DPAPI-protected key belongs to the service account.
Do not enrol with a manually launched copy under a different account.

```powershell
Get-Service DsseSteer,DsseWfp
Start-Service DsseSteer
Get-CimInstance Win32_Service -Filter "Name='DsseSteer'" | Select-Object State,StartMode
```

If the profile requests automatic start but the service remains Manual, treat reboot
persistence as unresolved and inspect the installation log. Do not count a manually
started service as a completed automatic-start installation.

## Then check it, on the machine

From the public repository root, or an administrator-provided copy of the verifier:

```powershell
.\clients\windows-wfp\packaging\verify-windows-install.ps1
```

Read all failed and `n/a` checks. Confirm recent heartbeats, active forwarding, the
customer organization in the Console, and an actual allowed HTTPS request with TLS
verification. Exercise a denied destination and check the recorded decision too.
A running driver and `enforcement=healthy` do not prove application TLS works.

Useful log: `C:\Program Files\DSSE\dsse-steer.log`. Representative messages include
`heartbeat sent`, `enforcement=healthy`, and `steer_mux_forwarded`. Check timestamps;
a retained heartbeat from a stopped process is not current health.

With several regions, the agent also reports the refreshed region set and its selected
region. A single-region profile may disable region failover; absence of a selection
message alone is not a fault. The signed region map defines allowed regions;
`region_priority` only orders that set. Lower rank is preferred, and unnamed regions rank last.

## Two trust paths

The OS certificate store and application-specific CA bundles are separate trust paths.
Browsers and tools using Schannel can use the Windows store. Other curl builds, Python,
Node, and similar programs may use their own CA bundles; check the particular program's
TLS backend and configuration rather than assuming from its name.

**Known limitation:** Windows provisioning does not automatically create and configure a
combined CA bundle for every such program. Browser success can coexist with command-line
certificate errors. Configure those programs to use a maintained public CA bundle plus
the intended organization's interception root, or a supported system-trust mode. Keep
TLS verification enabled. Recheck after certificate changes and agent upgrades.

If environment variables such as `CURL_CA_BUNDLE`, `REQUESTS_CA_BUNDLE`, or `NODE_EXTRA_CA_CERTS`
are used, update them in the process's actual launch environment. Already-running processes
may need restarting. Keep a shared bundle present while any process refers to it; remove
only the retired DSSE certificates, not the unrelated public roots.

## Proving the organizations are separate

Use the endpoint verifier and a controlled intercepted HTTPS destination. If investigating
manually with OpenSSL, capture the presented leaf and intermediate certificates, then
verify against one explicit trust anchor at a time:

```powershell
openssl verify -CAfile "$env:ProgramData\DSSE\interception-root.pem" -untrusted intermediates.pem leaf.pem
openssl verify -CAfile deployment-anchor.pem -untrusted intermediates.pem leaf.pem
openssl verify -CAfile public-ca-bundle.pem -untrusted intermediates.pem leaf.pem
```

For inspection under an independent customer root, verification should succeed with
that customer's root and fail with the deployment root and unrelated public roots.
A bypassed destination is unsuitable for this check. These three comparisons do not
prove all tenant isolation properties; also test that a different customer's identity
cannot access this customer's resources.

## Removing it

From the folder holding the original MSI, with administrator privileges:

```powershell
$msi = (Resolve-Path .\DsseAgent.msi).Path
$log = Join-Path $PWD 'uninstall.log'
$p = Start-Process msiexec.exe -Wait -PassThru -ArgumentList "/x `"$msi`" /qn /l*v `"$log`""
$p.ExitCode
```

Removal attempts to restore DNS, QUIC policy, and WFP filters before removing the services.
**Known limitation:** a successful uninstall may leave trusted certificates and enrolment
material behind. Run the post-uninstall check from the repository root:

```powershell
.\clients\windows-wfp\packaging\verify-windows-install.ps1 -AfterUninstall
```

Review remaining certificates and identity files. Remove obsolete certificates by their
verified fingerprint, never by subject name: two deployments can use the same name with
different keys. Preserve certificates independently installed by the administrator if
still needed, including a Console trust anchor. Do not delete a CA bundle while a process
or persistent environment setting still refers to it.

Finally, remove or block the device in the Console. Uninstalling software does not revoke
its identity at the deployment.

## Build the MSI

For source builds, follow [Packaging](../clients/windows-wfp/packaging/README.md), including
signature checks, `-DriverSys`/`-DriverAttested`, and generic-package requirements.
Keep test signing confined to a dedicated driver-development machine. Microsoft's
[signing requirements](https://learn.microsoft.com/en-us/windows-hardware/drivers/dashboard/code-signing-reqs)
are separate from DSSE's package build; an attestation signature is not a compatibility
or production-readiness certification for the complete agent.
