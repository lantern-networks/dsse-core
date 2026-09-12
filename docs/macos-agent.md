# macOS agent

The macOS agent uses a Network Extension to steer device traffic to DSSE. This guide
covers a fresh installation, local verification, trust troubleshooting, and removal.
Use an isolated lab for this experimental release.

For internal-access authentication, see the
[Windows and macOS OOB windows](east-west-policy.md#windows-and-macos-authentication-windows).
The macOS resident agent presents notifications and a menu-bar entry that open
its WKWebView authentication window; the Network Extension alone does not show it.

## Prerequisites

- A Mac meeting the package's minimum OS requirement, an administrator account, and a
  running [deployment](deployment.md) with a configured [customer organization](organizations.md).
- A signed, notarized package appropriate for that Mac and the deployment's expected publisher.
- Working DNS for the regional transport and recovery URLs in the profile.
- Approval for the system extension: interactive approval by an authorized user or the
  appropriate MDM policy. Root access over SSH alone does not supply that approval.

Apple describes the deployment controls under
[System extensions in macOS](https://support.apple.com/guide/deployment/depa5fb8376f/web).
Plan approval before a remote installation. Do not disable OS security protections to
replace a missing provisioning profile or approval.

## Obtain and verify the setup files

The PKG is a generic product package shared by independently operated deployments and
all their customer organizations. For a given release and supported platform/architecture,
its contents, signature, and SHA256 do not change with the deployment or tenant.
A deployment operator distributes the original signed file without rebuilding, modifying,
or signing it again. The administrator supplies the other
three files separately for the organization this device will join:

| File | Purpose |
|---|---|
| `LanternDsseAgent-<version>.pkg` | Signed and notarized installer |
| `install_profile.json` | Signed configuration and trust material |
| `enrolment_token.txt` | One-time approval for this device |
| `profile_signing_key.txt` | Public key that verifies the profile |

Keep DSSE deployment and organization CAs, profile/policy/update verification keys,
endpoint and recovery addresses, region configuration, device identities, and enrolment
tokens outside the PKG. The installer verifies the external profile and applies it to the device's
protected configuration directory. Apple provisioning profiles embedded in the signed app
authorize the product's code and Network Extension; they are not DSSE deployment or tenant profiles.

A new deployment has no endpoint package to download until the operator publishes one
through [Agent Releases](agent-updates.md). Supply the package separately if it is absent
from the configuration archive.

Extract the files into an empty directory; numbered or stale downloads are not substitutes
for the exact filenames. Verify the package and confirm the expected publisher:

```sh
pkgutil --check-signature LanternDsseAgent-<version>.pkg
spctl --assess --type install --verbose=2 LanternDsseAgent-<version>.pkg
```

Build `dsse-profileverify` as described in [Building](building.md#build-operator-tools-and-native-binaries),
then use the public key obtained through your trusted administrator handoff:

```sh
dsse-profileverify -profile install_profile.json -pin profile_signing_key.txt
```

Confirm the customer organization, transport names, posture, device CA pin, and expected
interception root. The operator organization `tenant_default` is not an enrolment target.
Resolve a wrong organization or failed signature before installing. Decoding the envelope
without verification is not a substitute for this check.

## Install and approve

From the directory containing the verified files:

```sh
sudo install -d -m 755 "/Library/Application Support/Dsse"
sudo install -m 644 install_profile.json profile_signing_key.txt \
  "/Library/Application Support/Dsse/"
sudo install -m 600 enrolment_token.txt "/Library/Application Support/Dsse/"
sudo installer -pkg LanternDsseAgent-<version>.pkg -target /
```

The package derives the configuration, enrols the device, installs the agent and updater,
and requests system-extension activation. Complete any system-extension and network
configuration approvals macOS presents. On recent macOS versions, Network Extensions
are under **System Settings → General → Login Items & Extensions**; the location can vary.

```sh
systemextensionsctl list
```

An extension listed as `activated waiting for user` is not ready. Ordinary browsing may
still work because the extension is not steering; that is not installation success.
If activation or deactivation is waiting for approval, resolve the OS request before
attempting repeated installations or removing the app manually.

## Then check it, on the machine

```sh
sudo "/Library/Application Support/Dsse/bin/dsse-verify-install"
```

Review every failure and unanswered check. Confirm actual steering and inspection,
certificate acceptance, the intended organization in the Console, and recent device
reports. Test an allowed application and a deliberately denied destination. Browser
success alone cannot establish that traffic passed through DSSE.

The installation-time `install_state.json` can contain a pending approval recorded before
activation completed. Use current `systemextensionsctl` output and the runtime verifier
to establish the present state.

## The part that decides whether it works: trust

There are two independent trust paths:

| Trust source | Examples |
|---|---|
| System keychain | Safari and applications using the system certificate verifier |
| Application CA bundle | Some curl, Node, Python, AWS CLI, and Git configurations |

Which path a command uses depends on its build and settings. Check both the browser and
the actual tools on the device. A running tunnel with a certificate error is not a
completed installation.

The package installs the interception authority from the verified profile and writes a
combined CA file at `/Library/Application Support/Dsse/trusted_ca_bundle.pem`. It supplies
settings for `SSL_CERT_FILE`, `NODE_EXTRA_CA_CERTS`, `CURL_CA_BUNDLE`,
`REQUESTS_CA_BUNDLE`, and `AWS_CA_BUNDLE`.

New zsh processes read the package's `/etc/zshenv` settings. A terminal or GUI application
already running may not inherit them. Check in a **new terminal**:

```sh
printenv NODE_EXTRA_CA_CERTS
```

For a GUI program launched by the user session, configure its supported trust settings;
if it uses Node's extra-CA setting, an example for that logged-in user is:

```sh
launchctl setenv NODE_EXTRA_CA_CERTS "/Library/Application Support/Dsse/trusted_ca_bundle.pem"
```

Restart the target application from the updated launch environment. Recheck after an
interception authority changes; a stale file can continue to trust a retired authority
while failing to trust the current one. Keep TLS verification enabled.

### Root versus intermediate

The profile can describe either an independent customer interception root or a shared
interception authority chaining to the deployment anchor. Prefer the configured customer's
own authority and inspect `interception_root_is_own` in verified profile output.

A matching certificate subject and issuer indicates a self-issued certificate; it is not
by itself proof of a valid self-signature or a trusted root. The package handles root and
intermediate trust differently: macOS uses `trustRoot` for a root and `trustAsRoot` when
an intermediate is explicitly trusted as an anchor. Programs using CA files may require
the full chain to the intended root unless configured to accept a partial chain.

Displaying an issuer with `openssl s_client | openssl x509` does not test browser trust.
The local verifier checks the OS trust path and actual traffic. For manual diagnosis with
a captured leaf, macOS provides:

```sh
security verify-cert -c leaf.pem -p ssl -s <destination-hostname>
```

For an independent customer root, also check [organization separation](windows-agent.md#proving-the-organizations-are-separate).
An issuer's display name alone does not prove which key signed a certificate.

## Enrolment and organization changes

A device identity is bound to its organization. If the agent reports that the deployment's
organization and the profile's organization differ, correct the setup rather than copying
an existing identity into another organization's configuration. The deployment refuses
an identity claim belonging to another tenant.

For reassignment, coordinate removal of the old enrolment and a fresh install with the
new organization's material. Verify that a new identity has been provisioned; reusing
residual identity files can cause the same refusal again.

## Restore normal networking

Before retiring a deployment, disable the installed transparent proxy from the logged-in
Mac user account. This operation works without the deployment. Run it **without sudo**:

```sh
"/Applications/LanternDsseAgent.app/Contents/MacOS/LanternDsseAgent" --disable
```

Wait for `disable completed error=none`. The app stops the tunnel and saves the proxy
configuration as disabled so its connection watchdog does not restart it. This keeps
the app, enrolment, and trust material installed; it is not an uninstall or a device
revocation. Verify ordinary browsing after the command completes. If an error is reported,
keep the installed app and include the full output when requesting help.

The preference belongs to the logged-in user's session. Running a separate root copy
is not a substitute for disabling that user's proxy. Deactivating or uninstalling the
system extension is a separate operation that can require OS approval or a restart.

## Removing it

```sh
sudo "/Library/Application Support/Dsse/bin/dsse-uninstall"
```

The uninstaller first asks the app to remove the transparent proxy configuration and
deactivate the extension. If that fails, it stops before deleting the app needed for
recovery. Resolve approval or a pending OS restart and retry; do not manually delete the
app while its proxy configuration remains active.

After removal, check extension state and restored connectivity. Review trust-store and
identity remnants, particularly on a Mac that has used several deployments. The current
`interception-root.pem` identifies the current certificate, not every previously installed
root. List candidates, compare fingerprints with retained setup records, and remove only
confirmed obsolete certificates:

```sh
security find-certificate -a -c "<certificate-name>" -Z /Library/Keychains/System.keychain
# Only after matching the intended certificate's fingerprint:
sudo security delete-certificate -Z <fingerprint> /Library/Keychains/System.keychain
```

Do not delete certificates by subject name alone. Preserve independently installed
administrator trust that is still needed. If programs still refer to a combined CA file,
remove only the obsolete DSSE certificates and update their launch settings; deleting
the entire bundle can break unrelated HTTPS connections.

Remove or block the old device in the Console too. Package removal is not server-side
revocation.

## Known limitations and troubleshooting

- Reinstallation can leave an extension pending uninstall on reboot. Inspect
  `systemextensionsctl list`, complete the requested restart, and verify before retrying.
- Activating an already-running app with `open -a` does not prove the newly installed
  executable has started. Check the installed version and current extension state.
- Same-version activation can report completion before the Network Extension runtime
  becomes available. If approval is complete but steering has not started, fully quit
  and reopen LanternDsseAgent once, then repeat the local runtime and inspected-traffic
  checks. This workaround was observed to restore startup; an activation callback or
  package receipt alone does not establish a working connection. If it still fails,
  retain the logs for diagnosis instead of repeatedly reinstalling.
- Repeated provider crashes can exhaust the watchdog's retry window. Inspect agent and
  extension logs and current state; a successful package receipt does not prove provider health.
- VM traffic on the endpoint may escape host steering. Review the device configuration's
  VM policy and the verifier's result; do not assume a host agent covers guest traffic.

## Building the package

Use macOS with Swift 6, Go, the Apple signing tools, and your own signing material.
For distribution, supply distinct app and extension provisioning profiles authorizing
Network Extension/system-extension use for your bundle IDs, matching private signing keys,
a Developer ID Installer identity, and a configured `notarytool` keychain profile.
See Apple's [Network Extension deployment guidance](https://developer.apple.com/documentation/technotes/tn3134-network-extension-provider-deployment).

From the public repository root (replace every example path and identity):

```sh
export DSSE_APP_BUNDLE_ID=com.example.dsse.agent
export DSSE_APP_GROUP=group.com.example.dsse
export DSSE_TEAM_ID='<your-Apple-Team-ID>'
export DSSE_PROFILE=/absolute/path/app.provisionprofile
export DSSE_SYSEXT_PROFILE=/absolute/path/systemextension.provisionprofile
export CODESIGN_IDENTITY='<matching-application-signing-identity>'
export DSSE_INSTALLER_SIGN='<matching-Developer-ID-Installer-identity>'
export DSSE_NOTARY_PROFILE='<your-notarytool-keychain-profile>'

sh clients/macos-network-extension/packaging/build_macos_ne_app.sh var/ne-app
DSSE_APP_SRC="$PWD/var/ne-app/LanternDsseAgent.app" \
  sh clients/macos-network-extension/packaging/build_macos_ne_pkg.sh var/ne-pkg
```

The extension bundle ID is the app ID plus `.networkextension`. Ensure the provisioning
profiles match these identities. Both scripts take an **output directory** as the first
argument; pass an existing app through `DSSE_APP_SRC`, not as the package script's argument.
Do not rely on a previously installed developer's app to supply profiles on a clean machine.

The build reports signature, notarization, and Gatekeeper checks. A development or
unnotarized build is not a distributable release package. Verify the resulting package
on a separate lab Mac before distributing it.
