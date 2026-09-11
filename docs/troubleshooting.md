# Troubleshooting

Start with the symptom below. Record the revision, platform, organization, region, and
time of the failure before changing settings. Keep TLS verification enabled while
diagnosing identity or trust failures.

## Deployment and sign-in

| Symptom | Check first | Next step |
|---|---|---|
| Containers do not start | `docker compose ... ps -a` and `logs --tail=100` in the generated directory | Check both service images, architecture, bind addresses, ports, and container subnet conflicts in [Building](building.md) |
| Host reaches a name, container cannot | DNS from both environments; generated aliases and reachable addresses | Correct name resolution using [Deployment](deployment.md); host-only DNS does not configure containers |
| Console certificate warning | Expected hostname, clock, and verified deployment anchor in the browser's trust store | Follow [First use](after-verify.md#1-trust-the-deployment-and-sign-in); do not accept an unknown certificate |
| Password works but MFA fails | Authenticator initialized from the bootstrap second-factor secret; synchronized clocks | Use the intended account and its recovery codes if needed; an API token is not a TOTP code |
| Customer screens return 403 | Console organization context and operator delegation | See [Organizations](organizations.md); authentication alone does not grant customer management |
| Fleet verifier reports `n/a` | Read the individual explanation and topology | Resolve missing prerequisites or record why the check is inapplicable; `n/a` is not a pass |

For the generated example, a name-and-chain-verified service probe is:

```sh
curl --fail --show-error --cacert deployment-anchor.pem \
  https://admin.region-a.example.test/healthz
```

Run where the anchor file is present and replace the URL. Health success establishes
only that probe; it does not establish endpoint steering or policy enforcement.

## Endpoint installation and trust

| Symptom | Check first | Next step |
|---|---|---|
| Setup archive contains no installer | Whether a platform package was published | Publish the signed package or supply it separately; see [Agent updates](agent-updates.md) |
| Package installs but device is inert | Exact profile/token/pin filenames; profile signature; OS approvals | Verify the external profile and use the [Windows](windows-agent.md) or [macOS](macos-agent.md) local verifier |
| Profile signature is rejected | Pin from the trusted administrator handoff; intended deployment | Obtain the matching authentic profile and pin; do not accept a key merely because it accompanied the rejected file |
| Enrolment is rejected | Customer organization, device CA configuration, unused token, existing identity | Issue material for the intended customer; revoke a lost unused approval before replacing it |
| macOS extension awaits approval | `systemextensionsctl list` and pending OS prompts | Complete activation or the requested restart, then run the local verifier; browsing alone does not prove activation |
| Windows driver does not start | `Get-Service DsseSteer,DsseWfp`, package architecture, accepted driver signature | Follow [Windows prerequisites](windows-agent.md#prerequisites); an MSI signature does not sign a kernel driver |
| Browser works but CLI reports an unknown CA | The specific program's CA bundle and launch environment | Follow [macOS trust](macos-agent.md#the-part-that-decides-whether-it-works-trust) or [Windows](windows-agent.md); retest in a new process |
| Device reports another organization | Residual enrolled identity and newly supplied profile | Coordinate fresh enrolment for reassignment; do not copy an old identity into a different tenant |

On macOS:

```sh
systemextensionsctl list
sudo "/Library/Application Support/Dsse/bin/dsse-verify-install"
```

On Windows, run the following from the repository root in an elevated PowerShell:

```powershell
Get-Service DsseSteer,DsseWfp
& .\clients\windows-wfp\packaging\verify-windows-install.ps1
```

## Traffic, policy, and audit

| Symptom | Check first | Next step |
|---|---|---|
| A flow expected to be denied succeeds | Actual steering, organization, matched rule, Connector enforcement mode | Review the broad initial allow rule and OBSERVE mode in [Organizations](organizations.md); test a deliberate deny |
| DLP does not block a test upload | DLP policy exists, is attached to the relevant Internet Access rule, and TLS inspection is enabled | Use synthetic matching data and confirm both a blocked upload and a normal upload |
| SaaS account restriction has no effect | Provider enabled for that tenant; request actually inspected | Follow [SaaS tenant restriction](saas-tenant-restriction.md); bypassed TLS cannot receive restriction headers |
| A policy save is not reflected everywhere | Applied epoch and generation on each Edge, peer health | Run the full fleet verifier and diagnose configuration delivery; author changes at the control plane |
| A private app is unreachable | Connector host can reach the app, tunnel identity, adopted Named Network route, access policy | Run the connector verifier below; [Connectors](connector.md) explains routes and cross-region access |
| Console says connector Connected, failover fails | All regional doors reachable from that connector host | A single live tunnel is insufficient; verify every configured door and real app traffic |
| Traffic works but audit records are missing | Correct tenant/time window, Edge spool growth, ingestion logs and `audit-ingest-authority.json` mapping | Confirm the control plane receives that customer's records, not just the operator's |
| Inspected site fails while other sites work | TLS rejection, policy decision, origin response, selected upstream engine | The standard engine uses Go HTTP/TLS; evaluate compatibility with synthetic traffic and review bypass candidates explicitly |

On the connector host, using its actual state directory:

```sh
sudo dsse-connector-install --verify --state-dir /var/lib/dsse-connector
```

## Updates and removal

An update offered in the Console may not have run on the endpoint. Compare the running
version, signed manifest, pinned update key, package publisher, rollout policy, digest,
and byte count. The update key is separate from the profile-signing key.

The manifest's `artifact_url` is fetched as written. Steering failover does not rewrite
that URL, so loss of its serving region can delay updates while traffic still works.
Update endpoints require enrolled-device mTLS; an unauthenticated request cannot validate
that a device can download its update. See [Agent updates](agent-updates.md).

If macOS removal stops at extension deactivation, resolve the OS approval or restart
before retrying. Keep the app required for deactivation. On Windows, run the documented
post-uninstall check and inspect remaining identity/trust material. Use each platform's
removal guide; do not delete certificates solely by their display names.

## Reporting an unresolved problem

Include the source revision, image/agent version, OS and architecture, single- or
multi-region shape, reproducible steps, expected and actual behavior, timestamps with
time zone, and relevant redacted verifier lines. Say what changed immediately before
the failure and whether it reproduces after that change is reversed.

Do not attach a generated deployment directory, bootstrap credentials, private keys,
enrolment tokens, or unreviewed logs. Remove internal hostnames, user/device identifiers,
and sensitive destinations from a public report while keeping the topology understandable.
For a possible vulnerability, use [SECURITY.md](../SECURITY.md) and avoid public technical details.
