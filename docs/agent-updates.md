# Updating a fleet

How a new agent build reaches machines that are already deployed, and who is allowed to authorise it.

The installer creates the release-signing key in the founding authority directory;
runtime nodes receive its public pin. Prepare a signed package before publishing a manifest.

## Three parties, and none of them can do another's job

```
the release side   signs a manifest        dsse-signupdate          holds the signing key
the Edge           relays it               -agent-update-manifest-dir, -agent-update-pin
the endpoint       verifies and executes   pins the same public key
```

**The Edge cannot sign one and the updater cannot sign one, deliberately.** The key that authorises *code* is
separate from the keys that authorise configuration, so no traffic node and no endpoint holds it. That is why
the release side needs a tool of its own.

## The key is already minted — find it before you make one

A deployment built by `dsse-install` mints the update-signing key itself and publishes only its public half:

```
<deployment>/authority/agent-update-signing.key    the key. Nothing at runtime mounts it, deliberately
<deployment>/agent-update-signing.pub              the public half
-agent-update-pin=<that public half>               what every node verifies published manifests against
```

**Sign with that one.** Minting a second key gives you a manifest the control plane rejects, because the pin
names the first; changing the pin to match instead orphans every device that already holds the old one.

```sh
dsse-signupdate -key <deployment>/authority/agent-update-signing.key -pubkey   # must equal the pin
```

**A control plane cannot sign a release, and that is the design.** `POST /admin/agent-updates` answers 412
on a deployment without a signing token — *this control plane holds no update-signing key* — and that is not
a deployment that cannot publish. The key that authorises code running unattended as root on every device is
kept out of every node on purpose; the route is to sign away from them and publish the envelope. The Console
says so on **Agent Releases → Publish a version**, and takes both files:

| field | what to give it |
|---|---|
| **Package file** | the installer, as built |
| **Signed release file** | the manifest you signed with the key above |

It checks that the signed file describes the package you chose before anything is published, so a manifest
signed for a different copy cannot reach the fleet.

**The download address in the manifest is used exactly as written, by every device, in every region.**
Both agents fetch `artifact_url` verbatim — neither rewrites it towards the region the device is steering to.
On a deployment with more than one region that means one region's address serves the whole fleet's updates:
steering fails over, updating does not, and a device whose named region is down stays on the build it has
until that region returns. It is not an outage — nothing is refused and nothing is left half-installed — but
it is worth choosing the address deliberately rather than taking the first region offered. A generated
deployment's names are per node, including the ones without a region in them, so on one of those there is no
name that survives losing a region; if updates must survive it, the address has to be one you serve.

## Mint a key only if there is none

For a release side that is not this deployment, or a deployment older than the key:

```sh
dsse-signupdate -generate -key release.key
```

```
cf3f57f8549eceb7c079d63575ccb69ff3bb56623644ea93ff0a1d9d61c5a68b
dsse-signupdate: key written to release.key. Pin the line above with -agent-update-pin on the
edge and --update-pin on the updater. Keep the FILE off both.
```

**That file is the authority to run code, with SYSTEM privileges, unattended, on every device that pins the
public half.** It does not belong on an Edge, on an endpoint, or in a repository. Protect the release-signing key separately from runtime credentials. This guide uses
the installer-generated file key and does not establish a production signing service.

It refuses to overwrite an existing key, because every endpoint that pinned the old one would begin reporting
untrusted manifests — which reads as a substitution attack rather than as a mistake.

## Write a manifest and sign it

The manifest describes one build for one platform:

```json
{
  "schema": "1",
  "version": "0.4.0",
  "platform": "darwin",
  "arch": "arm64",
  "channel": "stable",
  "delivery": "dsse",
  "artifact_kind": "pkg",
  "artifact_url": "https://updates.example/agent-0.4.0.pkg",
  "artifact_sha256": "39e828748caa42c2d03f632ab822cd00836d478f1db0a6590e42ebb55e493420",
  "artifact_size": 4096,
  "min_from_version": "0.3.0",
  "released_at": "2026-09-05T00:00:00Z",
  "not_after": "2027-09-05T00:00:00Z"
}
```

`artifact_size` is the exact byte count and is required: a short read must not verify. `not_after` is what
stops a manifest being replayed years later at a version nobody supports any more.

```sh
dsse-signupdate -key <deployment>/authority/agent-update-signing.key -manifest manifest.json -out manifest.signed.json
```

```
dsse-signupdate: ★ SIGNED THE AUTHORITY TO EXECUTE CODE. 0.4.0 darwin/arm64, delivery=dsse,
artifact sha256:39e828…, valid until 2027-09-05T00:00:00Z. Every endpoint pinning
cf3f57f854… will run this.
```

It reads back what it just authorised. That sentence is the last chance to notice you signed the wrong build.

## Publish through the Console

In the operator context, open **Agent Releases → Publish a version**. Select the actual
package and its signed release file. Confirm the platform, version, digest, byte count,
delivery URL, and intended rollout before publishing. The deployment verifies the
manifest against its configured update pin; the signature must describe these exact bytes.

The JSON above is an illustrative manifest, not a release to upload unchanged. Replace
its digest, size, timestamps, version, URL, and platform with the actual artifact values.
Build `dsse-signupdate` using [Building](building.md#build-operator-tools-and-native-binaries).

Devices then fetch from three endpoints, all of which require a **verified device transport identity** — an
mTLS certificate issued by this deployment's device CA:

```
GET /steer/agent-update-manifest    what build this device should be on
GET /steer/agent-update-plan        when, under the rollout control
GET /steer/agent-update-artifact    the bytes, when the Edge is serving them
```

Without a client certificate they answer `401 {"error":"a verified device transport identity is required"}`,
and a self-signed one is not enough — it must chain to the deployment's device CA.

## Verify delivery on a device

The update endpoints require an enrolled device's mTLS identity. The local single-Edge
API quickstart does not demonstrate this path: use a complete [deployment](deployment.md)
and a [macOS](macos-agent.md) or [Windows](windows-agent.md) lab endpoint.

Confirm that the endpoint verifies the manifest, obtains the intended package, applies
the rollout policy, and reports the new running version. Repeat the endpoint's local
verifier after the update. A Console upload or an offered manifest alone is not proof
that any device updated successfully.

## What a device already carries

An install profile names the keys a device will accept updates from, before any of this happens:

```json
"update_signing_keys": ["69c28c92…"],
"update_publisher_team_id": "<your-Apple-Team-ID>"
```

Read them with `dsse-profileverify` (see [operator-tools.md](operator-tools.md)) rather than assuming: a
device that pins a key nobody signs with will refuse every update, quietly, and go on reporting itself
healthy at the version it is stuck on.
