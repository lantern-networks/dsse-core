# Operations

Use this guide after [deployment verification and first use](after-verify.md). It describes
routine operation of an experimental lab; it does not establish availability targets,
production sizing, or a tested disaster-recovery procedure for your environment.

For CA structure, key custody, automatic certificate renewal, and the lifecycles
that still need operator action, see [PKI structure and lifecycle](pki.md).

## Keep a deployment record

Keep a private record of the source revision, image references or digests, agent versions,
topology, generated plan, node names, deployment directories, and Compose project names.
Record who holds the founding authority material and how to recover it. Store credentials
separately from ordinary maintenance notes. The generated directory, carry archives,
bootstrap output, and enrolment files contain sensitive material.

Use the selected revision's `dsse-install -plan ... -order` output as the topology's
command reference. Founding and joining regions may use different Compose project names.
Do not copy the founding node's `-p dsse` into commands for a joining region without checking.

## Routine checks

For the founding node, replace the directory with the actual generated directory:

```sh
export DSSE_DIR=/opt/dsse/region-a
cd "$DSSE_DIR"
docker compose -p dsse --env-file deployment.env ps -a
docker compose -p dsse --env-file deployment.env logs --tail=100
df -h "$DSSE_DIR"
```

`df` measures the filesystem containing that directory. Check the filesystems actually
holding database volumes and audit spools too. Successful initialization jobs may have
exited; long-running services should remain healthy. Logs can contain deployment metadata;
review and redact them before sharing.

| Check | Evidence to inspect |
|---|---|
| Fleet state | Full topology-specific `dsse-install -verify` output, including each control plane and Edge |
| Configuration delivery | Each Edge has applied the control plane's configuration; compare epoch and generation together |
| Customer operation | Recent device report, allowed and denied test flows, correct customer in the Console |
| Audit delivery | Test decisions appear for the same customer and time window; look for ingestion refusals and spool growth |
| Certificates | Current validity and renewal state of deployment, transport, device, and inspection certificates |
| Storage | Free space and growth of Postgres, ClickHouse, MinIO, and Edge audit spools |
| Connectors | Run the connector verifier on its host; check every configured regional endpoint |
| Endpoint software | Actual running version, local verifier results, and rollout status |

Choose check frequency from the lab's risk and workload. During an endurance run, record
start/end times, interruptions, workload, and certificate renewal events. Do not silently
restart the system and count the interval as uninterrupted operation.

The full fleet verifier includes active probes and can exercise enrolment using its
administrative credential. Treat it as a planned verification action and record it in
the test timeline; it is not a passive monitoring command.

## Upgrading persisted user risk

Before upgrading a deployment that uses manual user risk, read
[User risk state upgrades](user-risk-state-upgrade.md). User marks now include a tenant
and a distinct entity type. The state format and the fast risk feed both change;
all control planes and enforcing Edges must use the compatible revision.

## Change a policy or organization setting

1. Confirm the Console's organization context and the administrator's delegation.
2. Record the current setting and the intended allowed/denied result using synthetic data.
3. Save on the control plane. Allow its configuration synchronization cycle to reach the Edges.
4. Check the intended path through each relevant region and confirm the decision in audit records.
5. If the result differs, use [Troubleshooting](troubleshooting.md) before widening access.

A successful save proves persistence at the control plane; it does not prove fleet-wide
enforcement. Generation numbers from different epochs are not directly comparable.
Narrow the initial broad Internet Access rule and explicitly review Connector OBSERVE
mode. Configure and attach a DLP policy if upload inspection is required.

## Restarts and upgrades

For a single-machine lab, the generated Compose project can be stopped without deleting volumes:

```sh
cd "$DSSE_DIR"
docker compose -p dsse --env-file deployment.env stop
docker compose -p dsse --env-file deployment.env up -d
```

This interrupts that machine's services. On a three-region deployment, maintain quorum:
operate on one region at a time and restore its health before proceeding. Follow the
actual project name on each host. `down -v` deletes volumes and is not a restart procedure.

Before a service upgrade, retain the old revision and images, preserve recoverable state,
and review changes to configuration and storage. This release permits incompatible changes
without a migration path; replacing an image with an older one is not guaranteed to undo
a state migration. Validate the target revision on a separate lab before changing a fleet.
After a change, repeat fleet and endpoint checks plus allowed/denied traffic tests.
Use [Agent updates](agent-updates.md) for endpoint packages and signed manifests.

## Backups and recovery preparation

Inventory the founding authority material, generated configuration, shared stores, object
storage, and Edge audit spools. Protect private keys and backups with access controls and
encryption. A carry archive excludes `authority/` and is not a complete backup.

Coordinate a consistent backup using the storage components' supported mechanisms.
Copying live database files is not, by itself, evidence of a restorable backup. Record
the matching software revision and trust material. Validate restoration in an isolated
environment, preventing restored identities and services from reaching the active fleet.
Confirm administrator access, configuration, device identity, audit history, and actual
traffic after restoration. Record the measured recovery time and any data loss.

For lost administrator credentials, see the owner-level
[break-glass procedure](deployment.md#break-glass-and-closing-it). Do not re-mint the
deployment as account recovery. A new authority is a different trust relationship.

## Retiring a device or deployment

Block or remove the enrolled device in the Console and uninstall it using the platform
guide. Verify restored connectivity and review residual identity and CA material by
fingerprint. Package removal does not revoke server-side identity, and deleting one
current CA file does not remove previously trusted certificates.

Before retiring the whole lab, account for every endpoint and connector, required audit
retention, backups, and trust material. Remove storage only after those dependencies have
been handled. See [Verification](verification.md) for a record of what was actually checked.

See [Audit logs and data handling](audit-and-data.md) for store-specific retention and
[Administration](administration.md) for roles, delegation, and recovery authority.
