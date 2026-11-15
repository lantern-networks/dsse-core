# Moving from 0.4.2

0.4.3 keeps the 0.4.2 plan format, layouts, package names and enrolment files, and the
same data-layer images.

## Servers

Upgrade each machine with the 0.4.3 installer and the published `release-manifest.json`:

```sh
dsse-install -upgrade -dir /opt/dsse/region-a -release-manifest release-manifest.json
```

- **One machine.** Every service is replaced at once. Devices lose their connection while
  the services restart and reconnect by themselves; plan for an interruption of about a
  minute.
- **Several Regions.** Upgrade one machine at a time and wait until its devices have
  reconnected before the next. A Region's devices reconnect while its machine is replaced,
  in about half a minute; devices on other Regions stay connected. Private applications whose
  connectors are attached to the Region being replaced pause for up to about half a minute
  while the connectors move; those reached through connectors attached elsewhere keep
  working. After the last machine, run the check the command prints.
- The files an upgrade replaced are kept in `upgrade-kept/` in the deployment directory;
  the copy of `deployment.env` there holds secrets.
- If an upgrade stops part-way, run the same command again.

## Before you restart a 0.4.2 machine

A 0.4.2 Edge that has started once does not start again after its container or its machine
restarts; devices cannot connect until it does. Upgrading to 0.4.3 removes this. On a machine still
running 0.4.2, recreate the Edge container after a restart:

```sh
cd <deployment directory>
docker compose -p dsse --env-file deployment.env up -d --force-recreate --no-deps dsse-edge-a
```

`dsse-edge-a` is the Edge service of a one-machine deployment; `docker compose -p dsse ps` lists the
names on other layouts. The next restart needs it again.

## Sites on a 0.4.2 deployment of several Regions

On 0.4.2, after the database's primary has moved to another machine and back, a new Site, a new
connector command or a deleted Site may not reach the Edges: the connector is refused with
`the bootstrap secret is not this Site's`, and a deleted Site's connector command is still
accepted. Upgrading to 0.4.3 removes this. On 0.4.2, restart the control plane on every
machine, one machine at a time; the Edges then take the whole configuration again:

```sh
cd <deployment directory>
docker compose -p <project> --env-file deployment.env restart dsse-control-plane-a
```

`<project>` is the name `docker compose ls` shows on that machine.

## Behaviour that changes

- **Connector Access while observing.** A flow to a registered network is no longer
  decided by Internet Access rules while the Connector Access posture is OBSERVE. An
  organization that narrowed its access to private applications with Internet Access
  rules and left Connector Access observing should write those rules as Connector Access
  rules and move the posture forward; until then, enrolled devices can reach every
  registered network.
- **DLP.** An Internet Access rule's DLP setting does not apply to flows to registered
  networks.
- **DNS through the tunnel.** Address answers given to devices live at most five minutes,
  so devices ask again at least that often.
- **Revocation lists** are declared in the plan before a deployment is created; they cannot
  be added to a deployment that exists.

## Endpoints

- **Windows.** Devices enrolled with 0.4.2 keep working with 0.4.3 servers; the Windows package
  has no functional change.
- **macOS.** Install the 0.4.3 package over 0.4.2; the device keeps its enrolment. macOS may ask once
  to allow the DNS proxy configuration; a Mac that has allowed it before is not asked. From then on the Mac's name lookups are answered by its
  Edge (macOS 15 or later), so a zone your organization resolves on a Site must be forwarded in its
  DNS settings for those names to resolve on the Mac.
