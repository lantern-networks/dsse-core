# Changes since 0.4.2

The baseline is the published `v0.4.2-experimental` source and its artifacts. See
[Acceptance](verification.md) for what was installed and checked.

## Upgrading servers

| Area | 0.4.3 |
|---|---|
| Upgrade command | `dsse-install -upgrade -dir <deployment> -release-manifest release-manifest.json` moves one machine to another release: it writes the release's image references and regenerated files, fetches the images while the running services are untouched, replaces the services, and on a one-machine deployment runs the whole-deployment check. The files it replaced are kept beside the deployment. See [Moving from 0.4.2](upgrade.md) |
| Interrupted upgrades | An upgrade that stops part-way records that it has not finished. The same command continues it; a machine is not reported as running a release until its services have been replaced |
| Regeneration | An upgrade changes only what the release changes. Generated files that the machine's Compose file does not read are left as they were |
| `-up` on a running deployment | `-up` stops and names `-upgrade` instead of restarting services that are already running |
| Images already on the machine | `-upgrade`, and `-up` on the machines it reaches over SSH, fetch only the release's images the machine does not hold. Release images are pinned by digest, so a machine whose images were carried in can be upgraded without reaching the registry |

## Sites

| Area | 0.4.3 |
|---|---|
| After the database's primary moves | In 0.4.2, once the database's primary had moved — a rolling upgrade of a deployment of several Regions moves it — a Site created, given a new connector command or deleted reached no Edge until some other change moved the configuration. A new connector could not enrol, and a deleted Site's bootstrap secret was still accepted. The control plane now publishes every Site change. See [Moving from 0.4.2](upgrade.md) |
| Adding a connector for an organization held to some Regions | In 0.4.2, `Add connector` was refused (`connector enrollment edge_url is not in this tenant's permitted Edge endpoints`) whenever the request was answered by a control plane in a Region the organization may not use — for example after leadership moved. A command that names no Edge now sends the connector to the organization's own Region; a named Edge outside them is still refused |

## Installation

| Area | 0.4.3 |
|---|---|
| Layouts | `-up` stands up every published layout, including those whose first machine runs no Edge. It fetches each machine's images before starting it |
| Browser certificate | For layouts with dedicated Edge machines, `-install-portal-certificate` and `-portal-key` name files already on each Edge machine; the key never passes through a control-plane machine |
| Packages sent with `-ssh` | The package another machine started from — it holds that machine's identity and the fleet credential — is removed from that machine once it has started. Without `-ssh`, the printed steps say to remove it |
| Revocation lists | A plan may declare `deployment_crl_origins`, and optionally `deployment_crl_http_listen`. `-up` then installs the release's keyless publisher and an hourly re-signing timer, and every certificate the deployment issues names where its revocation status is published. See [Deployment](../../deployment.md#publishing-revocation-lists) |
| Resuming | A first step stopped before the plan was applied, and a store member given its vote before a failed wait, are both resumed by the same command without repeating what was done |

## Internet Access

| Area | 0.4.3 |
|---|---|
| Rules written for names | A flow whose destination the device gives as a name, as the macOS agent does, is decided by the rules written for that name when the flow opens. In 0.4.2 such a flow was matched only by the rules after them: a name denied above an "allow, not inspected" rule was reached without inspection, and with an inspecting rule it was refused only when the decrypted request was decided |

## Connector Access

| Area | 0.4.3 |
|---|---|
| Which layer decides | A flow to a registered network — a destination a Connector route carries — is decided and recorded by Connector Access in every posture. While the posture is OBSERVE, Connector Access allows and records the flow; Internet Access rules do not decide it. See [Connector Access](../../east-west-policy.md) |
| Decrypted requests | When HTTPS to a private application is decrypted, each request is decided by the flow's own organization's Connector Access rules. A rule that requires sign-in is satisfied for the connection that completed it |
| Log rows | A row names the rule that decided it, in the reader's language. A connection to a registered network is always recorded |
| Named destinations | A device may name a flow's destination instead of giving its address; the macOS agent does. A name whose address — the Edge's own answer, never one the device supplies — lies in a registered network is decided by Connector Access and carried by the connector, whether or not the name itself is registered. An HTTPS flow to a registered address is carried by the connector whatever name its TLS carries |
| Names and addresses | The Edge remembers which name an address was resolved from for as long as the device may use the address, and gives devices address answers that live at most five minutes. An IPv4 destination has one spelling (`::ffff:a.b.c.d` is the same destination as `a.b.c.d`) |
| Choosing a connector | Among several connectors for an application, one that is reachable now is chosen first, including connectors held by an Edge in another Region. An Edge that cannot reach a connector asks where it went instead of refusing until its next update |

## Certificates

| Area | 0.4.3 |
|---|---|
| Organization inspection roots | On a deployment that publishes revocation lists, an inspection root made from an organization's Certificates page names its revocation lists. The root keeps no key: it signs one list when it is made, valid as long as the issuing certificate beneath it, and its issuing certificate is withdrawn by replacing the root |

## Audit

| Area | 0.4.3 |
|---|---|
| Shipping | An Edge ships queued audit records many to a request. The control plane checks and answers each record as before. A control plane of an earlier release is sent one record per request. The installation check reports how many requests carried several records |

## Console

| Area | 0.4.3 |
|---|---|
| Rules | A destination can be added from the rule editor. A new rule is offered a priority ahead of the existing rules of its kind. The source list offers devices and the administrator's groups only |
| Addresses | A server address must be an IP address, a network range, a host name or a wildcard beneath one; anything else is refused |
| Connector Access posture | Changing the posture is confirmed in the Console's own dialog |
| Devices | "No update report" is counted only while the deployment offers an agent release |
| Elevated acts | An act refused in the moment after its time was granted is asked again for a few seconds |

## Windows

| Area | 0.4.3 |
|---|---|
| Guide | The commands find the installer by the name it is released under (`DsseAgent*.msi`) |
| Installation check | When a certificate names nowhere to check revocation, `verify-windows-install.ps1` reports revocation as not checked and goes on to check that the chain leads to the announced interception root |

## Restarting

| Area | 0.4.3 |
|---|---|
| Edge | An Edge starts again after its container or its machine restarts. In 0.4.2 an Edge that had started once failed every later start (`restore interception root compatibility view … device or resource busy`) until its container was recreated. See [Moving from 0.4.2](upgrade.md) |

## macOS

| Area | 0.4.3 |
|---|---|
| Name lookups | Every DNS query the Mac makes is answered by its Edge over the device's authenticated transport, so names an organization resolves on its Sites resolve on the Mac and queried names do not leave it in plain text. A query the Edge does not answer fails. macOS 15 or later. See [macOS agent](../../macos-agent.md#name-lookups) |
| Starting | Launching the agent does not restart an extension that is already the installed build, and a tunnel that did not start is started again |
| Turning steering on and off | `--disable` also turns off the DNS proxy; `--enable` turns both back on and reports whether the tunnel connected |
| Installing again after removal | The uninstaller sets the used enrolment token aside. The installer refuses a Mac that has nothing to enrol with before it changes anything, and takes a new token placed beside it |
| Refusals | What the installer says when it refuses is printed in the terminal it was run from |

## Windows

The Windows agent has no functional change from 0.4.2.

## Not changed in 0.4.3

| Area | 0.4.3 |
|---|---|
| Logs on several Regions | Each Region keeps its own records, and a log query is answered from one Region's records, not all of them. See [Audit and data](../../audit-and-data.md#find-and-correlate-an-event) |
