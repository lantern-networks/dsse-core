# Organizations

A deployment enforces for **organizations**. Every device belongs to one, every flow is decided under one, and
the authorities that make inspection possible are per-organization. A new deployment has none, and no device
can join until it has one.

This page is the step between [deployment.md](deployment.md) — where a deployment answers `-verify` — and
[macos-agent.md](macos-agent.md) / [windows-agent.md](windows-agent.md), where a device needs four artefacts
that only an organization can issue. It is written as the Admin Console does it.

**Before opening the Console, the machine you administer from has to trust the deployment's anchor** —
see [deployment.md](deployment.md#certificates). Otherwise the browser refuses before any screen appears.

## The organization a new deployment already has is not one of these

`dsse-install -organization <name>` sets the organization label in the deployment's initial certificates.
It does not create a customer tenant or change the operator tenant's display name (`tenant_default`).
Devices do not go into that operator tenant — approving one for it is refused, and `-verify` says so in the one check it
cannot answer until a customer organization exists:

```
  n/a   the enrolment path was checked   n/a here: a device is approved for a CUSTOMER organization, and this
                                         deployment has none yet
```

**The Console shows which organization you are acting as** in the header — `tenant_default` until you enter
one. Screens opened while it says that act on the operator's own organization, including
**Device configuration**, which would then issue a profile that puts the device in the wrong place.

For authenticated operator API writes, select the customer with `X-Operate-Tenant`.
Any organization named in the path or request body must match that selection.
Naming a customer without selecting it, or selecting a different customer, is refused.
The selected customer's standing delegation and any required elevation must also be active.
A customer's own administrator can continue to omit the header.

## 1. Create it — Tenants → + Add tenant

Complete the tenant creation dialog:

| field | what it decides |
|---|---|
| **Display name** | what everyone sees. The identifier behind it is issued automatically |
| **Time zone** | the zone reports and log timestamps are read in |
| **Home region** | where this organization's devices are served from by default |
| **Regions they may occupy** | their traffic and data stay inside the ones you tick |
| **Give them their own address on the Edges** | leave this ticked — see below |
| **Who runs it** | *We run it for them* is the delegation the operator needs to administer it |
| **Their first administrator** | optional; produces an invitation you hand over |

**"Give them their own address on the Edges" is the transport authority, and the dialog says why it is now
rather than later:** *their devices then verify this deployment with nothing but their own organization's
certificate, and no other tenant's name is offered to them. Doing it later means moving devices onto a new
name; doing it now does not, because they have none.*

**"Who runs it" is what makes the organization administrable by you.** Without the delegation, every
operator read inside it answers 403 — *…has not delegated its management to the operator* — including the
screen that issues device profiles. The organization can withdraw it at any time, which is what makes it a
delegation rather than a claim.

**The invitation is handed over, not sent.** Creating it with an administrator's address produces a dialog
that says *Nothing has been emailed* and offers **Copy message** / **Copy link only**. The link works once and
expires in 24 hours; issue a new one if it is lost.

## 2. Give it its own authorities — Enter → Certificates

The organization now exists, has its own door name and can be administered. Two things remain, and they are
what make a device this organization's rather than the deployment's:

- **device identity** — the CA that issues its devices' certificates. A device pins it, so without it a
  device cannot pin the authority that issues its own identity.
- **traffic inspection** — a root of this organization's own, with an issuing tier beneath it. This is what
  `interception root: this organization's own` means when you check a profile.

Enter the organization and open **Certificates & PKI → Certificates**. Each has a card, and each card offers
the two shapes an organization can be in — it brought a CA of its own, or this deployment makes one for it:

| card | if they brought one | if they did not |
|---|---|---|
| **This tenant's device identity** | **Register this tenant's device CA** — this deployment then admits what that CA issues | **Let this deployment issue them** |
| **This tenant's interception authority** | **Load this tenant's interception CA** — their root, issuing certificate and key | **Let this deployment make one** |

**For one-time-token enrolment, choose "Let this deployment issue them" for device identity.**
Registering an external device CA alone establishes trust in its certificates; it does not
supply a private key with which this deployment can issue a new device identity. Configure
the interception authority separately and confirm both in the profile before installation.

**Each act asks for time inside the organization first.** A dialog says what the act does and that the
organization sees you took it, when, and that it ended; it lasts twenty minutes and nothing renews it. This
is the delegation being exercised, not a permission check — the organization can withdraw it.

**The name on the certificates is the organization's display name**, fixed when the authority is minted and
never changed afterwards: `CN=<display name> Device Identity CA, O=<display name>`, not the identifier.

**The card above the authority says what traffic is inspected under right now, and it can lag by one
fetch.** An Edge learns about a new authority when it next fetches, so for that minute the screen says the
authority exists and the Edges have not picked up its issuing tier yet. Both sentences are true; the second
stops being said once they have.

**Step 3 is how you know these worked**, and it is worth doing before any device is installed.

## 3. Hand a device its setup — Enter → Device configuration

Enter the organization (the header changes to its name, and a banner says every change is audited), then
**Certificates & PKI → Device configuration**. The screen decides what a device on this deployment does:

- **Which devices** — every device in the organization, or a group;
- **Where devices connect** — the regions, in order;
- **When no Edge can be reached** — carry nothing, or carry traffic unfiltered;
- **Virtual machines on the device** — let them out or not;
- **Left uninspected** — the operating-system and certificate traffic to leave alone, each with what you give
  up by not looking.

**Make the configuration** produces the file, and the dialog offers these ways to hand it over:

| | what it is |
|---|---|
| **Download** | the signed configuration — `install_profile.json` |
| **Download the key** | the key that proves the file came from here. *A device that has the configuration and not the key installs and stays inert* — without it the file could name whatever key signed it |
| **Make the tokens** | one per device, used once. The configuration carries no identity, because it is the same for every device in the group |
| **Download everything for one device** | all four in one archive, for one machine, per platform |

**The archive is the short path.** It carries one approval for one machine: unarchive it, and open the
installer — it takes the other three files from the folder beside it. Delete the folder once the machine is up.

**The installer is in the archive only if this deployment has published one.** Publishing is an act somebody
performs, on **Agent Releases**, and a deployment that has just been stood up has published nothing: the
archive then carries the configuration, the key and the approval, and says so. The person you hand it to
cannot publish a release and has no way to fetch the installer from here, so **either publish one first, or
put the installer in the folder before you hand it over.**

## 4. Check the profile before installing it

```sh
dsse-profileverify -profile install_profile.json -pin profile_signing_key.txt
```

```
dsse-profileverify: signed by the pinned key. This is what the device would join.
  organization               tenant_<customer-id>
  posture                    fail-closed
  transport                  https://agents.region-a.example.test
  this organization's door   <customer-id>.example.test
  enrolment door             enrol.<customer-id>.example.test
  interception root          this organization's own
  device CA pin              <device-CA-SHA256-pin>
```

Four lines say step 2 worked: the organization on the first, its own door, **interception root: this
organization's own**, and a device CA pin rather than nothing. A profile issued before step 2 names the
organization, carries the deployment's shared root instead of its own, and has no pin.

## 5. Check endpoint name resolution

Devices dial the regional transport and recovery URLs in the verified profile. Those names
must resolve on the device to the intended deployment addresses. The profile also contains
`organization.transport_server_name` and `organization.enrolment_server_name`: these are
organization-specific SNI names used while connecting to a regional endpoint. A name used
only as SNI does not itself require an agent DNS lookup. Configure a DNS record if a tool
or client will connect directly to that name. Use the actual generated/profile values;
do not derive them from an organization's display name.

## What the organization carries from the moment it exists

Its **Internet Access** screen opens with one rule — *Everything, allowed and inspected — the rule to narrow
first* — which is the posture to narrow rather than a placeholder. **Connector access** starts in
**OBSERVE**: connections to internal resources are allowed and recorded, not blocked, with
**Start partial enforcement** on the same banner when the recorded list has been reviewed.

TLS inspection does not by itself configure DLP. To protect uploads, create a policy under
**DLP Policies**, choose its detectors and match action, then select that policy on the relevant
**Internet Access** rule with **Inspect (decrypt)** enabled. Confirm an upload containing only synthetic
test data is blocked and a normal upload succeeds before enrolling the rest of the fleet.

## Where it stands — the setup checklist

The **Tenants** list carries a SETUP column, and clicking it opens the organization's checklist: what each
thing lets you do, what it is now, and a control that takes you to where it is set. Six of the rows are the
Edge's — device identity, the inspection authority, the joining token, sign-in, the email domains and the
device allowance — and the control plane shows them as *held on the enforcement edge* rather than scoring
them, because only the Edge can answer them.

Then the device: [macos-agent.md](macos-agent.md) or [windows-agent.md](windows-agent.md).

See [SaaS tenant restriction](saas-tenant-restriction.md) to configure the four built-in account restriction providers for each tenant.

Continue with [IdP integration](idp.md), [Egress policy](egress-policy.md), and
[East-West policy and OOB step-up](east-west-policy.md) to configure the customer's
core access controls and verify their actual enforcement.
