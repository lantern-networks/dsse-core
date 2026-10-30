# East-West policy and out-of-band step-up

East-West policy controls access from a device to internal systems, connection by
connection. The Console presents outbound rules as **Connector Access** and
receiver-side rules as **Incoming Connections**. A reachable route or published
application is not itself authorization. Configure routing with the
[Connector guide](connector.md), identity with [IdP integration](idp.md), and then
the policy described here.

This guide describes the current experimental source, including limitations of
the shared federated step-up path. APIs, behavior, and migration procedures may
change. It does not claim complete per-hop assurance on every traffic path.

## Which traffic is East-West

Classification considers both the service family and destination locality.
Recognized families include SSH, RDP, SMB/CIFS, WinRM, WMI/RPC, DCOM/RPC, VNC,
RMM, database, and management TCP. Private, loopback, link-local, and explicitly
declared internal destinations are internal; connector reachable routes contribute
to that declaration. A globally routable destination is normally Internet Access
even on an SSH port. Unknown locality is not automatically treated as public.

An outbound rule applies at the initiating traffic path. Incoming Connections
uses Windows WFP receiver-side enforcement; macOS Network Extension does not
provide equivalent inbound enforcement. A rule targeting only macOS receivers is
rejected by the authoring validation; a mixed group can contain unsupported
receivers. Established-connection return traffic is not a new incoming-connection
permission. Verify both initiating and receiving platforms for the intended flow.

## Posture and rule stage are separate

New customers start in **OBSERVE** for Connector Access. This posture governs the
East-West layer; other admission, routing, or security checks can still reject a flow.

| Customer posture | Matching East-West rule | No matching East-West rule |
|---|---|---|
| OBSERVE | Traffic observed; East-West rules not enforced | Observed and allowed by this layer |
| PARTIAL ENFORCE | Rule applies, including its Warn/Enforce stage | Allowed by this layer |
| FULL ENFORCE | Rule applies, including its Warn/Enforce stage | Denied by this layer |

| Rule stage | Deny or Authenticate action |
|---|---|
| Warn | Allows the flow and records/notifies what would be enforced |
| Enforce | Denies or requires authentication as configured |

**FULL ENFORCE does not turn a Warn rule into a blocking rule.** Review both the
posture banner and each rule's stage. A rule's Active/Disabled status is another
independent setting. Lower priority numbers are evaluated first.

## Build policy from observed traffic

1. Enter the customer and open **Connector Access → Observations**. Exercise
   representative interactive, background, and administrative workloads.
2. Review uncovered flows and use **Adopt** to open the prefilled editor. Its
   initial source is **Any** and action is **Allow**; narrow and review these
   before saving. Observation is not approval.
3. Choose enrolled catalog devices or device groups as the source, named internal
   destinations, the service, and a distinct priority. The current outbound
   compiler resolves source selectors to device identities. The shared editor's
   person/IdP-group selectors are not compiled into equivalent identity conditions
   on this East-West path; use the documented device selectors and verify resolution.
4. Choose Allow, Deny, or Authenticate. For Authenticate, select the IdP and
   assurance requirement and review the [shared gate limits](idp.md#authentication-strength-and-current-limits).
   Use Warn only while deliberately observing the proposed restriction.
5. Select **Start partial enforcement**. Verify matched Allow, Deny, Authenticate,
   and Warn cases, plus the allowed unmatched case. Promote reviewed rules to Enforce.
6. Review remaining uncovered flows before **Turn on full enforcement**. Verify
   that an unmatched test connection is then denied, alongside intended allowed flows.

Coverage describes flows observed so far. Zero uncovered flows is not proof that
an offline device, monthly task, or disaster-recovery job has been exercised.
The Console warns about uncovered flows before full enforcement; it is not a
complete dependency analysis or an automatic release decision.

A non-Any source or destination that resolves to nothing matches nothing. In
PARTIAL ENFORCE such a failed match can fall through to the unmatched allow.
A named service matches its configured transport/port pairs, not its display name.
For example, a service named `Finance database` containing TCP/5432 does not also
allow TCP/3306 or UDP/5432. Renaming the service does not change that condition.
A deleted or unresolved named service matches nothing; only explicit **Any** removes
the service restriction. This does not expand which service families enter the
East-West layer. Legacy family-based API rules retain their family selectors.
Upgrade all Edges before publishing transport/port-based compiled rules from an
updated control plane. Older readers cannot apply these rules and see a nonmatching
family guard instead of an unrestricted service. In partial mode, unmatched flows
remain allowed; mixed-version enforcement is not an acceptance guarantee.

Mode, legacy rules, and grant TTL changes submitted together are saved as one update.
A refused or unconfirmed save returns an error and preserves the prior live policy.
Reload the settings before retrying: an unconfirmed filesystem flush does not prove
that disk contents stayed unchanged.

The **Allow machines with no signed-in user** option is an explicit alternate
path for Authenticate rules, disabled by default. Its attestation eligibility
check uses a verified mTLS transport identity; it does not itself require an
absent user or establish hardware attestation. Other admission/risk checks still
apply. Leave it off when the rule must require a person's interactive sign-in.

## Out-of-band step-up

Out-of-band (OOB) means authentication happens in a separate browser/window, not
inside the SSH, RDP, or SMB protocol. It does not necessarily mean a second device
or a second communication network.

```mermaid
sequenceDiagram
    participant N as Native application
    participant A as Endpoint agent
    participant E as Edge
    participant B as Default browser and portal
    participant I as IdP
    N->>A: Connect to internal service
    A->>E: Steered connection with device identity
    E-->>A: STEPUP URL; hold upstream connection
    A->>B: Open signed Portal link in the originating user's browser
    B->>I: OIDC authorization request
    I-->>B: Callback with authorization code
    E->>I: Broker exchanges and validates token
    E->>E: Record federated grant
    E-->>N: Resume when the grant is recognized, or require retry
```

Before testing, make sure the portal has reachable DNS and trusted HTTPS, the
customer IdP has the exact callback registered, the Edge can call the IdP, and the
endpoint can open the authentication UI without depending on the held connection.
Fleet nodes need current IdP configuration and the shared step-up binding secret.
The signed start URL binds the supplied device and customer to the ceremony.

On the steered native mux path, the Edge sends a STEPUP frame and holds the
connection before dialing upstream. It waits up to **120 seconds** for a grant.
If recognized while the application is still waiting, it can resume that same
connection. If the application gives up or the wait expires, retry the native
connection after authentication; the success page alone does not prove release.

There is a current customer-scope limitation: the initial/retried flow checks the
flow's tenant, but the held-flow polling helper checks the gate's default tenant.
For a customer distinct from that default, automatic release can miss a successful
customer grant. A new connection is evaluated with the flow's tenant. Do not
promise seamless resumption for every customer.

For HTTP browsers the shared path can use a redirect; non-browser HTTP gets an
authentication response and possibly `X-Dsse-Stepup-Url`. That header is not the
mux STEPUP frame and is not, by itself, automatic agent browser mediation.

### Windows and macOS authentication

For native SSH, RDP, SMB, and similar traffic, DSSE holds or denies the original
connection and sends an authentication request to the endpoint agent. The agent
opens the signed, short-lived Portal link in the **originating user's default
browser**. The Portal redirects to the configured IdP and validates the response.
An embedded WKWebView or WebView2 is not an IdP sign-in surface; the Windows
WebView2 helper is not part of the installer. This also permits IdPs that reject
embedded OAuth user agents.

The endpoint checks the Portal origin against its signed profile before opening
it. The Portal validates the signed request and expiry. On Windows, the agent
uses the WFP flow owner's SID, session, and logon identity; an unknown owner does
not fall back to SYSTEM or the active console. On macOS, the Network Extension
passes a protected request to the same login session's menu-bar app. A passive
notification does not itself authorize a connection.

After IdP sign-in, the Edge checks the verified identity, required assurance,
current policy, device, OS-session binding, and destination. A held connection
resumes only if its upstream connection succeeds. The agent can receive a
`resumed` or `not_resumed` result; a missing result must never be read as success.
If the application connection has already timed out, reconnect from that
application. The agent does not replay its traffic automatically.

For troubleshooting, check the signed Portal origin and expiry, the default
browser's certificate validation, the IdP response, the Edge's current policy,
and the original application's result separately. The IdP's server-side `ca_pem`
does not configure browser trust. A passkey or security-key flow must be tested
with the actual browser and IdP; a password-only test does not establish it.

## Grants and assurance boundaries

Two mechanisms exist and their controls must not be confused:

| Mechanism | Current boundary |
|---|---|
| Federated broker used by shared steered OOB / browser gate | Default eight-hour grant; checks validity, tenant, compatible device binding, and required ACR |
| East-West challenge/grant API | Challenge default five minutes; grants bind user/device/destination/protocol, with a default requested lifetime of 24 hours capped by configured tenant/rule TTLs; supports idle TTL on applicable grants |

The second mechanism's per-hop and idle limits do not automatically govern the
first. The federated gate checks the required provider, AMR, authentication age,
exact destination scope, device, and applicable OS-session ownership before
using a grant. Required ACR matching is exact; it is not a universal ranking
of authentication methods. A grant for one destination is not permission for
another. A `max_age=0` native grant is limited to one authenticated request.
Browser redirect paths reject that setting because the original request cannot
be resumed after the redirect.

Grant revocation or expiry affects subsequent checks. Do not assume every existing
TCP session terminates immediately: test new and already-established sessions
separately. Grant propagation across regions and survival after restart also need
verification; a successful local ceremony alone establishes neither.

## Verification and troubleshooting

Test on a narrow device group and a target you control, recording the posture,
stage, rule, IdP, claims, serving region, and application outcome.
For baseline-denial cases, first ensure no existing grant already satisfies the gate.

| Scenario | Result to establish |
|---|---|
| Observe / Warn | Connection is allowed and observed; no blocking claim |
| Partial versus Full, unmatched target | Allowed by the East-West layer in Partial; denied in Full |
| Enforce + Deny | Target connection is refused; an allowed control connection works |
| Authenticate + required ACR, no satisfying grant | Upstream remains held; OOB prompt appears |
| Baseline login then stronger login at the same IdP | Baseline does not satisfy the ACR; required ACR produces a usable grant |
| Cancel, weak claim, unreachable IdP, expired ceremony | No newly satisfying grant; connection remains unavailable absent another qualifying grant |
| Successful ceremony | Verify resumed connection or explicit retry, not just the success page |
| Different device, user, provider, destination, protocol | Record actual reuse and compare with the scope limitations above |
| Revocation, expiry, another region, restart | Verify new and existing connections separately |

Useful default-level logs on the mux path include `east_west_stepup_issued`,
`east_west_stepup_completed`, `east_west_stepup_incomplete`, `steer_mux_denied`,
and `east_west_locality_unknown`. For sign-in failure, inspect
`clientless_exchange_failed` / `clientless_jwks_failed` and the IdP validation result.
For successful sign-in but no connection, check the held-flow scope limitation,
grant distribution, native-client timeout, and the destination/Connector route.

Read-only APIs include `GET /admin/east-west`, `/admin/east-west/observations`,
`/admin/east-west/challenges`, and `/admin/east-west/grants`. The last two describe
the East-West challenge mechanism, not every federated broker ceremony. Use the
appropriate grant store/view when investigating. Document measured results using
[Verification](verification.md); this guide does not complete those tests.

Implementation references: [classification](../decision/locality.go),
[rule compiler](../policyrule/compile_eastwest.go), [rule evaluation](../decision/east_west.go),
[posture UI](../console/app.js), [observation workflow](../console/eastwestadvanced.js),
[shared gate](../cmd/dsse-edge/federated_auth_gate.go),
[mux hold and polling](../cmd/dsse-edge/main.go),
[challenge grants](../eastwest/grant.go), and
[admin routes](../cmd/dsse-edge/admin_east_west_routes.go).

Endpoint UI references: [Windows browser launcher](../clients/windows-wfp/steer/steer_stepup_owner_windows.go)
and [macOS notifications and menu](../clients/macos-network-extension/Sources/DsseAgentAppExecutable/StepUpStatusController.swift).

## Editing incoming exceptions

The Incoming Connections service picker selects one **TCP port**, using the
catalogue name as a label. For a service with several TCP ports, choose one port
per exception. UDP services are not offered because the current Windows export
cannot represent them. Non-TCP conditions are rejected by the exception API. Existing incompatible
records must be disabled, deleted, or changed to a supported condition before
a managed incoming policy can be exported.

Editing an existing exception keeps its current service condition unless you
explicitly choose another one. Reselect a catalogue service to replace an older
condition that used a display name as its service family. **Any service** explicitly
removes the service restriction. Owner-only edits retain disabled status, approval
and session settings, and the exact expiry timestamp; changing the date sets
midnight UTC for that date. Disabled and expired exceptions are excluded from export.

Operator API users can target an authorized customer in a POST body. DELETE uses
the current tenant context: enter that customer's context before deleting its
exception. The domain audit belongs to the target customer and identifies the operator.

The exception POST API preserves omitted fields on an existing ID, including
source, device group, transport/port, disabled status, approval/session settings,
and expiry. Explicit empty strings, zero, or false change those fields; `null`
is rejected. New records require an ID, business owner and RFC3339 expiry.
Validation and persistence complete before a change is reported as saved.

The current `server_initiated_export.v1` consumer supports TCP family mappings
and an explicit unconstrained service. It cannot enforce approval requirements
or per-session lifetime limits. Active exceptions with those conditions, an
unsupported transport/family, an invalid port, or a port without a transport are
rejected on write. Disabled records can retain approval/session settings, but
must be made representable before activation. This does not add UDP support.

Both administrator and device export endpoints refuse the **entire managed
policy** with HTTP 503 when an active stored record has an invalid expiry,
unknown mode/status, or unsupported condition. They do not silently omit a deny
while exporting a wider allow. Disabled and validly expired records are omitted.
Correct the reported exception and verify a successful fetch. The Windows
Defender Firewall poller keeps its last applied rules after a fetch error, so
an export refusal is **not** proof of a new restriction or timely removal of an
old allow. Check the endpoint's fetch logs and actual firewall state. Deliberately
switching to **Allow by default** returns an empty withdrawal document even when
incompatible records remain; it stops DSSE management rather than claiming those
exceptions were applied.
