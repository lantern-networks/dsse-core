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
Keep service references valid as well: an empty protocol selector on the compiled
East-West rule is broad across recognized East-West families.

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
    participant B as Agent WebView and portal
    participant I as IdP
    N->>A: Connect to internal service
    A->>E: Steered connection with device identity
    E-->>A: STEPUP URL; hold upstream connection
    A->>B: Open authentication window after OS-specific prompt
    B->>I: OIDC authorization request
    I-->>B: Callback with authorization code
    B->>E: Broker exchanges and validates token
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

### Windows and macOS authentication windows

The normal packaged native OOB experience uses a **DSSE-owned WebView window**.
It loads the portal and then the actual customer's IdP sign-in page. The application
being protected remains the original SSH/RDP/SMB client; the WebView supplies the
separate interactive sign-in surface.

| | Windows | macOS |
|---|---|---|
| WebView | WebView2 in `dsse-stepup-window.exe` | WKWebView in the resident agent's `StepUpAuthWindow` |
| How it opens | The steering service launches the helper in the active console user's session | The agent shows a notification and arms its menu-bar item; click the notification/action or the menu's authentication-window command |
| If notifications are unavailable | The normal helper path opens directly without requiring a notification click | When notification authorization is unavailable, the controller automatically opens the window |
| What the user sees | DSSE header, customer IdP page, and destination/status footer | DSSE header, customer IdP page, and destination/status footer |
| Success | Recognized approval page updates the status; window closes after about two seconds | Same approval/status behavior; window is hidden and its page cleared after about two seconds |
| Failure or manual close | A denial remains visible; closing before completion does not approve access | Denial or navigation failure remains visible; closing stops the page load and does not approve access |

On macOS, the notification's action corresponds to **Authenticate and connect**;
the menu command corresponds to **Open authentication window**. The current UI
labels are localized in Japanese. The resident agent must be running in the user's
session; a working Network Extension alone does not provide this interactive UI.

The Windows helper needs the WebView2 Runtime. If the helper executable is missing
or the agent cannot launch it, the launcher falls back to the user's default browser
with a tray notification. This fallback is not guaranteed after the helper has
already started: failure to embed WebView2 inside that process exits the helper.
Check the helper and Runtime when no usable window appears. The macOS controller
opens WKWebView; it does not implement the same external-browser fallback.

For the person making the connection:

1. Start the intended internal connection. When authentication is requested, check
   the destination shown by DSSE; on macOS, open the window from the notification
   or menu bar if it has not opened automatically.
2. Complete the customer's IdP sign-in and the required factor in that window.
   A DSSE logo or a displayed login page alone does not establish the achieved
   assurance; the Edge must validate the returned claims.
3. After approval, return to the original application and check that the operation
   proceeds. The window's success status and automatic close describe the portal
   result, not proof that the held connection resumed. Retry the connection if it
   timed out or encountered the customer-scope limitation described above.
4. If denied, cancelled, or unable to load the IdP, do not count the attempt as
   successful authentication. Resolve the error and start a fresh connection when
   a new ceremony is needed.

Both windows normally verify HTTPS. Windows uses WebView2's certificate validation;
macOS can additionally validate the portal host against the portal anchor supplied
in the applied profile, while other hosts retain default trust handling. The IdP
connection's server-side `ca_pem` does not configure WebView trust. Diagnose the
portal certificate, IdP certificate, and hostname separately.

Verify the actual sign-in method inside each shipped WebView, including any
passkey/security-key ceremony. Password sign-in in a WebView, or success in a
standalone browser, does not establish passkey support in that packaged app.
Provider restrictions on embedded sign-in and the app's platform configuration
can affect the result. Record the OS, agent package, WebView2 Runtime when relevant,
IdP, method, window outcome, and original connection outcome in the test evidence.

## Grants and assurance boundaries

Two mechanisms exist and their controls must not be confused:

| Mechanism | Current boundary |
|---|---|
| Federated broker used by shared steered OOB / browser gate | Default eight-hour grant; checks validity, tenant, compatible device binding, and required ACR |
| East-West challenge/grant API | Challenge default five minutes; grants bind user/device/destination/protocol, with a default requested lifetime of 24 hours capped by configured tenant/rule TTLs; supports idle TTL on applicable grants |

The second mechanism's per-hop and idle limits do not automatically govern the
first. The federated gate does not compare provider ID, AMR, authentication age,
or destination scope, and an unbound grant can satisfy its device check. Its
request path does not carry AMR/freshness requirements through to token validation.
The outbound compiler carrying a field and the Console displaying it are not proof
that every grant-consumption path enforces it. Required ACR matching is exact;
it is not a universal ranking of authentication methods.

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

Endpoint UI references: [Windows launcher](../clients/windows-wfp/steer/steer_stepup_windows.go),
[Windows WebView2 host](../clients/windows-wfp/stepupwindow/main.go),
[macOS notifications and menu](../clients/macos-network-extension/Sources/DsseAgentAppExecutable/StepUpStatusController.swift),
and [macOS WKWebView window](../clients/macos-network-extension/Sources/DsseAgentAppExecutable/StepUpAuthWindow.swift).
