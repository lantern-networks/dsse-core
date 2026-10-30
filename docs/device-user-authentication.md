# Device user and login-session authentication

Device-bound authentication can require the identity provider subject to match the OS user who originated the connection. An administrator assigns the mapping; a browser callback cannot create one. This applies to authentication-gated application traffic, including native TCP and inspected HTTP carried by the authenticated steering mux.

The authorization boundary is the combination of:

- Tenant and device identity verified by the device's mTLS connection.
- OS principal attributed by the privileged endpoint agent: a Windows SID or a macOS account UUID.
- Login incarnation: the Windows logon authentication LUID plus session, or the macOS audit session, combined with a random agent-process incarnation.
- The configured IdP, its verified issuer and subject (`sub`), and the current assignment revision.
- The destination, authentication assurance, freshness and current policy requirements.

Process IDs, display names, email addresses and the enrolling administrator are not substitutes for these identities. Processes in the same login may reuse a reusable grant for its permitted scope. A new login, another OS user, or an agent restart needs fresh authentication. `max_age=0` remains limited to the single pending request.

## Grant lifetime and IdP authentication freshness

`grant_ttl_seconds` limits how long a newly issued authorization can be reused,
measured from its issuance. Connector Access also applies the tenant's
`max_grant_ttl_seconds` ceiling; the smaller positive rule or tenant limit wins.
Zero leaves that level unset. Neither setting increases the broker's configured
default lifetime. Internet Access Authenticate rules carry their own positive
grant lifetime limit through the same federated flow.

The Edge signs the effective limit into the authentication request. The Portal
preserves it through callback and encrypted cross-process ceremony recovery, and
caps the issued grant. Every subsequent authorization checks the current policy
limit again, so an older, longer-lived grant cannot bypass a shortened limit.
Malformed or overflowing limits fail closed.

This is separate from `max_age_seconds`, which limits the age of the IdP's actual
`auth_time`. Renewing an expired authorization may reuse a valid IdP SSO session
when no fresh IdP authentication is required. `max_age=0` still permits only the
specific pending request. Grant-expiry checks authorize new requests and held
request resumption; they do not promise to terminate an already-established TCP
stream exactly at its grant deadline.

## Assignment and activation

Upgrade CPs and Edges using [the rolling-upgrade procedure](authentication-rolling-upgrades.md). Updated nodes advertise `device-user-session-v1`. Advertising support does **not** automatically enable this additional requirement in a distributed deployment.

1. Upgrade the endpoint agents that will use authenticated traffic. Check their actual OS process attribution, including the supported native applications. Do not activate while these clients cannot supply owner metadata. In particular, a Windows SMB redirector or macOS `smbfs` flow may appear to originate from a system/kernel account rather than the interactive user. Until `net use` and `mount_smbfs` are measured on the supported endpoint versions, do not claim that identity-bound SMB authentication is supported or activate this feature for an SMB-dependent deployment. A system-attributed SMB flow must fail closed instead of borrowing another user's approval.
2. Obtain the device identifier, OS principal and IdP subject from trusted administrator-controlled inventory and the IdP. Verify the correspondence; do not learn it from whoever first opens a sign-in link.
3. In **IdP integration → Edit**, choose an observed device account and an active user imported into the identity directory under the provider ID, then explicitly confirm the assignment. The observed account name is only a hint; an administrator must verify that the selected IdP user is the same person. The Console also offers an advanced form for exact device ID, OS account ID and OIDC `sub` when those lists are unavailable. The tenant-scoped `POST /admin/idp-connections` API accepts the same `device_user_bindings` field. For example, this additional field assigns a synthetic Windows account:

   ```json
   {
     "device_user_bindings": [
       {
         "device_id": "managed-device-123",
         "os_principal": "windows:S-1-5-21-100-200-300-1001",
         "subject": "idp-stable-subject-123"
       }
     ]
   }
   ```

   This fragment is not a complete provider configuration. macOS principals use `macos:` followed by the lower-case account UUID. Assignments belong to that tenant and provider. Different users on the same device have separate entries.

   The API returns a server-generated `revision` for each assignment. An unchanged mapping preserves it. Reassignment or removal and recreation generates a new revision; clients cannot restore an earlier revision. The Console omits the bindings field during ordinary provider edits when assignments did not change. An explicit empty array removes all assignments for that provider.

4. Verify that all non-retired CP and Edge members in the deployment census have fresh reports supporting the new capability. A deployment administrator then calls `POST /admin/auth-rollout/activate` with the census generation and the **complete** enabled-feature set, including:

   ```json
   {
     "generation": 1,
     "features": [
       "grant-evidence-v1",
       "single-request-v1",
       "device-user-session-v1"
     ]
   }
   ```

   Use the actual generation and retain any other enabled capabilities. The authority rejects activation if any member is missing support. Activation is monotonic; it is not a per-node bypass switch. As with other completed authentication upgrades, downgrading a single member is unsupported.

5. Plan endpoint agent upgrades and restarts in announced waves. The login-incarnation identifier includes a fresh agent-process value, so restarting or updating the agent requires every affected user to authenticate again, even when their OS login is unchanged. Verify a successful authentication by the assigned subject, rejection of a different subject, user/session isolation, assignment revocation, and Fleet sharing. Previously issued device-only grants no longer satisfy device-bound authentication after activation; this identity migration intentionally requires fresh evidence.

An ephemeral standalone runtime without distributed rollout state enforces the binding directly. A durable deployment needs the census and activation procedure. Missing or unreadable rollout state cannot restore device-only authorization.

## Processing and failure behavior

The agent places the OS owner in authenticated mux metadata. The Edge includes it in the signed, short-lived authentication request. The privileged browser launcher checks that owner metadata, when present, matches the original OS user/session. Ordinary web request headers cannot supply this identity.

The Portal checks the assignment before starting authentication and checks the verified token subject **and that assignment's original revision** again at callback. The gate checks the assignment, session and evidence again before releasing application traffic. Changing the assignment invalidates prior evidence even if the same subject is assigned again later. A changed assignment during an in-progress ceremony requires a new request; editing somebody else's assignment does not interrupt it.

Identity-bound grants carry a required-capability marker and use the modern storage/bundle partition. Released readers cannot authorize them as device-only grants. Existing authentication continues under the previous semantics while the distributed deployment has not activated identity binding; do not describe that migration phase as user/session isolation.

The agent is part of the trust boundary. A compromised privileged agent or device key is not addressed by OS attribution alone. Flows attributed only to SYSTEM, a daemon or an unavailable originating user do not acquire another interactive user's authentication by fallback.

### In-progress authentication during a failure

Sharing issued grants does not by itself recover an in-progress browser login.
For recovery after a Portal process restart, all expected CP and Edge members
must report support for `ceremony-recovery-v1`. An administrator must explicitly
add that capability to the complete enabled-feature set through
`POST /admin/auth-rollout/activate`. Advertising support is insufficient. Verify
that the signed configuration has reached the Edges before injecting a fault.
Do not enable it by bypassing the deployment census or mixed-version checks.

Recovery uses encrypted, browser-bound state, the deployment's shared step-up
signing secret, the same HTTPS Portal origin, and an unchanged provider
configuration. The callback still verifies PKCE, the browser binding, the
original deadline, the user assignment and any administrative freshness boundary.
Restarting a process does not extend the deadline. Missing or incompatible state
is refused; it must not become a locally issued approval when the CP authority
is unavailable.

Legacy owner-pinned configurations route a Node Portal to its owning Edge; they
can recover after that process returns, but cannot serve that origin while the
owner is absent. New declared shared-fleet profiles (`one-region-three-nodes`,
`three-regions-multi-edge`, and the separate single-entrance dedicated profile)
route an entrance's Portal across its declared healthy Edge pool. Every Edge needs
an approved SAN certificate for every declared origin, the shared binding key and
active ceremony recovery with CP one-time consumption. The Portal origin remains
fixed through start/callback. An entrance host outage still loses that entrance;
this does not move its IP or browser origin to another host. See the
[installation guide](releases/0.4.0/install-multi-edge.md).

A failed Edge also loses the TCP streams it owned. Restoring authentication state
does not migrate those streams or revive an application request that has already
failed. After successful authentication, an application may reconnect and reuse
a still-valid, reusable grant under current policy. A single-request approval
does not authorize a different request. If either the application hold or the
browser ceremony expires, report its actual outcome separately from identity
verification; a completed login page is not proof that the old stream resumed.

The native application hold is currently 120 seconds. A browser ceremony that
has already started has its own 10-minute deadline. Completing that ceremony
after the native hold ends can therefore issue a valid approval for subsequent
connections, while the old connection remains `not_resumed`. This is not an
extension of the old application hold. The browser ceremony's actual deadline
still rejects a late callback, including after a Portal process restart.

## Verification scope

Local tests cover real signed OIDC tokens from a disposable mock provider, wrong-subject callbacks, signed-link tampering, mapping changes, login isolation, shared grant storage, released-reader separation, feature activation and authority-read failure. The macOS package tests and Windows cross-build cover the implementation interfaces.

These checks do not establish acceptance for real Google, Okta or Entra tenants, macOS Network Extension sandbox execution, or Windows SMB/RDP impersonation. The Console now offers a tenant-scoped observed-account and IdP-directory picker, while keeping exact-ID entry as an advanced fallback. Observed account names are not identity evidence, the directory source must match the provider ID, and bulk assignment import is not yet available; large-scale activation still needs an operational review. Authenticated user-facing result requery and capability-gated Fleet-wide in-progress ceremony recovery are implemented. Real-provider and platform acceptance, including the deployment-specific failure cases, remain release checks. No live endpoint needs to be reconfigured to run the local tests.

An active raw policy with `max_age_seconds=0` must explicitly select the held `ssh`, `rdp`, or `smb` service family. Saving or activating a Web-capable policy with that requirement is rejected: redirecting a browser would discard the original request, so a new HTTP request could not consume its one-request authorization. Disabled or draft policies can be kept for editing, but activation checks again. The Console labels a consumed one-request approval **Used**, separately from an administrator-revoked approval.

For authored access rules, leaving the maximum authentication age blank omits
the requirement; entering zero explicitly requires authentication for one held
request. This distinction is preserved in saved rules and distributed policies.
An active authored rule with zero must be an outbound Connector Access rule.
The Internet Access editor cannot prove that its port selectors exclude Web
traffic, and inbound rules cannot hold a browser ceremony, so those combinations
are rejected when activated. A legacy device grant or device attestation alone
does not satisfy an explicit freshness or IdP assurance requirement.

Workload attestation is a separate condition. When a rule requires both workload
attestation and user authentication, a verified user cannot substitute for an
unverified workload: the workload proof must be present before the authentication
grant can release the flow.

### macOS authentication notification recovery

The resident agent reads only root-owned, signature-validated handoff records
for the originating OS user and audit session. It reads them on notification and
every two seconds, so a missed wakeup does not strand an application waiting for
a browser. Repeated reads do not reopen a delivered request or extend its
120-second UI lifetime. Completion results come from the authenticated mux, never
from the browser window. Replay bookkeeping and concurrent file reads are bounded;
notification recovery does not relax origin, signature or session checks.

Each distinct validated request receives one automatic browser launch. Bursts
are queued with at least two seconds between launches, rather than suppressing
new challenges for two minutes after a previous login. The queue is bounded to
32 live requests and never extends a request's original lifetime. Duplicate
delivery, a terminal result, or explicit manual opening cannot cause an extra
automatic tab. Failed OS browser launches retain the manual retry action; browser
launch itself is never treated as successful authentication.

Every new browser ceremony first shows the destination in the DSSE Portal.
Only the user's **Continue to sign in** action begins the IdP request. Merely
opening a tab cannot authorize another destination through an existing IdP SSO
session. The confirmation is bound to the browser and the complete
original request, and expires with the start link (at most two minutes).
It does not ask for an IdP password. With shared ceremony recovery and revocation
authority activated, signed device requests can display confirmation on one
Edge and submit it to another behind the same Portal origin, including after
a restart. No backend affinity is required. The proof cannot authorize a new
request, and atomic CP minting still issues at most one grant for the original
request across Edges. Same-process duplicate submissions are refused.
Anonymous starts and pre-activation confirmation remain process-local and need
a reload if that process is lost. Retry also returns to destination confirmation.

Update every serving Portal before relying on this confirmation requirement or
on `grant_ttl` in signed start links. Older Portals do not enforce these start
parameters. Do not enable a shorter grant cap on a partially updated fleet.
Complete or expire ceremonies started before the update before claiming the
confirmation requirement for every in-progress sign-in; encrypted legacy
callbacks may still finish within their original ten-minute deadline.

Administrator revocation is separate from IdP session expiration. See
[revoking access approvals](idp.md#review-and-revoke-access-approvals) for the
persistent freshness boundary and the required fleet capability. A new approval
ID cannot bypass it by reusing pre-revocation SSO evidence.
