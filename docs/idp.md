# Identity provider integration

DSSE uses an identity provider (IdP) to authenticate a person and obtain the claims
used by access policy. Device enrolment and its mTLS certificate are separate:
an IdP login does not enrol a device, and an enrolled device does not prove that a
person has just completed MFA. See [PKI](pki.md) for the device identity boundary.

This guide covers customer end-user sign-in and the federated broker used by
[Internet Access](egress-policy.md) and [East-West step-up](east-west-policy.md).
Administrator Console sign-in, administrative roles, and operator delegation have
separate configuration and authorization. Registering an end-user IdP does not
automatically grant its users administrative access.

DSSE is experimental. These instructions describe the current source; integration
and assurance behavior may change. Use the guide from the revision you deploy.

## Supported connection shape

The registry accepts `oidc`, `entra`, `google`, and `okta` connection types. These
are OIDC connections; this broker does not implement SAML. It uses authorization
code exchange with PKCE S256 and validates RS256-signed ID tokens against the
registered provider's JWKS. The type selector is not a certification that every
provider configuration or authentication method works.

The control plane authors the per-customer registry and default provider. Edges
receive it in signed configuration, including the client secret when one is used,
because the Edge performs the token exchange. Redaction in the Console means the
secret is not displayed again; it does not mean Edges never possess it.

## Configure a customer connection

1. Create and enter the [customer organization](organizations.md). Check the tenant
   shown in the Console header before configuring **IdP integration**.
2. Identify the deployed step-up portal base URL (`-clientless-base-url`). Register
   its exact callback, `<portal-base-url>/clientless/auth/callback`, in the IdP's
   OIDC application. Use the deployed HTTPS name and port, not an address copied
   from a different region or an older example.
3. Configure the IdP application to return the claims needed below and an ID token
   signed with RS256. Match its client authentication settings to the DSSE token
   exchange: DSSE submits `client_id`, a configured `client_secret`, and the PKCE
   verifier in the form body. Do not assume support for another client assertion
   or token-authentication method.
4. In **IdP integration**, add the connection using the actual provider metadata.
   Save the issuer and all three endpoint URLs explicitly for a reproducible setup.
5. Run **Test**, then perform a real sign-in through the target access rule. The
   first connection becomes the customer default; use **Set default** to change it.
   An Authenticate rule can select a named provider instead of the default, subject
   to the grant-reuse limitations below.

| Field | What to supply |
|---|---|
| Provider ID | Stable customer-local identifier such as `idp_corp` |
| Type / display name | Connection type and a name administrators recognize |
| Issuer URL | Exact expected `iss` value |
| Authorization endpoint | Provider's authorization URL; required by the registration API |
| Token endpoint / JWKS URI | URLs from that issuer's metadata; fill both explicitly |
| Client ID / client secret | OIDC application credentials; a blank secret on edit preserves the existing secret |
| Verified domains | Explicit allowed domains; despite the form's optional label, an empty list fails the broker's domain check |
| Domain match | `email_domain` requires a verified email; `google_hd` checks the hosted-domain claim |
| Assurance / methods / groups / hosted-domain claim | Optional claim-name overrides; defaults are `acr`, `amr`, `groups`, `hd` |
| Certificate authority | PEM CA certificates for an IdP using private TLS trust, if needed |

The current broker start path sends PKCE even though the connection form also has
a **Use PKCE** field. It requests `openid email profile`; configure required claims
in the provider's ID token rather than assuming DSSE requests provider-specific
group scopes or provisions a directory.

For `email_domain`, the broker requires `email_verified=true` as well as an allowed
email domain. For `google_hd`, it requires the configured hosted-domain claim to
match. A successful provider login without these claims is rejected by DSSE.
The allowed-domain list is an operator assertion; saving it is not DNS ownership
verification or an invitation to every user in that domain.

## Saving, changing the default and deleting

The Console reads and writes this registry through the control plane. Required
provider and organization reads must succeed before editing; unavailable or
malformed responses are shown with **Retry**, not as an empty registry. Changes
are confirmed against the submitted provider identity and metadata. If a request
is interrupted, reload before retrying because it may already have been applied.
Closing a pending form does not cancel the server request. In-page warnings are
not durable across a full reload.

Creation, editing, changing the default and deleting save the candidate registry
before changing live connections, defaults or configuration generation. A rejected
save returns HTTP 500 and retains the previous live state. An empty client secret
on edit preserves the current secret. The first connection becomes the default;
choose another default before deleting it while other connections remain. Deleting
the final connection removes the default too.

Accepted changes appear in **Logs & Audit** as `idp_connection_upserted`,
`idp_connection_default_set` or `idp_connection_deleted`, with the acting
administrator, tenant, target provider and result. Connection secrets, endpoint
URLs and claim values are not copied into these domain records. A rejected save
has a common administrative error record and no successful domain record. A
configuration audit does not prove that all Edges received the change or that a
real sign-in succeeded.

In-memory operation remains non-durable. Saved-without-atomicity results are logged
and accepted without a separate Console durability indicator. Partial physical
writes or ambiguous commits still require storage-level recovery. Tenant erasure
and bundle replacement retain separate best-effort persistence behavior; concurrent
writers and independent fleet delivery need deployment validation.

## TLS and reachability

There are two independent HTTPS paths:

- The user's browser must reach and trust both the portal and the IdP.
- Every serving Edge must reach and trust the IdP's discovery, token, and JWKS
  endpoints. A private `ca_pem` on the connection configures these server-side
  calls; it does not install that CA into the user's browser.

The portal needs its own trusted certificate. In a generated deployment,
`clientless/tls.crt` and `clientless/tls.key` supply that certificate when present.
Check the generated launch configuration and profile for the actual names and
trust. Fleet nodes need the shared step-up binding secret and current IdP registry;
a working Console connection test does not prove every Edge has applied them.

**Test** checks connectivity and metadata/JWKS consistency. It does not complete
an authorization-code exchange, verify a client secret, or demonstrate MFA.

## Browser access to a published private application

The optional `/clientless/apps/{application_id}` route requires explicit
`-clientless-access` enablement, an active verified IdP session cookie, and an
active, published private application in that session's tenant. High-sensitivity
applications require a managed device and cannot use this reduced-trust route.
This feature is separate from the standard-browser step-up ceremony used by
endpoint agents.

The application relay uses the verified caller's tenant to select its Connector
and policy. URL parameters cannot assert a user, group, device posture, delegated
identity, or a different tenant. Query and header values do not replace the
clientless browser's session cookie. A catalog read failure stops the request;
it does not select a legacy destination instead.

Direct `/apps/{application_id}` requests carrying a human session also require a
verified mTLS endpoint registered in the same tenant. A session already bound to
a device must match that device. A Connector certificate or a device identifier
stored in an IdP session is not proof of a managed endpoint. Administrators can
still author an explicit policy for anonymous access to a non-high-sensitivity
application; such requests have no verified user or managed-device identity.
These routes always require the current application policy to permit access.
An inventory read failure is different from an unregistered device: access
evaluation stops instead of dropping device risk or posture conditions. The
Console's risk API likewise returns an error instead of reporting an empty risk
value.

## Authentication strength and current limits

An Authenticate action and a phishing-resistant authentication requirement are
different settings. The provider must perform the required ceremony and issue the
corresponding signed claim; the browser opening or returning is insufficient.

| Setting | Current interpretation |
|---|---|
| `required_idp_id` | Selects the requested provider and restricts grant reuse to that provider |
| `min_acr` | Exact expected assurance value, not a numeric ordering of arbitrary ACR strings |
| `acr_claim` | Claim to read; a required value can match a scalar or an element of an array |
| `required_amr` | Every required method must be present in the verified token and reusable grant |
| `max_age_seconds` | Limits verified IdP `auth_time`; zero is restricted to one pending native request |
| `grant_ttl_seconds` | Caps grant issuance and reuse from issuance time; separate from IdP authentication age |

The shared federated gate checks tenant, exact device binding, provider/issuer
identity and configuration, destination scope, assurance, required methods,
authentication freshness, revocation and the current grant-lifetime cap. When
[device-user authentication](device-user-authentication.md) is activated, the OS
principal, login incarnation and administrator-assigned IdP subject must match too.
An unbound grant cannot release a device-bound flow. Signed start links preserve
these requirements through authorization and callback; incomplete, duplicated or
tampered parameters are rejected before an IdP redirect.

The broker requests `acr_values` and the authored `max_age` with OIDC authorization
code plus PKCE, and validates the resulting signed claims. It does not implement
provider-specific claims challenges. Test actual claims and negative cases with
the chosen provider; provider labels and Console presets are not evidence that an
IdP performed a requested factor.

Signed native requests have a bounded authentication window. With the configured
shared deployment key and activated ceremony-recovery capability, encrypted
browser-bound state can finish on another current Portal process behind the same
origin. Anonymous clientless starts remain process-local. The federated grant's
configured default is eight hours; positive rule and tenant ceilings can shorten
it. See [grant lifetime and freshness](device-user-authentication.md#grant-lifetime-and-idp-authentication-freshness)
and the [rolling-upgrade requirements](authentication-rolling-upgrades.md).

## Review and revoke access approvals

Open **Access Approvals** inside the customer organization. **Active** shows
unexpired approvals; **All (incl. used/revoked/expired)** includes history. Search by
person, email, device, destination or provider. The table includes captured
identity, binding, scope, assurance, sign-in method and validity. These are recorded
claims, not proof that every flow-policy requirement listed above is enforced.
An invalid or missing expiry is **Unknown expiry**, never Active. Failed or
malformed required reads show **Retry** instead of an empty list.

The page lists and revokes approvals; it has no manual creation or editing form.
**Revoke** asks for confirmation. Cancel sends no revocation request. The API
checks the exact tenant and grant together before applying the denial. Repeated
requests while a confirmation or write is pending are suppressed in the page.

Administrator revocation requires a new identity verification, rather than only
invalidating one cookie. DSSE persists a `reauthenticate_after` boundary for the
affected identity, device/account and resource. Older IdP SSO evidence cannot
mint or authorize a replacement approval, even under a different approval ID or
OS login session. New approvals must contain a verified `auth_time` strictly
later than that boundary. Token issuance and approval issuance times do not
substitute for authentication time. The boundary has no automatic expiry: IdP
SSO lifetimes are not bounded by the approval lifetime. Expired duplicate or
subsumed fences are compacted after the 15-minute replay
retention period. At more than 4096 distinct effective selectors in a tenant,
boundaries are consolidated to one **stricter tenant-wide boundary** at the latest
cutoff. Revocation is never rejected because that threshold was reached. Other
users, devices and resources in the same tenant may also need fresh identity
verification; the API returns `reauthentication_scope: tenant` and the Console
shows a warning. Existing denials are never weakened. Live and recent grant IDs
remain as replay tombstones until their own expiry plus retention; this threshold
bounds effective selectors, not those temporary tombstone rows. The wider
boundary survives restart and distribution. Tenant data erasure removes its
boundaries along with its other authentication data. Authorization uses an index
by tenant and user; an unidentified subject is conservatively matched within its
own tenant.

The Portal requests suitable authentication freshness from the IdP and checks
the returned signed evidence. IdPs that cannot request or prove that freshness
fail closed; do not interpret an account-selection screen or a successful redirect
as a fresh identity verification. Google account reauthentication is not claimed
as supported by the existing direct-provider integration.

After the new verification, an ordinary reusable approval may be issued under
the current policy. This does not turn the approval into a one-request grant.
Natural expiration and consumption of a one-request grant do not create an
administrator revocation boundary. Deny policies and device/account revocations
still apply after a new sign-in.

In a distributed deployment, update the CPs before Edges: the Portal checks the
CP's authenticated management authority before sign-in and commits approvals
there before publishing them locally once `revocation-reauthentication-v1` is
activated. No local-only approval is issued when that authority is unavailable;
already valid approvals may still authorize under current policy. A deployment
with one CP therefore cannot issue new approvals while that CP is unavailable.
Before activation, Edges retain local issuance and reporting for compatibility
with old CPs, and the administrative API still revokes the selected approval.
Its response explicitly sets `fresh_identity_required: false`, and the Console
warns that existing IdP SSO may authorize a replacement. Activation does not
silently add freshness boundaries to earlier ordinary revocations. All expected
CP/Edge processes must report and activate the capability for the stronger
operation. Do not reintroduce an older serving binary after activation.

Authorization misses use a separate, signed `/admin/authentication-grants`
management snapshot, rather than refetching the complete configuration. Both
this endpoint and `/admin/config-bundle` require an operator identity or an
operator-organization Edge API token with `admin.policy.read`; customer policy
readers cannot download them. These responses contain bearer grants and, for
the full configuration, IdP client secrets. They are available directly over the
trusted management channel and are never proxied by the browser-facing Console.
Tenant administrators use the scoped resource APIs instead. A
content version avoids transferring unchanged grants. Each signed response
includes a fresh read nonce and is checked against the existing pinned signing
keys. Concurrent misses do not wait behind another refresh; the Edge admits at
most one refresh per second. Old CPs without this endpoint continue using
ordinary periodic distribution, without unsigned or full-bundle fallback here.

If storage fails, the API returns HTTP 500 with `status: partial`, `applied: true`
and `persistence: unconfirmed`. The grant remains revoked in this server's memory,
but a restart can restore the older saved grant. Restore the storage service and
use **Retry saving revocation** before restarting. That retry saves an already
revoked grant again. A lost response has an unknown outcome; check the approval
and use **Retry revocation**. Warnings are held only in the current page and do not
survive navigation or a browser reload. A normal response confirms local acceptance;
it does not prove that all serving nodes received the revocation.

A completed in-place file write is reported separately: HTTP 200 with
`persistence: saved_non_atomic`. The page warns that this save completed, but
future interrupted writes could damage the snapshot. It does not request another
save for that completed write; use storage that permits atomic replacement.
If replacement completed but its final flush is unconfirmed, the API instead
returns the partial 500 above and retains the retry requirement. The snapshot may
already contain the change: an error is not proof that nothing was written.
New grants are not adopted into live state on that unconfirmed result. A completed,
synced in-place save retains the existing admission behavior.

**Logs & Audit** records `admin_access_grant_revoked` with result `revoked` or
`partial`, the acting administrator, tenant, time and a SHA-256 grant reference.
The common administrative write record retains the HTTP result and the same
reference. Grant IDs also serve as bearer-cookie values: the revocation route is
redacted in common, operator and break-glass audit records. Do not paste the ID
into tickets or public diagnostics. Existing audit records are not rewritten.

The revocation audit includes `persistence: saved_non_atomic` for a completed
non-atomic save and `persistence: unconfirmed` for a partial result. The common
HTTP audit alone does not describe the storage guarantee.

A configured successful persister is needed for restart retention. In-memory
operation and saved-without-atomicity fallbacks are not full durability guarantees.
Grant IDs are not reusable while their records remain in the store. Minting an
existing ID is refused, including a revoked or expired one. New approvals are
saved before they become active. A failed mint returns an error before the broker
issues its grant cookie.

Grant reports and configuration bundles preserve revocations. A stale active copy
cannot reactivate a retained revoked ID, change its tenant, or extend/change an
existing active approval's claims. A valid revocation retains the original claims.
Unknown expired active reports are ignored; revoked records are retained even
after expiry. Empty reports and omitted records do not delete existing approvals.

The entire incoming batch is validated before mutation. Invalid identities or
lifetimes return a report error (400); conflicting tenant/active claims return 409.
Correct the conflicting input before retrying: a rejected batch, including any
revocations inside it, has not been applied. A storage failure after validation
returns 500: denials stay effective locally, but new active approvals are not
adopted. The response counts local changes in that attempt, not durable completion.
The reporter retries on its next reconciliation; configuration sync leaves a failed
generation unapplied and retries it. A clean replay does not rewrite the store or
advance its generation. Upgrade all authorities and Edges before relying on this
behavior; an older node still has the earlier merge behavior.

Startup refuses an existing empty file, `null`, malformed data, mismatched saved
keys or invalid grant lifetimes. A rejected load leaves an already running store
and its writer intact. Restore a verified backup rather than deleting the file or
replacing it with `{}` to bypass the check; a genuinely missing initial snapshot
and an explicitly configured empty object remain valid inputs. This cannot recover
revocations already lost from every retained copy.

A running store refuses to replace or detach its writer while changes are pending
persistence. Repair the current storage and retry saving before switching it; a
valid but older snapshot must not discard an unsaved local denial. This guard is
not a restore procedure for already missing revocation history. In-memory operation,
multiple writers, and durability handling in other approval stores remain separate
considerations.

These controls do not establish shared-storage writer coordination or a fleet-wide
transaction. Partial physical writes, ambiguous commits, tenant erasure, unbounded
retention, duplicate JSON object members and global generation continuity still
need separate validation. Real IdP sign-in, independently running nodes, complete
machine-certificate authorization and existing connections require deployment tests.

## Verify and troubleshoot

Use test accounts and a disposable target. Record the tenant, serving Edge,
provider ID, rule, and configuration revision without recording tokens or secrets.
Start baseline-denial tests without an existing grant that already satisfies the gate.

| Check | Evidence to collect |
|---|---|
| Allowed account | Completed token validation, resulting grant, and permitted target connection |
| Wrong domain or missing verified-email/hosted-domain claim | DSSE rejects the callback; no new usable grant |
| Required ACR absent or different | Rejection with no grant satisfying that ACR |
| Baseline then stronger authentication | Same IdP and same intended user; baseline cannot satisfy the ACR-gated flow, stronger authentication can |
| Existing grant from another provider/device/destination | Measure actual reuse; compare with the explicit limits above |
| Grant expiry or revocation | New connection is re-evaluated; test existing sessions separately |
| Another serving region | Registry, TLS, callback routing, grant distribution, and real target access work there too |

For `no usable IdP`, check customer scope, default/required provider, and Edge bundle
application. For `invalid_client`, check client credentials and token endpoint.
For TLS failures, distinguish browser trust from Edge-to-IdP trust. For callback
rejection, inspect issuer, audience, nonce, expiry, domain, and assurance claims.
If sign-in succeeds but a native connection remains held, continue with the
[OOB checks](east-west-policy.md#out-of-band-step-up).

Read-only API entry points are `GET /admin/idp-connections` and
`GET /admin/idp-connections/{id}/test`, using the authenticated customer context.
Before deleting a provider, move the default when other providers remain and
review rules referencing it. Deletion is not a substitute for revoking existing grants.

Implementation references: [registry](../idpregistry/idpregistry.go),
[Console form](../console/idp.js), [connection test](../cmd/dsse-edge/idp_connection_check.go),
[OIDC validation](../oidcbroker/validate.go), [authorization request](../oidcbroker/authorize.go),
[broker](../cmd/dsse-edge/clientless_broker.go),
[flow gate](../cmd/dsse-edge/federated_auth_gate.go), and
[registry distribution](../cmd/dsse-edge/config_bundle_idp_connections.go).

## Rolling grant-storage compatibility (development)

The shared PostgreSQL authority now keeps `grants` as the map understood by the
released 0.3.1 writer. New evidence is stored separately in `grants_evidence_v1`;
both keys are updated in one transaction. Backups must include both keys.
Request-bound grants are absent from the legacy key and legacy bundle field.
They travel in `protected_grants` and use the versioned `/grant-report-v2` report
endpoint, so an older CP cannot silently acknowledge them after dropping their
requirements. Unknown required features deny only the affected grant; unknown
JSON fields are retained.

This storage change alone does **not** establish rolling-upgrade readiness.
Authoritative membership and capability tracking for every CP and Edge, the
mixed-version acceptance phase for legacy evidence, and authenticated native
traffic across actual process replacement remain required. The current gate
still refuses grants without provider evidence. Do not claim that an already
authenticated legacy user avoids reauthentication during upgrade yet. A fleet
view containing only nodes that recently reported is insufficient to conclude
that all older nodes have been upgraded.

Draining prevents new authentication starts and waits. It does not revoke an
already issued grant or immediately cancel an existing callback. Request-bound
grants expire no later than their original ceremony deadline; retries do not
extend that deadline. Expired protected rows are removed after a ten-minute
grace. The rolling authority conservatively retains ordinary legacy rows until
a complete-fleet cutover can be established. Local caches prune expired rows.

### Grant visibility between Edges

A successful Portal callback reports the saved grant to the control plane before
returning its completion page, with a three-second publication bound. The periodic
report remains a retry path when the authority is unavailable. Before starting
another authentication ceremony after a local authorization miss, an Edge makes
a bounded read of the authority's signed configuration and imports only its grant
evidence. Concurrent misses are coalesced and reads are limited to once per second
per Edge. Invalid, unsigned or incomplete evidence cannot authorize traffic.
Device, OS session, destination, assurance and current policy lifetime checks still
apply after import. This avoids waiting for the normal report and configuration
poll intervals when a user's next connection reaches a different Edge.
