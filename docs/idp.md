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

## Authentication strength and current limits

An Authenticate action and a phishing-resistant authentication requirement are
different settings. The provider must perform the required ceremony and issue the
corresponding signed claim; the browser opening or returning is insufficient.

| Setting | Current interpretation |
|---|---|
| `required_idp_id` | Selects the provider requested by the step-up URL |
| `min_acr` | Exact expected assurance value, not a numeric ordering of arbitrary ACR strings |
| `acr_claim` | Claim to read; a required value can match a scalar or an element of an array |
| `required_amr` | Authored required methods; the token validator can check all supplied values, but the shared flow path has the limitation below |
| `max_age_seconds` | Authored freshness requirement; not a guarantee that the shared broker forces a fresh IdP authentication |

**The shared federated flow gate currently checks a live tenant grant, compatible
device binding, and the required ACR. It does not check the grant's provider ID,
AMR, authentication age, or destination scope.** The step-up URL/start path does not
carry the rule's AMR and freshness requirements through to validation. An unbound
grant can also satisfy the gate's device check. Do not describe this path as strict
per-user, per-device, per-destination authorization with every form field enforced.

The broker requests `acr_values`; it does not implement provider-specific claims
challenges or a `max_age`/`prompt` freshness round-trip here. Provider labels and
the Console's strength presets do not overcome these limits. Check the actual
claims and negative cases on the exact deployed path before relying on assurance.

Pending browser authentication state is process-local and expires after ten
minutes. A restart or a callback reaching a different process can require a fresh
attempt. The broker's federated grant has a default lifetime of eight hours;
this is distinct from the East-West challenge/grant API's lifetimes.

## Review and revoke access approvals

Open **Access Approvals** inside the customer organization. **Active** shows
unexpired approvals; **All (incl. revoked/expired)** includes history. Search by
person, email, device, destination or provider. The table includes captured
identity, binding, scope, assurance, sign-in method and validity. These are recorded
claims, not proof that every flow-policy requirement listed above is enforced.
An invalid or missing expiry is **Unknown expiry**, never Active. Failed or
malformed required reads show **Retry** instead of an empty list.

The page lists and revokes approvals; it has no manual creation or editing form.
**Revoke** asks for confirmation. Cancel sends no revocation request. The API
checks the exact tenant and grant together before applying the denial. Repeated
requests while a confirmation or write is pending are suppressed in the page.

If storage fails, the API returns HTTP 500 with `status: partial`, `applied: true`
and `persistence: unconfirmed`. The grant remains revoked in this server's memory,
but a restart can restore the older saved grant. Restore the storage service and
use **Retry saving revocation** before restarting. That retry saves an already
revoked grant again. A lost response has an unknown outcome; check the approval
and use **Retry revocation**. Warnings are held only in the current page and do not
survive navigation or a browser reload. A normal response confirms local acceptance;
it does not prove that all serving nodes received the revocation.

**Logs & Audit** records `admin_access_grant_revoked` with result `revoked` or
`partial`, the acting administrator, tenant, time and a SHA-256 grant reference.
The common administrative write record retains the HTTP result and the same
reference. Grant IDs also serve as bearer-cookie values: the revocation route is
redacted in common, operator and break-glass audit records. Do not paste the ID
into tickets or public diagnostics. Existing audit records are not rewritten.

A configured successful persister is needed for restart retention. In-memory
operation and saved-without-atomicity fallbacks are not full durability guarantees.
Other mutation and distribution paths still need validation: reminting an existing
ID or merging an active copy can currently overwrite a revocation, and those paths
retain best-effort saving. Do not treat this page's local acceptance as a verified
fleet-wide denial. Concurrent writers, real IdP sign-in, independent nodes and
existing connections require separate testing.

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
