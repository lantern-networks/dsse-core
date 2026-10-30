# Admin Console

The Console is a separate application served by `dsse-console`. It uses the control
plane's admin API over TLS and provides administrator sign-in, MFA, and organization-scoped
management. Edges enforce the resulting configuration.

## Start and sign in

The installer generates the Console service with the rest of the deployment. Follow
[Deployment](../docs/deployment.md), then [First use](../docs/after-verify.md).
Open the generated `https://console.<region>.<deployment>/console.html` URL after installing
the deployment trust anchor on the administrator's machine. Use the named administrator
created by `dsse-install -bootstrap-admin`, including its second factor.

Do not substitute a plain static-file server for this deployment: it omits the Console
server's authentication and routing behavior. Do not accept a browser certificate exception
as proof that the Console belongs to the intended deployment.

## Build

Build the image from the repository root using [Building](../docs/building.md).
Its assets are included in `dsse-console:release`; rebuild that image when changing them.

The interface supports English and Japanese. The tenant context displayed in the header
selects the organization being administered. See [Organizations](../docs/organizations.md)
for the first customer setup and [Agent updates](../docs/agent-updates.md) for package publication.

## TLS and origins

Use the generated deployment names and configuration. Browser API requests need both a
trusted TLS chain and the configured Console origin. If a request is blocked, check the
certificate, the API destination, and the allowed origin; do not disable these checks.
Third-party browser assets are documented in [vendor/README.md](vendor/README.md).

## Follow the active control plane

On ordinary browser navigation (`/`, `/index.html`, `/console.html`), each Console
verifies the declared CPs' direct private HTTPS `/leader` endpoints using the
deployment CA and exact TLS names. Exactly one CP must confirm leadership.
If the request has already reached the Console on that CP, it stays on the
requested origin, including another regional or shared Console name. HAProxy
already sends those names to the active Console. Keeping that reachable entrance
allows management access when the active CP's own public entrance is down but
the CP and its Console remain healthy.

Only a standby Console redirects navigation to the active CP's configured Console
origin. The target is never taken from a query, forwarded header or CP response.
The move uses a temporary, noncached HTTP 302. The existing server-side
authentication gate applies both when staying on an origin and after a redirect.

Sessions are host-only cookies. A different Console hostname may therefore require
sign-in again; cookies, bearer tokens, query parameters and fragments are not
transferred. Activation links, OIDC callbacks, API calls, form submissions and
subresource requests remain on their original origin. An open edit form is not
moved in the background. Reloading the Console checks leadership again.

If no unique leader is verified, or a leadership change would create a redirect
loop, the page returns 503 with a same-origin retry link. `/ready` retains its
local-CP readiness semantics for HAProxy. In a one-Region three-node deployment,
the existing regional Console name is shared; HAProxy routes it to the active
node rather than inventing a new public hostname for each CP.

The installer writes `DSSE_CONSOLE_LEADER_ROUTING` into each CP host's environment
and passes it into `dsse-console` through Compose. Apply the complete reviewed plan
on the affected hosts and recreate the Console service after upgrading its image.
Allow Console-to-CP private TCP 19543 between the declared nodes. Use direct CP
addresses for probes, never leader-aware public front doors. Console TLS chains
must cover every public Console name that the L4 can deliver to that backend.
An unset routing value preserves legacy behavior; invalid nonempty configuration
refuses startup. For manually managed deployments its JSON shape is:

```json
{
  "local_node": "cp-a",
  "candidates": [
    {
      "node": "cp-a",
      "leader_url": "https://10.20.0.10:19543/leader",
      "tls_name": "admin.region-a.example.test",
      "console_origin": "https://console.region-a.example.test"
    },
    {
      "node": "cp-b",
      "leader_url": "https://10.21.0.10:19543/leader",
      "tls_name": "admin.region-b.example.test",
      "console_origin": "https://console.region-b.example.test"
    },
    {
      "node": "cp-c",
      "leader_url": "https://10.22.0.10:19543/leader",
      "tls_name": "admin.region-c.example.test",
      "console_origin": "https://console.region-c.example.test"
    }
  ]
}
```

Replace the example with the **complete** declared CP set and the correct local
node on each host. All destinations must be approved deployment HTTPS origins;
no request credential is sent on a leader probe. Navigation bursts share a
one-second discovery cache, and probes share a two-second total timeout. This
is navigation assistance, not leadership election or a substitute for CP write
fencing. A stopped entrance cannot send a browser redirect; enter through a
reachable, trusted deployment Console name. A shared name must resolve to a
surviving entrance. Before accepting the deployment, stop only the active CP
host's public HAProxy, leave the CP leader running, and check sign-in and an
authorized revocation through both other entrances and the shared name. Keep
host-only sessions and verify that a write is neither redirected nor replayed.
