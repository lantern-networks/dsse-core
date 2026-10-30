# Changes since 0.3.1

This summarizes what changed; it does not claim that every acceptance item passed. See [Acceptance and limitations](verification.md).
The baseline is the published `v0.3.1-experimental` source and its actual artifacts.

| Area | 0.4.0 change and operational consequence |
|---|---|
| Topology | Existing one-Region/three-combined-node transport distribution; three-Region layout with one dedicated CP+HAProxy and two dedicated Edge hosts per Region, nine product hosts in total. A separate single-entrance/two-Edge profile was used for authentication evaluation and does not replace the three-node topology |
| Entrances | Three independent entrances shared across tenants. In one Region each entrance distributes browser, endpoint and Connector traffic to all three combined-node Edges; in three Regions each entrance uses only its own Region's dedicated Edges. The three-Region profile was installed from the released images with real endpoints; a one-Region installation from the released images remains open. Authentication grants and revocation remain shared across the six-Edge deployment |
| Browser authentication | Native agents open the OS default browser. The Portal displays the destination and requires confirmation before redirecting to the configured OIDC provider. DSSE does not put third-party provider sign-in inside its embedded WebView |
| Browser-start compatibility | Explicit shared-fleet mode requires a signed endpoint-bound request. Anonymous or process-local clientless starts used in older deployments return 401; an upgraded binary with only the historical origin trust list retains the owner-pinned migration path |
| Admin Console | Navigation verifies the active CP. Requests already on its Console retain their reachable entrance; a standby Console redirects to a configured active Console origin. Writes and authentication parameters are not replayed; another hostname may require sign-in again |
| Native applications | Authenticated steering supports pending non-Web TCP requests. Resumption rechecks current policy and authorization. A timed-out application may need to reconnect; authentication success alone does not prove socket resumption |
| Identity | Grants bind tenant, device, originating OS user/login incarnation, IdP issuer/subject, destination, assurance and freshness. Each grant authorizes only the destination that triggered it. Administrator assignment and fleet capability activation are required for device-user enforcement |
| Authentication reuse | Other Edges/Regions can reuse a shared evidence-backed grant only for that same destination and when its remaining conditions match. `max_age=0` authorizes only its specific pending request. Policy lifetime, actual IdP authentication age and pending-link expiry are separate |
| Revocation | Shared revocation blocks reuse; administrator-requested fresh verification cannot be satisfied by silently reusing the old IdP authentication. Propagation is measured and bounded by refresh behavior, not instantaneous or an atomic fleet-wide acknowledgment |
| Pending sign-in | Capability-gated encrypted ceremony recovery and atomic completion support another healthy Edge behind the same Portal origin. Established sockets do not migrate to a replacement process |
| Localization | DSSE Portal destination-confirmation, completion and error pages support Japanese and English. IdP interface language is managed separately |
| Routing | Endpoint/Connector health checks select another authorized entrance, in the same or another authorized Region, after an entrance fails. Regional IP takeover is not a universal requirement. IPv6 data traffic requires working IPv6 egress on every participating Edge |
| Resource settings | Pure data connection/byte/lifetime quotas are configurable without arbitrary replacement defaults. Agent mux behavior remains unchanged. Authentication/replay protection and other security admission defaults remain enabled; review each setting's scope |
| Audit storage | Bundled MinIO is removed. A fresh deployment may retain audit history in the local persistent hot store without S3, or configure an operator-managed external S3 archive. Local-only mode has no S3 Object Lock or cold-archive verification; archive-enabled mode requires separate bucket and credential provisioning |
| Dependencies and data layer | Spilo/PostgreSQL 16 (`3.2-p2`) changes to source-built Spilo with PostgreSQL 18.6 and Patroni 4.1.5; etcd 3.5.15 changes to source-built 3.7.2; ClickHouse 24 changes to 26.8.36.3; HAProxy 2.9 changes to 3.4.7. The released images ran the three-Region acceptance installation; database failover, backup/restore and migration from 0.3.1 remain open |
| Security boundary | Fleet configuration/grant distribution is restricted to authorized deployment authorities. Tenant administration APIs remain tenant-scoped. 0.4.0 acceptance covers fresh installations only; 0.3.1 upgrades are outside this release's supported path |
| Compatibility | Capability negotiation accommodates old Connector TCP limits. Authentication storage/evidence and rollout membership require a coordinated migration; a new binary alone does not activate all features |
| Process command line | Generated control-plane, Edge and archive-publisher launch scripts pass secrets through environment variables named by `-secret-env`, so `ps` and `/proc/<pid>/cmdline` no longer show the admin token, PostgreSQL DSN, ClickHouse password or other secret flags. See [Deployment](../../deployment.md#secrets-and-the-process-command-line) |
| Origin TLS | Inspected HTTPS now offers the TLS 1.2 cipher suites Chrome offers by default, adding four static-RSA suites to Go's defaults, so sites that open in Chrome also open through DSSE. An organization can choose **Strict** to keep ECDHE-only key exchange. See [Upstream TLS compatibility](../../upstream-tls.md) |
| Log search errors | When the hot store cannot be reached, log search, export and other admin routes answer `503 log store unavailable`, or `502 log store request failed` when ClickHouse returns an error. The response no longer repeats the store address, the query or the search terms; the detail goes to the server log. `GET /admin/hot-store/health` returns only `status` to an organization's administrator; its deployment-wide counters and last error, which name internal hosts, are for deployment-wide administration |
| Abandoned endpoint flows | An Edge flow with no traffic in either direction for 180 seconds is closed by default again (`DSSE_NE_TUNNEL_IDLE_TIMEOUT_SECONDS`). Making performance quotas opt-in had removed this bound; because the Windows agent does not tell the Edge when an application closes a connection, and macOS flows also stayed open, abandoned flows then accumulated on Edges and endpoints without limit. See [Operator resource quotas](../../runtime-resource-quotas.md#resource-protection-defaults) |
| Windows uninstall and recovery | On a PC with many firewall rules, listing them took longer than the 15-second limit, so recovery reported a problem and uninstall ended with MSI error 1603. Cleanup now lists the rules a second time only after deleting one, under a single two-minute guard that stops only a hung PowerShell |

Details: [Topology](../../three-regions-multi-edge.md),
[one-region evaluation](../../one-region-multi-edge.md),
[device-user authentication](../../device-user-authentication.md),
[authentication upgrades](../../authentication-rolling-upgrades.md),
[resource settings](../../runtime-resource-quotas.md).

Keycloak password and Passkey ceremonies have been exercised with a real browser.
That is not certification of direct Google Workspace, Okta or Microsoft Entra ID,
every assurance combination, SMB user attribution, every operating system version,
or production capacity. See [the acceptance record](verification.md).
