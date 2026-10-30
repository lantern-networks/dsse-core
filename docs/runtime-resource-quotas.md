# Operator resource quotas

DSSE does not impose an unconfigured active-connection count, per-flow byte
budget, or established TCP session lifetime. Unset and `0` disable the data-plane
quotas below. Positive values are operator choices, not replacement default
ceilings. This policy does not disable security admission controls on
unauthenticated or authentication paths.
Physical memory, CPU, file descriptors, backend capacity, and protocol number
representations still determine achievable capacity. No unlimited throughput is
promised.

## Server settings

Set these variables in the environment of the actual service, for example in a
systemd override or the service's Compose `environment` override, then restart
that service. These are host resource settings, not access authorization rules.
Values must be non-negative; malformed, negative, non-finite, or
unrepresentable values are rejected at service startup, before traffic is
accepted, instead of selecting a hidden default or crashing on the first flow.

| Setting | Applies to | Unit and scope |
| --- | --- | --- |
| `DSSE_CONNECTOR_MAX_TCP_CONNECTIONS` | Connector | Connections across the entire process: pending dials, all Edge attachments, and private TCP round trips |
| `DSSE_TCP_STREAM_MAX_BYTES` | Edge stream sender | Combined upstream/downstream bytes per Connector TCP flow |
| `DSSE_TCP_STREAM_MAX_LIFETIME_SECONDS` | Edge stream sender | Lifetime per Connector TCP flow |
| `DSSE_TCP_STREAM_IDLE_TIMEOUT_SECONDS` | Edge stream sender | Idle time per Connector TCP flow |
| `DSSE_NE_MAX_SESSIONS` | Edge runtime-copy session API | Active sessions per runtime-copy handler |
| `DSSE_NE_SESSION_IDLE_TIMEOUT_SECONDS` | Edge runtime-copy session API | Idle time per session |
| `DSSE_NE_TUNNEL_IDLE_TIMEOUT_SECONDS` | Edge raw runtime-copy tunnel | Idle time with no traffic in either direction |
| `DSSE_SWG_MAX_CONNECTIONS_PER_HOST` | Edge HTTP egress | Active connections per destination host in each transport |
| `DSSE_HTTP2_MAX_CONCURRENT_STREAMS` | Edge, interception, broker | Streams per accepted HTTP/2 connection |
| `DSSE_HTTP_IDLE_TIMEOUT_SECONDS` | Edge, Console, interception | Idle established HTTP connection time |
| `CONSOLE_MAX_CONNECTIONS` | Console | Connections per Console process |
| `DSSE_EGRESS_MAX_CONNECTIONS_PER_ENGINE` | libcurl egress | Active connections per engine; an explicit positive value queues excess transfers |

HTTP/2 encodes its stream count as `uint32`. An omitted setting preserves the
previous per-connection defaults: 250 in the interception engine and 10000 in
the network-extension interception and broker paths. An explicitly configured
`0` advertises the protocol representation maximum. These admission controls
are independent of the agent's multiplexing pool, which is unchanged.
The same HTTP/2 setting also bounds the underlying HTTP/2 handler/queue admission
used for Rapid Reset resistance. Explicit `0` disables that effective bound; it
is a security tradeoff, not an ordinary performance tuning recommendation.

`DSSE_EGRESS_ENGINE_WORKERS` optionally selects a positive number of libcurl
event loops. Unset/0 uses `GOMAXPROCS`; it is resource-derived execution
parallelism, not a fixed total connection quota. The libcurl active connection
quota and its unused connection cache are separate settings. See the official
[active connection](https://curl.se/libcurl/c/CURLMOPT_MAX_TOTAL_CONNECTIONS.html)
and [idle cache](https://curl.se/libcurl/c/CURLMOPT_MAXCONNECTS.html) documentation.

The Connector's private health endpoint reports `tcp_admission.active` and
`tcp_admission.max_connections`. A positive quota includes in-flight dials so
parallel opens cannot overbook it. Rejection preserves existing connections.
Failed dials, closed streams, and lost transports release reservations and
underlying sockets. Each process has its own budget; this is not a fleet quota.

## Security admission is separate

The public, unauthenticated enrollment endpoint retains its existing protection
of 5 requests per second with a burst of 20 per actual source IP, per process.
It bounds attacker-controlled CSR processing. This is not a data-plane throughput
quota. `DSSE_ENROL_REQUESTS_PER_SECOND` can explicitly select another rate;
`0` explicitly disables that limiter. An omitted rate retains the protection.
With an explicit positive rate, an omitted burst derives from that rate, with
room for at least one whole request. `DSSE_ENROL_BURST` selects a burst directly;
`0` derives one from the enabled rate. Certificate-authenticated renewal is
separate and does not inherit this bootstrap limiter.

Authentication start rates, anonymous/pending/retained request budgets, waiting
flow reservations, result retention capacity, and native browser request lists
retain their existing bounds. Their role in abuse resistance, ownership and
replay-state protection must be reviewed before changing them. Do not treat
every count or timer as an artificial performance quota. Link expiry, fresh
verification, authorization and replay validation remain mandatory.

Public Console connection admission retains its default of 4096 unless
`CONSOLE_MAX_CONNECTIONS` is explicitly configured. Hardened Edge/Admin HTTP,
Console HTTP and the interception engine retain their 120-second idle timeout
unless `DSSE_HTTP_IDLE_TIMEOUT_SECONDS` is explicitly configured. Their existing
header parsing deadlines remain enforced. An explicit `0` disables the relevant
admission/idle protection; omission does not. The network-extension HTTP/2 path
had no such idle default and retains that behavior. These are protection/workload
tradeoffs requiring individual review, not proof that every inherited numeric
value is optimal.

## Generated HAProxy configuration

Set `DSSE_HAPROXY_MAX_CONNECTIONS` and/or
`DSSE_HAPROXY_SESSION_IDLE_TIMEOUT_SECONDS` **when running the installer**.
Positive values are rendered into the configuration. With unset/0, DSSE omits
`maxconn` and disables established client/server/tunnel idle expiry. HAProxy
derives its inherent capacity from OS descriptor and memory resources; omission
does not remove those physical limits. See [HAProxy's configuration
manual](https://docs.haproxy.org/2.9/configuration.html#maxconn).

Generated Compose services inherit the platform hard descriptor limit and raise
its soft limit to that hard limit before starting HAProxy. No new DSSE numeric
`nofile` ceiling is introduced. Operators may explicitly select their own
`ulimits` in a Compose override. TCP keepalive is enabled on client and server
sides to detect vanished peers independently of healthy-session idle policy.
The actual probe interval is the host kernel's keepalive configuration.

At startup, the generated entrypoint passes HAProxy `-m` the lesser of Linux
`MemAvailable` and remaining cgroup memory, rounded down to MiB. HAProxy uses its
own connection/buffer/SSL memory model to compute capacity; DSSE does not guess
bytes per descriptor or introduce a fixed connection count. This is a startup
budget, not a memory reservation: other workloads can subsequently consume
memory. Missing memory information or less than one MiB available rejects startup.

The generated config has a private, mode-0600 Unix stats socket. On the Linux
Docker host, run `sudo dsse-install -verify-proxy-resources -dir /path/to/deployment`
to report each owned running proxy's version, actual `Maxconn`, and kernel soft/
hard `nofile` values and HAProxy's effective memory budget. The stats socket has
read-only `user` privilege. Docker, `/proc/PID/root` and socket read permission are
required. An unavailable measurement is an error, not an inferred success.
`Maxconn` is HAProxy's computed admission capacity, not a throughput benchmark.
A small platform hard limit remains small and must be changed by the operator.

Existing configurations preserved by the installer are not silently rewritten:
update both the config and Compose startup wrapper before claiming these
settings are effective. The verification command is read-only and does not
regenerate authorities or modify a deployment.

## macOS endpoint settings

The host administrator may create
`/Library/Application Support/Dsse/performance-limits.json`:

```json
{
  "max_concurrent_connections": 0,
  "max_bytes_per_flow": 0,
  "idle_timeout_seconds": 0,
  "max_session_exchanges_per_flow": 0
}
```

An absent file or omitted field disables that quota. Positive integer values
apply respectively to the live-copy registry, each flow's combined bytes, idle
time, and the legacy session-exchange path. The file must be root-owned, regular,
not a symlink, and not group/world-writable. Unknown fields and invalid values
are rejected. Restart the network extension to load a changed file. This does
not change the adaptive mux pool or its existing tuning.

Existing optional `DSSE_NE_FLOW_IDLE_REAP_SECONDS` and
`DSSE_NE_HIGH_LOAD_IDLE_REAP_SECONDS` overrides remain available. Their default
idle reapers are disabled; an administrator's positive override enables one.

On Windows, targeted redirect mode's `--max-flows` defaults to `0`. An explicitly
positive value still stops after that many flows. Continuous whole-device
`--steer-all` already runs without this stop count. Windows mux pool tuning is
unchanged.

## Upgrade and retained protections

The authenticated Connector/mesh WebSocket upgrade negotiates
`X-Dsse-TCP-Quotas: operator-v1` independently for each peer. Only a peer advertising
this capability receives zero (unconfigured) or extended TCP byte/time metadata.
For an absent/unknown capability, the sender projects the wire values into the
released receiver's own limits: 1 GiB bytes, at most one hour lifetime and five
minutes idle when configured positive. Stricter operator settings remain intact.
Old peers still impose their old 32/1024 connection bounds. Upgrade those peers
to remove their inherited bounds; an upgraded fleet has no such default data
quota. Both directions of old/new Edge and Connector interoperability are
covered by an opt-in actual-executable integration test. The legacy
`concurrent_connection_cap` wire field remains an interoperability hint; updated
receivers do not treat a sender's hint as operator admission policy. Existing
explicit service environments, configuration files, and older installed
endpoint binaries remain effective until replaced or changed.

TLS, signatures, route/tenant authorization, revocation, authentication age,
one-request grants, link expiry, frame and header parsing bounds remain
enforced. So do backpressure, finite **unused** cache retention, peer-liveness
checks, connection-establishment deadlines, and cleanup after peer EOF/RST.
These do not cap a healthy established flow's total bytes or lifetime. Storage
retention and explicit commercial or access policies are separate controls;
removing a performance quota does not disable authorization.


## Abandoned half-close cleanup and revocation storage

`DSSE_NE_ABANDONED_HALF_CLOSE_LINGER_MILLISECONDS` separates orphan cleanup from
healthy TCP idle policy. Omission preserves the previous 22,500 ms cleanup
window (the old 180-second idle default divided by eight). Explicit `0` disables
this cleanup; positive values select a window. It reclaims a zero-byte half-closed
flow with no reverse progress. A request that sent data may still await a delayed
reply, and active traffic is not subject to this orphan timer. Caller cancellation
also closes both bridge endpoints. The existing interactive east-west linger is
unchanged.

`DSSE_REAUTHENTICATION_FENCE_COMPACTION_THRESHOLD` preserves the existing default
4096 per tenant. This is a **compaction threshold, never a revocation rejection
limit**. Above it, a stricter tenant-wide freshness boundary consolidates narrow
boundaries. Smaller values cause broader reauthentication more often. Explicit
`0` disables broadening compaction, increasing retained storage; it does not
expire, discard or bypass revocations. Use consistent values across authority
writers. After the independent 15-minute ceremony/replay retention horizon,
expired denial records discard personal display claims and spent request payload,
while preserving selectors, cutoff, protected format and unknown future evidence.

Snapshot writers are serialized independently from authorization readers. New
allows are published only after persistence; failed/ambiguous denials remain
locally latched. Encoding and persistence I/O do not hold the authorization
read lock. Complete file/SQL snapshots and fleet distribution still scale with
total retained rows: this change does not provide row-level SQL storage or delta
distribution, and their cost must be included in capacity planning.

Shared authorization reads start one background snapshot refresh halfway through
the existing five-second freshness window. Load/decode run outside the writer
and authorization locks. An unchanged authority digest avoids repeat decoding;
a concurrent local mutation or persistence rebind discards an obsolete refresh.
Reads use confirmed published state only while it remains fresh, and immediately
fail closed on a failed refresh or at five seconds, rather than waiting for SQL
or using indefinitely stale revocation information. A refresh's age starts before
I/O. If a large snapshot cannot refresh inside that window, availability can
suffer; this does not claim to solve full-snapshot storage throughput. Explicit
checked administration may still wait for its synchronous refresh.

## Connector liveness and Region movement

Connector `-heartbeat-interval` and `-heartbeat-timeout` both default to `5s`
and must be positive durations. They bound the small authenticated health
exchange and runtime re-registration, independently of data-stream idle/lifetime quotas. Three consecutive
failures are still required. Detection normally takes up to about 20 seconds;
registration, fleet attachment and route propagation add to end-to-end recovery.
Other management calls and identity enrollment retain their 30-second budget, and an explicitly shorter
HTTP client deadline is preserved. A responding authorization refusal triggers
re-registration, rather than treating it as an unreachable Region.

Each heartbeat, registration and primary-tunnel verdict carries the selected
entrance and a local selection revision. A late verdict cannot advance a new
selection, including a return to the same URL. Failback no longer leaves a global
self-close flag that can suppress the next genuine outage. A cross-Region move
closes held old-Region tunnels; a move between entrances in the same named Region
continues to preserve surviving Edge attachments.
