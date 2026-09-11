# Getting started

This optional quickstart builds one Edge and queries its policy API over loopback HTTPS.
It is **not a deployment**: it uses local fixture files and disables deployment requirements
with `-lab-mode`. To install DSSE with the Console and endpoint enrolment, use
[Deployment](deployment.md) and `dsse-install`.

## Prerequisites and build

Use a Unix shell, Git, Go 1.26 or newer, curl, and OpenSSL with `req -addext` support.
Port 18443 must be free. The commands start from a new checkout of the **public repository**:

```sh
git clone https://github.com/lantern-networks/dsse-core.git
cd dsse-core
go build -o dsse-edge ./cmd/dsse-edge
umask 077
```

Keep this directory open in a second terminal for the API requests. All paths below are
relative to it. Save the two JSON blocks under the filenames shown.

## A certificate for it to serve

The Edge is HTTPS-only. For a local look, a self-signed certificate is enough — name both the hostname and
the address, because you will reach it by one and the certificate must carry the other:

```sh
openssl req -x509 -newkey rsa:2048 -nodes -keyout tls.key -out tls.crt -days 365 \
  -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
```

## A policy, and a bundle that names it

Two files, and the second one is the one that is easy to skip.

`policy.json` — one rule:

```json
{
  "id": "pol-allow-users",
  "tenant_id": "acme",
  "name": "allow humans",
  "priority": 100,
  "status": "active",
  "conditions": { "actor_type": "human" },
  "action": { "decision": "allow" }
}
```

`bundle.json` — the active bundle for this local process (the checksum and signature are
mock fixture values, not a signed deployment configuration):

```json
{
  "id": "pb-getting-started",
  "tenant_id": "acme",
  "version": "1",
  "policy_schema_version": "2026.05.22",
  "checksum": "sha256:mock-checksum",
  "signature": "mock-signature",
  "signing_key_id": "mock-local-signing-key",
  "target_scope": { "target_type": "local_edge", "edge_region_id": "region-a", "edge_cluster_id": "local-edge-001" },
  "policy_ids": ["pol-allow-users"],
  "compiled_policy_ref": "policy.json",
  "bundle_type": "standard",
  "created_at": "2026-01-01T00:00:00Z",
  "expires_at": "2036-01-01T00:00:00Z",
  "status": "active"
}
```

**A policy the bundle does not name is carried and enforced by nothing.** It will load, it will appear in the
admin API, it will say `active`, and every request will be denied. The bundle is the list of what is in force.

**`actor_type` is `human`, not `user`.** The actor type is derived at the trust boundary and never taken from
the caller — a client must not be able to name its own — so it is `human` on every request that has not been
attributed to a machine identity. A rule written for any other value cannot match anything. If you write one
anyway, the refusal now tells you: *the closest rule is "…", and it requires actor_type="user" (this request
has "human")*.

## Run it

```sh
./dsse-edge \
  -listen 127.0.0.1:18443 \
  -tls-cert tls.crt -tls-key tls.key \
  -policy ./policy.json -bundle ./bundle.json -schema-dir ./schemas \
  -admin-token labtoken -admin-token-break-glass-armed \
  -edge-region-id region-a -log-dir ./var/logs \
  -no-control-plane -lab-mode
```

It prints:

```
listening (HTTPS, hot-reloadable cert) on 127.0.0.1:18443
```

Four of those flags are worth understanding rather than copying.

**`-schema-dir ./schemas`** — the default is a path inside a source checkout, so a binary you moved somewhere
else cannot find it. Point it at the `schemas/` directory of this repository.

**`-no-control-plane`** — an Edge refuses to start without one, deliberately: config, admission and revocation
are authored on a control plane, and an Edge holding its own truth drifts from the fleet while reporting
itself healthy. This flag says "this is a single-process look, not a deployment", and the Edge says so in its
log for as long as it runs.

**`-lab-mode`** — supplies the production requirements this single process is not going to meet. Without it
the Edge refuses to start and lists all of them at once: a connector secret changed from the default and at
least 32 characters, an admin token at least 32 characters, connector runtime secrets required, a workload
attestation secret, and a nonce store. Every one of those is a real requirement of running outside lab-mode;
none of them belongs in a first look.

**`-admin-token-break-glass-armed`** — a token that is set but not armed authenticates nothing. The Edge warns
about it at startup, and the admin API answers 401 until it is armed. On a real deployment you would not use
this at all: you would bootstrap a named administrator and close the break-glass — see
[deployment.md](deployment.md).

## Ask it something

```sh
curl --cacert tls.crt https://localhost:18443/healthz
```

It answers a JSON document rather than `ok` — the region it believes it is in, whether it holds a database,
where its logs go and whether they are durable, and which address families it can egress on. On a first run
the useful line is `"status":"ok"`.

A decision:

```sh
curl --cacert tls.crt -X POST https://localhost:18443/decisions/evaluate \
  -H 'Content-Type: application/json' -d '{"tenant_id":"acme"}'
```

```json
{ "decision": "allow", "reason": "Request matched the active lab policy." }
```

And the admin API, which is how policy is read and written on a running node:

```sh
curl --cacert tls.crt https://localhost:18443/admin/policies -H 'Authorization: Bearer labtoken'   # 200
curl --cacert tls.crt https://localhost:18443/admin/policies                                        # 401
```

## Stop the quickstart

Press **Ctrl-C** in the terminal running `dsse-edge`. The generated certificate, key, JSON
files, binary, and `var/logs/` remain in this checkout; do not commit the generated files.
The loopback certificate has not been installed into an OS trust store.

## What this is not

This is one process with local files as its only source of truth. It has no control plane, so nothing is
authored anywhere else and nothing is revoked; no organization has its own authorities, so nothing is
inspected under a customer's own interception CA; and `-lab-mode` has switched off requirements that exist for
good reasons.

The next page is [deployment.md](deployment.md), which mints a real deployment with `dsse-install` — its
authorities, its control plane, its regions — and [macos-agent.md](macos-agent.md) or
[windows-agent.md](windows-agent.md) for putting a device on it.
