# Independent deployment CRL publication

Deployment certificates can encode multiple issuer-bound HTTP CRL distribution
points (CDPs). The deployment signer runs only on the founding control-plane
host. A second failure domain may publish copies of the same signed DER, so an
endpoint can obtain current revocation status when that host is unavailable.
This is publication redundancy, not a second signing authority. A revoked
certificate cannot appear in the replica until the signer issues a new CRL and
the replica fetches it.

Plan both public HTTP origins **before issuing any deployment certificate**.
CDPs are part of the signed certificate and cannot be added later. Route one
origin to the founding host's keyless publisher and the other to a keyless
publisher on an independent host. The latter may share an already planned IdP
fixture host; it needs its own HTTP name and port-80 route. It must not reuse a
Portal TLS origin or introduce an HTTP redirect. The publisher's Host check
must list precisely the origin encoded in the certificates.

Prepare a private replica working directory containing only these public CA
certificates, copied from the **same issued deployment**:

```text
root.crt
management-ca.crt
console-server-ca.crt       # if this issuer is present in the deployment
transport-ca.crt
device-ca.crt
lantern_dsse_interception_root_ca.pem
deployment-crl/             # writable by the replica updater; no key or ledger
```

Never copy `authority/`, `.key` files, or the revocation ledger to this host.
Keep the certificate files read-only and pin their fingerprints as part of the
deployment inventory. The replica validates every issuing CA against the local
root and fetches every issuer's signed DER through the declared signer origin.
It refuses invalid signatures, issuer identities, missing or near-expired
status, lower CRL numbers, same-number changes, and removal of known
revocations. It fetches and validates the complete set before writing any
file; a publication marker makes the keyless HTTP handler return 503 during an
interrupted update. Failed network fetches leave the last complete publication
in place until it expires.

With `dsse-deployment-crl` installed on the replica host, generate its Linux
systemd units from the public-only directory. The output directory must be
private and outside that public directory. The source origin is the signing
host's **public HTTP CRL origin**, not a private-key or management endpoint.
The replica origin is the **other** CDP origin encoded in every issuing CA.

```sh
sudo /usr/local/bin/dsse-deployment-crl -dir /var/lib/dsse-crl-replica -mode replica-units \
  -source-origin http://signer-crl.example.test \
  -replica-origin http://replica-crl.example.test \
  -units-dir /root/dsse-crl-replica-units
sudo /root/dsse-crl-replica-units/install-deployment-crl-replica-services.sh
```

The activation script creates a dedicated unprivileged account, verifies its
access to only the public certificates, obtains all CRLs, checks freshness,
and only then enables the HTTP service. It also enables a supervised ten-minute
replication timer. The updater has write access only to `deployment-crl/`;
the HTTP service has no writable path. If first replication fails, the
publisher is not enabled. Re-running activation with a valid existing replica
is safe. On non-systemd hosts, equivalent supervised services can use these
commands:

```sh
dsse-deployment-crl -dir /var/lib/dsse-crl-replica -mode replicate \
  -source-origin http://signer-crl.example.test
dsse-deployment-crl -dir /var/lib/dsse-crl-replica -mode replica-ready
dsse-deployment-crl -dir /var/lib/dsse-crl-replica -mode serve \
  -origins http://replica-crl.example.test -listen 127.0.0.1:18081
```

The signer renews hourly; the ten-minute replica interval and two-hour minimum
remaining lifetime give a bounded propagation window while leaving time for
incident response. The public frontend must expose the
replica's loopback handler at the **exact** HTTP host and path in each CDP.
Only the signed CRL route should be reachable there. Protect the replica's
write directory from other processes; a symlinked public directory or CRL
file is rejected.

Before admitting clients, fetch every encoded CDP from outside the signer host
and verify the returned DER is identical, signed by the expected issuer and
fresh. Then stop the signer host and repeat an actual endpoint Online
revocation check against the replica. Keep it stopped only long enough to
measure the outage path. Do not infer Windows behavior from a successful Linux
HTTP probe: Windows must pass its own strict Online test without a Soft-Fail
setting. The imported Browser Portal and external IdP certificate chains use
their issuers' separate OCSP or CDP services and need independent checks.
