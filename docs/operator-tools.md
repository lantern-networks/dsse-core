# The tools a deployment ships with

Five programs beside the ones that run: they answer questions about material you are holding, before it
reaches a machine where being wrong is expensive. Run them from the public repository or build them as shown below.

They are built the same way as everything else:

```sh
mkdir -p bin
go build -o bin/dsse-profileverify ./cmd/dsse-profileverify
export PATH="$PWD/bin:$PATH"
```

## `dsse-profileverify` — what does this profile actually say, and was it signed by us?

The device lane hands over a signed install profile and a pin. The profile is a base64 envelope, so the only
way to read it without this is to decode it by hand — and decoding it tells you nothing about whether it is
genuine.

```sh
dsse-profileverify -profile install_profile.json -pin profile_signing_key.txt
```

It verifies the signature against the pin and then answers in two places at once. On **stderr**, what the
device would join, in the order a person checks it:

```
dsse-profileverify: signed by the pinned key. This is what the device would join.
  organization               tenant_…
  posture                    fail-closed
  transport                  https://agents.<region>.<deployment>
  this organization's door   ….<deployment>
  enrolment door             enrol.….<deployment>
  interception root          this organization's own
  device CA pin              02915d60…92fcec
```

On **stdout**, the verified payload as JSON — the whole of it, including the deployment anchor, the steer
exclusions and the update-signing keys. The split is deliberate: the macOS package's postinstall pipes stdout
straight into the derivation, so a person gets the summary and a pipeline gets what it always got.

**Run it before installing anything, not after.** The summary can catch configuration problems before installation — the organization is wrong, no interception root is carried, the exclusions are somebody else's.

When it refuses, it names both possibilities rather than guessing:

```
the envelope says it was signed by key id "edge-agent-policy-…", and it was checked against
pinned public key 5851e1bb65…429443. Two different faults produce this: if that pin is NOT the
anchor this device provisioned with, the document may be perfectly good and the VERIFIER is
wrong; if it IS the right anchor, then this document was not signed by that authority and
must not be applied
```

**One profile-signing key serves the whole deployment, not one per organization.** Profiles are signed by the
deployment's authority; the organization is a field *inside* the signed payload. So the same pin verifies
every organization's profile, and a pin from organization A verifying organization B's profile is correct
rather than a leak. What separates the organizations is further in — their own device CA, transport authority
and interception authority, all of which this tool prints.

## `dsse-keycheck` — would a device accept this public key?

```sh
dsse-keycheck -agent-policy-key <hex>
```

```
dsse-keycheck: accepted (64 hex chars)
```

and, for something that would have shipped and then been refused at runtime:

```
dsse-keycheck: REJECTED (9 hex chars). A device accepts either a 64-char Ed25519 key or a
130-char uncompressed ECDSA-P256 point that is actually ON the curve — the length being right
is not enough, and this value would be refused at runtime after shipping.
```

Exit status is 0 for accepted and 1 for rejected, so it belongs in a build. The point of it is the last
clause: a key of the right length that is not a point on the curve looks correct everywhere except on the
device that has to verify with it.

## `dsse-signupdate` — the authority to run code on the fleet

An agent update is a set of bytes plus a signed manifest that authorises them. This mints the key and signs
the manifest.

```sh
dsse-signupdate -generate -key update.key     # prints the PUBLIC half; keep the file off every node
dsse-signupdate -key update.key -manifest manifest.json -out manifest.signed.json
dsse-signupdate -key update.key -pubkey       # the value -agent-update-pin and --update-pin take
```

The public half is what an Edge and an endpoint pin. **The file is the authority to run code on every device
that pinned it** — it does not belong on an Edge, on an endpoint, or in the repository, and the tool says so
where it prints it.

It refuses to overwrite an existing key:

```
refusing to overwrite an update-signing key — every endpoint that pinned it would start
reporting untrusted manifests, which reads as a substitution attack
```

## `dsse-genprofile` and `dsse-enroll-cp`

Two reference implementations rather than operator tools.

**`dsse-genprofile`** signs an install profile, which is what an Admin Console does server-side for a fleet.
It is useful for a lab or a CI job that needs a profile without a Console. It never prints the private key —
only the public pin the agent verifies against.

**`dsse-enroll-cp`** stands up the enrolment endpoint on its own: verify an eligibility token, sign a device
CSR with a device CA, assign an organization and group, return the certificate and the CA. A real deployment
serves this from its control plane; this is the same handler with nothing else around it, for reading and for
testing against.
