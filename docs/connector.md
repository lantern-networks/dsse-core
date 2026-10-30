# Connectors

A connector publishes the things inside a network — a subnet, a server, an internal name — to the deployment,
over a tunnel it opens **outbound**. Nothing is exposed inbound, and no firewall hole is made for it. The connector host must be able to reach the configured regional endpoints and the private applications.

Configure authorization separately with [East-West policy and OOB step-up](east-west-policy.md)
and [IdP integration](idp.md). A connected connector does not prove the intended
allow, deny, or authentication rule is enforced.

## What a connector is placed by

An administrator, at the Console, in one visit to one screen. It hands over three things, and the third is the
one that is easy to skip:

1. **the program** — the connector itself, for the machine's platform and architecture;
2. **the settings** — a file, downloaded, carried whole;
3. **a way to check it** — run on the machine afterwards, because the Console cannot see what the machine
   ended up with.

`Sites → (a site) → Add connector`. A site is where the machine is; a connector is the machine.

## On the machine

```sh
tar xzf dsse-connector-linux-<arch>.tar.gz
sudo ./dsse-connector-install --profile dsse-connector-<site>.json
```

That is what the screen prints under **Run this on that machine**, and it is the whole install — the settings
file is downloaded beside the program and the command is taken as it stands.

**There is a second form for a machine you cannot put a file on**, and it is not on the surface: the screen
carries it under a line reading *Cannot put a file on that machine*. Opening that shows the same install with
the settings inline —

```sh
sudo dsse-connector-install --token <base64> --state-dir /var/lib/dsse-connector
```

— *the same one-time key, typed instead of carried*, in the screen's own words. Both work. Use whichever suits
how the machine is reached; the file is the one the screen offers first.

The install enrols, obtains an identity of the connector's own from the deployment, writes its state under
`/var/lib/dsse-connector`, installs a system service and starts it:

```
  site        branch-site
  organization <the organization whose site this is>
  door 1      region-a=https://agents.region-a.<deployment>
  door 2      region-b=https://agents.region-b.<deployment>
  door 3      region-c=https://agents.region-c.<deployment>
  tried in this order; losing one does not take this location off the network
  installed /etc/systemd/system/dsse-connector.service — this connector comes back after a reboot.
```

**The settings file is a credential until the Edge acknowledges the connector registration.** It carries a one-time bootstrap
secret; the identity that replaces it is minted on the machine and never travels. Carry the file once, over a
channel you trust, and delete the copies it leaves behind after successful registration.
The connector retains a pending bootstrap credential in its private state file while
identity issuance or first registration is incomplete. Restarting resumes with the
same connector ID; it does not require deleting state or issuing another profile.
After the Edge acknowledges registration, the pending credential is removed from
state and later registration uses the runtime identity. Treat the state directory
as secret throughout this process; it also holds the long-lived private identity.

**The doors are why the shape matters.** On a three-region deployment the file names all three, tried in
order, so a connector whose region goes keeps the estate behind it reachable. On a one-machine deployment it
names one, and the screen says so rather than implying otherwise.

## Then check it, on the machine

```sh
sudo dsse-connector-install --verify --state-dir /var/lib/dsse-connector
```

That is the line the screen prints under **Then check it on the same machine**, `--state-dir` included: the
check reads the state the install wrote, and on a machine where it was written somewhere else the check has
nothing to read.

The verifier checks installation, identity, connectivity, and reboot persistence. Example output:

```
  ok    this machine has a connector installed       /var/lib/dsse-connector
  ok    this connector has enrolled                  conn-… in site branch-site, organization <organization>
  ok    it has an identity of its own                connector.crt, subject "conn-…"
  ok    the identity came from this deployment       issued by "<organization> Device Identity CA"
  ok    the identity names this connector            conn-…
  ok    the identity is valid now                    until … (59d left)
  ok    this connector knows where the deployment is 3 doors, tried in this order: region-a=…, region-b=…, region-c=…
  ok    the connection to the deployment is pinned   /var/lib/dsse-connector/edge-ca.pem, 1 anchor(s)
  ok    each door answers this connector             3 of 3 — every door answered
  ok    the program this machine starts is on it     /usr/local/bin/dsse-connector
  ok    it comes back after a reboot                 /etc/systemd/system/dsse-connector.service
```

**Two of them exist for an install that was told `--no-service`**, and on such a machine they read:

```
  FAIL  the program this machine starts is on it     /usr/local/bin/dsse-connector is not there
  FAIL  it comes back after a reboot                 no service: this connector runs until this machine restarts
```

They are worth reading rather than dismissing: one asks whether the thing that starts the connector actually
exists, the other whether the location stays reachable across a restart. A connector that is running right
now and cannot come back is a site that goes dark at the next reboot, and nothing about the running process
says so.

**The identity must belong to the customer organization's site.** Confirm the enrolled
organization and the verifier's certificate-chain check. An issuer display name alone
is not evidence of tenant isolation; see [Organizations](organizations.md).

```
  ok  this connector has enrolled                  conn-… in site hq, organization …
  ok  the identity came from this deployment       issued by "… Device CA"
  ok  this connector knows where the deployment is 3 doors, tried in this order: …
  ok  the connection to the deployment is pinned   edge-ca.pem, 1 anchor(s)
  ok  each door answers this connector             3 of 3 — … answered; … answered; … answered
  ok  it comes back after a reboot                 /etc/systemd/system/dsse-connector.service
```

**This is the step the Console cannot do for you.** It shows *Connected* the moment one tunnel arrives, so a
connector holding one of its three doors looks exactly like one holding all three — until the day the door it
holds is the one that goes. `--verify` asks each door in turn, from the machine, which is the only place that
question can be answered.

## The programs a deployment holds

The connector program cannot come down the agents' signed-artifact lane: that route is inside the tunnel under
mandatory mTLS, and a connector has no identity until the program it does not yet have has enrolled it. So the
deployment holds the programs, and the person carrying the settings carries the program in the same act, with
a digest to check on arrival.

**A deployment seeds one program from its own image — its own architecture, and no other.** Build the Edge
images on arm64 machines and the deployment offers an arm64 connector; a branch office running x86 has
nothing it can run, and **Add connector** says so and names who fixes it. Build the other and add it:

```sh
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o out/dsse-connector         ./cmd/dsse-connector
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o out/dsse-connector-install ./cmd/dsse-connector-install
tar czf dsse-connector-linux-amd64.tar.gz -C out dsse-connector dsse-connector-install
```

Then, as the operator and outside every organization, **Agent Releases → Connector programs**: choose the
archive, choose `linux/amd64`, state the build, **Add it**. The screen lists what the deployment holds
afterwards, and **Add connector** offers the new pair from that moment.

**The digest is not typed** — the screen computes it from the bytes it is about to send and declares it, and
the deployment refuses an upload that does not match. Without something to check against, publishing is a way
to stage anything and
call it published. **The version is not, and should be given anyway:** the deployment asks whether every node
runs the same build and names any that disagree, and a connector installed from a program nobody identified is
outside that question. What the deployment seeds carries its own build; what an operator publishes carries
what the operator declares, and the screen says "build not stated" when that is nothing.

## What a connector reaches, and who decides

Routes are the **control plane's**, not the connector's. Nothing on the machine says what it fronts — its
state directory holds an identity, an anchor and a service, and no allowlist to drift out of date — so a route
added at the Console reaches it without anyone returning to the machine.

**A subnet is named before it is bound.** The deployment refuses a raw CIDR, on purpose:

```
raw CIDR bindings are not accepted: define "10.20.9.0/24" as a Named Network on the Networks page,
then bind it by network_id
```

A range typed into a connector's routes is a fact about that connector; the same range defined once, on the
Networks page, is a fact about the estate that policy, boundaries and every other connector can refer to.
So `Networks → add`, then `Sites → (a site) → (a connector) → Routes → add`, choosing the network by name.
What comes back names both, and says whether it actually carries traffic:

```json
{"network_id":"branch-subnet","network_name":"Branch subnet","network_cidrs":["10.20.9.0/24"],
 "kind":"network","source":"admin","held":false,"pending":false,"routable":true}
```

A connector may also *report* subnets it can see. These reports are informational; the administration API
does not accept adopting or holding self-reported routes. To configure a reported subnet, define it on the
Networks page and bind that Named Network to the connector.

## Concurrent TCP streams

Updated Connectors and Edge relays have no implementation-imposed TCP connection
count limit. The previous fixed 32-stream and 1024-stream bounds are removed from
receiver admission. File descriptors, memory, backend capacity, and other OS
resource limits still apply; this does not guarantee unlimited throughput.

An operator may set `DSSE_CONNECTOR_MAX_TCP_CONNECTIONS` in the Connector service
environment to a non-negative integer. Unset or `0` imposes no connection-count
limit. A positive value applies to the entire Connector process, including
pending dials, all Edge attachments, and the private TCP round-trip endpoint. It
is not multiplied by the number of tunnels, Edges, users, or applications.
Negative and malformed values prevent startup. Configure the service environment
(for example, a systemd override or container environment) and restart the service
to apply the chosen budget. This is a host-operator resource setting, not an
Internet Access or Connector Access authorization rule or a Console setting.

`GET /healthz` on the Connector's private listener reports `tcp_admission.active`
and `tcp_admission.max_connections` (`0` means no configured count limit).
Rejection at an explicitly configured budget preserves established connections.
Closing a connection, failing a dial, or losing a tunnel releases its reservations.
Each Connector process has its own budget; this is not a fleet-wide quota.

The legacy `concurrent_connection_cap` frame field is retained as an
interoperability hint for older receivers and is not an admission policy on
updated receivers. Old Connector and Edge relay binaries still enforce their old
limits: update both roles to remove these limits throughout the path. Route
authorization, mTLS, explicit operator byte budgets, and payload frame sizes remain enforced.
See [operator resource quotas](runtime-resource-quotas.md) for the full settings
and upgrade requirements across server and endpoint paths.

## Region failover

If a connector loses its tunnel, it tries the other configured regions and reports the
lost endpoint, retry target, and new tunnel in its log. Recovery time depends on detection,
network conditions, and the other regions' health; no fixed failover latency is promised.
A one-region deployment has no alternative endpoint.

Test from an enrolled device that the private application remains reachable after the
selected region becomes unavailable. A new tunnel log alone does not prove the application's
path or policy. Restore the region and check connectivity again.

## What the deployment can then say about it

`dsse-install -verify` turns three of its own checks from placeholders into measurements the moment a
connector exists:

```
  ok  every control plane holds the same connectors  1 connector(s), the same set on all 3 control planes
  ok  the Edges can route to the deployment's connectors  all 3 Edge(s) see every one of the deployment's 1 connector(s)
  ok  the deployment says whether it has a data-plane mesh  every Edge's mesh link is up, and a destination a
      connector fronts crosses to that connector's region whenever the link is live
```

The last one is what makes a connector a property of the **deployment** rather than of the region it sits in:
a device meeting the region-b Edge reaches an application fronted by a connector in region-a, without anything
being named by hand.
