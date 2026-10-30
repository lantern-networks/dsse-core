# Upstream TLS compatibility

For inspected HTTPS, the Edge establishes its own TLS connection to the destination.
By default, that connection offers the same TLS 1.2 cipher suites as Chrome, so a
site that failed only because it accepts nothing but static RSA key exchange now
opens. Other differences between Chrome and the Edge can still make a site fail; see
[When a browser works](#when-a-browser-works-but-dsse-reports-a-handshake-failure).
An organization can choose a stricter profile instead.

In Console, select the organization and open **Web & Traffic → Inspection Settings**.
The **Origin TLS compatibility** setting belongs to the selected organization;
the deployment-wide inspection posture on the same page has a different scope.
An administrator with policy-write permission can change the setting. Read-only
administrators can inspect it if their role permits policy reads.

| Mode | Behavior |
|---|---|
| Same as browsers (default, `browser_compatible`) | Offers the TLS 1.2 cipher suites Chrome offers, in addition to the Go TLS client's defaults: the four static RSA suites below. |
| Strict (`strict`) | Offers only the Go TLS client's default suites. Every TLS 1.2 key exchange is ECDHE. Sites that accept only static RSA key exchange do not open. |

The suites added by the default profile are:

- `TLS_RSA_WITH_AES_128_GCM_SHA256`
- `TLS_RSA_WITH_AES_256_GCM_SHA384`
- `TLS_RSA_WITH_AES_128_CBC_SHA`
- `TLS_RSA_WITH_AES_256_CBC_SHA`

Every other TLS 1.2 suite Chrome offers (ECDHE with AES-GCM, ChaCha20-Poly1305
and AES-CBC-SHA) is already a Go default, and TLS 1.3 is available in both modes.
The reference is the ClientHello of Chrome 156. Neither mode enables 3DES, RC4,
CBC-SHA256, TLS 1.0 or TLS 1.1; Chrome does not offer them either. TLS 1.2 remains
the minimum. Normal HTTP/2 negotiation remains enabled where the base transport
supports it; the mode does not force every destination to HTTP/1.1. Static RSA
does not meet HTTP/2's cipher requirements, and a server offering an incompatible
HTTP/2 combination is not repaired by replaying the request over another protocol.

Static RSA key exchange has no forward secrecy: if a server that uses it has its
private key compromised later, previously recorded sessions with that server can
be decrypted. The Edge lists ECDHE suites ahead of static RSA, and most servers that
support ECDHE select it, but the server makes the choice: a server configured to prefer
static RSA uses it, and that connection has no forward secrecy. Choose **Strict** when the
organization prefers refusing such servers to reaching them. The Edge records each
use of a static RSA suite so operators can identify these origins.

## Checks and inspection stay in place

The setting affects the Edge-to-destination leg of inspected HTTPS. It does not
change device/Connector mTLS, Portal or Console listeners, authentication grants,
or the organization's decision about which traffic to inspect.

Certificate trust, hostname and validity checks remain in force in both modes.
Organizational private authorities remain scoped to that organization. A handshake
failure does not add a trusted root, disable certificate verification, create an
inspection bypass, or trigger a compatibility-specific HTTP retry. Authorization,
URL policy, DLP and normal traffic logging still apply. This feature does not add
general upstream CRL/OCSP checking; see [Upstream trust](../upstreamtrust/README.md).

The profile applies to the standard Go upstream transport. Custom TLS dialers,
opaque transports and explicitly authored cipher lists retain their existing
constraints; this setting does not override those independent TLS engines.

Connections and TLS resumption state are separated by organization, trust transport
and mode. After a mode change reaches an Edge, a new request does not use that
organization's connection pool for the other mode. Requests already in progress are
not forcibly disconnected. Distribution is asynchronous: verify the configuration
has reached the relevant Edges before relying on the new mode across a deployment.
A flow that is not associated with an organization uses the default profile.

## When a browser works but DSSE reports a handshake failure

With the default profile, a site that negotiates with Chrome using one of the
suites above negotiates with the Edge as well. An error such as
`remote error: tls: handshake failure` can still have other causes, such as a
certificate the server selects by client signature algorithms, or a server that
filters clients by other properties. Check the destination's TLS configuration and
the Edge's connection diagnostics. If the organization has chosen **Strict**, the
first thing to check is whether the destination accepts only static RSA.

The Console keeps the tradeoff notice visible while the default profile is saved
or selected. If a save cannot be confirmed, it shows the last confirmed mode and
requires **Reload** before another save. Selecting **Strict** alone does not change
the saved setting or remove the notice.

A generic handshake failure is not proof of certificate pinning. DSSE does not
turn this error into an inspection-bypass candidate or automatically change the TLS
mode. The **Pinned Sites** workflow registers inspection bypasses and is not a
substitute for this setting.

## API and deployment

`GET /admin/upstream-tls` reads the effective mode for the authorized organization.
An organization that has never chosen a mode reads `browser_compatible`.
`POST /admin/upstream-tls` accepts one of these JSON bodies:

```json
{"mode":"browser_compatible"}
```

```json
{"mode":"strict"}
```

Use the normal Console/API authentication and organization context. Choosing an
organization does not grant permission to administer it. Writes use the existing
durable policy store and administrative audit path; the control plane distributes
the effective mode for every organization in its signed tenant configuration, so
an organization that never chose a mode is sent `browser_compatible` explicitly.
An organization that saved `strict` keeps it.

Upgrade the control planes first. An Edge that predates this default but already
supports the setting applies the distributed `browser_compatible` mode with the
two static RSA AES-GCM suites only; it offers the two AES-CBC suites after it is
upgraded. An Edge older than the setting ignores the field and keeps the Go
defaults. Deleting an organization resets its stored mode to the default.

## References

- [Go TLS configuration](https://pkg.go.dev/crypto/tls#Config)
- [RFC 9325, cipher suite recommendations](https://www.rfc-editor.org/rfc/rfc9325.html#section-4.1)
- [RFC 9113, HTTP/2 TLS cipher suites](https://www.rfc-editor.org/rfc/rfc9113.html#section-9.2.2)
