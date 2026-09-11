# Security Policy

`dsse-core` is security software (a Secure Service Edge data plane: TLS interception, mTLS device
identity, policy enforcement). We take vulnerabilities seriously and appreciate responsible disclosure.

## Reporting a vulnerability

**Please do not open a public issue for security vulnerabilities.**

Use GitHub's [private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
— "Report a vulnerability" under the repository's **Security** tab. It reaches the maintainers and nowhere
else, and it asks you to trust no address you found on a website.

That is the only private channel we publish, deliberately: a security contact that cannot be verified is
worth less than no contact at all. If you cannot use it, open a public issue asking for a private channel and
**include no details of the finding** — a request for a channel discloses nothing, and we will come to you.

Please include:

- the affected component (package or reference binary) and version/commit,
- a description of the issue and its impact,
- reproduction steps or a proof of concept, if possible.

We aim to acknowledge a report within a few business days and to keep you updated as we investigate and
fix the issue. We will credit reporters who wish to be acknowledged.

## Scope

In scope: the `dsse-core` library packages and the binaries (`dsse-edge` — which is both the Edge and,
with `-control-plane`, the control plane —
`dsse-connector`) and endpoint agents in this repository.

Out of scope: deployment misconfiguration (e.g. running without TLS where the binaries require it is
already prevented; weak operator-chosen secrets), and third-party dependencies (please report those
upstream, though we welcome a heads-up).

## Security model notes

- The reference edge/control-plane refuse to start without TLS — there is no plaintext path.
- Protect the root, issuing, and Edge inspection keys. Their compromise can authorize
  interception within the affected trust scope; short-lived leaves do not remove that risk.
  See [PKI structure and lifecycle](docs/pki.md).
- DLP findings omit matched payload values. Logs and exports can still contain identifying
  user, device, account, and destination metadata. Review and sanitize records before
  sharing them; see [Audit logs and data handling](docs/audit-and-data.md).
- Consult the [release overview](docs/release-overview.md) for initial allow/observe
  settings and documented enforcement limitations. These are part of evaluating the
  experimental implementation, not a claim of independently audited protection.
