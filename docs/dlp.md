# Data loss prevention (DLP)

This guide describes the current upload inspection path. DSSE is experimental; detectors,
policy fields, and enforcement behavior may change. Read it with [Egress policy](egress-policy.md).

## Enable a policy

1. Enter the customer organization in the Console and confirm its name in the header.
2. Under **DLP Policies**, create a reusable policy. Select identifiers, a minimum count,
   and the action on a match. The editor initially selects **Observe**.
3. On the relevant **Internet Access** rule, enable **Inspect (decrypt)** and select the
   DLP policy. Creating a DLP policy alone does not attach it to traffic.
4. Check rule priority, destination, and inspection bypasses. Confirm the Edge has the
   intended configuration before testing from an enrolled endpoint.
5. Upload synthetic matching and nonmatching data to a destination you control. Check
   the receiver as well as **DLP Findings** and the access log.

HTTPS content must reach the decrypted HTTP egress path. Bypassed TLS, opaque tunnels,
and traffic that does not traverse that path do not gain DLP coverage from this setting.
This path scans upload bodies on `POST`, `PUT`, and `PATCH`; it is not a general scan of
downloads, endpoint files, or every network protocol.

## What can be detected

| Detector | Scope |
|---|---|
| `my_number` / `corporate_number` | Japanese individual / corporate number formats with checksum validation |
| `credit_card` | Candidate card numbers with Luhn validation |
| `api_key` | Recognized key/token patterns and private-key headers; not every kind of secret |
| `email` / `phone` | Email patterns / supported Japanese mobile-number patterns |
| Custom classifier | Server-side Go regular expressions (RE2 syntax) or keyword lists |
| Exact data matching (EDM) | Values matched against a named fingerprint dataset |

The browser's regex preview uses JavaScript and is only a convenience. Test the saved
classifier through the Edge. Pattern or checksum matches do not establish that a number
was issued, that a credential is live, or that all sensitive information was found.

EDM values reach the administration service in plaintext during submission; the dataset
store retains tenant-salted hashes rather than the source values. Protect the upload,
hashing configuration, stored hashes, and backups. Hashing is not a promise of anonymity.
The known-safe **allowlist retains its authored values in readable form** for administration.
Use it only for deliberate non-sensitive exceptions, and test that nearby real matches
remain detectable. Custom keywords are also authored configuration, not secret storage.

## Actions and account scope

| Action | Current behavior on a qualifying match |
|---|---|
| Observe | Record a finding and permit the upload |
| Warn | Record the warning and permit the upload; no blocking confirmation dialog |
| Block | Interrupt the upload; the HTTP handler returns 403 |
| Authenticate | Interrupt the upload; the handler returns 401 / `dlp_authenticate_required` |

For a rule with several selected identifiers, any identifier reaching its minimum count
can trigger it. Across triggered rules, the strongest action wins:
`block` > `authenticate` > `warn` > `observe`.
The DLP `authenticate` response does not itself start the East-West OOB ceremony or
promise automatic replay of the upload. See [East-West step-up](east-west-policy.md)
for that separate workflow.

The default instance scope is **any**. **Corporate** and **personal** scopes classify the
account email available in the egress decision against the organization's IdP verified
domains. Without an account signal or configured domains, the class is unknown and
neither scoped rule applies. Keep an `any` rule when unknown accounts must remain covered;
a destination hostname alone does not establish its signed-in account.

Optional composite DLP conditions can raise device risk after a pattern of detections.
Subsequent risk-based access policy determines the consequence; recording risk does not
by itself mean every future connection is blocked.

## Content and enforcement limits

Text-like bodies use a streaming scanner or a guarded reader for interrupting rules.
The guard withholds the detection window, but earlier cleared bytes may already have
reached the destination. A blocked streaming request is not an atomic rollback of the
whole upload; confirm receiver-side behavior for the application you intend to protect.

Recognized Office Open XML, PDF, and multipart uploads use bounded buffering and text
extraction. This is not OCR or complete inspection of arbitrary archives, binary formats,
embedded objects, or every part of an encrypted document. Extraction and size limits
can leave content unexamined. Multipart extraction can skip unsupported or failed parts
while inspecting other parts, so a partly inspected upload is not proof of full coverage.

The default `-dlp-block-uninspectable-files=false` forwards oversized buffered files and
files whose extraction fails, with service-log warnings. Setting it to `true` blocks
those paths when an interrupting DLP policy applies. It does not convert every unsupported
format or skipped multipart part into a denial. Confirm the effective process flag;
the presence of a Block policy alone does not change this default.

**DLP Findings contains detections, not a complete scan ledger.** Ordinary unscannable
bodies do not produce a per-request skipped-scan finding. No finding can mean no match,
no applicable policy, or no inspection. Findings carry types/counts and context rather
than the matched value; context can still identify a user or destination. See
[Audit logs and data handling](audit-and-data.md).

## Acceptance checks

Use a unique synthetic keyword such as `DSSE_DLP_DEMO_ONLY_7F29` in a custom classifier;
do not use a real credential or personal record. Preserve the rule and revision with results.

| Check | Evidence to collect |
|---|---|
| Matching vs nonmatching text | Response, receiver bytes, matching rule, action, finding |
| Observe / Warn / Block | Permitted warning behavior versus actual interruption |
| Any / corporate / personal / unknown | Account evidence and whether the scoped rule applies |
| Known-safe exception | Suppressed exception and an unsuppressed nearby test value |
| PDF / OOXML / multipart | Actual extracted test content; include an unsupported part |
| Oversized or unextractable file | Effective flag, service warning, and receiver outcome |
| TLS bypass or unattached policy | Deliberately uncovered control case, recorded as such |

These are test instructions, not a report that these cases passed on your deployment.

Implementation: [policy actions](../dlp/policy.go), [detectors](../dlp/identifiers.go),
[upload hook](../cmd/dsse-edge/swg_http_egress_dlp.go),
[account classification](../cmd/dsse-edge/dlp_instance.go), and
[file extraction](../fileextract/extract.go).
