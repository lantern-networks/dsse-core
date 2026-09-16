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

## Loading and confirming library changes

The three **Sensitive Data** tabs require a valid list and matching organization before
editing. A failed or malformed response displays a reload action instead of an editable
empty list. If a save response is missing, malformed or does not match the submitted
change, the Console keeps the draft and reports an unconfirmed result. The server may
already have saved it. Close the editor, reload the list and inspect the saved state before
making another change. Administrative audit records describe the server's outcome, so a
committed change can have a successful audit even when its browser response was lost.

List and mutation responses include `tenant_id`. The Console sends `expected_tenant_id`
on writes (a query parameter for dataset deletion); a nonempty value that differs from
the authenticated request context is rejected without changing the library. Older API
clients may omit this precondition and remain scoped to their authenticated request context. Serve the Console and API from
compatible versions: the updated editors refuse responses without organization identity.
This guards context changes, not simultaneous edits by administrators in one tenant.

## Managing known-safe exceptions

Use **Sensitive Data → Allowlist** only for confirmed non-sensitive values. Numeric
identifiers accept digits with spaces, hyphens, parentheses or periods as grouping;
email addresses ignore case. All other detector types, including custom identifiers,
EDM and secrets, compare the trimmed literal value exactly. An alphanumeric value such
as `ORDER-4111111111111111` does not authorize the card number embedded inside it.

With `-dlp-allowlist-store` configured, an edit is published only after the save succeeds.
An error retains the previous live exceptions, but cannot prove disk rollback if storage
wrote before reporting failure. Check saved configuration before retrying. With no store,
changes are in memory only. The API replaces the whole list: `{"values":[]}` clears it;
a missing/null field, blank entry or more than 1,000 entries is rejected. Exact duplicates
are removed. Reload before editing when other administrators may be changing the list;
there is no revision-based conflict detection.

The signed configuration bundle carries authored known-safe values, and receivers compile
them with their local allowlist salt. Protect configuration access and backups. Update
both the publisher and receiving nodes to use this distribution support: older receivers
ignore the section. A section missing from an older publisher preserves the receiver's
existing exceptions; an explicit empty map clears them. A receiving save failure leaves
the DLP library unapplied so the same generation can be retried. This is not a transaction
across every configuration store. Verify the applied generation and both an exempted
sample and an unlisted control through each Edge.

The administration audit records actor, tenant, endpoint and outcome without values.
It is not a per-value change diff. A suppressed finding produces no DLP finding event;
confirm the upload result and access logs as well as an unsuppressed control.

## Saving custom identifiers

Use **Sensitive Data → Identifiers** to add, edit, or delete patterns and keyword lists.
When `-dlp-classifier-store` is configured, these edits must be accepted by that store
before the authored definitions and compiled scanner are updated. A failed or unconfirmed
save returns an error and leaves the current live definitions in place. A storage error
can occur after bytes were written: the error does not prove that the on-disk snapshot
is unchanged. Check storage health and the saved configuration before retrying. Without
a configured store, changes are in memory only and do not survive a restart.

The API replaces the entire tenant list; send `{"classifiers":[]}` to clear it explicitly.
A missing or null `classifiers` field is rejected. Concurrent administrators should reload
before editing: this endpoint does not provide revision-based conflict detection.
Successful local saving does not establish delivery to another Edge or inspection of traffic.

The administration write audit records the actor, tenant, endpoint and outcome, without
classifier patterns, keyword values or preview text. It is not a per-identifier change diff
or a detection event. Follow the traffic checks below to confirm actual DLP coverage.

## Saving exact-match datasets

Use **Sensitive Data → Exact-Data-Match** to create or replace a named dataset.
Values must be single ASCII tokens containing letters, digits, or `- _ . @ +`, up to
128 bytes after surrounding whitespace is trimmed. Matching lowercases letters and
removes `-` and `_`. Normalized duplicates count once; values shorter than five
normalized characters are ignored. Multiword phrases, other character sets and longer
tokens are unsupported and rejected. A replacement with no usable values is rejected
without deleting the previous dataset. Use **Delete** to remove it explicitly.
Previously stored hashes cannot reveal whether the original values met these rules.
Reimport an older dataset from its source values to apply the current validation.

With `-dlp-fingerprint-store` configured, creation, replacement and deletion confirm
storage before updating the local scanner. A rejected or unconfirmed save leaves the
previous live dataset in place and reports an error. As with custom identifiers, an
error may follow a disk write; inspect storage before retrying. Without configured
storage, changes are in memory only. These local outcomes do not confirm delivery to
other Edges or inspection of traffic. The write audit records endpoint, actor, tenant
and outcome without submitted values; it is not a dataset-level change history.

EDM snapshots now save a format version, the hashing salt and the dataset hashes
together. A restarted node restores that salt even when it differs from its startup
default. Hashes cannot be moved to a different salt without the original values.
Protect snapshots and backups: salts and hashes still permit guessing attacks.

Existing snapshots without a version use the node's original startup salt. They are
not rewritten during loading; a subsequent save writes the versioned format. If an
older receiver previously saved hashes from a different salt, that lost salt cannot
be recovered from the snapshot. Restore the correct source configuration or reimport
the original values. Do not downgrade a node that adopted a different salt: older
binaries ignore the stored salt and may silently stop matching those datasets.

A missing configured snapshot permits first startup, but an existing empty, malformed,
unsupported-version or invalid dataset snapshot now prevents startup. Preserve the
file, investigate the storage failure and restore a known-good backup or the authoritative
configuration; deleting it would discard the detectors. A valid explicit empty dataset
map represents a cleared library. Runtime store replacement validates the whole candidate
before replacing its state and writer; failed loads retain both. Pending unsaved changes
must reach the existing writer before it can be replaced or detached.

This restoration guarantee applies to the EDM store. Other DLP library stores and the
atomic persistence of a received configuration bundle require separate validation.

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
