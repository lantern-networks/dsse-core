# Recovering an interrupted file-backed device-CA withdrawal

A registry with `pending_withdrawals` deliberately prevents startup. It means an
administrator began removing an authority, but the registry and device admission
trust file have not both been confirmed. Restart alone cannot complete it. The
procedure below completes the original removal offline; do not simply delete the
receipt or restore an older CA file and restart.

This procedure is for a single-writer file deployment only. PostgreSQL-backed
registry/trust updates use their database transaction and must not be repaired by
editing an unrelated local file. Keep the affected process stopped throughout.

1. Locate the actual `-tenant-ca-registry` file and, on an enforcing node, the
   `-device-client-ca-store` file. Resolve their configured paths before editing.
   Take access-restricted copies of both files and all `ca_file` references. Do not
   change private issuance keys or the separate `-transport-trust-store` (the
   latter is what devices trust about servers, not admission of device clients).
2. Read each `pending_withdrawals` record: `tenant_id`, `fingerprint` and
   `trust_required`. A fingerprint is lowercase SHA-256 of the certificate's DER
   encoding, not of its PEM text. Match it against certificates in that tenant's
   `ca_pem` or referenced `ca_file`. For a PEM containing multiple certificates,
   check each certificate separately. Stop if the tenant or fingerprint cannot be
   established from the saved receipt and registry; use the retained copies to
   investigate, not a guessed replacement.
3. Prepare a replacement registry. Remove only the certificates identified by
   those receipts from the matching tenant entries. Preserve every unrelated
   certificate, tenant and `material_managed_tenants` entry. If a referenced PEM
   contains both removed and retained certificates, use a new reference file or
   inline only the retained certificates; do not modify a file shared by another
   purpose. Remove an entry only when it has no remaining CA certificates.
4. When `trust_required` is true on a node that accepts device connections, remove
   those same certificates from the device-client-CA store's `anchors_pem`.
   Preserve all other fields and anchors and increase its positive `serial` by
   one (do not wrap or lower it). On a CP that serves no device listener, this
   local device store is absent by design; the final registry is what the signed
   configuration carries to Edges. If the node uses a startup-fixed client trust
   file, reconcile that configured file as well before any device listener starts.
5. Validate both candidate JSON documents and every remaining PEM, and compare
   the remaining certificate fingerprints and tenant mapping with the backups.
   Keep the pending receipts in the registry while installing the device trust
   file. Write via a temporary file in the same directory, preserve restricted
   ownership/mode, replace atomically and flush the file and containing directory.
   Only after the trust write is confirmed, install the registry with exactly the
   completed receipts removed using the same durable replacement procedure.
   A crash before this final step still leaves the startup interlock in place.
6. Start the node. Check the CA inventory and admission readiness. Confirm that a
   certificate under the withdrawn authority is rejected and that a retained
   authority still admits its intended tenant. On a CP, also confirm that the
   signed registry reaches the Edges before considering withdrawal complete.
   Record the original receipt, outcome and checks in the operator's incident
   record; offline recovery does not fabricate a successful HTTP audit event.

If removal leaves no valid admission authorities, do not start a device-serving
node with an empty pool. Complete the supported replacement-CA enrollment and
adoption process first. If the replacement files cannot be verified, keep the
node stopped and use the saved copies for investigation.
