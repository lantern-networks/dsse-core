-- Admin-issued enrolment tokens, as ROWS rather than a serialised blob.
--
-- The blob-backed store loads once at boot and mutates an in-memory copy, which makes a token one-time within a
-- single Edge and not across several: two Edges sharing one blob would each hold their own idea of what had been
-- spent and could both honour the same token. Spending has to be a decision the database makes, once, which is
-- what a conditional UPDATE on this table gives.
--
-- token_hash is a SHA-256 of the secret. The secret itself is never stored anywhere: it exists in the issuance
-- response and nowhere else, so a dump of this table yields no usable credential. UNIQUE on it because a lookup
-- by hash is how a presented token is resolved, and two rows with the same hash would make that ambiguous.
CREATE TABLE IF NOT EXISTS enrolment_tokens (
  id           text PRIMARY KEY,
  token_hash   text NOT NULL UNIQUE,
  tenant_id    text NOT NULL,
  device_group text NOT NULL DEFAULT '',
  label        text NOT NULL DEFAULT '',
  -- Which admin authorised this machine. NOT NULL because an unattributable approval is not an approval — it is
  -- the question an operator actually has months later when a device turns up somewhere it should not be.
  issued_by    text NOT NULL,
  issued_at    timestamptz NOT NULL,
  expires_at   timestamptz NOT NULL,
  -- Spent: set by the conditional UPDATE, together and never separately, so a row can never claim to have been
  -- used by nobody.
  used_at      timestamptz,
  used_by      text,
  revoked_at   timestamptz,
  revoked_by   text,
  created_at   timestamptz NOT NULL DEFAULT now(),
  CHECK (expires_at > issued_at),
  CHECK ((used_at IS NULL) = (used_by IS NULL))
);

-- The Console lists a tenant's tokens newest-first and counts the unspent ones against the cap; both are
-- tenant-scoped, and the count is read on every issuance.
CREATE INDEX IF NOT EXISTS enrolment_tokens_tenant_issued_idx
  ON enrolment_tokens (tenant_id, issued_at DESC);
