-- 035: one row per device identity, so "this identity has already enrolled" is a decision every issuer shares.
--
-- ★ IT WAS DECIDED FROM MEMORY AND SAVED AS A BLOB. The enrolled inventory lives in one JSON document written
-- with an unconditional UPSERT, so two Edges that both hold a device CA each answered from the state they
-- happened to load: the second issued a certificate for a device name the first had already used. Giving each
-- node its OWN file made that worse rather than better — the enrolment markers then cannot reach each other at
-- all. The enrolment TOKEN store was given per-row conditional updates for exactly this reason; the identity
-- claim was not, and this is that.
--
-- The claim is (tenant, identity). reenrolment_grant is the administrator's permission counter: a claim may
-- only be taken when the grant being claimed under is NEWER than the one the current claim was taken under,
-- which is the same rule the in-memory merge uses and the reason a re-arm can still let a re-imaged machine
-- back in. Two racing issuers under the same grant means exactly one UPDATE reports a row.
CREATE TABLE IF NOT EXISTS enrolled_identity_claims (
  tenant_id         text        NOT NULL,
  identity          text        NOT NULL,
  reenrolment_grant integer     NOT NULL DEFAULT 0,
  claimed_at        timestamptz NOT NULL DEFAULT now(),
  claimed_by        text        NOT NULL DEFAULT '',
  PRIMARY KEY (tenant_id, identity)
);

-- Which node took a claim, and when, is what an incident asks first: two certificates for one name is a
-- question about WHERE, and a claim with no claimant can only answer that it happened.
CREATE INDEX IF NOT EXISTS enrolled_identity_claims_claimed_at_idx
  ON enrolled_identity_claims (claimed_at DESC);
