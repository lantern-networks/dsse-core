-- 036: a record that the EXISTING fleet has been imported into the identity claim, once, for the deployment.
--
-- ★ ONE NODE'S BACKFILL PROVES ONLY THAT NODE (2026-08-13, twenty-sixth review). 035 gave every issuer a
-- shared place to consume an identity, and each node backfills what IT knows is already enrolled. During a
-- rolling upgrade the new issuer starts with a node-local ledger holding no enrolment markers at all: its
-- backfill claims nothing, reports success, and it begins issuing while every identity that only the OLD
-- issuer knows about is still unclaimed. The gap is invisible from either node — one has the markers and the
-- other has the certificates to hand out.
--
-- So the migration has an end, and the end is written down. A node may declare it only if it actually
-- contributed enrolments, or if an operator states that this deployment has no fleet to migrate. An issuer
-- that can do neither refuses to start rather than issuing into an unfinished migration.
CREATE TABLE IF NOT EXISTS enrolled_identity_claim_barrier (
  id           boolean     PRIMARY KEY DEFAULT true CHECK (id),  -- exactly one row, by construction
  completed_at timestamptz NOT NULL DEFAULT now(),
  completed_by text        NOT NULL DEFAULT '',
  identities   integer     NOT NULL DEFAULT 0,
  reason       text        NOT NULL DEFAULT ''
);
