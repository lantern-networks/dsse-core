-- 037: bring claim rows written before the tenant key was canonicalised onto the key everything now uses.
--
-- ★ CANONICALISING THE KEY WITHOUT MOVING THE ROWS RE-OPENS THE HOLE IT CLOSED (2026-08-13, twenty-seventh
-- review). 035 shipped with a case-preserved tenant, and the fix lower-cased it in every claim OPERATION —
-- so a row written as ('Tenant_A','device-1') became unreachable from ('tenant_a','device-1'). ClaimIdentity
-- no longer collides with it, the INSERT succeeds, and a second certificate is issued under a permission that
-- was already spent. ReleaseIdentity and the backfill cannot see it either, so the stale row is never
-- repaired: the defect returns for every identity claimed before the upgrade, and stays.
--
-- Rows are MERGED, not replaced. Two spellings can fold onto one key, and the survivor must be the one with
-- the HIGHEST grant — the newest administrator permission — because lowering a grant is precisely what lets
-- an identity be claimed a second time.

-- Step 1: of the rows that will collide, keep only the greatest. Ordering by (grant, claimed_at, tenant_id)
-- makes the choice total, so this is deterministic and can be re-run.
DELETE FROM enrolled_identity_claims a
 USING enrolled_identity_claims b
 WHERE lower(a.tenant_id) = lower(b.tenant_id)
   AND a.identity = b.identity
   AND (a.reenrolment_grant, a.claimed_at, a.tenant_id) < (b.reenrolment_grant, b.claimed_at, b.tenant_id);

-- Step 2: with at most one row per lowered key, the rename cannot conflict.
UPDATE enrolled_identity_claims
   SET tenant_id = lower(tenant_id)
 WHERE tenant_id <> lower(tenant_id);
