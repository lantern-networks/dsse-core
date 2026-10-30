-- Tenant IDs are exact, case-distinct identities. Historical case folding of
-- enrolled_identity_claims could merge two organizations' one-time claims.
-- No customer data migration is needed for the first 0.4.0 release. Keep this
-- version as a no-op so fresh installations can apply the selected sequence
-- without rewriting the claim keys.
SELECT 1;
