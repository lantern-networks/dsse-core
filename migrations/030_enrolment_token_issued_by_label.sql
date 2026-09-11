-- Who approved a device, recorded at issuance rather than resolved later.
--
-- The record kept the approving administrator's principal id, which resolves to a person only while that
-- account exists. Approvals outlive the people who granted them — that is the ordinary case, not the edge
-- case — so an approval became unattributable the day somebody left, which is exactly the question this
-- record exists to answer.
--
-- Nullable and additive: tokens issued before this carry no label, and the display falls back to resolving
-- the id while the account is still there.
ALTER TABLE enrolment_tokens ADD COLUMN IF NOT EXISTS issued_by_label TEXT;
