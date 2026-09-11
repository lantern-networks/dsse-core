-- Who turned the standing delegation OFF.
--
-- The operator decided on 2026-08-20 that an MSSP operator may not turn a delegation back on that the
-- organization itself withdrew. That rule needs one durable fact: whether the last withdrawal came from the
-- customer or from the operator ending their own engagement.
--
-- Dropped, it reads false, and the rule fails OPEN — the operator reopens what the customer closed and the
-- customer's screen says they may. This is the same class as 039 and 040, where the Postgres backend silently
-- did not carry a field the file store held and the envelope was inert in the backend the production
-- documentation names.
ALTER TABLE admin_tenant_models
    ADD COLUMN IF NOT EXISTS operator_delegation_withdrawn_by_customer boolean NOT NULL DEFAULT false;
