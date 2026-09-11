-- 041: erasure orders are recorded by name, for the same reason deletions are (migration 038) — only more
-- sharply, because an erasure is the only operation whose completion depends on a node acting.
--
-- ★ THE MEASURED DEFECT (2026-08-18). The Postgres tenant-model backend implemented Get/Update/List/Put/Delete
-- and DeletedTenants, and NOTHING ELSE. OrderPurge and PurgeOrders existed only on the file store, and both
-- call sites reach them through a type assertion:
--
--     if orderer, ok := tenantModelStore.(interface{ OrderPurge(string, time.Time) }); ok { ... }
--
-- On a Postgres control plane that assertion is false, so ordering an erasure recorded no order at all, the
-- handler carried on to erase this node's own copy, and answered with a result. Every other node that ever
-- served the tenant was never told — and per the file store's own comment, a node that has not yet erased a
-- tenant "is only ever told by this list". The customer's data stayed on those nodes, and the operator who
-- ordered the erasure had a successful response saying otherwise.
--
-- Orders are NEVER cleared. An Edge that was offline when the order was given is only ever told by this list,
-- and an order that disappears once "most" nodes have acted is how one node quietly keeps a customer's data.
-- Ordering twice keeps the first instant: the order is not a new fact the second time.
CREATE TABLE IF NOT EXISTS admin_tenant_model_purge_orders (
	tenant_id text NOT NULL,
	ordered_at timestamptz NOT NULL,
	PRIMARY KEY (tenant_id)
);
