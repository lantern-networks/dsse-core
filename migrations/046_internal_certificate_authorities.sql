-- The certificate authorities an ORGANIZATION vouches for when an Edge verifies one of that organization's
-- PRIVATE assets — the intranet server behind a connector, the internal API, the appliance on a VLAN.
--
-- Interception makes the Edge the TLS client to the asset, and until 2026-09-01 that direction had no trust
-- anywhere in the deployment: the Edge verified an intranet server against the platform's PUBLIC roots, which
-- are exactly the set that will never contain an organization's internal authority. The flow was decrypted
-- correctly and then refused, which from a browser is indistinguishable from the connector being down.
--
-- Owned by the control plane so it survives a restart and so every Edge in every region reads the same list.
-- Deliberately NOT the organization's interception root, which is a different thing with a similar name: that
-- one exists to be trusted BY DEVICES for certificates this deployment mints.
CREATE TABLE IF NOT EXISTS internal_certificate_authorities (
  id              text NOT NULL,
  tenant_id       text NOT NULL,
  name            text NOT NULL DEFAULT '',
  certificate_pem text NOT NULL,
  created_at      text NOT NULL DEFAULT '',
  updated_at      text NOT NULL DEFAULT '',
  PRIMARY KEY (id, tenant_id)
);
CREATE INDEX IF NOT EXISTS internal_certificate_authorities_tenant_idx ON internal_certificate_authorities (tenant_id);
