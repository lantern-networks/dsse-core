ALTER TABLE device_inventory DROP CONSTRAINT device_inventory_device_trust_level_check;
ALTER TABLE device_inventory ADD CONSTRAINT device_inventory_device_trust_level_check CHECK (device_trust_level IN ('managed', 'unmanaged', 'unknown', 'noncompliant'));
