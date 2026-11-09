-- The order in which a site's connectors use the deployment's entrances, as region IDs separated by commas.
-- Empty means the site's own region first, then the deployment's order (acceptance C, 2026-11-08).
ALTER TABLE admin_sites ADD COLUMN IF NOT EXISTS door_order text NOT NULL DEFAULT '';
