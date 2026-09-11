-- The hot store's schema. Applied on first boot by the ClickHouse image's /docker-entrypoint-initdb.d hook.
--
-- ★★★ IT SHIPS WITH THE BINARY THAT READS IT. The published tree carried the ClickHouse client and no schema
-- at all, which is the same defect the Postgres migrations already record: a deployment would have started a
-- hot store the product could not write to, on a table nobody could have supplied.
--
-- Columnar and LowCardinality so that decrypting and logging everything stays affordable. Ingest is HTTP
-- INSERT ... FORMAT JSONEachRow and query is HTTP SELECT ... FORMAT JSON, so there is no client library here.
CREATE DATABASE IF NOT EXISTS dsse;

CREATE TABLE IF NOT EXISTS dsse.events
(
    event_id         String,
    tenant_id        LowCardinality(String),
    -- ★★★ WHICH REGION IT CAME FROM, AS A COLUMN. With the region only inside the opaque `raw` JSON, a
    -- region's data cannot be SELECTED, RETAINED or DELETED without a full scan — which is the whole of what
    -- data residency has to mean here. It is in the partition key so that dropping or moving one region's
    -- data is a partition operation rather than a mutation over everything.
    edge_region_id   LowCardinality(String),
    -- ★★ THE ZONE BELONGS TO THE COLUMN. Without it a naive timestamp string is parsed in the SERVER's
    -- timezone, so the same INSERT means a different instant on a Tokyo box than on a UTC one. The value is
    -- always UTC ticks internally; this attribute only decides how a naive string is read.
    ts               DateTime64(3, 'UTC'),
    stream           LowCardinality(String),
    finding_type     LowCardinality(String),
    action           LowCardinality(String),
    application_id   String,
    user_id          String,
    device_id        String,
    destination      String,
    identifier_types Array(String),
    instance_class   LowCardinality(String),
    rule_id          String,
    raw              String
)
ENGINE = MergeTree
PARTITION BY (tenant_id, edge_region_id, toYYYYMMDD(ts))
ORDER BY (tenant_id, edge_region_id, ts, event_id)
TTL toDateTime(ts) + INTERVAL 30 DAY DELETE
-- ★ SINGLE-ROW INSERTS ARE IDEMPOTENT BY TOKEN. The Edge ships records with a retain-and-replay spool, so the
-- same record arrives more than once whenever the control plane was briefly away. The ingest path sets the
-- insert deduplication token to stream+event_id; without this window the retries double-count, and a report
-- that overstates is worse than one that is missing.
SETTINGS non_replicated_deduplication_window = 10000;
