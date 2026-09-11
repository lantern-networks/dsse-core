-- Rollups maintained at ingest. The product's trend queries read this table rather than scanning events, and
-- ClickHouseStore.rollupTable() names it — so it is not an optimization a deployment may skip.
CREATE TABLE IF NOT EXISTS dsse.events_rollup_5m
(
    tenant_id     LowCardinality(String),
    bucket        DateTime,
    stream        LowCardinality(String),
    finding_type  LowCardinality(String),
    action        LowCardinality(String),
    events        SimpleAggregateFunction(sum, UInt64),
    users         AggregateFunction(uniq, String),
    destinations  AggregateFunction(uniq, String),
    devices       AggregateFunction(uniq, String)
)
ENGINE = AggregatingMergeTree
PARTITION BY (tenant_id, toYYYYMMDD(bucket))
ORDER BY (tenant_id, bucket, stream, finding_type, action)
TTL toDateTime(bucket) + INTERVAL 400 DAY DELETE;

CREATE MATERIALIZED VIEW IF NOT EXISTS dsse.events_rollup_5m_mv TO dsse.events_rollup_5m AS
SELECT
    tenant_id,
    toStartOfFiveMinutes(ts)  AS bucket,
    stream,
    finding_type,
    action,
    toUInt64(count())         AS events,
    uniqState(user_id)        AS users,
    uniqState(destination)    AS destinations,
    uniqState(device_id)      AS devices
FROM dsse.events
GROUP BY tenant_id, bucket, stream, finding_type, action;
