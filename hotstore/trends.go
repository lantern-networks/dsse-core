package hotstore

import (
	"context"
	"time"
)

// Trends is served from the ingest-time rollup, not the raw event firehose, so the query cost is independent of
// raw flow count. It is an OPTIONAL capability: only backends that maintain a rollup implement TrendsCapable
// (ClickHouse does, via its materialized view). Callers type-assert the Store to TrendsCapable and fall back /
// 501 when it is absent — so the base Store interface stays minimal and the non-rollup backends (JSONL/Postgres)
// are not forced to grow a method they cannot serve cheaply.
type TrendsCapable interface {
	Trends(ctx context.Context, query TrendsQuery) (TrendsResult, error)
}

// TrendsQuery selects a tenant's event-activity time series over a window. Granularity is one of "5m" (the rollup's
// native bucket), "1h", or "1d"; empty defaults to "5m". Stream / FindingType are optional equality filters. From
// defaults to To-24h and To defaults to now.
type TrendsQuery struct {
	TenantID    string
	From        *time.Time
	To          *time.Time
	Stream      string
	FindingType string
	Granularity string
}

// TrendBucket is one aggregated point: the count of events and the distinct users / destinations / devices in that
// (bucket, stream, finding_type, action) cell.
type TrendBucket struct {
	Bucket       time.Time `json:"bucket"`
	Stream       string    `json:"stream"`
	FindingType  string    `json:"finding_type"`
	Action       string    `json:"action"`
	Events       int64     `json:"events"`
	Users        int64     `json:"users"`
	Destinations int64     `json:"destinations"`
	Devices      int64     `json:"devices"`
}

type TrendsResult struct {
	TenantID    string        `json:"tenant_id"`
	From        time.Time     `json:"from"`
	To          time.Time     `json:"to"`
	Granularity string        `json:"granularity"`
	Buckets     []TrendBucket `json:"buckets"`
}
