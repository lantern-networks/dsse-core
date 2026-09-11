package main

import (
	"os"
	"strconv"
	"strings"
	"time"

	accessdecision "github.com/lantern-networks/dsse-core/accessdecision"
)

// newAccessDecisionStore reads the capacity bound AND the idle TTL from the environment (codename env names) and
// injects them into the extracted store, keeping the OSS package env-name-free. The store is a RECENT-decision
// cache (same-flow event validation + admin detail lookups), so it expires by IDLE time by default: a decision
// is kept alive by activity and reclaimed only once its flow goes quiet — the count cap alone left a low-traffic
// Edge hoarding thousands of long-dead decisions (it only evicts once `capacity` newer ones arrive). Idle TTL
// keeps it proportional to recent traffic without cutting off long-lived flows; capacity is the spike backstop.
func newAccessDecisionStore() *accessdecision.Store {
	capacity := accessDecisionStoreDefaultCapacity
	if raw := strings.TrimSpace(os.Getenv("DSSE_DECISION_STORE_CAPACITY")); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil {
			capacity = parsed // <=0 => unbounded
		}
	}
	ttl := accessDecisionStoreDefaultTTL
	if raw := strings.TrimSpace(os.Getenv("DSSE_DECISION_STORE_TTL_SECONDS")); raw != "" {
		if secs, err := strconv.Atoi(raw); err == nil {
			ttl = time.Duration(secs) * time.Second // <=0 => idle expiry disabled (count-only)
		}
	}
	return accessdecision.NewStoreWithTTL(capacity, ttl)
}
