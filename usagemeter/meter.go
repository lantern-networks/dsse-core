package usagemeter

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lantern-networks/dsse-core/model"
)

var UsageMeterIDFallbackCounter atomic.Uint64

type UsageMeterRuntimeStore interface {
	UsageMeterSummaryReader
	Record(UsageMeterRecord)
}

type UsageMeterSummaryReader interface {
	Summary(tenantID string, periodStart, periodEnd time.Time) UsageMeterSummary
}

type UsageMeterRecordReader interface {
	UsageMeterRecords(tenantID string, periodStart, periodEnd time.Time) ([]UsageMeterRecord, error)
}

type UsageMeterStore struct {
	mu      sync.RWMutex
	records []UsageMeterRecord
	// index maps (tenant_id, record id) -> slice position so Record dedups in O(1). Without it Record scanned
	// the WHOLE records slice on every call to find a same-id record to replace — but decision records carry a
	// UNIQUE id per request, so the scan never matched, appended, and grew: O(N) per request -> O(N^2) under
	// load (~19% of Edge CPU in a profile). Only records with both id and tenant set are indexed (matching the
	// dedup guard below); records without an id are appended untracked, exactly as before.
	index map[string]int
	// capacity is a FIFO high-watermark for the IN-MEMORY store (<=0 = unbounded, the back-compat default).
	// Decision records carry a unique id per request, so without a bound the slice grows forever — a memory +
	// GC leak under sustained load (the other per-request edge stores, inspection + access-decision, are already
	// FIFO-bounded; production usage metering uses -usage-meter-store=postgres which is durable). When the slice
	// exceeds capacity it is trimmed to 3/4 capacity (hysteresis) so eviction amortizes to O(1) per Record, not
	// a rebuild every call. Governance seat records re-record on the next snapshot, so dropping an old one self-
	// heals; decision records are observability/proxy and FIFO-dropping the oldest is acceptable in memory mode.
	capacity int
}

func usageMeterIndexKey(tenantID, id string) string { return tenantID + "\x00" + id }

func NewUsageMeterStore(records ...UsageMeterRecord) *UsageMeterStore {
	return NewUsageMeterStoreWithCapacity(0, records...)
}

// NewUsageMeterStoreWithCapacity builds an in-memory store with a FIFO bound (capacity<=0 = unbounded).
func NewUsageMeterStoreWithCapacity(capacity int, records ...UsageMeterRecord) *UsageMeterStore {
	store := &UsageMeterStore{index: map[string]int{}, capacity: capacity}
	for _, r := range records {
		store.records = append(store.records, r)
		if r.ID != "" && r.TenantID != "" {
			store.index[usageMeterIndexKey(r.TenantID, r.ID)] = len(store.records) - 1
		}
	}
	store.evictIfOverCapacityLocked()
	return store
}

// evictIfOverCapacityLocked trims the oldest records down to 3/4 capacity when the high-watermark is exceeded
// and rebuilds the index for the kept records. Caller holds store.mu.
func (store *UsageMeterStore) evictIfOverCapacityLocked() {
	if store.capacity <= 0 || len(store.records) <= store.capacity {
		return
	}
	keep := store.capacity - store.capacity/4
	if keep < 1 {
		keep = 1
	}
	drop := len(store.records) - keep
	trimmed := make([]UsageMeterRecord, keep) // fresh backing array so the dropped records are GC'd
	copy(trimmed, store.records[drop:])
	store.records = trimmed
	store.index = make(map[string]int, keep)
	for i, r := range store.records {
		if r.ID != "" && r.TenantID != "" {
			store.index[usageMeterIndexKey(r.TenantID, r.ID)] = i
		}
	}
}

func (store *UsageMeterStore) Record(record UsageMeterRecord) {
	if store == nil {
		return
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.index == nil {
		store.index = map[string]int{}
	}
	if record.ID != "" && record.TenantID != "" {
		key := usageMeterIndexKey(record.TenantID, record.ID)
		if i, ok := store.index[key]; ok && i >= 0 && i < len(store.records) {
			store.records[i] = record // replace in place — O(1)
			return
		}
		store.records = append(store.records, record)
		store.index[key] = len(store.records) - 1
		store.evictIfOverCapacityLocked()
		return
	}
	store.records = append(store.records, record)
	store.evictIfOverCapacityLocked()
}

func (store *UsageMeterStore) Add(record UsageMeterRecord) {
	store.Record(record)
}

func (store *UsageMeterStore) Summary(tenantID string, periodStart, periodEnd time.Time) UsageMeterSummary {
	if store == nil {
		return SummarizeUsageMeterRecords(nil, tenantID, periodStart, periodEnd)
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	return SummarizeUsageMeterRecords(append([]UsageMeterRecord(nil), store.records...), tenantID, periodStart, periodEnd)
}

func (store *UsageMeterStore) UsageMeterRecords(tenantID string, periodStart, periodEnd time.Time) ([]UsageMeterRecord, error) {
	if store == nil {
		return nil, nil
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	records := make([]UsageMeterRecord, 0, len(store.records))
	for _, record := range store.records {
		if record.TenantID == tenantID && UsageMeterRecordOverlaps(record, periodStart, periodEnd) {
			records = append(records, record)
		}
	}
	return records, nil
}

type UsageMeterRecord struct {
	ID            string           `json:"id"`
	TenantID      string           `json:"tenant_id"`
	SchemaVersion string           `json:"schema_version"`
	PeriodStart   time.Time        `json:"period_start"`
	PeriodEnd     time.Time        `json:"period_end"`
	MeterType     string           `json:"meter_type"`
	SubjectType   string           `json:"subject_type"`
	SubjectID     *string          `json:"subject_id"`
	Quantity      float64          `json:"quantity"`
	Unit          string           `json:"unit"`
	Quota         *UsageMeterQuota `json:"quota"`
	Dimensions    map[string]any   `json:"dimensions"`
	CollectedAt   time.Time        `json:"collected_at"`
	Metadata      map[string]any   `json:"metadata"`
}

type UsageMeterQuota struct {
	QuotaID          string  `json:"quota_id"`
	IncludedQuantity float64 `json:"included_quantity"`
	OverageQuantity  float64 `json:"overage_quantity"`
	SoftCapExceeded  bool    `json:"soft_cap_exceeded"`
	HardCapExceeded  bool    `json:"hard_cap_exceeded"`
}

type UsageMeterSummary struct {
	TenantID    string                            `json:"tenant_id"`
	PeriodStart string                            `json:"period_start"`
	PeriodEnd   string                            `json:"period_end"`
	Records     int                               `json:"records"`
	Meters      map[string]UsageMeterMeterSummary `json:"meters"`
}

type UsageMeterHealth struct {
	TenantID       string   `json:"tenant_id"`
	Status         string   `json:"status"`
	Mode           string   `json:"mode"`
	Reasons        []string `json:"reasons"`
	CheckedAt      string   `json:"checked_at"`
	PendingRecords int      `json:"pending_records"`
	SpooledRecords int      `json:"spooled_records"`
	LastError      string   `json:"last_error,omitempty"`
}

type UsageMeterMeterSummary struct {
	MeterType   string                  `json:"meter_type"`
	Unit        string                  `json:"unit"`
	Aggregation string                  `json:"aggregation"`
	Quantity    float64                 `json:"quantity"`
	Subjects    int                     `json:"subjects"`
	Quota       *UsageMeterQuotaSummary `json:"quota,omitempty"`
}

type UsageMeterQuotaSummary struct {
	QuotaIDs         []string `json:"quota_ids"`
	IncludedQuantity float64  `json:"included_quantity"`
	OverageQuantity  float64  `json:"overage_quantity"`
	SoftCapExceeded  bool     `json:"soft_cap_exceeded"`
	HardCapExceeded  bool     `json:"hard_cap_exceeded"`
}

func SummarizeUsageMeterRecords(records []UsageMeterRecord, tenantID string, periodStart, periodEnd time.Time) UsageMeterSummary {
	records = DedupeUsageMeterRecords(records)
	summary := UsageMeterSummary{
		TenantID:    tenantID,
		PeriodStart: periodStart.UTC().Format(time.RFC3339),
		PeriodEnd:   periodEnd.UTC().Format(time.RFC3339),
		Meters:      map[string]UsageMeterMeterSummary{},
	}
	subjectsByMeter := map[string]map[string]bool{}
	quotaIDsByMeter := map[string]map[string]bool{}
	for _, record := range records {
		if record.TenantID != tenantID || !UsageMeterRecordOverlaps(record, periodStart, periodEnd) {
			continue
		}
		summary.Records++
		aggregation := UsageMeterAggregation(record.MeterType)
		meter := summary.Meters[record.MeterType]
		newMeter := meter.MeterType == ""
		if newMeter {
			meter = UsageMeterMeterSummary{
				MeterType:   record.MeterType,
				Unit:        record.Unit,
				Aggregation: aggregation,
			}
		}
		meter.Quantity = UsageMeterAggregate(meter.Quantity, record.Quantity, aggregation, newMeter)
		if meter.Unit == "" {
			meter.Unit = record.Unit
		}
		if subjectsByMeter[record.MeterType] == nil {
			subjectsByMeter[record.MeterType] = map[string]bool{}
		}
		subjectsByMeter[record.MeterType][UsageMeterSubjectKey(record)] = true
		meter.Subjects = len(subjectsByMeter[record.MeterType])
		if record.Quota != nil {
			newQuota := meter.Quota == nil
			if meter.Quota == nil {
				meter.Quota = &UsageMeterQuotaSummary{}
			}
			if quotaIDsByMeter[record.MeterType] == nil {
				quotaIDsByMeter[record.MeterType] = map[string]bool{}
			}
			if record.Quota.QuotaID != "" && !quotaIDsByMeter[record.MeterType][record.Quota.QuotaID] {
				quotaIDsByMeter[record.MeterType][record.Quota.QuotaID] = true
				meter.Quota.QuotaIDs = append(meter.Quota.QuotaIDs, record.Quota.QuotaID)
			}
			meter.Quota.IncludedQuantity = UsageMeterAggregate(meter.Quota.IncludedQuantity, record.Quota.IncludedQuantity, aggregation, newQuota)
			meter.Quota.OverageQuantity = UsageMeterAggregate(meter.Quota.OverageQuantity, record.Quota.OverageQuantity, aggregation, newQuota)
			meter.Quota.SoftCapExceeded = meter.Quota.SoftCapExceeded || record.Quota.SoftCapExceeded
			meter.Quota.HardCapExceeded = meter.Quota.HardCapExceeded || record.Quota.HardCapExceeded
		}
		summary.Meters[record.MeterType] = meter
	}
	return summary
}

func DedupeUsageMeterRecords(records []UsageMeterRecord) []UsageMeterRecord {
	if len(records) == 0 {
		return nil
	}
	result := make([]UsageMeterRecord, 0, len(records))
	indexByKey := map[string]int{}
	for _, record := range records {
		if strings.TrimSpace(record.ID) == "" || strings.TrimSpace(record.TenantID) == "" {
			result = append(result, record)
			continue
		}
		key := record.TenantID + "\x00" + record.ID
		if index, ok := indexByKey[key]; ok {
			result[index] = record
			continue
		}
		indexByKey[key] = len(result)
		result = append(result, record)
	}
	return result
}

func UsageMeterRecordOverlaps(record UsageMeterRecord, periodStart, periodEnd time.Time) bool {
	if record.PeriodEnd.IsZero() || record.PeriodStart.IsZero() {
		return false
	}
	return record.PeriodEnd.After(periodStart) && record.PeriodStart.Before(periodEnd)
}

func UsageMeterSubjectKey(record UsageMeterRecord) string {
	if record.SubjectID != nil && *record.SubjectID != "" {
		return record.SubjectType + ":" + *record.SubjectID
	}
	return record.SubjectType
}

func UsageMeterAggregation(meterType string) string {
	switch meterType {
	case "automation_concurrency", "decision_burst":
		return "peak_max"
	default:
		return "sum"
	}
}

func UsageMeterAggregate(current, next float64, aggregation string, first bool) float64 {
	if aggregation == "peak_max" {
		if first || next > current {
			return next
		}
		return current
	}
	return current + next
}

// UsageMeterHealthFor builds the store health snapshot. storeMode is injected by the caller (the edge
// glue type-switches on its concrete store type, including the Postgres-backed store, which this package
// does not import).
func UsageMeterHealthFor(store UsageMeterRuntimeStore, tenantID, storeMode string, now time.Time) UsageMeterHealth {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	health := UsageMeterHealth{
		TenantID:  tenantID,
		Status:    "ok",
		Mode:      storeMode,
		Reasons:   []string{},
		CheckedAt: now.UTC().Format(time.RFC3339),
	}
	if store == nil {
		health.Status = "unconfigured"
		health.Reasons = []string{"usage_meter_store_unconfigured"}
		return health
	}
	if reporter, ok := store.(interface {
		PendingRecordCounts(tenantID string) (memoryPending int, spooled int, err error)
	}); ok {
		memoryPending, spooled, err := reporter.PendingRecordCounts(tenantID)
		health.PendingRecords = memoryPending
		health.SpooledRecords = spooled
		if err != nil {
			health.Status = "degraded"
			health.Reasons = append(health.Reasons, "usage_meter_spool_error")
			health.LastError = "usage meter spool is unavailable"
		}
		if memoryPending > 0 || spooled > 0 {
			health.Status = "degraded"
			health.Reasons = append(health.Reasons, "usage_meter_pending_records")
		}
	}
	return health
}

func UsageMeterWindowFromQuery(values url.Values, now time.Time) (time.Time, time.Time, error) {
	periodStart := time.Date(now.UTC().Year(), now.UTC().Month(), 1, 0, 0, 0, 0, time.UTC)
	periodEnd := periodStart.AddDate(0, 1, 0)
	if raw := values.Get("period_start"); raw != "" {
		parsed, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			return time.Time{}, time.Time{}, fmt.Errorf("period_start must be RFC3339")
		}
		periodStart = parsed.UTC()
	}
	if raw := values.Get("period_end"); raw != "" {
		parsed, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			return time.Time{}, time.Time{}, fmt.Errorf("period_end must be RFC3339")
		}
		periodEnd = parsed.UTC()
	}
	if !periodEnd.After(periodStart) {
		return time.Time{}, time.Time{}, fmt.Errorf("period_end must be after period_start")
	}
	return periodStart, periodEnd, nil
}

func RecordUsageMeterDecision(store UsageMeterRuntimeStore, decision model.AccessDecision, now time.Time) {
	if store == nil {
		return
	}
	store.Record(UsageMeterRecordFromAccessDecision(decision, now))
}

func RecordUsageMeterGovernanceSnapshot(store UsageMeterRuntimeStore, tenantID string, humanSeatCount int, humanMeasurementScope string, registeredNHISeatCount int, periodStart, periodEnd, now time.Time) {
	if store == nil || strings.TrimSpace(tenantID) == "" {
		return
	}
	if humanSeatCount > 0 {
		humanMeasurementScope = valueOrDefault(strings.TrimSpace(humanMeasurementScope), "admin_auth_principals_proxy_until_identity_directory")
	}
	if usageMeterGovernanceSnapshotShouldWrite(store, "human_seat", tenantID, humanSeatCount, humanMeasurementScope, periodStart, periodEnd) {
		store.Record(UsageMeterGovernanceSeatRecord("human_seat", tenantID, humanSeatCount, periodStart, periodEnd, now, map[string]any{
			"billing_treatment": "subscription_base_observation",
			"measurement_scope": humanMeasurementScope,
			"human_seat_count":  humanSeatCount,
		}, map[string]any{
			"pricing_model":  "human_seat_base_with_observable_usage_controls",
			"billing_action": "observe_only",
		}))
	}
	nhiSeatCount := registeredNHISeatCount
	nhiMeasurementScope := "registered_nhi_registry_active"
	if nhiSeatCount <= 0 {
		nhiSeatCount = ObservedUsageMeterNHISeatCount(store, tenantID, periodStart, periodEnd)
		nhiMeasurementScope = "observed_nhi_identities_from_decision_meter"
	}
	if usageMeterGovernanceSnapshotShouldWrite(store, "nhi_seat", tenantID, nhiSeatCount, nhiMeasurementScope, periodStart, periodEnd) {
		store.Record(UsageMeterGovernanceSeatRecord("nhi_seat", tenantID, nhiSeatCount, periodStart, periodEnd, now, map[string]any{
			"billing_treatment": "governance_observation",
			"measurement_scope": nhiMeasurementScope,
			"active_nhi_count":  nhiSeatCount,
		}, map[string]any{
			"pricing_model":  "nhi_not_billable_seat_mvp",
			"billing_action": "observe_only",
		}))
	}
}

func UsageMeterGovernanceSeatRecord(meterType, tenantID string, quantity int, periodStart, periodEnd, now time.Time, dimensions, metadata map[string]any) UsageMeterRecord {
	return UsageMeterRecord{
		ID:            UsageMeterSnapshotID(meterType, tenantID, periodStart, periodEnd),
		TenantID:      tenantID,
		SchemaVersion: "usage_meter.v1",
		PeriodStart:   periodStart.UTC(),
		PeriodEnd:     periodEnd.UTC(),
		MeterType:     meterType,
		SubjectType:   "tenant",
		SubjectID:     stringPtr(tenantID),
		Quantity:      float64(quantity),
		Unit:          "seat",
		Dimensions:    dimensions,
		CollectedAt:   now.UTC(),
		Metadata:      metadata,
	}
}

func ObservedUsageMeterNHISeatCount(store UsageMeterRuntimeStore, tenantID string, periodStart, periodEnd time.Time) int {
	reader, ok := store.(UsageMeterRecordReader)
	if !ok {
		return 0
	}
	records, err := reader.UsageMeterRecords(tenantID, periodStart, periodEnd)
	if err != nil {
		log.Printf("usage meter governance snapshot could not read NHI observations: %v", err)
	}
	seen := map[string]bool{}
	for _, record := range records {
		if record.MeterType != "decision" {
			continue
		}
		if id := StringUsageMeterDimension(record.Dimensions, "actor_nhi_id"); id != "" {
			seen[id] = true
			continue
		}
		if record.SubjectType == "nhi" && record.SubjectID != nil && strings.TrimSpace(*record.SubjectID) != "" && *record.SubjectID != record.TenantID {
			seen[*record.SubjectID] = true
		}
	}
	return len(seen)
}

func StringUsageMeterDimension(dimensions map[string]any, key string) string {
	if dimensions == nil {
		return ""
	}
	switch value := dimensions[key].(type) {
	case string:
		return strings.TrimSpace(value)
	case *string:
		if value == nil {
			return ""
		}
		return strings.TrimSpace(*value)
	default:
		return ""
	}
}

func UsageMeterSnapshotID(meterType, tenantID string, periodStart, periodEnd time.Time) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{
		meterType,
		tenantID,
		periodStart.UTC().Format(time.RFC3339Nano),
		periodEnd.UTC().Format(time.RFC3339Nano),
	}, "\x00")))
	return "usage_" + meterType + "_snapshot_" + hex.EncodeToString(sum[:8])
}

func UsageMeterRecordFromAccessDecision(decision model.AccessDecision, now time.Time) UsageMeterRecord {
	periodStart := time.Date(now.UTC().Year(), now.UTC().Month(), 1, 0, 0, 0, 0, time.UTC)
	periodEnd := periodStart.AddDate(0, 1, 0)
	subjectType, subjectID := UsageMeterSubjectForAccessDecision(decision)
	return UsageMeterRecord{
		ID:            randomUsageMeterID("usage_decision_", now),
		TenantID:      decision.TenantID,
		SchemaVersion: "usage_meter.v1",
		PeriodStart:   periodStart,
		PeriodEnd:     periodEnd,
		MeterType:     "decision",
		SubjectType:   subjectType,
		SubjectID:     stringPtr(subjectID),
		Quantity:      1,
		Unit:          "decision",
		Dimensions: map[string]any{
			"actor_type":                stringValue(decision.ActorType),
			"actor_nhi_id":              stringPtrValue(decision.ActorNHIID),
			"subject_user_id":           stringPtrValue(decision.SubjectUserID),
			"delegated_access_grant_id": stringPtrValue(decision.DelegatedAccessGrantID),
			"application_id":            decision.ApplicationID,
			"source_stream":             "decision_traces",
			"decision_quota_basis":      "human_seat",
		},
		CollectedAt: now.UTC(),
		Metadata: map[string]any{
			"pricing_model":  "core_decision_quota_initial_hypothesis",
			"billing_action": "observe_only",
		},
	}
}

func UsageMeterSubjectForAccessDecision(decision model.AccessDecision) (string, string) {
	if decision.ActorNHIID != nil && *decision.ActorNHIID != "" {
		return "nhi", *decision.ActorNHIID
	}
	switch stringValue(decision.ActorType) {
	case "nhi":
		return "nhi", decision.TenantID
	case "delegated_agent", "ai_agent", "automation":
		return "system", decision.TenantID
	case "service_account", "system":
		return "system", decision.TenantID
	default:
		if decision.SubjectUserID != nil && *decision.SubjectUserID != "" {
			return "human", *decision.SubjectUserID
		}
		if decision.UserID != nil && *decision.UserID != "" {
			return "human", *decision.UserID
		}
		return "tenant", decision.TenantID
	}
}

func randomUsageMeterID(prefix string, fallback time.Time) string {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err == nil {
		return prefix + hex.EncodeToString(buf[:])
	} else {
		log.Printf("WARN: crypto/rand failed for usage meter id, falling back to process-local entropy: %v", err)
	}
	return fmt.Sprintf("%s%d_%d_%d", prefix, fallback.UTC().UnixNano(), os.Getpid(), UsageMeterIDFallbackCounter.Add(1))
}
