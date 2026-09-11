package usagemeter

import (
	"log"
	"strings"
	"time"
)

// ★ THE SEAT NUMBER USED TO BE FIXED BY WHOEVER ASKED FIRST (2026-08-19, measured on the reference lab).
//
// The governance snapshot was written only if the period had no record yet — `if _, ok := existing.Meters[...];
// !ok`. So the FIRST node to answer a usage summary in a billing period decided the number for that period and
// nothing ever revised it. Demonstrated live: suspending one person took the directory from 43 active to 42
// and the recorded seat count stayed at 43 for the rest of the month.
//
// It is safe to re-record because the record ID is deterministic in (meter type, tenant, period) and both
// backends upsert by it — the memory store replaces in place, Postgres has ON CONFLICT DO UPDATE. A refreshed
// snapshot REPLACES the period's row; it does not add a second one that a "sum" aggregation would double-count.
//
// ★ BUT A GUESS MUST NOT OVERWRITE A MEASUREMENT. Two nodes answer for the same tenant, and they do not know
// the same things: an Edge whose directory has not arrived counts admin principals as a PROXY, while a node
// holding the directory counts the actual people. Refreshing blindly would let whichever node was asked last
// win, so a proxy could overwrite a real count — the same defect wearing the opposite mask. A node may only
// overwrite a record measured with a scope no stronger than its own.
var usageMeterScopeStrength = map[string]int{
	// Counted from the thing being measured.
	"identity_directory_active_humans": 2,
	"registered_nhi_registry_active":   2,
	// Stood in for it because the real source was not available on this node.
	"admin_auth_principals_proxy_until_identity_directory": 1,
	"observed_nhi_identities_from_decision_meter":          1,
}

func usageMeterMeasurementStrength(scope string) int {
	if strength, ok := usageMeterScopeStrength[strings.TrimSpace(scope)]; ok {
		return strength
	}
	// An unrecognised scope is treated as the weakest thing that can still be written: it may establish a
	// record where there is none, and may not displace one whose provenance this code understands.
	return 0
}

// usageMeterGovernanceSnapshotShouldWrite reports whether this node should write the period's governance
// snapshot for a meter: yes when there is nothing recorded, when the value has moved, or when this node
// measures it better than whatever is there. No when it would only restate what is already recorded, and no
// when this node is guessing at something another node measured.
func usageMeterGovernanceSnapshotShouldWrite(store UsageMeterRuntimeStore, meterType, tenantID string, quantity int, scope string, periodStart, periodEnd time.Time) bool {
	if store == nil || quantity <= 0 {
		return false
	}
	existing, found := usageMeterGovernanceSnapshot(store, meterType, tenantID, periodStart, periodEnd)
	if !found {
		return true
	}
	mine := usageMeterMeasurementStrength(scope)
	theirs := usageMeterMeasurementStrength(StringUsageMeterDimension(existing.Dimensions, "measurement_scope"))
	if mine < theirs {
		return false
	}
	if mine > theirs {
		return true
	}
	return int(existing.Quantity) != quantity
}

// usageMeterGovernanceSnapshot returns the period's recorded snapshot for a meter type. A store that cannot be
// read reports "not found", which makes this node write — an unreadable store must not silently freeze a
// number, and the write is an upsert on a deterministic id, so the worst case is restating the same value.
func usageMeterGovernanceSnapshot(store UsageMeterRuntimeStore, meterType, tenantID string, periodStart, periodEnd time.Time) (UsageMeterRecord, bool) {
	reader, ok := store.(UsageMeterRecordReader)
	if !ok {
		return UsageMeterRecord{}, false
	}
	records, err := reader.UsageMeterRecords(tenantID, periodStart, periodEnd)
	if err != nil {
		log.Printf("usage meter governance snapshot could not read the recorded %s: %v", meterType, err)
		return UsageMeterRecord{}, false
	}
	wanted := UsageMeterSnapshotID(meterType, tenantID, periodStart, periodEnd)
	for _, record := range records {
		if record.ID == wanted {
			return record, true
		}
	}
	return UsageMeterRecord{}, false
}
