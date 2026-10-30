package main

import (
	"strings"
	"sync"
	"time"

	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/revocation"
)

// DLP → device risk (S4, ). Individual DLP detections are noise; the
// actionable signal is a DEVICE behaving abnormally. A RAW COUNT is meaningless (false positives dominate), so a
// device's risk is raised only when its recent detections satisfy a COMPOSITE CONDITION — an AND of volume +
// type-diversity + destination-concentration + burst-window + destination-class. Diversity is the strongest FP
// filter: a single type dribbling to one benign host never trips; a real exfil (many distinct confidential types
// to one place in a burst) does. The conditions live on the DLP Policy that produced the detection.

// deviceRiskMarker marks a device elevated-risk (satisfied by *revocation.HighRiskOverlay).
type deviceRiskMarker interface {
	RaiseDeviceRisk(deviceID, severity string) (revocation.AutomaticRiskResult, error)
}

// dlpDetectionRecord is one device's DLP detection: the identifier types found, where it was going, the
// destination instance class, and when.
type dlpDetectionRecord struct {
	tenantID      string
	types         []string
	destination   string
	instanceClass string // "" | corporate | personal
	at            time.Time
	retainUntil   time.Time
}

type dlpRiskOwner struct{ tenant, device string }

type dlpDeviceRiskAggregator struct {
	mu     sync.Mutex
	hits   map[dlpRiskOwner][]dlpDetectionRecord
	marker deviceRiskMarker
}

func newDLPDeviceRiskAggregator(marker deviceRiskMarker) *dlpDeviceRiskAggregator {
	return &dlpDeviceRiskAggregator{hits: map[dlpRiskOwner][]dlpDetectionRecord{}, marker: marker}
}

type dlpDeviceRiskResult struct {
	ConditionSeverity string // strongest satisfied condition, not an acknowledgement
	revocation.AutomaticRiskResult
	Err error
}

// Record notes a detection for a device and evaluates the given device-risk conditions (from the matched DLP
// policy). Separates the satisfied condition from application and storage. No-op when the
// device id is empty, there are no conditions, or the record carries no types.
func (a *dlpDeviceRiskAggregator) Record(deviceID string, rec dlpDetectionRecord, conditions []model.DLPDeviceRiskCondition, now time.Time) dlpDeviceRiskResult {
	result := dlpDeviceRiskResult{}
	tenant := strings.TrimSpace(rec.tenantID)
	deviceID = strings.TrimSpace(deviceID)
	if a == nil || tenant == "" || deviceID == "" || len(conditions) == 0 || len(rec.types) == 0 {
		return result
	}
	rec.at = now
	rec.types = append([]string(nil), rec.types...)
	// Retain each detection for the longest window of the policy that
	// produced it. A later short-window policy must not erase that history.
	var retention time.Duration
	for _, c := range conditions {
		if window := deviceRiskWindow(c.WindowSeconds); window > retention {
			retention = window
		}
	}
	rec.retainUntil = now.Add(retention)
	owner := dlpRiskOwner{tenant, deviceID}
	a.mu.Lock()
	kept := a.hits[owner][:0]
	for _, r := range a.hits[owner] {
		if r.retainUntil.After(now) {
			kept = append(kept, r)
		}
	}
	kept = append(kept, rec)
	a.hits[owner] = kept
	records := append([]dlpDetectionRecord(nil), kept...)
	marker := a.marker
	a.mu.Unlock()

	// Evaluate every condition so policy order cannot weaken the requested mark.
	ranks := map[string]int{"medium": 1, "high": 2, "critical": 3}
	for _, c := range conditions {
		severity := evaluateDeviceRiskCondition(records, c, now)
		if severity != "" && (result.ConditionSeverity == "" || ranks[severity] > ranks[result.ConditionSeverity]) {
			result.ConditionSeverity = severity
		}
	}
	if result.ConditionSeverity != "" {
		result.AutomaticRiskResult.Persistence = "not_attempted"
		if marker == nil {
			result.Err = revocation.ErrRiskUnavailable
		} else {
			result.AutomaticRiskResult, result.Err = marker.RaiseDeviceRisk(deviceID, result.ConditionSeverity)
		}
	}
	return result
}

// evaluateDeviceRiskCondition reports the severity to set if the device's records satisfy the condition, else "".
// A condition is an AND of: enough records (min_count) AND enough distinct types (min_distinct_types), within the
// window, optionally only to personal/outside-org or unverified destinations, and — when same_destination — concentrated on a
// single destination.
func evaluateDeviceRiskCondition(records []dlpDetectionRecord, c model.DLPDeviceRiskCondition, now time.Time) string {
	window := deviceRiskWindow(c.WindowSeconds)
	cutoff := now.Add(-window)

	// In-window records, honoring the destination-class filter.
	var inWindow []dlpDetectionRecord
	for _, r := range records {
		if !r.at.After(cutoff) {
			continue
		}
		if !dlpInstanceScopeApplies(c.DestinationClass, r.instanceClass) {
			continue
		}
		inWindow = append(inWindow, r)
	}
	if len(inWindow) == 0 {
		return ""
	}

	severity := strings.ToLower(strings.TrimSpace(c.Severity))
	if severity == "" {
		severity = "high"
	}

	if c.SameDestination {
		// Evaluate per destination: one destination must satisfy count + diversity (single-place exfil).
		byDest := map[string][]dlpDetectionRecord{}
		for _, r := range inWindow {
			byDest[r.destination] = append(byDest[r.destination], r)
		}
		for _, group := range byDest {
			if deviceRiskCountAndDiversityMet(group, c) {
				return severity
			}
		}
		return ""
	}
	if deviceRiskCountAndDiversityMet(inWindow, c) {
		return severity
	}
	return ""
}

func deviceRiskWindow(seconds int) time.Duration {
	if seconds <= 0 {
		return time.Hour
	}
	// Saturate at time.Duration's representable limit; never wrap a valid
	// long configured window into the one-hour default.
	const maxDuration = time.Duration(1<<63 - 1)
	if uint64(seconds) > uint64(maxDuration/time.Second) {
		return maxDuration
	}
	return time.Duration(seconds) * time.Second
}

func deviceRiskCountAndDiversityMet(records []dlpDetectionRecord, c model.DLPDeviceRiskCondition) bool {
	if c.MinCount > 0 && len(records) < c.MinCount {
		return false
	}
	if c.MinDistinctTypes > 0 {
		distinct := map[string]bool{}
		for _, r := range records {
			for _, t := range r.types {
				distinct[t] = true
			}
		}
		if len(distinct) < c.MinDistinctTypes {
			return false
		}
	}
	return true
}
