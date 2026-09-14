package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	_ "net/http/pprof" // DIAGNOSTIC: registers /debug/pprof on http.DefaultServeMux; served only when -pprof-listen is set
	"net/url"
	"strings"
	"time"

	// The IANA timezone database, compiled in. The runtime image is FROM scratch, so there is no
	// /usr/share/zoneinfo and time.LoadLocation would fail for EVERY zone — including the ones an operator
	// just typed into the Console. Validation that passes on a developer's machine and rejects everything in
	// the container is worse than no validation, because it looks like the operator's mistake.
	_ "time/tzdata"

	"github.com/lantern-networks/dsse-core/hotstore"
)

func adminLogFilenames() []string {
	return []string{
		"access.log.jsonl",
		"audit.log.jsonl",
		"decision_trace.log.jsonl",
		"connector.log.jsonl",
		"human_approval_events.log.jsonl",
		"delegated_access_grants.log.jsonl",
		"tool_call_events.log.jsonl",
		"inspection_events.log.jsonl",
		"config_generations.log.jsonl",
	}
}

func adminLogStreamFilename(stream string) (string, bool) {
	normalized := strings.TrimSpace(stream)
	if filename, ok := adminLogStreamFilenameMap()[normalized]; ok {
		return filename, true
	}
	return "", false
}

func adminLogStreamFilenameMap() map[string]string {
	aliases := map[string]string{
		"access":                  "access.log.jsonl",
		"audit":                   "audit.log.jsonl",
		"decision_trace":          "decision_trace.log.jsonl",
		"connector":               "connector.log.jsonl",
		"human_approval_events":   "human_approval_events.log.jsonl",
		"delegated_access_grants": "delegated_access_grants.log.jsonl",
		"tool_call_events":        "tool_call_events.log.jsonl",
		"inspection_events":       "inspection_events.log.jsonl",
		"device_state":            "device_state.log.jsonl",
		"config_generations":      "config_generations.log.jsonl",
	}
	return aliases
}

type unknownAdminLogStreamError struct {
	stream string
}

func (err unknownAdminLogStreamError) Error() string {
	return fmt.Sprintf("unknown admin log stream %q", err.stream)
}

func adminLogQuery(store hotstore.Store, tenantID, stream string, query url.Values) (map[string]any, error) {
	result, err := adminLogSearch(store, tenantID, stream, query)
	if err != nil {
		return nil, err
	}
	return result.response(), nil
}

func adminLogExport(store hotstore.Store, tenantID, stream string, query url.Values) (adminLogSearchResult, error) {
	result, err := adminLogSearch(store, tenantID, stream, query)
	if err != nil {
		return adminLogSearchResult{}, err
	}
	return result, nil
}

type adminLogRegionCoverage struct {
	Status             string `json:"status"`
	UnknownRegionCount *int64 `json:"unknown_region_count"`
}

type adminLogSearchResult struct {
	regionCoverage *adminLogRegionCoverage
	stream         string
	limit          int
	filters        map[string]string
	query          string
	totalScanned   int
	totalMatches   int
	nextCursor     *string
	rows           []map[string]any
}

func (result adminLogSearchResult) response() map[string]any {
	return map[string]any{
		"region_coverage": result.regionCoverage,
		"stream":          result.stream,
		"limit":           result.limit,
		"filters":         result.filters,
		"query":           result.query,
		"total_scanned":   result.totalScanned,
		"total_matches":   result.totalMatches,
		"returned":        len(result.rows),
		"next_cursor":     result.nextCursor,
		"rows":            result.rows,
	}
}

func adminLogSearch(store hotstore.Store, tenantID, stream string, query url.Values) (adminLogSearchResult, error) {
	return adminLogSearchWithLimitBounds(store, tenantID, stream, query, 25, 200)
}

func adminLogSearchWithLimitBounds(store hotstore.Store, tenantID, stream string, query url.Values, defaultLimit, maxLimit int) (adminLogSearchResult, error) {
	if store == nil {
		return adminLogSearchResult{}, fmt.Errorf("hot store is not configured")
	}
	searchQuery, err := adminLogSearchQuery(tenantID, stream, query, defaultLimit, maxLimit)
	if err != nil {
		return adminLogSearchResult{}, err
	}
	result, err := store.Search(context.Background(), searchQuery)
	if err != nil {
		return adminLogSearchResult{}, err
	}

	var coverage *adminLogRegionCoverage
	if strings.TrimSpace(searchQuery.Filters["edge_region_id"]) != "" {
		coverage = &adminLogRegionCoverage{Status: "unavailable"}
		if counter, ok := store.(hotstore.UnknownRegionCounter); ok {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			count, countErr := counter.CountUnknownRegion(ctx, searchQuery)
			cancel()
			if countErr == nil && count >= 0 {
				coverage.Status = "available"
				coverage.UnknownRegionCount = &count
			}
		}
	}
	return adminLogSearchResult{
		regionCoverage: coverage,
		stream:         result.Stream,
		limit:          result.Limit,
		filters:        result.Filters,
		query:          result.Query,
		totalScanned:   result.TotalScanned,
		totalMatches:   result.TotalMatches,
		nextCursor:     result.NextCursor,
		rows:           result.Rows,
	}, nil
}

func adminLogSearchQuery(tenantID, stream string, query url.Values, defaultLimit, maxLimit int) (hotstore.SearchQuery, error) {
	if _, ok := adminLogStreamFilename(stream); !ok {
		return hotstore.SearchQuery{}, unknownAdminLogStreamError{stream: stream}
	}
	from, to, err := adminLogTimeRange(query)
	if err != nil {
		return hotstore.SearchQuery{}, err
	}
	return hotstore.SearchQuery{
		TenantID: tenantID,
		Stream:   stream,
		Filters:  adminLogFilters(query),
		Text:     strings.ToLower(strings.TrimSpace(query.Get("q"))),
		From:     from,
		To:       to,
		Limit:    boundedIntQuery(query.Get("limit"), defaultLimit, 1, maxLimit),
		Cursor:   strings.TrimSpace(query.Get("cursor")),
	}, nil
}

func adminLogTimeRange(query url.Values) (*time.Time, *time.Time, error) {
	var from *time.Time
	var to *time.Time
	if raw := strings.TrimSpace(query.Get("from")); raw != "" {
		parsed, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			return nil, nil, fmt.Errorf("parse from: %w", err)
		}
		from = &parsed
	}
	if raw := strings.TrimSpace(query.Get("to")); raw != "" {
		parsed, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			return nil, nil, fmt.Errorf("parse to: %w", err)
		}
		to = &parsed
	}
	return from, to, nil
}

func adminLogRowWithinTimeRange(row map[string]any, from, to *time.Time) bool {
	if from == nil && to == nil {
		return true
	}
	raw := firstNonEmptyString(row["timestamp"], row["occurred_at"], row["created_at"])
	if raw == "" {
		return false
	}
	timestamp, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return false
	}
	if from != nil && timestamp.Before(*from) {
		return false
	}
	if to != nil && timestamp.After(*to) {
		return false
	}
	return true
}

func adminLogFilters(query url.Values) map[string]string {
	filterableFields := []string{
		"id",
		"tenant_id",
		// ★ WHICH REGION THE RECORD CAME FROM (2026-08-24). Until the region became a column it lived inside
		// the record's JSON, and only for some streams, so "show me this region's records" could not be asked
		// at all. It is the question every residency answer starts from — what may be retained, exported or
		// deleted for one region cannot be decided before it can be SELECTED.
		"edge_region_id",
		"access_decision_id",
		"decision",
		"application_id",
		"destination",
		"user_id",
		"subject_user_id",
		"device_id",
		"actor_type",
		"actor_nhi_id",
		"session_id",
		"policy_id",
		"service_family",
		"event_type",
		"tool_id",
		"human_approval_event_id",
		"delegated_access_grant_id",
		"inspection_event_id",
	}
	filters := map[string]string{}
	for _, field := range filterableFields {
		value := strings.TrimSpace(query.Get(field))
		if value != "" {
			filters[field] = value
		}
	}
	return filters
}

func adminLogRowMatches(row map[string]any, filters map[string]string, textQuery string) bool {
	for field, expected := range filters {
		if stringValue(row[field]) != expected {
			return false
		}
	}
	if textQuery == "" {
		return true
	}
	encoded, err := json.Marshal(row)
	if err != nil {
		return false
	}
	return strings.Contains(strings.ToLower(string(encoded)), textQuery)
}

func statusForAdminLogQueryError(err error) int {
	var unknownStream unknownAdminLogStreamError
	if errors.As(err, &unknownStream) {
		return http.StatusNotFound
	}
	return http.StatusBadRequest
}
