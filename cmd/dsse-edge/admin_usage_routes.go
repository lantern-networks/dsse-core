package main

import (
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/hotstore"
	humanidentity "github.com/lantern-networks/dsse-core/humanidentity"
	nhi "github.com/lantern-networks/dsse-core/nhi"
	usagemeter "github.com/lantern-networks/dsse-core/usagemeter"
)

// Admin ops-health readers — auth-store health, usage summary/health, and the
// event-activity trend rollup — moved verbatim out of newServerWithConfig (Phase 2
// route-registration split). Parameter names match the constructor's locals.
func registerUsageEventsRoutes(mux *http.ServeMux, adminEndpoint func(string, http.HandlerFunc) http.HandlerFunc, adminAuth adminAuthRuntimeStore, usageMeters usagemeter.UsageMeterRuntimeStore, adminHotStore hotstore.Store, humanIdentities humanidentity.HumanIdentityDirectoryRuntimeStore, nonHumanIdentities nhi.RuntimeStore) {
	mux.HandleFunc("GET /admin/auth/health", adminEndpoint("admin.state.read", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, adminAuthStoreHealthFor(r.Context(), adminAuth, adminTenantIDFromRequest(r), time.Now()))
	}))
	mux.HandleFunc("GET /admin/usage/summary", adminEndpoint("admin.usage.read", func(w http.ResponseWriter, r *http.Request) {
		now := time.Now()
		periodStart, periodEnd, err := usagemeter.UsageMeterWindowFromQuery(r.URL.Query(), now)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		tenantID := adminTenantIDFromRequest(r)
		if !now.UTC().Before(periodStart.UTC()) && now.UTC().Before(periodEnd.UTC()) {
			if stats, err := adminAuthStatsFor(r.Context(), adminAuth, tenantID); err == nil {
				humanSeatCount := stats.Principals
				humanMeasurementScope := "admin_auth_principals_proxy_until_identity_directory"
				if directoryStats, err := humanIdentities.Stats(r.Context(), tenantID, now); err == nil {
					if directoryStats.Total > 0 {
						humanSeatCount = directoryStats.Active
						humanMeasurementScope = "identity_directory_active_humans"
					}
				} else {
					log.Printf("usage meter governance snapshot could not read identity directory: %v", err)
				}
				registeredNHI := 0
				if count, err := nonHumanIdentities.CountActive(r.Context(), tenantID, now); err == nil {
					registeredNHI = count
				} else {
					log.Printf("usage meter governance snapshot could not read NHI registry: %v", err)
				}
				usagemeter.RecordUsageMeterGovernanceSnapshot(usageMeters, tenantID, humanSeatCount, humanMeasurementScope, registeredNHI, periodStart, periodEnd, now)
			} else {
				log.Printf("usage meter governance snapshot skipped: %v", err)
			}
		}
		writeJSON(w, http.StatusOK, usageMeters.Summary(tenantID, periodStart, periodEnd))
	}))
	mux.HandleFunc("GET /admin/usage/health", adminEndpoint("admin.usage.read", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, usagemeter.UsageMeterHealthFor(usageMeters, adminTenantIDFromRequest(r), usageMeterStoreMode(usageMeters), time.Now()))
	}))
	// Event-activity time series for the tenant, served from the ingest-time ROLLUP (event_log_design.md/) —
	// per-(bucket, stream, finding_type, action) counts + distinct users/destinations/devices — so the query cost
	// is independent of raw flow count. Backed by the ClickHouse materialized view; returns 501 on a hot store that
	// keeps no rollup (JSONL/Postgres). Params: from/to (RFC3339), granularity (5m|1h|1d), optional stream +
	// finding_type filters. strictly scoped to the requesting admin's authenticated tenant.
	mux.HandleFunc("GET /admin/events/trends", adminEndpoint("admin.usage.read", func(w http.ResponseWriter, r *http.Request) {
		tenantID := adminTenantIDFromRequest(r)
		if strings.TrimSpace(tenantID) == "" {
			writeError(w, http.StatusForbidden, fmt.Errorf("admin tenant is required for event trends"))
			return
		}
		trender, ok := adminHotStore.(hotstore.TrendsCapable)
		if !ok {
			writeError(w, http.StatusNotImplemented, fmt.Errorf("event trends require a rollup-capable hot store (ClickHouse); the configured backend keeps no ingest-time rollup"))
			return
		}
		q := hotstore.TrendsQuery{
			TenantID:    tenantID,
			Granularity: r.URL.Query().Get("granularity"),
			Stream:      r.URL.Query().Get("stream"),
			FindingType: r.URL.Query().Get("finding_type"),
		}
		if v := strings.TrimSpace(r.URL.Query().Get("from")); v != "" {
			t, err := time.Parse(time.RFC3339, v)
			if err != nil {
				writeError(w, http.StatusBadRequest, fmt.Errorf("invalid from (want RFC3339): %w", err))
				return
			}
			q.From = &t
		}
		if v := strings.TrimSpace(r.URL.Query().Get("to")); v != "" {
			t, err := time.Parse(time.RFC3339, v)
			if err != nil {
				writeError(w, http.StatusBadRequest, fmt.Errorf("invalid to (want RFC3339): %w", err))
				return
			}
			q.To = &t
		}
		res, err := trender.Trends(r.Context(), q)
		if err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("event trends: %w", err))
			return
		}
		writeJSON(w, http.StatusOK, res)
	}))
}
