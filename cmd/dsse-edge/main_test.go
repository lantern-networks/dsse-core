package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	agenttelemetry "github.com/lantern-networks/dsse-core/agenttelemetry"
	"github.com/lantern-networks/dsse-core/edgeplane"
	humanidentity "github.com/lantern-networks/dsse-core/humanidentity"
	nhi "github.com/lantern-networks/dsse-core/nhi"
	swg "github.com/lantern-networks/dsse-core/swg"
	usagemeter "github.com/lantern-networks/dsse-core/usagemeter"

	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/decision"
	devicestore "github.com/lantern-networks/dsse-core/device"
	"github.com/lantern-networks/dsse-core/hotstore"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
	sessionstore "github.com/lantern-networks/dsse-core/session"
	"github.com/lantern-networks/dsse-core/swghttprewrite"
	"github.com/lantern-networks/dsse-core/tunnel"
)

type recordingHotStore struct {
	query       hotstore.SearchQuery
	exportQuery hotstore.SearchQuery
}

type failingGeneratedObjectStore struct {
	readErr error
}

func (store failingGeneratedObjectStore) WriteGzipJSONL(string, []map[string]any) (string, error) {
	return "", fmt.Errorf("unexpected WriteGzipJSONL")
}

func (store failingGeneratedObjectStore) WriteGzipJSONLStream(string, func() (map[string]any, bool, error)) (string, error) {
	return "", fmt.Errorf("unexpected WriteGzipJSONLStream")
}

func (store failingGeneratedObjectStore) ReadGeneratedFile(string) ([]byte, error) {
	if store.readErr != nil {
		return nil, store.readErr
	}
	return nil, fmt.Errorf("read failed")
}

func (store failingGeneratedObjectStore) ListGeneratedFiles(string, string, int) ([]string, error) {
	return nil, fmt.Errorf("unexpected ListGeneratedFiles")
}

func auditLogEventTypes(audits []model.AuditLog) map[string]bool {
	events := map[string]bool{}
	for _, audit := range audits {
		events[audit.EventType] = true
	}
	return events
}

func TestAppendAdminAuditMirrorsToOutboxBestEffort(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	outbox := &recordingAdminAuditOutboxDeadReader{insertErr: fmt.Errorf("outbox down")}
	audit := model.AuditLog{
		ID:        "audit_admin_api_token_rotated_test",
		TenantID:  "tenant_lab_001",
		EventType: "admin_api_token_rotated",
		Timestamp: time.Date(2026, 5, 24, 1, 0, 0, 0, time.UTC).Format(time.RFC3339),
		Metadata:  map[string]any{"admin_api_token_id": "admin_token_new_001"},
	}

	if err := appendAdminAudit(context.Background(), writer, outbox, audit, time.Date(2026, 5, 24, 1, 0, 1, 0, time.UTC)); err != nil {
		t.Fatalf("appendAdminAudit returned error: %v", err)
	}
	rows, err := readAuditRowsExcludingWrapper(writer)
	if err != nil {
		t.Fatalf("ReadJSONL returned error: %v", err)
	}
	if got, want := len(rows), 1; got != want {
		t.Fatalf("audit row count = %d, want %d", got, want)
	}
	if rows[0]["event_type"] != "admin_api_token_rotated" {
		t.Fatalf("audit row = %#v, want token rotation event", rows[0])
	}
	if got, want := len(outbox.insertedAudits), 1; got != want {
		t.Fatalf("outbox inserted audit count = %d, want %d", got, want)
	}
}

func (store *recordingHotStore) Search(_ context.Context, query hotstore.SearchQuery) (hotstore.SearchResult, error) {
	store.query = query
	filters := map[string]string{}
	for key, value := range query.Filters {
		filters[key] = value
	}
	filters["tenant_id"] = query.TenantID
	return hotstore.SearchResult{
		Stream:       query.Stream,
		Limit:        query.Limit,
		Filters:      filters,
		Query:        query.Text,
		TotalScanned: 1,
		TotalMatches: 1,
		Rows: []map[string]any{
			{"id": "hot_001", "tenant_id": query.TenantID, "stream": query.Stream, "decision": filters["decision"]},
		},
	}, nil
}

func (store *recordingHotStore) ExportRows(_ context.Context, query hotstore.SearchQuery, yield hotstore.RowHandler) (hotstore.ExportResult, error) {
	store.exportQuery = query
	rows := []map[string]any{
		{"id": "export_hot_001", "tenant_id": query.TenantID, "stream": query.Stream, "decision": query.Filters["decision"]},
		{"id": "export_hot_002", "tenant_id": query.TenantID, "stream": query.Stream, "decision": query.Filters["decision"]},
	}
	for _, row := range rows {
		if err := yield(row); err != nil {
			return hotstore.ExportResult{}, err
		}
	}
	filters := map[string]string{}
	for key, value := range query.Filters {
		filters[key] = value
	}
	filters["tenant_id"] = query.TenantID
	return hotstore.ExportResult{
		Stream:       query.Stream,
		Limit:        query.Limit,
		Filters:      filters,
		Query:        query.Text,
		TotalScanned: len(rows),
		TotalMatches: len(rows),
		RowsExported: len(rows),
	}, nil
}

func (store *recordingHotStore) RelatedByAccessDecisionID(_ context.Context, query hotstore.RelatedLogQuery) (hotstore.RelatedLogResult, error) {
	return hotstore.RelatedLogResult{
		AccessDecisionID: query.AccessDecisionID,
		TotalRows:        1,
		RowsByStream: map[string][]map[string]any{
			"access": {
				{"id": "hot_related_001", "tenant_id": query.TenantID, "access_decision_id": query.AccessDecisionID},
			},
		},
	}, nil
}

type cancellingHotStore struct {
	jobStore *adminExportJobStore
	jobID    string
}

func (store *cancellingHotStore) Search(_ context.Context, query hotstore.SearchQuery) (hotstore.SearchResult, error) {
	return hotstore.SearchResult{Stream: query.Stream, Limit: query.Limit}, nil
}

func (store *cancellingHotStore) ExportRows(_ context.Context, query hotstore.SearchQuery, yield hotstore.RowHandler) (hotstore.ExportResult, error) {
	jobID := store.jobID
	if jobID == "" {
		for _, job := range store.jobStore.List(query.TenantID) {
			if job.Status == "running" {
				jobID = job.ID
				break
			}
		}
	}
	if jobID == "" {
		return hotstore.ExportResult{}, fmt.Errorf("running export job is absent")
	}
	if _, err := store.jobStore.MarkCancelled(jobID, query.TenantID, "admin_lab_bypass", "test_cancel", time.Now()); err != nil {
		return hotstore.ExportResult{}, err
	}
	if err := yield(map[string]any{"id": "row_cancelled", "tenant_id": query.TenantID}); err != nil {
		return hotstore.ExportResult{}, err
	}
	return hotstore.ExportResult{
		Stream:       query.Stream,
		Limit:        query.Limit,
		Filters:      map[string]string{"tenant_id": query.TenantID},
		TotalScanned: 1,
		TotalMatches: 1,
		RowsExported: 1,
	}, nil
}

func (store *cancellingHotStore) RelatedByAccessDecisionID(_ context.Context, query hotstore.RelatedLogQuery) (hotstore.RelatedLogResult, error) {
	return hotstore.RelatedLogResult{AccessDecisionID: query.AccessDecisionID, RowsByStream: map[string][]map[string]any{}}, nil
}

type contextCancellingHotStore struct {
	cancel context.CancelFunc
}

func (store *contextCancellingHotStore) Search(_ context.Context, query hotstore.SearchQuery) (hotstore.SearchResult, error) {
	return hotstore.SearchResult{Stream: query.Stream, Limit: query.Limit}, nil
}

func (store *contextCancellingHotStore) ExportRows(ctx context.Context, query hotstore.SearchQuery, yield hotstore.RowHandler) (hotstore.ExportResult, error) {
	if store.cancel != nil {
		store.cancel()
	}
	<-ctx.Done()
	return hotstore.ExportResult{
		Stream:       query.Stream,
		Limit:        query.Limit,
		Filters:      map[string]string{"tenant_id": query.TenantID},
		TotalScanned: 0,
		TotalMatches: 0,
		RowsExported: 0,
	}, ctx.Err()
}

func (store *contextCancellingHotStore) RelatedByAccessDecisionID(_ context.Context, query hotstore.RelatedLogQuery) (hotstore.RelatedLogResult, error) {
	return hotstore.RelatedLogResult{AccessDecisionID: query.AccessDecisionID, RowsByStream: map[string][]map[string]any{}}, nil
}

func TestHealthzHandler(t *testing.T) {
	handler := newTestHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if !strings.Contains(rec.Body.String(), `"status":"ok"`) {
		t.Fatalf("body = %s, want status ok", rec.Body.String())
	}
}

func TestAdminStateSummarizesRuntimeStores(t *testing.T) {
	logDir := t.TempDir()
	writer, err := logs.NewWriter(logDir)
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	evaluator := testEvaluator()
	registry := connector.NewRegistry()
	if _, err := registry.Register(model.ConnectorRegistration{
		ID:               "conn_lab_001",
		TenantID:         "tenant_lab_001",
		ConnectorGroupID: "cg_lab_001",
		PrivateBaseURL:   "http://127.0.0.1:18091",
		ApplicationIDs:   []string{"app_dummy_https"},
	}, time.Now()); err != nil {
		t.Fatalf("register connector returned error: %v", err)
	}
	if _, err := registry.Register(model.ConnectorRegistration{
		ID:               "conn_other_001",
		TenantID:         "tenant_other",
		ConnectorGroupID: "cg_other_001",
		PrivateBaseURL:   "http://127.0.0.1:18092",
		ApplicationIDs:   []string{"app_dummy_https"},
	}, time.Now()); err != nil {
		t.Fatalf("register other tenant connector returned error: %v", err)
	}
	devices := devicestore.NewStore()
	if _, err := devices.Register(model.Device{
		ID:       "dev_lab_001",
		TenantID: "tenant_lab_001",
		UserID:   "user_lab_001",
	}, evaluator.PolicyBundle, time.Now()); err != nil {
		t.Fatalf("register device returned error: %v", err)
	}
	humanApprovals := newHumanApprovalEventStore()
	if _, err := humanApprovals.Upsert(model.HumanApprovalEvent{ID: "hae_lab_001", TenantID: "tenant_lab_001", ActorNHIID: stringPtr("nhi_soc_agent_001"), ActionType: stringPtr("ticket:create"), ApprovalResult: "approved"}); err != nil {
		t.Fatalf("upsert human approval returned error: %v", err)
	}
	delegatedGrants := newDelegatedAccessGrantStore()
	if _, err := delegatedGrants.Upsert(model.DelegatedAccessGrant{ID: "dag_lab_001", TenantID: "tenant_lab_001", SubjectUserID: "user_lab_001", ActorNHIID: "nhi_soc_agent_001", Status: "active", ExpiresAt: time.Now().Add(time.Minute).UTC().Format(time.RFC3339)}); err != nil {
		t.Fatalf("upsert delegated grant returned error: %v", err)
	}
	decisionStore := newAccessDecisionStore()
	decisionStore.Upsert(model.AccessDecision{ID: "dec_lab_001", TenantID: "tenant_lab_001", ActorType: "human", ApplicationID: "app_dummy_https", PolicyID: "pol_lab_https_allow_001", PolicyBundleID: evaluator.PolicyBundle.ID, PolicyBundleVersion: evaluator.PolicyBundle.Version, Decision: "allow", ReasonCodes: []string{"policy_matched"}, Actions: []model.DecisionAction{}, CacheStatus: "miss", TTLSeconds: 60})
	inspectionEvents := newInspectionEventStore()
	inspectionEvents.Upsert(model.InspectionEvent{ID: "ie_lab_001", TenantID: "tenant_lab_001", AccessDecisionID: stringPtr("dec_lab_001"), ApplicationID: stringPtr("app_dummy_https"), Timestamp: time.Now().UTC().Format(time.RFC3339), Metadata: map[string]any{}})
	if err := writer.Append("access.log.jsonl", map[string]any{"id": "alog_lab_001", "decision": "allow"}); err != nil {
		t.Fatalf("append access log returned error: %v", err)
	}
	handler := newServerWithConfig(serverConfig{
		Evaluator:        evaluator,
		Writer:           writer,
		Registry:         registry,
		DeviceStore:      devices,
		HumanApprovals:   humanApprovals,
		DelegatedGrants:  delegatedGrants,
		DecisionStore:    decisionStore,
		InspectionEvents: inspectionEvents,
		RouteProfiles: map[string]edgeplane.ApplicationRouteProfile{
			"app_dummy_https": {
				Destination:            "dummy-private-app.local",
				DestinationPort:        443,
				Protocol:               "tcp",
				ServiceFamily:          "https",
				DestinationRole:        "private_app",
				ApplicationSensitivity: "medium",
				PrivatePath:            "/private-app/dummy",
			},
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/admin/state", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var state map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&state); err != nil {
		t.Fatalf("decode admin state: %v", err)
	}
	counts, ok := state["counts"].(map[string]any)
	if !ok {
		t.Fatalf("counts = %#v", state["counts"])
	}
	for key, expected := range map[string]float64{
		"policies":                1,
		"applications":            1,
		"connectors":              1,
		"devices":                 1,
		"access_decisions":        1,
		"inspection_events":       1,
		"human_approval_events":   1,
		"delegated_access_grants": 1,
	} {
		if counts[key] != expected {
			t.Fatalf("counts[%s] = %#v, want %.0f", key, counts[key], expected)
		}
	}
	recentLogs, ok := state["recent_logs"].(map[string]any)
	if !ok {
		t.Fatalf("recent_logs = %#v", state["recent_logs"])
	}
	accessLog, ok := recentLogs["access.log.jsonl"].(map[string]any)
	if !ok || accessLog["count"] != float64(1) {
		t.Fatalf("access log summary = %#v", recentLogs["access.log.jsonl"])
	}
	applications, ok := state["applications"].([]any)
	if !ok || len(applications) != 1 {
		t.Fatalf("applications = %#v", state["applications"])
	}
	policies, ok := state["policies"].([]any)
	if !ok || len(policies) != 1 {
		t.Fatalf("policies = %#v", state["policies"])
	}
}

// by default the Edge is API-only — GET /admin returns 410 (the Console is a separate-host app
// that calls the admin API), not the embedded GUI.
func TestAdminConsoleApiOnlyByDefault(t *testing.T) {
	handler := newTestHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusGone {
		t.Fatalf("API-only Edge should return 410 for GET /admin, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestAdminConsoleGoneUnderEveryConfigWhileAPIsStayProtected(t *testing.T) {
	// the Edge is API-only. The embedded console was DELETED (main.go decomposition Phase 1,
	// b) — the real Console is the separate-host app
	// under repo-root console/. No configuration may bring the embedded copy back: even the most permissive
	// config (lab mode + legacy admin token) gets 410 on GET /admin while the admin API stays protected.
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	handler := newServerWithConfig(serverConfig{
		Evaluator:  testEvaluator(),
		Writer:     writer,
		AdminToken: "legacy-admin-token",
		LabMode:    boolPtr(true),
	})

	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusGone {
		t.Fatalf("GET /admin status = %d, want %d (the embedded console must stay deleted)", rec.Code, http.StatusGone)
	}

	apiReq := httptest.NewRequest(http.MethodGet, "/admin/state", nil)
	apiRec := httptest.NewRecorder()
	handler.ServeHTTP(apiRec, apiReq)
	if apiRec.Code != http.StatusUnauthorized {
		t.Fatalf("admin API without token status = %d, want %d, body=%s", apiRec.Code, http.StatusUnauthorized, apiRec.Body.String())
	}
}

func TestAdminUsageSummaryEndpoint(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	usageMeters := usagemeter.NewUsageMeterStore(
		readUsageMeterSampleForTest(t, "usage_meter_automation_concurrency_lab.json"),
		readUsageMeterSampleForTest(t, "usage_meter_nhi_decision_lab.json"),
		readUsageMeterSampleForTest(t, "usage_meter_nhi_seat_lab.json"),
	)
	handler := newServerWithConfig(serverConfig{
		Evaluator:   testEvaluator(),
		Writer:      writer,
		UsageMeters: usageMeters,
	})
	req := httptest.NewRequest(http.MethodGet, "/admin/usage/summary?period_start=2026-05-01T00:00:00Z&period_end=2026-06-01T00:00:00Z", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var summary usagemeter.UsageMeterSummary
	if err := json.NewDecoder(rec.Body).Decode(&summary); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if summary.Records != 3 {
		t.Fatalf("summary records = %d, want 3", summary.Records)
	}
	assertUsageMeterSummary(t, summary.Meters["decision"], "decision", "decision", "sum", 125000, 1)
	assertUsageMeterSummary(t, summary.Meters["nhi_seat"], "nhi_seat", "seat", "sum", 12, 1)
	assertUsageMeterSummary(t, summary.Meters["automation_concurrency"], "automation_concurrency", "concurrent_execution", "peak_max", 18, 1)
}

func containsAnyString(values []any, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func containsString(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func TestAdminUsageSummaryEndpointRecordsGovernanceSnapshot(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	now := time.Now().UTC()
	actorNHIID := "nhi_summary_agent_001"
	usageMeters := usagemeter.NewUsageMeterStore(usagemeter.UsageMeterRecordFromAccessDecision(model.AccessDecision{
		TenantID:      "tenant_lab_001",
		ApplicationID: "app_dummy_https",
		ActorType:     "delegated_agent",
		ActorNHIID:    &actorNHIID,
	}, now))
	adminAuth := newAdminAuthStore()
	adminAuth.UpsertPrincipal(adminPrincipal{
		ID:        "admin_usage_summary_001",
		TenantID:  "tenant_lab_001",
		Subject:   "sub_usage_summary",
		Email:     "usage-summary@example.jp",
		Roles:     []string{"owner"},
		IDPID:     "keycloak_lab",
		Status:    "active",
		CreatedAt: now.Add(-time.Hour).Format(time.RFC3339),
	})
	adminAuth.UpsertSession(adminSession{
		ID:               "admin_sess_usage_summary_001",
		TenantID:         "tenant_lab_001",
		AdminPrincipalID: "admin_usage_summary_001",
		Subject:          "sub_usage_summary",
		Roles:            []string{"owner"},
		AuthTime:         now.Add(-time.Minute).Format(time.RFC3339),
		MFAState:         "fresh",
		CreatedAt:        now.Add(-time.Minute).Format(time.RFC3339),
		ExpiresAt:        now.Add(time.Hour).Format(time.RFC3339),
		LastActiveAt:     now.Format(time.RFC3339),
		Status:           "active",
	})
	handler := newServerWithConfig(serverConfig{
		Evaluator:   testEvaluator(),
		Writer:      writer,
		UsageMeters: usageMeters,
		AdminAuth:   adminAuth,
		LabMode:     boolPtr(false),
	})
	req := httptest.NewRequest(http.MethodGet, "/admin/usage/summary", nil)
	req.AddCookie(&http.Cookie{Name: "admin_session", Value: "admin_sess_usage_summary_001"})
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var summary usagemeter.UsageMeterSummary
	if err := json.NewDecoder(rec.Body).Decode(&summary); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	assertUsageMeterSummary(t, summary.Meters["human_seat"], "human_seat", "seat", "sum", 1, 1)
	assertUsageMeterSummary(t, summary.Meters["nhi_seat"], "nhi_seat", "seat", "sum", 1, 1)
}

func TestAdminUsageSummaryEndpointUsesNHIRegistrySnapshot(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	now := time.Now().UTC()
	adminAuth := newAdminAuthStore()
	adminAuth.UpsertPrincipal(adminPrincipal{
		ID:        "admin_usage_nhi_registry_001",
		TenantID:  "tenant_lab_001",
		Subject:   "sub_usage_nhi_registry",
		Email:     "usage-nhi-registry@example.jp",
		Roles:     []string{"owner"},
		IDPID:     "keycloak_lab",
		Status:    "active",
		CreatedAt: now.Add(-time.Hour).Format(time.RFC3339),
	})
	adminAuth.UpsertSession(adminSession{
		ID:               "admin_sess_usage_nhi_registry_001",
		TenantID:         "tenant_lab_001",
		AdminPrincipalID: "admin_usage_nhi_registry_001",
		Subject:          "sub_usage_nhi_registry",
		Roles:            []string{"owner"},
		AuthTime:         now.Add(-time.Minute).Format(time.RFC3339),
		MFAState:         "fresh",
		CreatedAt:        now.Add(-time.Minute).Format(time.RFC3339),
		ExpiresAt:        now.Add(time.Hour).Format(time.RFC3339),
		LastActiveAt:     now.Format(time.RFC3339),
		Status:           "active",
	})
	nhiRegistry := nhi.NewStore()
	if _, err := nhiRegistry.Upsert(context.Background(), model.NonHumanIdentity{ID: "nhi_active_001", Name: "Active Agent 1", NHIType: "ai_agent", OwnerUserID: "user_owner_001", Status: "active"}, "tenant_lab_001", now); err != nil {
		t.Fatalf("Upsert active NHI 1 returned error: %v", err)
	}
	if _, err := nhiRegistry.Upsert(context.Background(), model.NonHumanIdentity{ID: "nhi_active_002", Name: "Active Agent 2", NHIType: "service_account", OwnerUserID: "user_owner_001", Status: "active"}, "tenant_lab_001", now); err != nil {
		t.Fatalf("Upsert active NHI 2 returned error: %v", err)
	}
	if _, err := nhiRegistry.Upsert(context.Background(), model.NonHumanIdentity{ID: "nhi_suspended_001", Name: "Suspended Agent", NHIType: "ai_agent", OwnerUserID: "user_owner_001", Status: "suspended"}, "tenant_lab_001", now); err != nil {
		t.Fatalf("Upsert suspended NHI returned error: %v", err)
	}
	usageMeters := usagemeter.NewUsageMeterStore()
	handler := newServerWithConfig(serverConfig{
		Evaluator:          testEvaluator(),
		Writer:             writer,
		UsageMeters:        usageMeters,
		AdminAuth:          adminAuth,
		NonHumanIdentities: nhiRegistry,
		LabMode:            boolPtr(false),
	})
	req := httptest.NewRequest(http.MethodGet, "/admin/usage/summary", nil)
	req.AddCookie(&http.Cookie{Name: "admin_session", Value: "admin_sess_usage_nhi_registry_001"})
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var summary usagemeter.UsageMeterSummary
	if err := json.NewDecoder(rec.Body).Decode(&summary); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	assertUsageMeterSummary(t, summary.Meters["human_seat"], "human_seat", "seat", "sum", 1, 1)
	assertUsageMeterSummary(t, summary.Meters["nhi_seat"], "nhi_seat", "seat", "sum", 2, 1)
	records, err := usageMeters.UsageMeterRecords("tenant_lab_001", time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC), time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC).AddDate(0, 1, 0))
	if err != nil {
		t.Fatalf("UsageMeterRecords returned error: %v", err)
	}
	foundRegisteredScope := false
	for _, record := range records {
		if record.MeterType == "nhi_seat" && usagemeter.StringUsageMeterDimension(record.Dimensions, "measurement_scope") == "registered_nhi_registry_active" {
			foundRegisteredScope = true
		}
	}
	if !foundRegisteredScope {
		t.Fatalf("nhi_seat registry measurement scope not recorded: %#v", records)
	}
}

func TestAdminUsageSummaryEndpointUsesHumanIdentityDirectorySnapshot(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	now := time.Now().UTC()
	adminAuth := newAdminAuthStore()
	adminAuth.UpsertPrincipal(adminPrincipal{
		ID:        "admin_usage_identity_directory_001",
		TenantID:  "tenant_lab_001",
		Subject:   "sub_usage_identity_directory",
		Email:     "usage-identity-directory@example.jp",
		Roles:     []string{"owner"},
		IDPID:     "keycloak_lab",
		Status:    "active",
		CreatedAt: now.Add(-time.Hour).Format(time.RFC3339),
	})
	adminAuth.UpsertSession(adminSession{
		ID:               "admin_sess_usage_identity_directory_001",
		TenantID:         "tenant_lab_001",
		AdminPrincipalID: "admin_usage_identity_directory_001",
		Subject:          "sub_usage_identity_directory",
		Roles:            []string{"owner"},
		AuthTime:         now.Add(-time.Minute).Format(time.RFC3339),
		MFAState:         "fresh",
		CreatedAt:        now.Add(-time.Minute).Format(time.RFC3339),
		ExpiresAt:        now.Add(time.Hour).Format(time.RFC3339),
		LastActiveAt:     now.Format(time.RFC3339),
		Status:           "active",
	})
	humanIdentities := humanidentity.NewHumanIdentityDirectoryStore()
	if _, err := humanIdentities.Upsert(context.Background(), model.HumanIdentity{ID: "human_active_001", TenantID: "tenant_lab_001", Subject: "user_active_001", Status: "active"}, "tenant_lab_001", now); err != nil {
		t.Fatalf("Upsert active human 1 returned error: %v", err)
	}
	if _, err := humanIdentities.Upsert(context.Background(), model.HumanIdentity{ID: "human_active_002", TenantID: "tenant_lab_001", Subject: "user_active_002", Status: "active"}, "tenant_lab_001", now); err != nil {
		t.Fatalf("Upsert active human 2 returned error: %v", err)
	}
	if _, err := humanIdentities.Upsert(context.Background(), model.HumanIdentity{ID: "human_suspended_001", TenantID: "tenant_lab_001", Subject: "user_suspended_001", Status: "suspended"}, "tenant_lab_001", now); err != nil {
		t.Fatalf("Upsert suspended human returned error: %v", err)
	}
	usageMeters := usagemeter.NewUsageMeterStore()
	handler := newServerWithConfig(serverConfig{
		Evaluator:       testEvaluator(),
		Writer:          writer,
		UsageMeters:     usageMeters,
		AdminAuth:       adminAuth,
		HumanIdentities: humanIdentities,
		LabMode:         boolPtr(false),
	})
	req := httptest.NewRequest(http.MethodGet, "/admin/usage/summary", nil)
	req.AddCookie(&http.Cookie{Name: "admin_session", Value: "admin_sess_usage_identity_directory_001"})
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var summary usagemeter.UsageMeterSummary
	if err := json.NewDecoder(rec.Body).Decode(&summary); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	assertUsageMeterSummary(t, summary.Meters["human_seat"], "human_seat", "seat", "sum", 2, 1)
	records, err := usageMeters.UsageMeterRecords("tenant_lab_001", time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC), time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC).AddDate(0, 1, 0))
	if err != nil {
		t.Fatalf("UsageMeterRecords returned error: %v", err)
	}
	foundDirectoryScope := false
	for _, record := range records {
		if record.MeterType == "human_seat" && usagemeter.StringUsageMeterDimension(record.Dimensions, "measurement_scope") == "identity_directory_active_humans" {
			foundDirectoryScope = true
		}
	}
	if !foundDirectoryScope {
		t.Fatalf("human_seat identity directory measurement scope not recorded: %#v", records)
	}
}

func TestAdminHumanIdentityEndpointsUpsertAndList(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	handler := newServerWithConfig(serverConfig{
		Evaluator: testEvaluator(),
		Writer:    writer,
	})
	body := `{
		"id":"human_admin_endpoint_001",
		"tenant_id":"tenant_lab_001",
		"subject":"sub_human_admin_endpoint_001",
		"email":"human-admin@example.jp",
		"display_name":"Endpoint Human",
		"source":"lab_import",
		"department":"security",
		"status":"active",
		"metadata":{"purpose":"test"}
	}`
	createReq := httptest.NewRequest(http.MethodPost, "/admin/human-identities", strings.NewReader(body))
	createReq.Header.Set("content-type", "application/json")
	createRec := httptest.NewRecorder()

	handler.ServeHTTP(createRec, createReq)

	if createRec.Code != http.StatusOK {
		t.Fatalf("create status = %d, want %d: %s", createRec.Code, http.StatusOK, createRec.Body.String())
	}
	var created model.HumanIdentity
	if err := json.NewDecoder(createRec.Body).Decode(&created); err != nil {
		t.Fatalf("decode created human identity: %v", err)
	}
	if created.ID != "human_admin_endpoint_001" || created.TenantID != "tenant_lab_001" || created.Status != "active" {
		t.Fatalf("created human identity = %#v", created)
	}
	otherBody := `{
		"id":"human_admin_endpoint_002",
		"subject":"sub_human_admin_endpoint_002",
		"source":"hris",
		"status":"suspended"
	}`
	otherReq := httptest.NewRequest(http.MethodPost, "/admin/human-identities", strings.NewReader(otherBody))
	otherReq.Header.Set("content-type", "application/json")
	otherRec := httptest.NewRecorder()
	handler.ServeHTTP(otherRec, otherReq)
	if otherRec.Code != http.StatusOK {
		t.Fatalf("second create status = %d, want %d: %s", otherRec.Code, http.StatusOK, otherRec.Body.String())
	}

	listReq := httptest.NewRequest(http.MethodGet, "/admin/human-identities?source=lab_import&status=active&limit=1", nil)
	listRec := httptest.NewRecorder()
	handler.ServeHTTP(listRec, listReq)

	if listRec.Code != http.StatusOK {
		t.Fatalf("list status = %d, want %d: %s", listRec.Code, http.StatusOK, listRec.Body.String())
	}
	var list humanidentity.HumanIdentityDirectoryListResponse
	if err := json.NewDecoder(listRec.Body).Decode(&list); err != nil {
		t.Fatalf("decode list response: %v", err)
	}
	if list.Source != "lab_import" || list.Status != "active" || list.Limit != 1 || list.Count != 1 || list.ActiveCount != 1 || len(list.Identities) != 1 || list.Identities[0].ID != "human_admin_endpoint_001" {
		t.Fatalf("list = %#v", list)
	}
	sourcesReq := httptest.NewRequest(http.MethodGet, "/admin/human-identities/sources", nil)
	sourcesRec := httptest.NewRecorder()
	handler.ServeHTTP(sourcesRec, sourcesReq)
	if sourcesRec.Code != http.StatusOK {
		t.Fatalf("sources status = %d, want %d: %s", sourcesRec.Code, http.StatusOK, sourcesRec.Body.String())
	}
	var sources humanidentity.HumanIdentitySourceListResponse
	if err := json.NewDecoder(sourcesRec.Body).Decode(&sources); err != nil {
		t.Fatalf("decode source list response: %v", err)
	}
	if sources.TenantID != "tenant_lab_001" || sources.Count != 2 || len(sources.Sources) != 2 {
		t.Fatalf("sources = %#v", sources)
	}
	if sources.Sources[0].Source != "hris" || sources.Sources[0].Suspended != 1 || sources.Sources[1].Source != "lab_import" || sources.Sources[1].Active != 1 {
		t.Fatalf("source summaries = %#v", sources.Sources)
	}
	policyBody := `{
		"source":"lab_import",
		"connector_type":"csv",
		"enabled":true,
		"reconcile_missing":true,
		"expected_interval_seconds":3600,
		"stale_after_seconds":7200,
		"metadata":{"connector_id":"lab_csv"}
	}`
	policyReq := httptest.NewRequest(http.MethodPost, "/admin/human-identities/sources/policies", strings.NewReader(policyBody))
	policyReq.Header.Set("content-type", "application/json")
	policyRec := httptest.NewRecorder()
	handler.ServeHTTP(policyRec, policyReq)
	if policyRec.Code != http.StatusOK {
		t.Fatalf("source policy status = %d, want %d: %s", policyRec.Code, http.StatusOK, policyRec.Body.String())
	}
	var policy humanidentity.HumanIdentitySourcePolicy
	if err := json.NewDecoder(policyRec.Body).Decode(&policy); err != nil {
		t.Fatalf("decode source policy: %v", err)
	}
	if policy.TenantID != "tenant_lab_001" || policy.Source != "lab_import" || policy.ConnectorType != "csv" || !policy.Enabled || !policy.ReconcileMissing || policy.StaleAfterSeconds != 7200 {
		t.Fatalf("source policy = %#v", policy)
	}
	policiesReq := httptest.NewRequest(http.MethodGet, "/admin/human-identities/sources/policies", nil)
	policiesRec := httptest.NewRecorder()
	handler.ServeHTTP(policiesRec, policiesReq)
	if policiesRec.Code != http.StatusOK {
		t.Fatalf("source policy list status = %d, want %d: %s", policiesRec.Code, http.StatusOK, policiesRec.Body.String())
	}
	var policies humanidentity.HumanIdentitySourcePolicyListResponse
	if err := json.NewDecoder(policiesRec.Body).Decode(&policies); err != nil {
		t.Fatalf("decode source policy list: %v", err)
	}
	if policies.TenantID != "tenant_lab_001" || policies.Count != 1 || len(policies.Policies) != 1 || policies.Policies[0].Source != "lab_import" {
		t.Fatalf("source policy list = %#v", policies)
	}
	dueReq := httptest.NewRequest(http.MethodGet, "/admin/human-identities/sources/due", nil)
	dueRec := httptest.NewRecorder()
	handler.ServeHTTP(dueRec, dueReq)
	if dueRec.Code != http.StatusOK {
		t.Fatalf("source due status = %d, want %d: %s", dueRec.Code, http.StatusOK, dueRec.Body.String())
	}
	var due humanidentity.HumanIdentitySourceDueListResponse
	if err := json.NewDecoder(dueRec.Body).Decode(&due); err != nil {
		t.Fatalf("decode source due list: %v", err)
	}
	if due.TenantID != "tenant_lab_001" || due.Count != 1 || len(due.Sources) != 1 || due.Sources[0].Source != "lab_import" || due.Sources[0].ConnectorType != "csv" || due.Sources[0].DueReason != "source_policy_unobserved" {
		t.Fatalf("source due list = %#v", due)
	}
	audits, err := readAuditRowsExcludingWrapper(writer)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	found := false
	foundPolicy := false
	for _, row := range audits {
		if row["event_type"] == "human_identity_upserted" && row["target_id"] == "human_admin_endpoint_001" {
			found = true
		}
		if row["event_type"] == "human_identity_source_policy_upserted" && row["target_id"] == "lab_import" {
			foundPolicy = true
		}
	}
	if !found {
		t.Fatalf("human_identity_upserted audit not found in %#v", audits)
	}
	if !foundPolicy {
		t.Fatalf("human_identity_source_policy_upserted audit not found in %#v", audits)
	}
}

func TestAdminHumanIdentityImportEndpoint(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	handler := newServerWithConfig(serverConfig{
		Evaluator: testEvaluator(),
		Writer:    writer,
	})
	body := `{
		"source":"scim",
		"import_run_id":"human_import_run_endpoint_001",
		"dry_run":true,
		"reconcile_missing":true,
		"identities":[
			{"id":"human_import_001","subject":"sub_human_import_001","email":"import-one@example.jp","status":"active"},
			{"id":"human_import_002","subject":"sub_human_import_002","status":"suspended"}
		]
	}`
	req := httptest.NewRequest(http.MethodPost, "/admin/human-identities/import", strings.NewReader(body))
	req.Header.Set("content-type", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("import status = %d, want %d: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var result humanidentity.HumanIdentityDirectoryImportResponse
	if err := json.NewDecoder(rec.Body).Decode(&result); err != nil {
		t.Fatalf("decode import response: %v", err)
	}
	if !result.DryRun || result.Requested != 2 || result.Upserted != 2 || result.Deactivated != 0 || result.ActiveCount != 1 || len(result.Identities) != 2 {
		t.Fatalf("import result = %#v", result)
	}
	if result.ImportRunID != "human_import_run_endpoint_001" {
		t.Fatalf("import_run_id = %q, want endpoint run ID", result.ImportRunID)
	}
	if result.Identities[0].Source != "scim" || result.Identities[1].Source != "scim" {
		t.Fatalf("imported identities did not inherit source: %#v", result.Identities)
	}
	audits, err := readAuditRowsExcludingWrapper(writer)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	found := false
	for _, row := range audits {
		if row["event_type"] == "human_identities_imported" {
			found = true
			if row["metadata"] != nil {
				if metadata, ok := row["metadata"].(map[string]any); ok && metadata["reconcile_missing"] != true {
					t.Fatalf("human_identities_imported metadata = %#v, want reconcile_missing=true", metadata)
				}
			}
		}
	}
	if !found {
		t.Fatalf("human_identities_imported audit not found in %#v", audits)
	}
	listReq := httptest.NewRequest(http.MethodGet, "/admin/human-identities", nil)
	listRec := httptest.NewRecorder()
	handler.ServeHTTP(listRec, listReq)
	if listRec.Code != http.StatusOK {
		t.Fatalf("list after dry-run status = %d, want %d: %s", listRec.Code, http.StatusOK, listRec.Body.String())
	}
	var list humanidentity.HumanIdentityDirectoryListResponse
	if err := json.NewDecoder(listRec.Body).Decode(&list); err != nil {
		t.Fatalf("decode list after dry-run: %v", err)
	}
	if list.Count != 0 {
		t.Fatalf("dry-run import mutated endpoint store: %#v", list)
	}

	body = `{
		"source":"scim",
		"import_run_id":"human_import_run_endpoint_002",
		"checkpoint":"cursor_endpoint_002",
		"identities":[
			{"id":"human_import_003","subject":"sub_human_import_003","status":"active"}
		]
	}`
	req = httptest.NewRequest(http.MethodPost, "/admin/human-identities/import", strings.NewReader(body))
	req.Header.Set("content-type", "application/json")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("non-dry import status = %d, want %d: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	runsReq := httptest.NewRequest(http.MethodGet, "/admin/human-identities/import-runs?source=scim&limit=10", nil)
	runsRec := httptest.NewRecorder()
	handler.ServeHTTP(runsRec, runsReq)
	if runsRec.Code != http.StatusOK {
		t.Fatalf("import runs status = %d, want %d: %s", runsRec.Code, http.StatusOK, runsRec.Body.String())
	}
	var runs humanidentity.HumanIdentityImportRunListResponse
	if err := json.NewDecoder(runsRec.Body).Decode(&runs); err != nil {
		t.Fatalf("decode import runs response: %v", err)
	}
	if runs.TenantID != "tenant_lab_001" || runs.Source != "scim" || runs.Count != 1 || runs.Runs[0].ImportRunID != "human_import_run_endpoint_002" || runs.Runs[0].Source != "scim" || runs.Runs[0].Checkpoint != "cursor_endpoint_002" || runs.Runs[0].Upserted != 1 || runs.Runs[0].Active != 1 {
		t.Fatalf("import run summaries = %#v", runs)
	}
	healthReq := httptest.NewRequest(http.MethodGet, "/admin/human-identities/sources/health", nil)
	healthRec := httptest.NewRecorder()
	handler.ServeHTTP(healthRec, healthReq)
	if healthRec.Code != http.StatusOK {
		t.Fatalf("source health status = %d, want %d: %s", healthRec.Code, http.StatusOK, healthRec.Body.String())
	}
	var sourceHealth humanidentity.HumanIdentitySourceHealthResponse
	if err := json.NewDecoder(healthRec.Body).Decode(&sourceHealth); err != nil {
		t.Fatalf("decode source health response: %v", err)
	}
	if sourceHealth.TenantID != "tenant_lab_001" || sourceHealth.Status != "ok" || sourceHealth.SourceCount != 1 || len(sourceHealth.Sources) != 1 || sourceHealth.Sources[0].Source != "scim" {
		t.Fatalf("source health = %#v, want ok scim source", sourceHealth)
	}
	stateReq := httptest.NewRequest(http.MethodGet, "/admin/human-identities/sources/state", nil)
	stateRec := httptest.NewRecorder()
	handler.ServeHTTP(stateRec, stateReq)
	if stateRec.Code != http.StatusOK {
		t.Fatalf("source state status = %d, want %d: %s", stateRec.Code, http.StatusOK, stateRec.Body.String())
	}
	var sourceState humanidentity.HumanIdentitySourceStateListResponse
	if err := json.NewDecoder(stateRec.Body).Decode(&sourceState); err != nil {
		t.Fatalf("decode source state response: %v", err)
	}
	if sourceState.TenantID != "tenant_lab_001" || sourceState.Count != 1 || len(sourceState.States) != 1 || sourceState.States[0].Source != "scim" || sourceState.States[0].LastImportRunID != "human_import_run_endpoint_002" || sourceState.States[0].Checkpoint != "cursor_endpoint_002" {
		t.Fatalf("source state = %#v, want scim checkpoint", sourceState)
	}
	detailReq := httptest.NewRequest(http.MethodGet, "/admin/human-identities/import-runs/human_import_run_endpoint_002", nil)
	detailRec := httptest.NewRecorder()
	handler.ServeHTTP(detailRec, detailReq)
	if detailRec.Code != http.StatusOK {
		t.Fatalf("import run detail status = %d, want %d: %s", detailRec.Code, http.StatusOK, detailRec.Body.String())
	}
	var detail humanidentity.HumanIdentityImportRunDetailResponse
	if err := json.NewDecoder(detailRec.Body).Decode(&detail); err != nil {
		t.Fatalf("decode import run detail response: %v", err)
	}
	if detail.ImportRunID != "human_import_run_endpoint_002" || detail.Summary.Checkpoint != "cursor_endpoint_002" || detail.Summary.Upserted != 1 || len(detail.UpsertedIdentities) != 1 || detail.UpsertedIdentities[0].ID != "human_import_003" {
		t.Fatalf("import run detail = %#v", detail)
	}
	absentReq := httptest.NewRequest(http.MethodGet, "/admin/human-identities/import-runs/human_import_run_absent", nil)
	absentRec := httptest.NewRecorder()
	handler.ServeHTTP(absentRec, absentReq)
	if absentRec.Code != http.StatusNotFound {
		t.Fatalf("absent import run status = %d, want %d: %s", absentRec.Code, http.StatusNotFound, absentRec.Body.String())
	}
}

func TestAdminHumanIdentityImportEndpointRejectsOversizedBody(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	handler := newServerWithConfig(serverConfig{
		Evaluator: testEvaluator(),
		Writer:    writer,
	})
	req := httptest.NewRequest(http.MethodPost, "/admin/human-identities/import", strings.NewReader(oversizedHumanIdentityImportBody()))
	req.Header.Set("content-type", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "request body too large") {
		t.Fatalf("oversized admin import status = %d, body = %s", rec.Code, rec.Body.String())
	}
}

func TestAdminHumanIdentityImportEndpointRecordsFailureState(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	handler := newServerWithConfig(serverConfig{
		Evaluator: testEvaluator(),
		Writer:    writer,
	})
	body := `{
		"source":"scim",
		"import_run_id":"human_import_run_failure_001",
		"checkpoint":"cursor_failure_001",
		"identities":[
			{"id":"human_import_failure_001","subject":"sub_human_import_failure_001","status":"blocked"}
		]
	}`
	req := httptest.NewRequest(http.MethodPost, "/admin/human-identities/import", strings.NewReader(body))
	req.Header.Set("content-type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("failed import status = %d, want %d: %s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
	stateReq := httptest.NewRequest(http.MethodGet, "/admin/human-identities/sources/state", nil)
	stateRec := httptest.NewRecorder()
	handler.ServeHTTP(stateRec, stateReq)
	if stateRec.Code != http.StatusOK {
		t.Fatalf("source state status = %d, want %d: %s", stateRec.Code, http.StatusOK, stateRec.Body.String())
	}
	var sourceState humanidentity.HumanIdentitySourceStateListResponse
	if err := json.NewDecoder(stateRec.Body).Decode(&sourceState); err != nil {
		t.Fatalf("decode source state response: %v", err)
	}
	if sourceState.Count != 1 || len(sourceState.States) != 1 || sourceState.States[0].Source != "scim" || sourceState.States[0].Status != "error" || sourceState.States[0].LastImportRunID != "human_import_run_failure_001" || sourceState.States[0].Checkpoint != "cursor_failure_001" || sourceState.States[0].LastError == "" {
		t.Fatalf("source state = %#v, want failed import checkpoint", sourceState)
	}
}

func TestHumanIdentityConnectorMetadataAllowedRequiresStringConnectorID(t *testing.T) {
	if humanidentity.HumanIdentityConnectorMetadataAllowed(map[string]any{"connector_id": 123}, "123") {
		t.Fatal("numeric connector_id metadata was allowed, want deny-closed")
	}
	if !humanidentity.HumanIdentityConnectorMetadataAllowed(map[string]any{"connector_id": "conn_runtime_scim"}, "conn_runtime_scim") {
		t.Fatal("string connector_id metadata was rejected")
	}
	if !humanidentity.HumanIdentityConnectorMetadataAllowed(map[string]any{"connector_id": ""}, "conn_runtime_scim") {
		t.Fatal("empty connector_id metadata should preserve unassigned source semantics")
	}
}

func TestRuntimeHumanIdentitySourceDueAndImportRequireConnectorAuth(t *testing.T) {
	relaxConnectorMTLSPresentationForTest(t)
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	now := time.Date(2026, 5, 25, 4, 0, 0, 0, time.UTC)
	store := humanidentity.NewHumanIdentityDirectoryStore()
	if _, err := humanidentity.HumanIdentityDirectoryUpsertSourcePolicy(context.Background(), store, "tenant_lab_001", humanidentity.HumanIdentitySourcePolicy{
		Source:                  "scim_runtime",
		ConnectorType:           "scim",
		Enabled:                 true,
		ReconcileMissing:        true,
		ExpectedIntervalSeconds: 3600,
		Metadata:                map[string]any{"connector_id": "conn_runtime_scim"},
	}, now); err != nil {
		t.Fatalf("upsert runtime source policy returned error: %v", err)
	}
	if _, err := humanidentity.HumanIdentityDirectoryUpsertSourcePolicy(context.Background(), store, "tenant_lab_001", humanidentity.HumanIdentitySourcePolicy{
		Source:                  "scim_other",
		ConnectorType:           "scim",
		Enabled:                 true,
		ReconcileMissing:        false,
		ExpectedIntervalSeconds: 3600,
		Metadata:                map[string]any{"connector_id": "conn_other_scim"},
	}, now); err != nil {
		t.Fatalf("upsert second runtime source policy returned error: %v", err)
	}
	handler := newServerWithConfig(serverConfig{
		Evaluator:       testEvaluator(),
		Writer:          writer,
		HumanIdentities: store,
		ConnectorSecret: "tenant-runtime-secret",
		LabMode:         boolPtr(false),
	})

	dueReq := httptest.NewRequest(http.MethodGet, "/identity-sources/due", nil)
	dueRec := httptest.NewRecorder()
	handler.ServeHTTP(dueRec, dueReq)
	if dueRec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized due status = %d, want %d", dueRec.Code, http.StatusUnauthorized)
	}
	dueReq = httptest.NewRequest(http.MethodGet, "/identity-sources/due", nil)
	dueReq.Header.Set(connectorSecretHeader, "tenant-runtime-secret")
	dueRec = httptest.NewRecorder()
	handler.ServeHTTP(dueRec, dueReq)
	if dueRec.Code != http.StatusBadRequest || !strings.Contains(dueRec.Body.String(), "connector id is required") {
		t.Fatalf("missing connector id due status = %d, body = %s", dueRec.Code, dueRec.Body.String())
	}
	dueReq = httptest.NewRequest(http.MethodGet, "/identity-sources/due", nil)
	dueReq.Header.Set(connectorSecretHeader, "tenant-runtime-secret")
	dueReq.Header.Set(connectorIDHeader, "conn_runtime_scim")
	dueRec = httptest.NewRecorder()
	handler.ServeHTTP(dueRec, dueReq)
	if dueRec.Code != http.StatusOK {
		t.Fatalf("authorized due status = %d, want %d: %s", dueRec.Code, http.StatusOK, dueRec.Body.String())
	}
	var due humanidentity.HumanIdentitySourceDueListResponse
	if err := json.NewDecoder(dueRec.Body).Decode(&due); err != nil {
		t.Fatalf("decode runtime source due: %v", err)
	}
	if due.TenantID != "tenant_lab_001" || due.Count != 1 || due.Sources[0].Source != "scim_runtime" || due.Sources[0].DueReason != "source_policy_unobserved" || fmt.Sprint(due.Sources[0].Metadata["connector_id"]) != "conn_runtime_scim" {
		t.Fatalf("runtime source due = %#v", due)
	}

	importBody := `{
		"source":"scim_runtime",
		"import_run_id":"human_import_runtime_001",
		"checkpoint":"cursor_runtime_001",
		"identities":[
			{"id":"human_runtime_001","subject":"sub_human_runtime_001","status":"active"}
		]
	}`
	importReq := httptest.NewRequest(http.MethodPost, "/identity-sources/import", strings.NewReader(importBody))
	importReq.Header.Set("content-type", "application/json")
	importRec := httptest.NewRecorder()
	handler.ServeHTTP(importRec, importReq)
	if importRec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized runtime import status = %d, want %d", importRec.Code, http.StatusUnauthorized)
	}
	importReq = httptest.NewRequest(http.MethodPost, "/identity-sources/import", strings.NewReader(importBody))
	importReq.Header.Set("content-type", "application/json")
	importReq.Header.Set(connectorSecretHeader, "tenant-runtime-secret")
	importRec = httptest.NewRecorder()
	handler.ServeHTTP(importRec, importReq)
	if importRec.Code != http.StatusBadRequest || !strings.Contains(importRec.Body.String(), "connector id is required") {
		t.Fatalf("missing connector id runtime import status = %d, body = %s", importRec.Code, importRec.Body.String())
	}
	importReq = httptest.NewRequest(http.MethodPost, "/identity-sources/import", strings.NewReader(importBody))
	importReq.Header.Set("content-type", "application/json")
	importReq.Header.Set(connectorSecretHeader, "tenant-runtime-secret")
	importReq.Header.Set(connectorIDHeader, "conn_other_scim")
	importRec = httptest.NewRecorder()
	handler.ServeHTTP(importRec, importReq)
	if importRec.Code != http.StatusForbidden {
		t.Fatalf("wrong connector runtime import status = %d, want %d: %s", importRec.Code, http.StatusForbidden, importRec.Body.String())
	}
	importReq = httptest.NewRequest(http.MethodPost, "/identity-sources/import", strings.NewReader(importBody))
	importReq.Header.Set("content-type", "application/json")
	importReq.Header.Set(connectorSecretHeader, "tenant-runtime-secret")
	importReq.Header.Set(connectorIDHeader, "conn_runtime_scim")
	importRec = httptest.NewRecorder()
	handler.ServeHTTP(importRec, importReq)
	if importRec.Code != http.StatusOK {
		t.Fatalf("authorized runtime import status = %d, want %d: %s", importRec.Code, http.StatusOK, importRec.Body.String())
	}
	var result humanidentity.HumanIdentityDirectoryImportResponse
	if err := json.NewDecoder(importRec.Body).Decode(&result); err != nil {
		t.Fatalf("decode runtime import response: %v", err)
	}
	if result.TenantID != "tenant_lab_001" || result.Source != "scim_runtime" || result.ImportRunID != "human_import_runtime_001" || result.Checkpoint != "cursor_runtime_001" || !result.ReconcileMissing || result.Upserted != 1 || result.ActiveCount != 1 {
		t.Fatalf("runtime import result = %#v", result)
	}
	audits, err := readAuditRowsExcludingWrapper(writer)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	found := false
	for _, row := range audits {
		if row["event_type"] == "human_identities_imported" {
			if row["actor_user_id"] != nil || row["source_ip"] != nil {
				t.Fatalf("runtime import audit included raw actor/source fields: %#v", row)
			}
			found = true
		}
	}
	if !found {
		t.Fatalf("runtime import audit not found in %#v", audits)
	}
}

func TestRuntimeHumanIdentityImportRejectsOversizedBody(t *testing.T) {
	relaxConnectorMTLSPresentationForTest(t)
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	handler := newServerWithConfig(serverConfig{
		Evaluator:       testEvaluator(),
		Writer:          writer,
		ConnectorSecret: "tenant-runtime-secret",
		LabMode:         boolPtr(false),
	})
	req := httptest.NewRequest(http.MethodPost, "/identity-sources/import", strings.NewReader(oversizedHumanIdentityImportBody()))
	req.Header.Set("content-type", "application/json")
	req.Header.Set(connectorSecretHeader, "tenant-runtime-secret")
	req.Header.Set(connectorIDHeader, "conn_runtime_scim")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "request body too large") {
		t.Fatalf("oversized runtime import status = %d, body = %s", rec.Code, rec.Body.String())
	}
}

func oversizedHumanIdentityImportBody() string {
	return `{"source":"scim","import_run_id":"human_import_oversized","identities":[],"padding":"` + strings.Repeat("x", maxIdentitySourceImportBodyBytes) + `"}`
}

func TestAdminNonHumanIdentityEndpointsUpsertAndList(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	handler := newServerWithConfig(serverConfig{
		Evaluator: testEvaluator(),
		Writer:    writer,
	})
	body := `{
		"id":"nhi_admin_endpoint_001",
		"tenant_id":"tenant_lab_001",
		"name":"Endpoint Agent",
		"nhi_type":"ai_agent",
		"owner_user_id":"user_owner_001",
		"allowed_application_ids":["app_dummy_https"],
		"allowed_scopes":["ticket:create"],
		"allowlist_enforced":true,
		"status":"active",
		"metadata":{"purpose":"test"}
	}`
	createReq := httptest.NewRequest(http.MethodPost, "/admin/non-human-identities", strings.NewReader(body))
	createReq.Header.Set("content-type", "application/json")
	createRec := httptest.NewRecorder()

	handler.ServeHTTP(createRec, createReq)

	if createRec.Code != http.StatusOK {
		t.Fatalf("create status = %d, want %d: %s", createRec.Code, http.StatusOK, createRec.Body.String())
	}
	var created model.NonHumanIdentity
	if err := json.NewDecoder(createRec.Body).Decode(&created); err != nil {
		t.Fatalf("decode created NHI: %v", err)
	}
	if created.ID != "nhi_admin_endpoint_001" || created.TenantID != "tenant_lab_001" || created.Status != "active" {
		t.Fatalf("created NHI = %#v", created)
	}
	if !created.AllowlistEnforced {
		t.Fatalf("created AllowlistEnforced = false, want true")
	}

	listReq := httptest.NewRequest(http.MethodGet, "/admin/non-human-identities", nil)
	listRec := httptest.NewRecorder()
	handler.ServeHTTP(listRec, listReq)

	if listRec.Code != http.StatusOK {
		t.Fatalf("list status = %d, want %d: %s", listRec.Code, http.StatusOK, listRec.Body.String())
	}
	var list nhi.ListResponse
	if err := json.NewDecoder(listRec.Body).Decode(&list); err != nil {
		t.Fatalf("decode list response: %v", err)
	}
	if list.Count != 1 || list.ActiveCount != 1 || len(list.Identities) != 1 || list.Identities[0].ID != "nhi_admin_endpoint_001" {
		t.Fatalf("list = %#v", list)
	}
	if list.WarningCount != 0 || len(list.GovernanceWarnings) != 0 {
		t.Fatalf("list warnings = %#v, want none for scoped NHI", list.GovernanceWarnings)
	}
}

func TestNonHumanIdentityListReportsGovernanceWarnings(t *testing.T) {
	now := time.Now().UTC()
	store := nhi.NewStore()
	for _, item := range []model.NonHumanIdentity{
		{ID: "nhi_ai_empty_001", TenantID: "tenant_lab_001", Name: "Unscoped AI", NHIType: "ai_agent", OwnerUserID: "owner_001", Status: "active"},
		{ID: "nhi_automation_empty_001", TenantID: "tenant_lab_001", Name: "Unscoped Automation", NHIType: "automation", OwnerUserID: "owner_001", Status: "active", AllowedApplicationIDs: []string{"app_dummy_https"}},
		{ID: "nhi_service_empty_001", TenantID: "tenant_lab_001", Name: "Service Account", NHIType: "service_account", OwnerUserID: "owner_001", Status: "active"},
		{ID: "nhi_ai_suspended_001", TenantID: "tenant_lab_001", Name: "Suspended AI", NHIType: "ai_agent", OwnerUserID: "owner_001", Status: "suspended"},
		{ID: "nhi_ai_strict_empty_001", TenantID: "tenant_lab_001", Name: "Strict Empty AI", NHIType: "ai_agent", OwnerUserID: "owner_001", Status: "active", AllowlistEnforced: true},
	} {
		if _, err := store.Upsert(context.Background(), item, item.TenantID, now); err != nil {
			t.Fatalf("upsert %s returned error: %v", item.ID, err)
		}
	}
	result, err := nhi.List(context.Background(), store, "tenant_lab_001", now)
	if err != nil {
		t.Fatalf("nhi.List returned error: %v", err)
	}
	if result.Count != 5 || result.ActiveCount != 4 {
		t.Fatalf("result counts = %#v, want count 5 active 4", result)
	}
	if result.WarningCount != 3 || len(result.GovernanceWarnings) != 3 {
		t.Fatalf("warnings = %#v, want three compatibility-mode AI/automation empty allowlist warnings", result.GovernanceWarnings)
	}
	codesByID := map[string]map[string]bool{}
	for _, warning := range result.GovernanceWarnings {
		if codesByID[warning.ID] == nil {
			codesByID[warning.ID] = map[string]bool{}
		}
		codesByID[warning.ID][warning.Code] = true
	}
	if !codesByID["nhi_ai_empty_001"]["empty_allowed_application_ids"] || !codesByID["nhi_ai_empty_001"]["empty_allowed_scopes"] {
		t.Fatalf("AI warnings by ID = %#v, want app and scope warnings", codesByID)
	}
	if !codesByID["nhi_automation_empty_001"]["empty_allowed_scopes"] || codesByID["nhi_automation_empty_001"]["empty_allowed_application_ids"] {
		t.Fatalf("automation warnings by ID = %#v, want scope-only warning", codesByID)
	}
	if len(codesByID["nhi_service_empty_001"]) != 0 || len(codesByID["nhi_ai_suspended_001"]) != 0 {
		t.Fatalf("warnings by ID = %#v, want no service-account or suspended warnings", codesByID)
	}
	if len(codesByID["nhi_ai_strict_empty_001"]) != 0 {
		t.Fatalf("warnings by ID = %#v, want no warning for explicit strict empty allowlist", codesByID)
	}
}

func TestNonHumanIdentityAllowlistEnforcedDeniesEmptyAllowlists(t *testing.T) {
	compat := model.NonHumanIdentity{ID: "nhi_compat_001", NHIType: "ai_agent", Status: "active"}
	strict := model.NonHumanIdentity{ID: "nhi_strict_001", NHIType: "ai_agent", Status: "active", AllowlistEnforced: true}

	if !nhi.ApplicationAllowed(compat, "app_dummy_https") {
		t.Fatalf("compat empty application allowlist denied, want Phase 1 compatibility allow")
	}
	if !nhi.ScopeAllowed(compat, "ticket:create") {
		t.Fatalf("compat empty scope allowlist denied, want Phase 1 compatibility allow")
	}
	if scope, denied := nhi.FirstDisallowedScope(compat, []string{"ticket:create"}); denied || scope != "" {
		t.Fatalf("compat disallowed scope = %q/%v, want none", scope, denied)
	}

	if nhi.ApplicationAllowed(strict, "app_dummy_https") {
		t.Fatalf("strict empty application allowlist allowed, want deny")
	}
	if nhi.ScopeAllowed(strict, "ticket:create") {
		t.Fatalf("strict empty scope allowlist allowed, want deny")
	}
	if scope, denied := nhi.FirstDisallowedScope(strict, []string{"ticket:create"}); !denied || scope != "ticket:create" {
		t.Fatalf("strict disallowed scope = %q/%v, want ticket:create denied", scope, denied)
	}
	if scope, denied := nhi.FirstDisallowedScope(strict, nil); !denied || scope != "" {
		t.Fatalf("strict empty requested scopes = %q/%v, want deny with empty scope", scope, denied)
	}
}

func TestAdminNonHumanIdentityEndpointRejectsCrossTenantBody(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	handler := newServerWithConfig(serverConfig{
		Evaluator: testEvaluator(),
		Writer:    writer,
	})
	body := `{"id":"nhi_cross_tenant_001","tenant_id":"tenant_other","name":"Cross Tenant","nhi_type":"ai_agent","owner_user_id":"user_owner_001","status":"active"}`
	req := httptest.NewRequest(http.MethodPost, "/admin/non-human-identities", strings.NewReader(body))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d: %s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

func TestRuntimeEventRegistrationEnforcesNHIAllowlists(t *testing.T) {
	now := time.Now().UTC()
	nhiRegistry := nhi.NewStore()
	if _, err := nhiRegistry.Upsert(context.Background(), model.NonHumanIdentity{
		ID:                    "nhi_limited_001",
		Name:                  "Limited Agent",
		NHIType:               "ai_agent",
		OwnerUserID:           "user_owner_001",
		Status:                "active",
		AllowedApplicationIDs: []string{"app_allowed_001"},
		AllowedScopes:         []string{"ticket:create"},
	}, "tenant_lab_001", now); err != nil {
		t.Fatalf("upsert limited NHI returned error: %v", err)
	}
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	handler := newServerWithConfig(serverConfig{
		Evaluator:          testEvaluator(),
		Writer:             writer,
		NonHumanIdentities: nhiRegistry,
	})

	wrongGrantApp := `{
		"id":"dag_limited_wrong_app_001",
		"tenant_id":"tenant_lab_001",
		"subject_user_id":"user_lab_001",
		"actor_nhi_id":"nhi_limited_001",
		"application_id":"app_blocked_001",
		"scopes":["ticket:create"],
		"expires_at":"2030-01-01T00:00:00Z",
		"status":"active",
		"metadata":{}
	}`
	req := httptest.NewRequest(http.MethodPost, "/delegated-grants", strings.NewReader(wrongGrantApp))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("wrong app grant status = %d, want %d, body=%s", rec.Code, http.StatusForbidden, rec.Body.String())
	}

	wrongGrantScope := `{
		"id":"dag_limited_wrong_scope_001",
		"tenant_id":"tenant_lab_001",
		"subject_user_id":"user_lab_001",
		"actor_nhi_id":"nhi_limited_001",
		"application_id":"app_allowed_001",
		"scopes":["ticket:delete"],
		"expires_at":"2030-01-01T00:00:00Z",
		"status":"active",
		"metadata":{}
	}`
	req = httptest.NewRequest(http.MethodPost, "/delegated-grants", strings.NewReader(wrongGrantScope))
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("wrong scope grant status = %d, want %d, body=%s", rec.Code, http.StatusForbidden, rec.Body.String())
	}

	approvalBody := `{
		"id":"hae_limited_wrong_scope_001",
		"tenant_id":"tenant_lab_001",
		"approval_source":"admin_console",
		"approver_user_id":"approver_lab_001",
		"actor_nhi_id":"nhi_limited_001",
		"application_id":"app_allowed_001",
		"action_type":"ticket:delete",
		"approval_result":"approved",
		"metadata":{}
	}`
	req = httptest.NewRequest(http.MethodPost, "/human-approvals/events", strings.NewReader(approvalBody))
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("wrong scope approval status = %d, want %d, body=%s", rec.Code, http.StatusForbidden, rec.Body.String())
	}

	toolBody := `{
		"id":"tce_limited_wrong_app_001",
		"tenant_id":"tenant_lab_001",
		"actor_nhi_id":"nhi_limited_001",
		"application_id":"app_blocked_001",
		"tool_id":"tool_ticket_create_001",
		"action_type":"ticket:create",
		"timestamp":"2026-05-22T00:01:00Z",
		"metadata":{}
	}`
	req = httptest.NewRequest(http.MethodPost, "/tools/events", strings.NewReader(toolBody))
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("wrong app tool status = %d, want %d, body=%s", rec.Code, http.StatusForbidden, rec.Body.String())
	}

	allowedGrant := `{
		"id":"dag_limited_allowed_001",
		"tenant_id":"tenant_lab_001",
		"subject_user_id":"user_lab_001",
		"actor_nhi_id":"nhi_limited_001",
		"application_id":"app_allowed_001",
		"scopes":["ticket:create"],
		"expires_at":"2030-01-01T00:00:00Z",
		"status":"active",
		"metadata":{}
	}`
	req = httptest.NewRequest(http.MethodPost, "/delegated-grants", strings.NewReader(allowedGrant))
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("allowed grant status = %d, want %d, body=%s", rec.Code, http.StatusAccepted, rec.Body.String())
	}
}

func TestAdminUsageHealthEndpointReportsSpoolBacklog(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	now := time.Now().UTC()
	usageMeters := &postgresUsageMeterStore{SpoolDir: t.TempDir()}
	tenantRecord := readUsageMeterSampleForTest(t, "usage_meter_nhi_decision_lab.json")
	usageMeters.Record(tenantRecord)
	otherTenantRecord := tenantRecord
	otherTenantRecord.ID = "usage_other_tenant_spooled_001"
	otherTenantRecord.TenantID = "tenant_other_001"
	usageMeters.Record(otherTenantRecord)
	adminAuth := newAdminAuthStore()
	adminAuth.UpsertPrincipal(adminPrincipal{
		ID:        "admin_usage_health_001",
		TenantID:  "tenant_lab_001",
		Subject:   "sub_usage_health",
		Email:     "usage-health@example.jp",
		Roles:     []string{"owner"},
		IDPID:     "keycloak_lab",
		Status:    "active",
		CreatedAt: now.Add(-time.Hour).Format(time.RFC3339),
	})
	adminAuth.UpsertSession(adminSession{
		ID:               "admin_sess_usage_health_001",
		TenantID:         "tenant_lab_001",
		AdminPrincipalID: "admin_usage_health_001",
		Subject:          "sub_usage_health",
		Roles:            []string{"owner"},
		AuthTime:         now.Add(-time.Minute).Format(time.RFC3339),
		MFAState:         "fresh",
		CreatedAt:        now.Add(-time.Minute).Format(time.RFC3339),
		ExpiresAt:        now.Add(time.Hour).Format(time.RFC3339),
		LastActiveAt:     now.Format(time.RFC3339),
		Status:           "active",
	})
	handler := newServerWithConfig(serverConfig{
		Evaluator:   testEvaluator(),
		Writer:      writer,
		UsageMeters: usageMeters,
		AdminAuth:   adminAuth,
		LabMode:     boolPtr(false),
	})
	req := httptest.NewRequest(http.MethodGet, "/admin/usage/health", nil)
	req.AddCookie(&http.Cookie{Name: "admin_session", Value: "admin_sess_usage_health_001"})
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var health usagemeter.UsageMeterHealth
	if err := json.NewDecoder(rec.Body).Decode(&health); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if health.Status != "degraded" || health.Mode != "postgres" || health.SpooledRecords != 1 {
		t.Fatalf("health = %#v, want degraded postgres with one spooled record", health)
	}
	if !stringSliceContains(health.Reasons, "usage_meter_pending_records") {
		t.Fatalf("health reasons = %#v, want usage_meter_pending_records", health.Reasons)
	}
}

func TestAdminUsageSummaryEndpointRejectsInvalidWindow(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	handler := newServerWithConfig(serverConfig{
		Evaluator: testEvaluator(),
		Writer:    writer,
	})
	req := httptest.NewRequest(http.MethodGet, "/admin/usage/summary?period_start=2026-06-01T00:00:00Z&period_end=2026-05-01T00:00:00Z", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestAdminHotStoreMirrorHealthEndpoint(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	monitor := newHotStoreAppendMirrorMonitor()
	monitor.RecordIngestFailure("access", "access.log.jsonl", fmt.Errorf("postgres unavailable"), time.Date(2026, 5, 23, 4, 20, 0, 0, time.UTC))
	handler := newServerWithConfig(serverConfig{
		Evaluator:      testEvaluator(),
		Writer:         writer,
		HotStoreMirror: monitor,
	})

	req := httptest.NewRequest(http.MethodGet, "/admin/hot-store/health", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("hot store health status = %d, want %d, body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var health hotStoreAppendMirrorHealth
	if err := json.Unmarshal(rec.Body.Bytes(), &health); err != nil {
		t.Fatalf("decode hot store health: %v", err)
	}
	if health.Status != "degraded" || health.Stats["ingest_failures"] != 1 || health.LastStream != "access" {
		t.Fatalf("health = %#v, want degraded access ingest failure", health)
	}
}

func TestAdminAsyncExportJobWritesGzippedTenantScopedNDJSON(t *testing.T) {
	logDir := t.TempDir()
	writer, err := logs.NewWriter(logDir)
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	for _, row := range []map[string]any{
		{"id": "alog_001", "tenant_id": "tenant_lab_001", "event_type": "access_allowed", "timestamp": "2026-05-23T01:10:00Z"},
		{"id": "alog_002", "tenant_id": "tenant_lab_001", "event_type": "access_allowed", "timestamp": "2026-05-23T03:10:00Z"},
		{"id": "alog_003", "tenant_id": "tenant_other_001", "event_type": "access_allowed", "timestamp": "2026-05-23T01:10:00Z"},
	} {
		if err := writer.Append("access.log.jsonl", row); err != nil {
			t.Fatalf("append access log returned error: %v", err)
		}
	}
	exportJobs := newAdminExportJobStore()
	outbox := &recordingAdminAuditOutboxDeadReader{}
	handler := newServerWithConfig(serverConfig{
		Evaluator:        testEvaluator(),
		Writer:           writer,
		Registry:         connector.NewRegistry(),
		AdminExportJobs:  exportJobs,
		AdminAuditOutbox: outbox,
	})
	body := `{
		"stream":"access",
		"format":"ndjson",
		"filters":{"event_type":"access_allowed"},
		"from":"2026-05-23T01:00:00Z",
		"to":"2026-05-23T02:00:00Z"
	}`
	req := httptest.NewRequest(http.MethodPost, "/admin/export-jobs", strings.NewReader(body))
	req.Header.Set("x-admin-principal-id", "admin_user_test_001")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusAccepted, rec.Body.String())
	}
	var job adminExportJob
	if err := json.NewDecoder(rec.Body).Decode(&job); err != nil {
		t.Fatalf("decode export job: %v", err)
	}
	if job.Status != "completed" || job.RowCount != 1 || job.ObjectRef == nil || job.PayloadChecksum == nil {
		t.Fatalf("job = %#v, want completed single-row export with object ref and checksum", job)
	}
	if job.Metadata["total_matches"] != float64(1) && job.Metadata["total_matches"] != 1 {
		t.Fatalf("job metadata = %#v, want total_matches 1", job.Metadata)
	}
	if job.Metadata["truncated"] != false {
		t.Fatalf("job metadata = %#v, want truncated false", job.Metadata)
	}
	if job.Metadata["progress_phase"] != "completed" || job.Metadata["rows_exported"] != float64(1) && job.Metadata["rows_exported"] != 1 {
		t.Fatalf("job metadata = %#v, want completed progress", job.Metadata)
	}
	if job.CreatedByAdminPrincipalID != "admin_lab_bypass" {
		t.Fatalf("created_by = %s", job.CreatedByAdminPrincipalID)
	}
	getReq := httptest.NewRequest(http.MethodGet, "/admin/export-jobs/"+job.ID, nil)
	getRec := httptest.NewRecorder()
	handler.ServeHTTP(getRec, getReq)
	if getRec.Code != http.StatusOK {
		t.Fatalf("get status = %d, want %d, body=%s", getRec.Code, http.StatusOK, getRec.Body.String())
	}
	listReq := httptest.NewRequest(http.MethodGet, "/admin/export-jobs", nil)
	listRec := httptest.NewRecorder()
	handler.ServeHTTP(listRec, listReq)
	if listRec.Code != http.StatusOK {
		t.Fatalf("list status = %d, want %d, body=%s", listRec.Code, http.StatusOK, listRec.Body.String())
	}
	var listResult map[string][]adminExportJob
	if err := json.NewDecoder(listRec.Body).Decode(&listResult); err != nil {
		t.Fatalf("decode export job list: %v", err)
	}
	if len(listResult["jobs"]) != 1 || listResult["jobs"][0].ID != job.ID {
		t.Fatalf("list result = %#v, want created job", listResult)
	}
	matches, err := filepath.Glob(filepath.Join(logDir, "exports", "tenant_lab_001", "*", "*", "*", "*.ndjson.gz"))
	if err != nil || len(matches) != 1 {
		t.Fatalf("export matches = %#v, err=%v", matches, err)
	}
	file, err := os.Open(matches[0])
	if err != nil {
		t.Fatalf("open export: %v", err)
	}
	defer file.Close()
	gzipReader, err := gzip.NewReader(file)
	if err != nil {
		t.Fatalf("open gzip export: %v", err)
	}
	exported, err := io.ReadAll(gzipReader)
	if err != nil {
		t.Fatalf("read gzip export: %v", err)
	}
	if err := gzipReader.Close(); err != nil {
		t.Fatalf("close gzip export: %v", err)
	}
	if !strings.Contains(string(exported), `"id":"alog_001"`) || strings.Contains(string(exported), `"id":"alog_002"`) || strings.Contains(string(exported), `"id":"alog_003"`) {
		t.Fatalf("exported = %s, want tenant-scoped time-filtered row", string(exported))
	}
	downloadURLReq := httptest.NewRequest(http.MethodPost, "/admin/export-jobs/"+job.ID+"/download-url", nil)
	downloadURLReq.Host = "edge.example.local"
	downloadURLRec := httptest.NewRecorder()
	handler.ServeHTTP(downloadURLRec, downloadURLReq)
	if downloadURLRec.Code != http.StatusCreated {
		t.Fatalf("download-url status = %d, want %d, body=%s", downloadURLRec.Code, http.StatusCreated, downloadURLRec.Body.String())
	}
	var downloadURLResponse adminDownloadURLResponse
	if err := json.NewDecoder(downloadURLRec.Body).Decode(&downloadURLResponse); err != nil {
		t.Fatalf("decode download-url response: %v", err)
	}
	if downloadURLResponse.PayloadChecksum != *job.PayloadChecksum || downloadURLResponse.RowCount != job.RowCount {
		t.Fatalf("download-url response = %#v", downloadURLResponse)
	}
	parsedDownloadURL, err := url.Parse(downloadURLResponse.DownloadURL)
	if err != nil {
		t.Fatalf("parse download url: %v", err)
	}
	downloadReq := httptest.NewRequest(http.MethodGet, parsedDownloadURL.Path, nil)
	downloadRec := httptest.NewRecorder()
	handler.ServeHTTP(downloadRec, downloadReq)
	if downloadRec.Code != http.StatusOK {
		t.Fatalf("download status = %d, want %d, body=%s", downloadRec.Code, http.StatusOK, downloadRec.Body.String())
	}
	if downloadRec.Result().Header.Get("x-payload-checksum") != *job.PayloadChecksum {
		t.Fatalf("download checksum header = %q", downloadRec.Result().Header.Get("x-payload-checksum"))
	}
	if downloadRec.Result().Header.Get("cache-control") != "no-store" || downloadRec.Result().Header.Get("referrer-policy") != "no-referrer" {
		t.Fatalf("download security headers = %#v", downloadRec.Result().Header)
	}
	downloadedGzip, err := gzip.NewReader(bytes.NewReader(downloadRec.Body.Bytes()))
	if err != nil {
		t.Fatalf("open downloaded gzip: %v", err)
	}
	downloaded, err := io.ReadAll(downloadedGzip)
	if err != nil {
		t.Fatalf("read downloaded gzip: %v", err)
	}
	if err := downloadedGzip.Close(); err != nil {
		t.Fatalf("close downloaded gzip: %v", err)
	}
	if string(downloaded) != string(exported) {
		t.Fatalf("downloaded = %s, want exported = %s", string(downloaded), string(exported))
	}
	secondDownloadRec := httptest.NewRecorder()
	handler.ServeHTTP(secondDownloadRec, downloadReq)
	if secondDownloadRec.Code != http.StatusNotFound {
		t.Fatalf("second download status = %d, want %d", secondDownloadRec.Code, http.StatusNotFound)
	}
	auditRows, err := readAuditRowsExcludingWrapper(writer)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	if len(auditRows) != 6 || auditRows[1]["event_type"] != "admin_export_task_enqueued" || auditRows[3]["event_type"] != "admin_export_completed" || auditRows[4]["event_type"] != "admin_export_url_issued" || auditRows[5]["event_type"] != "admin_export_downloaded" {
		t.Fatalf("audit rows = %#v, want export lifecycle audit", auditRows)
	}
	taskMetadata := auditRows[1]["metadata"].(map[string]any)
	if taskMetadata["idempotency_key"] == "" || taskMetadata["timeout_seconds"] != float64(defaultAdminExportWorkerTimeoutSeconds) || taskMetadata["cancel_check_interval_rows"] != float64(defaultAdminExportWorkerCancelCheckIntervalRows) {
		t.Fatalf("task audit metadata = %#v, want worker task lease/retry contract fields", taskMetadata)
	}
	if _, ok := taskMetadata["retry_policy"].(map[string]any); !ok {
		t.Fatalf("task audit retry policy = %#v, want object", taskMetadata["retry_policy"])
	}
	if auditRows[5]["actor_user_id"] != "anonymous_token_bearer" {
		t.Fatalf("download audit actor = %#v, want anonymous_token_bearer", auditRows[5])
	}
	downloadMetadata := auditRows[5]["metadata"].(map[string]any)
	if downloadMetadata["issued_by_admin_principal_id"] != "admin_lab_bypass" || downloadMetadata["download_actor_known"] != false {
		t.Fatalf("download audit metadata = %#v", downloadMetadata)
	}
	gotOutboxEvents := auditLogEventTypes(outbox.insertedAudits)
	for _, want := range []string{"admin_export_url_issued", "admin_export_downloaded"} {
		if !gotOutboxEvents[want] {
			t.Fatalf("outbox inserted audits = %#v, want %s", gotOutboxEvents, want)
		}
	}
}

func TestAdminAsyncExportJobRecordsTruncationMetadata(t *testing.T) {
	logDir := t.TempDir()
	writer, err := logs.NewWriter(logDir)
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	for _, row := range []map[string]any{
		{"id": "alog_001", "tenant_id": "tenant_lab_001", "event_type": "access_allowed", "timestamp": "2026-05-23T01:10:00Z"},
		{"id": "alog_002", "tenant_id": "tenant_lab_001", "event_type": "access_allowed", "timestamp": "2026-05-23T01:20:00Z"},
		{"id": "alog_003", "tenant_id": "tenant_lab_001", "event_type": "access_allowed", "timestamp": "2026-05-23T01:30:00Z"},
	} {
		if err := writer.Append("access.log.jsonl", row); err != nil {
			t.Fatalf("append access log returned error: %v", err)
		}
	}
	handler := newServerWithConfig(serverConfig{
		Evaluator: testEvaluator(),
		Writer:    writer,
		Registry:  connector.NewRegistry(),
	})
	body := `{
		"stream":"access",
		"format":"ndjson",
		"filters":{"event_type":"access_allowed"},
		"from":"2026-05-23T01:00:00Z",
		"to":"2026-05-23T02:00:00Z",
		"limit":1
	}`
	req := httptest.NewRequest(http.MethodPost, "/admin/export-jobs", strings.NewReader(body))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusAccepted, rec.Body.String())
	}
	var job adminExportJob
	if err := json.NewDecoder(rec.Body).Decode(&job); err != nil {
		t.Fatalf("decode export job: %v", err)
	}
	if job.RowCount != 1 || job.Metadata["truncated"] != true {
		t.Fatalf("job = %#v, want row_count 1 and truncated true", job)
	}
	if job.Metadata["total_matches"] != float64(3) {
		t.Fatalf("job metadata = %#v, want total_matches 3", job.Metadata)
	}
	auditRows, err := readAuditRowsExcludingWrapper(writer)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	completed := auditRows[len(auditRows)-1]
	metadata := completed["metadata"].(map[string]any)
	if metadata["truncated"] != true || metadata["total_matches"] != float64(3) {
		t.Fatalf("completed audit metadata = %#v, want truncation details", metadata)
	}
}

func TestAdminAsyncExportJobRejectsInvalidLimit(t *testing.T) {
	handler := newTestHandler(t)
	body := `{"stream":"access","format":"ndjson","from":"2026-05-23T00:00:00Z","to":"2026-05-24T00:00:00Z","limit":1000001}`
	req := httptest.NewRequest(http.MethodPost, "/admin/export-jobs", strings.NewReader(body))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

func TestAdminEndpointsCanRequireToken(t *testing.T) {
	// Drives an admin route with the shared break-glass token, which is off by default now.
	armBreakGlassForTest(t)
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	outbox := &recordingAdminAuditOutboxDeadReader{}
	handler := newServerWithConfig(serverConfig{
		Evaluator:        testEvaluator(),
		Writer:           writer,
		Registry:         connector.NewRegistry(),
		AdminToken:       "secret-admin-token",
		AdminAuditOutbox: outbox,
	})
	// A request with NO credential is an anonymous probe: 401, but NOT audited (b — auditing it recorded a
	// spurious "Admin auth failed" on every login when the Console checked session state before sign-in).
	req := httptest.NewRequest(http.MethodGet, "/admin/state", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status without token = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
	if rows, _ := readAuditRowsExcludingWrapper(writer); len(rows) != 0 {
		t.Fatalf("no-credential probe must NOT be audited, got %#v", rows)
	}

	// A request WITH an INVALID token is a rejected authentication attempt: 401, AND audited as admin_auth_failed.
	badReq := httptest.NewRequest(http.MethodGet, "/admin/state", nil)
	badReq.Header.Set("authorization", "Bearer wrong-token")
	badRec := httptest.NewRecorder()
	handler.ServeHTTP(badRec, badReq)
	if badRec.Code != http.StatusUnauthorized {
		t.Fatalf("status with bad token = %d, want %d", badRec.Code, http.StatusUnauthorized)
	}
	auditRows, err := readAuditRowsExcludingWrapper(writer)
	if err != nil {
		t.Fatalf("ReadJSONL returned error: %v", err)
	}
	if len(auditRows) != 1 || auditRows[0]["event_type"] != "admin_auth_failed" {
		t.Fatalf("audit rows = %#v, want admin_auth_failed for a rejected attempt", auditRows)
	}
	if !auditLogEventTypes(outbox.insertedAudits)["admin_auth_failed"] {
		t.Fatalf("outbox inserted audits = %#v, want admin_auth_failed", outbox.insertedAudits)
	}

	// A request with the VALID token succeeds.
	okReq := httptest.NewRequest(http.MethodGet, "/admin/state", nil)
	okReq.Header.Set("authorization", "Bearer secret-admin-token")
	okRec := httptest.NewRecorder()
	handler.ServeHTTP(okRec, okReq)
	if okRec.Code != http.StatusOK {
		t.Fatalf("status with token = %d, want %d, body=%s", okRec.Code, http.StatusOK, okRec.Body.String())
	}
}

func TestAdminEndpointChecksRBACPermission(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	adminAuth := newAdminAuthStore()
	adminAuth.UpsertPrincipal(adminPrincipal{ID: "admin_approver_001", TenantID: "tenant_lab_001", Subject: "sub_approver", Email: "approver@example.jp", Roles: []string{"approver"}, IDPID: "keycloak_lab", Status: "active", CreatedAt: time.Now().UTC().Add(-time.Hour).Format(time.RFC3339)})
	adminAuth.UpsertSession(adminSession{ID: "admin_sess_approver_001", TenantID: "tenant_lab_001", AdminPrincipalID: "admin_approver_001", Subject: "sub_approver", Roles: []string{"approver"}, AuthTime: time.Now().UTC().Add(-time.Minute).Format(time.RFC3339), MFAState: "fresh", CreatedAt: time.Now().UTC().Add(-time.Minute).Format(time.RFC3339), ExpiresAt: time.Now().UTC().Add(time.Hour).Format(time.RFC3339), LastActiveAt: time.Now().UTC().Format(time.RFC3339), Status: "active"})
	adminAuth.UpsertPrincipal(adminPrincipal{ID: "admin_analyst_001", TenantID: "tenant_lab_001", Subject: "sub_analyst", Email: "analyst@example.jp", Roles: []string{"analyst"}, IDPID: "keycloak_lab", Status: "active", CreatedAt: time.Now().UTC().Add(-time.Hour).Format(time.RFC3339)})
	adminAuth.UpsertSession(adminSession{ID: "admin_sess_analyst_001", TenantID: "tenant_lab_001", AdminPrincipalID: "admin_analyst_001", Subject: "sub_analyst", Roles: []string{"analyst"}, AuthTime: time.Now().UTC().Add(-time.Minute).Format(time.RFC3339), MFAState: "fresh", CreatedAt: time.Now().UTC().Add(-time.Minute).Format(time.RFC3339), ExpiresAt: time.Now().UTC().Add(time.Hour).Format(time.RFC3339), LastActiveAt: time.Now().UTC().Format(time.RFC3339), Status: "active"})
	outbox := &recordingAdminAuditOutboxDeadReader{}
	handler := newServerWithConfig(serverConfig{
		Evaluator:        testEvaluator(),
		Writer:           writer,
		Registry:         connector.NewRegistry(),
		AdminAuth:        adminAuth,
		AdminToken:       "secret-admin-token",
		AdminAuditOutbox: outbox,
	})
	req := httptest.NewRequest(http.MethodGet, "/admin/logs/access", nil)
	req.AddCookie(&http.Cookie{Name: "admin_session", Value: "admin_sess_approver_001"})
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status with approver role = %d, want %d, body=%s", rec.Code, http.StatusForbidden, rec.Body.String())
	}
	auditRows, err := readAuditRowsExcludingWrapper(writer)
	if err != nil {
		t.Fatalf("ReadJSONL returned error: %v", err)
	}
	if len(auditRows) != 1 || auditRows[0]["event_type"] != "admin_rbac_denied" {
		t.Fatalf("audit rows = %#v, want admin_rbac_denied", auditRows)
	}
	if !auditLogEventTypes(outbox.insertedAudits)["admin_rbac_denied"] {
		t.Fatalf("outbox inserted audits = %#v, want admin_rbac_denied", outbox.insertedAudits)
	}

	req = httptest.NewRequest(http.MethodGet, "/admin/logs/access", nil)
	req.AddCookie(&http.Cookie{Name: "admin_session", Value: "admin_sess_analyst_001"})
	rec = httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status with analyst role = %d, want %d, body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
}

func TestAdminEndpointAcceptsSessionCookie(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	adminAuth := newAdminAuthStore()
	adminAuth.UpsertPrincipal(adminPrincipal{
		ID:        "admin_user_session_001",
		TenantID:  "tenant_lab_001",
		Subject:   "sub_admin_session_001",
		Email:     "admin-session@example.jp",
		Roles:     []string{"analyst"},
		IDPID:     "keycloak_lab",
		Status:    "active",
		CreatedAt: time.Now().UTC().Add(-time.Hour).Format(time.RFC3339),
	})
	adminAuth.UpsertSession(adminSession{
		ID:               "admin_sess_session_001",
		TenantID:         "tenant_lab_001",
		AdminPrincipalID: "admin_user_session_001",
		Subject:          "sub_admin_session_001",
		Roles:            []string{"analyst"},
		AuthTime:         time.Now().UTC().Add(-time.Minute).Format(time.RFC3339),
		MFAState:         "fresh",
		CreatedAt:        time.Now().UTC().Add(-time.Minute).Format(time.RFC3339),
		ExpiresAt:        time.Now().UTC().Add(time.Hour).Format(time.RFC3339),
		LastActiveAt:     time.Now().UTC().Format(time.RFC3339),
		Status:           "active",
	})
	handler := newServerWithConfig(serverConfig{
		Evaluator:  testEvaluator(),
		Writer:     writer,
		Registry:   connector.NewRegistry(),
		AdminAuth:  adminAuth,
		AdminToken: "legacy-token-not-used",
	})
	req := httptest.NewRequest(http.MethodGet, "/admin/logs/access", nil)
	req.AddCookie(&http.Cookie{Name: "admin_session", Value: "admin_sess_session_001"})
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status with admin session cookie = %d, want %d, body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
}

func TestAdminSessionRequiresPrincipal(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	adminAuth := newAdminAuthStore()
	adminAuth.UpsertSession(adminSession{
		ID:               "admin_sess_missing_principal_001",
		TenantID:         "tenant_lab_001",
		AdminPrincipalID: "admin_missing_001",
		Subject:          "sub_missing",
		Roles:            []string{"analyst"},
		AuthTime:         time.Now().UTC().Add(-time.Minute).Format(time.RFC3339),
		MFAState:         "fresh",
		CreatedAt:        time.Now().UTC().Add(-time.Minute).Format(time.RFC3339),
		ExpiresAt:        time.Now().UTC().Add(time.Hour).Format(time.RFC3339),
		LastActiveAt:     time.Now().UTC().Format(time.RFC3339),
		Status:           "active",
	})
	handler := newServerWithConfig(serverConfig{
		Evaluator:  testEvaluator(),
		Writer:     writer,
		Registry:   connector.NewRegistry(),
		AdminAuth:  adminAuth,
		AdminToken: "legacy-token-not-used",
	})
	req := httptest.NewRequest(http.MethodGet, "/admin/logs/access", nil)
	req.AddCookie(&http.Cookie{Name: "admin_session", Value: "admin_sess_missing_principal_001"})
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status with missing principal = %d, want %d, body=%s", rec.Code, http.StatusUnauthorized, rec.Body.String())
	}
}

func TestAdminLabBypassDisabledWhenAuthStoreHasRecords(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	adminAuth := newAdminAuthStore()
	adminAuth.UpsertPrincipal(adminPrincipal{
		ID:        "admin_configured_001",
		TenantID:  "tenant_lab_001",
		Subject:   "sub_configured",
		Email:     "configured@example.jp",
		Roles:     []string{"analyst"},
		IDPID:     "keycloak_lab",
		Status:    "active",
		CreatedAt: time.Now().UTC().Add(-time.Hour).Format(time.RFC3339),
	})
	handler := newServerWithConfig(serverConfig{
		Evaluator: testEvaluator(),
		Writer:    writer,
		Registry:  connector.NewRegistry(),
		AdminAuth: adminAuth,
	})
	req := httptest.NewRequest(http.MethodGet, "/admin/logs/access", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status with configured auth store and no credentials = %d, want %d, body=%s", rec.Code, http.StatusUnauthorized, rec.Body.String())
	}
}

func TestAdminLabBypassIgnoresAuthRecordsFromOtherTenants(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	adminAuth := newAdminAuthStore()
	adminAuth.UpsertPrincipal(adminPrincipal{
		ID:        "admin_other_tenant_001",
		TenantID:  "tenant_other_001",
		Subject:   "sub_other_tenant",
		Email:     "other-tenant@example.jp",
		Roles:     []string{"analyst"},
		IDPID:     "keycloak_lab",
		Status:    "active",
		CreatedAt: time.Now().UTC().Add(-time.Hour).Format(time.RFC3339),
	})
	handler := newServerWithConfig(serverConfig{
		Evaluator: testEvaluator(),
		Writer:    writer,
		Registry:  connector.NewRegistry(),
		AdminAuth: adminAuth,
	})
	req := httptest.NewRequest(http.MethodGet, "/admin/state", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status with only other-tenant auth records = %d, want %d, body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
}

func TestAdminSessionMutatingRequestRequiresCSRF(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	adminAuth := newAdminAuthStore()
	adminAuth.UpsertPrincipal(adminPrincipal{ID: "admin_user_session_write_001", TenantID: "tenant_lab_001", Subject: "sub_admin_session_write_001", Email: "admin-write@example.jp", Roles: []string{"admin"}, IDPID: "keycloak_lab", Status: "active", CreatedAt: time.Now().UTC().Add(-time.Hour).Format(time.RFC3339)})
	adminAuth.UpsertSession(adminSession{ID: "admin_sess_write_001", TenantID: "tenant_lab_001", AdminPrincipalID: "admin_user_session_write_001", Subject: "sub_admin_session_write_001", Roles: []string{"admin"}, AuthTime: time.Now().UTC().Add(-time.Minute).Format(time.RFC3339), MFAState: "fresh", CreatedAt: time.Now().UTC().Add(-time.Minute).Format(time.RFC3339), ExpiresAt: time.Now().UTC().Add(time.Hour).Format(time.RFC3339), LastActiveAt: time.Now().UTC().Format(time.RFC3339), Status: "active", Metadata: map[string]any{adminCSRFTokenKey: "csrf-test-token"}})
	outbox := &recordingAdminAuditOutboxDeadReader{}
	handler := newServerWithConfig(serverConfig{
		Evaluator:        testEvaluator(),
		Writer:           writer,
		Registry:         connector.NewRegistry(),
		AdminAuth:        adminAuth,
		AdminToken:       "legacy-token-not-used",
		AdminAuditOutbox: outbox,
	})
	body := `{"name":"csrf-test","roles":["auditor"],"expires_at":"2099-01-01T00:00:00Z"}`
	req := httptest.NewRequest(http.MethodPost, "/admin/api-tokens", strings.NewReader(body))
	req.AddCookie(&http.Cookie{Name: "admin_session", Value: "admin_sess_write_001"})
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status without csrf = %d, want %d, body=%s", rec.Code, http.StatusForbidden, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodPost, "/admin/api-tokens", strings.NewReader(body))
	req.AddCookie(&http.Cookie{Name: "admin_session", Value: "admin_sess_write_001"})
	req.Header.Set("x-csrf-token", "wrong-token")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status with wrong csrf = %d, want %d, body=%s", rec.Code, http.StatusForbidden, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodPost, "/admin/api-tokens", strings.NewReader(body))
	req.AddCookie(&http.Cookie{Name: "admin_session", Value: "admin_sess_write_001"})
	req.Header.Set("x-csrf-token", "csrf-test-token")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status with csrf = %d, want %d, body=%s", rec.Code, http.StatusCreated, rec.Body.String())
	}
	gotOutboxEvents := auditLogEventTypes(outbox.insertedAudits)
	for _, want := range []string{"admin_csrf_required", "admin_api_token_created"} {
		if !gotOutboxEvents[want] {
			t.Fatalf("outbox inserted audits = %#v, want %s", gotOutboxEvents, want)
		}
	}
}

func TestAdminLogoutMirrorsAuditOutbox(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	adminAuth := newAdminAuthStore()
	adminAuth.UpsertPrincipal(adminPrincipal{ID: "admin_user_logout_001", TenantID: "tenant_lab_001", Subject: "sub_logout", Email: "logout@example.jp", Roles: []string{"admin"}, IDPID: "keycloak_lab", Status: "active", CreatedAt: time.Now().UTC().Add(-time.Hour).Format(time.RFC3339)})
	adminAuth.UpsertSession(adminSession{ID: "admin_sess_logout_001", TenantID: "tenant_lab_001", AdminPrincipalID: "admin_user_logout_001", Subject: "sub_logout", Roles: []string{"admin"}, AuthTime: time.Now().UTC().Add(-time.Minute).Format(time.RFC3339), MFAState: "fresh", CreatedAt: time.Now().UTC().Add(-time.Minute).Format(time.RFC3339), ExpiresAt: time.Now().UTC().Add(time.Hour).Format(time.RFC3339), LastActiveAt: time.Now().UTC().Format(time.RFC3339), Status: "active", Metadata: map[string]any{adminCSRFTokenKey: "csrf-logout-token"}})
	outbox := &recordingAdminAuditOutboxDeadReader{}
	handler := newServerWithConfig(serverConfig{
		Evaluator:        testEvaluator(),
		Writer:           writer,
		Registry:         connector.NewRegistry(),
		AdminAuth:        adminAuth,
		AdminAuditOutbox: outbox,
		OIDC: oidcConfig{
			Issuer:      "http://issuer.example/realms/dsse-lab",
			ClientID:    "dsse-edge",
			RedirectURI: "http://127.0.0.1:18086/admin/oidc/callback",
		},
	})

	logoutReq := httptest.NewRequest(http.MethodPost, "/admin/logout", nil)
	logoutReq.AddCookie(&http.Cookie{Name: "admin_session", Value: "admin_sess_logout_001"})
	logoutReq.Header.Set("x-csrf-token", "csrf-logout-token")
	logoutRec := httptest.NewRecorder()
	handler.ServeHTTP(logoutRec, logoutReq)
	if logoutRec.Code != http.StatusOK {
		t.Fatalf("logout status = %d, want %d, body=%s", logoutRec.Code, http.StatusOK, logoutRec.Body.String())
	}
	gotOutboxEvents := auditLogEventTypes(outbox.insertedAudits)
	for _, want := range []string{"admin_logout"} {
		if !gotOutboxEvents[want] {
			t.Fatalf("outbox inserted audits = %#v, want %s", gotOutboxEvents, want)
		}
	}
}

func TestEdgeGeneratedRuntimeIDsAreRandomizedForSameTimestamp(t *testing.T) {
	now := time.Date(2026, 5, 24, 18, 40, 0, 0, time.UTC)
	assertDistinctPrefixed := func(name, prefix, first, second string) {
		t.Helper()
		if !strings.HasPrefix(first, prefix) || !strings.HasPrefix(second, prefix) {
			t.Fatalf("%s ids = %q, %q, want prefix %q", name, first, second, prefix)
		}
		if first == second {
			t.Fatalf("%s ids are equal for same timestamp: %q", name, first)
		}
	}

	exportReq := adminExportJobRequest{Stream: "access_logs", Format: "ndjson"}
	firstExport := newAdminExportJob(exportReq, "tenant_lab_001", "admin_lab_001", now)
	secondExport := newAdminExportJob(exportReq, "tenant_lab_001", "admin_lab_001", now)
	assertDistinctPrefixed("export job", "export_", firstExport.ID, secondExport.ID)

	breakGlassReq := breakGlassSessionRequest{
		TenantID:        "tenant_lab_001",
		UserID:          "user_breakglass_001",
		Reason:          "incident response",
		DurationSeconds: 900,
	}
	breakGlassStore := newBreakGlassRequestStore()
	firstBreakGlass, err := breakGlassStore.Create(breakGlassReq, "tenant_lab_001", now)
	if err != nil {
		t.Fatalf("create first break-glass request returned error: %v", err)
	}
	secondBreakGlass, err := breakGlassStore.Create(breakGlassReq, "tenant_lab_001", now)
	if err != nil {
		t.Fatalf("create second break-glass request returned error: %v", err)
	}
	assertDistinctPrefixed("break-glass request", "bgr_", firstBreakGlass.ID, secondBreakGlass.ID)

	httpReq := httptest.NewRequest(http.MethodPost, "/break-glass/sessions", nil)
	firstAuth, err := breakGlassAuthenticationEvent(breakGlassReq, "tenant_lab_001", httpReq, now)
	if err != nil {
		t.Fatalf("first break-glass authentication event returned error: %v", err)
	}
	secondAuth, err := breakGlassAuthenticationEvent(breakGlassReq, "tenant_lab_001", httpReq, now)
	if err != nil {
		t.Fatalf("second break-glass authentication event returned error: %v", err)
	}
	assertDistinctPrefixed("break-glass authentication event", "auth_bg_", firstAuth.ID, secondAuth.ID)
	assertDistinctPrefixed("break-glass session", breakGlassSessionPrefix, firstAuth.SessionID, secondAuth.SessionID)

	approver := "admin_lab_001"
	actorNHI := "nhi_agent_001"
	actionType := "tool.execute"
	firstApproval := model.HumanApprovalEvent{
		ApproverUserID: &approver,
		ActorNHIID:     &actorNHI,
		ActionType:     &actionType,
		ApprovalResult: "approved",
	}
	secondApproval := firstApproval
	if err := normalizeHumanApprovalEvent(&firstApproval, "tenant_lab_001", now); err != nil {
		t.Fatalf("normalize first human approval returned error: %v", err)
	}
	if err := normalizeHumanApprovalEvent(&secondApproval, "tenant_lab_001", now); err != nil {
		t.Fatalf("normalize second human approval returned error: %v", err)
	}
	assertDistinctPrefixed("human approval event", "hae_", firstApproval.ID, secondApproval.ID)

	firstGrant := model.DelegatedAccessGrant{SubjectUserID: "user_001", ActorNHIID: actorNHI}
	secondGrant := firstGrant
	if err := normalizeDelegatedAccessGrant(&firstGrant, "tenant_lab_001", now); err != nil {
		t.Fatalf("normalize first delegated grant returned error: %v", err)
	}
	if err := normalizeDelegatedAccessGrant(&secondGrant, "tenant_lab_001", now); err != nil {
		t.Fatalf("normalize second delegated grant returned error: %v", err)
	}
	assertDistinctPrefixed("delegated access grant", "dag_", firstGrant.ID, secondGrant.ID)

	var firstInspection model.InspectionEvent
	var secondInspection model.InspectionEvent
	if err := normalizeInspectionEvent(&firstInspection, "tenant_lab_001", now); err != nil {
		t.Fatalf("normalize first inspection event returned error: %v", err)
	}
	if err := normalizeInspectionEvent(&secondInspection, "tenant_lab_001", now); err != nil {
		t.Fatalf("normalize second inspection event returned error: %v", err)
	}
	assertDistinctPrefixed("inspection event", "ie_", firstInspection.ID, secondInspection.ID)
}

func TestLegacyAdminTokenIgnoresClientSuppliedIdentity(t *testing.T) {
	// Drives an admin route with the shared break-glass token, which is off by default now.
	armBreakGlassForTest(t)
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	handler := newServerWithConfig(serverConfig{
		Evaluator:  testEvaluator(),
		Writer:     writer,
		Registry:   connector.NewRegistry(),
		AdminToken: "legacy-admin-token",
	})
	req := httptest.NewRequest(http.MethodPost, "/admin/export-jobs", strings.NewReader(`{"stream":"access","format":"ndjson","from":"2026-05-23T00:00:00Z","to":"2026-05-24T00:00:00Z"}`))
	req.Header.Set("authorization", "Bearer legacy-admin-token")
	req.Header.Set("x-admin-principal-id", "spoofed_admin")
	req.Header.Set("x-admin-roles", "approver")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status with legacy token = %d, want %d, body=%s", rec.Code, http.StatusAccepted, rec.Body.String())
	}
	var job adminExportJob
	if err := json.NewDecoder(rec.Body).Decode(&job); err != nil {
		t.Fatalf("decode export job: %v", err)
	}
	if job.CreatedByAdminPrincipalID != "admin_legacy_token" {
		t.Fatalf("created_by = %q, want admin_legacy_token", job.CreatedByAdminPrincipalID)
	}
}

func TestAdminRolesFromRequestDoesNotDefaultOwner(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/admin/state", nil)
	if roles := adminRolesFromRequest(req); len(roles) != 0 {
		t.Fatalf("roles without header = %#v, want empty", roles)
	}
	req.Header.Set("x-admin-roles", "owner")
	req.Header.Set("x-admin-principal-id", "spoofed_admin")
	if roles := adminRolesFromRequest(req); len(roles) != 0 {
		t.Fatalf("roles from client supplied header = %#v, want empty", roles)
	}
	if principalID := adminPrincipalIDFromRequest(req); principalID != "admin_lab_001" {
		t.Fatalf("principal from client supplied header = %q, want fallback", principalID)
	}
	if tenantID := adminTenantIDFromRequest(req); tenantID != "" {
		t.Fatalf("tenant from request without auth context = %q, want empty", tenantID)
	}
	req = requestWithAdminIdentity(req, adminIdentity{
		PrincipalID: "admin_context_001",
		TenantID:    "tenant_lab_001",
		Roles:       []string{"auditor"},
		AuthMethod:  "admin_api_token",
	})
	if principalID := adminPrincipalIDFromRequest(req); principalID != "admin_context_001" {
		t.Fatalf("principal from context = %q", principalID)
	}
	if roles := adminRolesFromRequest(req); len(roles) != 1 || roles[0] != "auditor" {
		t.Fatalf("roles from context = %#v", roles)
	}
	if tenantID := adminTenantIDFromRequest(req); tenantID != "tenant_lab_001" {
		t.Fatalf("tenant from context = %q", tenantID)
	}
	if method := adminAuthMethodFromRequest(req); method != "admin_api_token" {
		t.Fatalf("auth method from context = %q", method)
	}
}

func TestAdminAccessDecisionDetailCorrelatesLogs(t *testing.T) {
	logDir := t.TempDir()
	writer, err := logs.NewWriter(logDir)
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	decisionStore := newAccessDecisionStore()
	decisionStore.Upsert(model.AccessDecision{
		ID:                  "dec_detail_001",
		TenantID:            "tenant_lab_001",
		ActorType:           "delegated_agent",
		ApplicationID:       "app_dummy_https",
		PolicyID:            "pol_lab_nhi_tool_allow_001",
		PolicyBundleID:      "pb_lab_20260522_001",
		PolicyBundleVersion: "2026.05.22.001",
		Decision:            "allow",
		ReasonCodes:         []string{"policy_matched"},
		Actions:             []model.DecisionAction{},
		CacheStatus:         "miss",
		TTLSeconds:          60,
		Metadata:            map[string]any{},
	})
	for filename, row := range map[string]map[string]any{
		"access.log.jsonl":            {"id": "alog_detail_001", "tenant_id": "tenant_lab_001", "access_decision_id": "dec_detail_001"},
		"decision_trace.log.jsonl":    {"id": "trace_detail_001", "tenant_id": "tenant_lab_001", "access_decision_id": "dec_detail_001"},
		"audit.log.jsonl":             {"id": "audit_detail_001", "tenant_id": "tenant_lab_001", "access_decision_id": "dec_detail_001"},
		"tool_call_events.log.jsonl":  {"id": "tce_detail_001", "tenant_id": "tenant_lab_001", "access_decision_id": "dec_detail_001"},
		"inspection_events.log.jsonl": {"id": "ie_detail_001", "tenant_id": "tenant_lab_001", "access_decision_id": "dec_detail_001"},
	} {
		if err := writer.Append(filename, row); err != nil {
			t.Fatalf("append %s returned error: %v", filename, err)
		}
	}
	handler := newServerWithConfig(serverConfig{
		Evaluator:     testEvaluator(),
		Writer:        writer,
		Registry:      connector.NewRegistry(),
		DecisionStore: decisionStore,
	})
	req := httptest.NewRequest(http.MethodGet, "/admin/access-decisions/dec_detail_001", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var detail map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&detail); err != nil {
		t.Fatalf("decode detail: %v", err)
	}
	if detail["access_decision_id"] != "dec_detail_001" {
		t.Fatalf("detail = %#v, want decision id", detail)
	}
	summary, ok := detail["summary"].(map[string]any)
	if !ok || summary["related_log_rows"] != float64(5) {
		t.Fatalf("summary = %#v, want 5 related rows", detail["summary"])
	}
	related, ok := detail["related_logs"].(map[string]any)
	if !ok {
		t.Fatalf("related_logs = %#v", detail["related_logs"])
	}
	inspectionRows, ok := related["inspection_events"].([]any)
	if !ok || len(inspectionRows) != 1 {
		t.Fatalf("inspection rows = %#v", related["inspection_events"])
	}
}

func TestAdminAccessDecisionDetailScopesTenant(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	decisionStore := newAccessDecisionStore()
	decisionStore.Upsert(model.AccessDecision{
		ID:                  "dec_other_tenant_001",
		TenantID:            "tenant_other_001",
		ActorType:           "human",
		ApplicationID:       "app_dummy_https",
		PolicyID:            "pol_lab_https_allow_001",
		PolicyBundleID:      "pb_lab_20260522_001",
		PolicyBundleVersion: "2026.05.22.001",
		Decision:            "allow",
		ReasonCodes:         []string{"policy_matched"},
		Actions:             []model.DecisionAction{},
		CacheStatus:         "miss",
		TTLSeconds:          60,
		Metadata:            map[string]any{},
	})
	if err := writer.Append("access.log.jsonl", map[string]any{
		"id":                 "alog_other_tenant_001",
		"tenant_id":          "tenant_other_001",
		"access_decision_id": "dec_other_tenant_001",
	}); err != nil {
		t.Fatalf("append access log returned error: %v", err)
	}
	handler := newServerWithConfig(serverConfig{
		Evaluator:     testEvaluator(),
		Writer:        writer,
		Registry:      connector.NewRegistry(),
		DecisionStore: decisionStore,
	})
	req := httptest.NewRequest(http.MethodGet, "/admin/access-decisions/dec_other_tenant_001", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusNotFound, rec.Body.String())
	}
}

func TestDecisionEvaluateHandlerWritesLogs(t *testing.T) {
	logDir := t.TempDir()
	writer, err := logs.NewWriter(logDir)
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	domainOutbox := &recordingDomainEventOutbox{}
	usageMeters := usagemeter.NewUsageMeterStore()
	handler := newServerWithConfig(serverConfig{
		Evaluator:         testEvaluator(),
		Writer:            writer,
		Registry:          connector.NewRegistry(),
		DomainEventOutbox: domainOutbox,
		UsageMeters:       usageMeters,
	})
	body := `{
		"tenant_id":"tenant_lab_001",
		"session_id":"sess_lab_001",
		"user_id":"user_lab_001",
		"subject_user_id":"user_lab_001",
		"actor_type":"human",
		"device_id":"dev_lab_001",
		"application_id":"app_dummy_https",
		"application_sensitivity":"medium",
		"source_ip":"127.0.0.1",
		"source_port":50100,
		"destination":"dummy-private-app.local",
		"destination_ip":"127.0.0.1",
		"destination_port":8443,
		"protocol":"tcp",
		"fqdn":"dummy-private-app.local",
		"sni":"dummy-private-app.local",
		"service_family":"https",
		"connection_initiator":"client",
		"source_role":"managed_endpoint",
		"destination_role":"private_app"
	}`
	req := httptest.NewRequest(http.MethodPost, "/decisions/evaluate", strings.NewReader(body))
	req.Header.Set("content-type", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var dec model.AccessDecision
	if err := json.NewDecoder(rec.Body).Decode(&dec); err != nil {
		t.Fatalf("decode decision response: %v", err)
	}
	if dec.Decision != "allow" {
		t.Fatalf("decision = %q, want allow", dec.Decision)
	}
	assertLogExists(t, logDir, "access.log.jsonl")
	// decision_trace was folded into the access log (double-write collapse) — one domain event, not two.
	domainEvents := domainOutbox.insertedEvents()
	if len(domainEvents) != 1 {
		t.Fatalf("domain events = %#v, want a single access log event", domainEvents)
	}
	streams := map[string]domainEventOutboxEnvelope{}
	for _, event := range domainEvents {
		streams[event.Stream] = event
	}
	if streams["access_logs"].EventPlane != "access" || streams["access_logs"].EventType != "access_log_recorded" || streams["access_logs"].Payload["access_decision_id"] != dec.ID {
		t.Fatalf("access domain event = %#v", streams["access_logs"])
	}
	now := time.Now().UTC()
	periodStart := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	usageSummary := usageMeters.Summary("tenant_lab_001", periodStart, periodStart.AddDate(0, 1, 0))
	assertUsageMeterSummary(t, usageSummary.Meters["decision"], "decision", "decision", "sum", 1, 1)
}

func TestDecisionEvaluateDomainOutboxFailureDoesNotBlock(t *testing.T) {
	logDir := t.TempDir()
	writer, err := logs.NewWriter(logDir)
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	handler := newServerWithConfig(serverConfig{
		Evaluator:         testEvaluator(),
		Writer:            writer,
		Registry:          connector.NewRegistry(),
		DomainEventOutbox: &recordingDomainEventOutbox{err: fmt.Errorf("domain outbox down")},
	})
	body := `{
		"tenant_id":"tenant_lab_001",
		"session_id":"sess_lab_001",
		"user_id":"user_lab_001",
		"subject_user_id":"user_lab_001",
		"actor_type":"human",
		"device_id":"dev_lab_001",
		"application_id":"app_dummy_https",
		"application_sensitivity":"medium",
		"source_ip":"127.0.0.1",
		"destination":"dummy-private-app.local",
		"destination_port":8443,
		"protocol":"tcp",
		"service_family":"https",
		"connection_initiator":"client",
		"source_role":"managed_endpoint",
		"destination_role":"private_app"
	}`
	req := httptest.NewRequest(http.MethodPost, "/decisions/evaluate", strings.NewReader(body))
	req.Header.Set("content-type", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	assertLogExists(t, logDir, "access.log.jsonl")
}

func TestAuthenticationEventCreatesSession(t *testing.T) {
	logDir := t.TempDir()
	writer, err := logs.NewWriter(logDir)
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	domainOutbox := &recordingDomainEventOutbox{}
	handler := newServerWithConfig(serverConfig{
		Evaluator:         testEvaluator(),
		Writer:            writer,
		Registry:          connector.NewRegistry(),
		DomainEventOutbox: domainOutbox,
	})
	body := `{
		"id":"auth_lab_001",
		"tenant_id":"tenant_lab_001",
		"user_id":"user_lab_001",
		"subject_user_id":"user_lab_001",
		"session_id":"sess_lab_001",
		"idp_id":"idp_keycloak_lab",
		"method":"oidc_authorization_code",
		"amr":["pwd","otp"],
		"acr":"urn:mfa:fresh",
		"mfa_state":"fresh",
		"auth_time":"2026-05-22T00:00:00Z",
		"expires_at":"2026-05-22T01:00:00Z",
		"source_ip":"127.0.0.1",
		"device_id":"dev_lab_001",
		"result":"success",
		"timestamp":"2026-05-22T00:00:00Z",
		"metadata":{}
	}`
	createReq := httptest.NewRequest(http.MethodPost, "/auth/events", strings.NewReader(body))
	createRec := httptest.NewRecorder()
	handler.ServeHTTP(createRec, createReq)
	if createRec.Code != http.StatusCreated {
		t.Fatalf("create session status = %d, want %d, body=%s", createRec.Code, http.StatusCreated, createRec.Body.String())
	}
	var session model.Session
	if err := json.NewDecoder(createRec.Body).Decode(&session); err != nil {
		t.Fatalf("decode session response: %v", err)
	}
	if session.ID != "sess_lab_001" {
		t.Fatalf("session id = %q, want sess_lab_001", session.ID)
	}

	getReq := httptest.NewRequest(http.MethodGet, "/sessions/sess_lab_001", nil)
	getRec := httptest.NewRecorder()
	handler.ServeHTTP(getRec, getReq)
	if getRec.Code != http.StatusOK {
		t.Fatalf("get session status = %d, want %d, body=%s", getRec.Code, http.StatusOK, getRec.Body.String())
	}
	auditLog, err := os.ReadFile(filepath.Join(logDir, "audit.log.jsonl"))
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	if !strings.Contains(string(auditLog), "authentication_event_recorded") {
		t.Fatalf("audit log = %s, want authentication_event_recorded", string(auditLog))
	}
	domainEvents := domainOutbox.insertedEvents()
	if len(domainEvents) != 1 || domainEvents[0].Stream != "authentication_events" || domainEvents[0].EventType != "authentication_event_recorded" || domainEvents[0].Payload["session_id"] != "sess_lab_001" {
		t.Fatalf("domain events = %#v", domainEvents)
	}
}

func TestStringArrayClaimAcceptsKeycloakStringAMR(t *testing.T) {
	values := map[string]any{"amr": "otp"}
	amr := stringArrayClaim(values, "amr")
	if len(amr) != 1 || amr[0] != "otp" {
		t.Fatalf("amr = %v, want [otp]", amr)
	}
	if mfaStateFromAMR(amr) != "fresh" {
		t.Fatalf("mfa state = %s, want fresh", mfaStateFromAMR(amr))
	}
}

func TestMockCallbackSessionEnrichesDecision(t *testing.T) {
	logDir := t.TempDir()
	writer, err := logs.NewWriter(logDir)
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	evaluator := testEvaluator()
	evaluator.Policies = append([]model.Policy{
		{
			ID:       "pol_lab_mfa_https_allow_001",
			TenantID: "tenant_lab_001",
			Priority: 50,
			Conditions: map[string]any{
				"actor_type":     "human",
				"application_id": "app_dummy_https",
				"service_family": "https",
				"mfa_state":      "fresh",
				"amr": map[string]any{
					"op":    "contains",
					"value": "otp",
				},
			},
			Action: model.PolicyAction{Decision: "allow"},
			Status: "active",
		},
	}, evaluator.Policies...)
	handler := newServer(evaluator, writer, connector.NewRegistry())

	callbackReq := httptest.NewRequest(http.MethodGet, "/auth/mock/callback?code=mock-code&state=mock-state&session_id=sess_oidc_mock_001", nil)
	callbackRec := httptest.NewRecorder()
	handler.ServeHTTP(callbackRec, callbackReq)
	if callbackRec.Code != http.StatusCreated {
		t.Fatalf("callback status = %d, want %d, body=%s", callbackRec.Code, http.StatusCreated, callbackRec.Body.String())
	}

	decisionReq := httptest.NewRequest(http.MethodPost, "/decisions/evaluate", strings.NewReader(`{
		"session_id":"sess_oidc_mock_001",
		"actor_type":"human",
		"application_id":"app_dummy_https",
		"application_sensitivity":"medium",
		"destination":"dummy-private-app.local",
		"destination_port":8443,
		"protocol":"tcp",
		"service_family":"https",
		"connection_initiator":"client",
		"source_role":"managed_endpoint",
		"destination_role":"private_app"
	}`))
	decisionRec := httptest.NewRecorder()
	handler.ServeHTTP(decisionRec, decisionReq)
	if decisionRec.Code != http.StatusOK {
		t.Fatalf("decision status = %d, want %d, body=%s", decisionRec.Code, http.StatusOK, decisionRec.Body.String())
	}
	var dec model.AccessDecision
	if err := json.NewDecoder(decisionRec.Body).Decode(&dec); err != nil {
		t.Fatalf("decode decision response: %v", err)
	}
	if dec.Decision != "allow" {
		t.Fatalf("decision = %q, want allow", dec.Decision)
	}
	if dec.PolicyID != "pol_lab_mfa_https_allow_001" {
		t.Fatalf("policy_id = %q, want pol_lab_mfa_https_allow_001", dec.PolicyID)
	}
	if dec.UserID == nil || *dec.UserID != "user_lab_001" {
		t.Fatalf("user_id = %v, want user_lab_001", dec.UserID)
	}
	if dec.AuthenticationEventID == nil {
		t.Fatalf("authentication_event_id is nil")
	}
	if dec.Metadata["mfa_state"] != "fresh" {
		t.Fatalf("metadata mfa_state = %v", dec.Metadata["mfa_state"])
	}
	if !recorderHasCookie(callbackRec, "session_id") {
		t.Fatalf("mock callback did not set session_id cookie: %#v", callbackRec.Result().Cookies())
	}
}

func TestPrivateAppBrowserReauthenticationRedirectPreservesReturnTo(t *testing.T) {
	logDir := t.TempDir()
	writer, err := logs.NewWriter(logDir)
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	handler := newServerWithConfig(serverConfig{
		Evaluator: testEvaluatorWithPolicies([]model.Policy{
			{
				ID:       "pol_private_app_reauth_without_session_001",
				TenantID: "tenant_lab_001",
				Priority: 10,
				Conditions: map[string]any{
					"application_id":     "app_private_internal_web",
					"service_family":     "https",
					"session_id_present": "false",
				},
				Action: model.PolicyAction{Decision: "require_reauthentication"},
				Status: "active",
			},
		}),
		Writer:   writer,
		Registry: connector.NewRegistry(),
	})

	registerReq := httptest.NewRequest(http.MethodPost, "/connectors/register", strings.NewReader(`{
		"id":"conn_private_001",
		"tenant_id":"tenant_lab_001",
		"connector_group_id":"cgrp_private_001",
		"name":"Private App Connector",
		"edge_region_id":"local",
		"edge_cluster_id":"local-edge-001",
		"application_ids":["app_private_internal_web"],
		"private_base_url":"http://connector-private.local",
		"status":"registered",
		"metadata":{}
	}`))
	registerReq.Header.Set(connectorSecretHeader, defaultConnectorSecret)
	registerRec := httptest.NewRecorder()
	handler.ServeHTTP(registerRec, registerReq)
	if registerRec.Code != http.StatusCreated {
		t.Fatalf("register status = %d, want %d, body=%s", registerRec.Code, http.StatusCreated, registerRec.Body.String())
	}

	appPath := "/apps/app_private_internal_web?connector_id=conn_private_001"
	req := httptest.NewRequest(http.MethodGet, appPath, nil)
	req.Header.Set("accept", "text/html")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	location := rec.Header().Get("Location")
	parsedLocation, parseErr := url.Parse(location)
	if parseErr != nil {
		t.Fatalf("parse redirect location %q: %v", location, parseErr)
	}
	if rec.Code != http.StatusFound || parsedLocation.Path != "/auth/oidc/login" || parsedLocation.Query().Get("return_to") != appPath {
		t.Fatalf("status=%d location=%q body=%s, want OIDC login redirect preserving return_to", rec.Code, location, rec.Body.String())
	}

	jsonReq := httptest.NewRequest(http.MethodGet, appPath, nil)
	jsonReq.Header.Set("accept", "application/json")
	jsonRec := httptest.NewRecorder()
	handler.ServeHTTP(jsonRec, jsonReq)
	if jsonRec.Code != http.StatusUnauthorized {
		t.Fatalf("json status = %d, want %d, body=%s", jsonRec.Code, http.StatusUnauthorized, jsonRec.Body.String())
	}
	var dec model.AccessDecision
	if err := json.NewDecoder(jsonRec.Body).Decode(&dec); err != nil {
		t.Fatalf("decode JSON decision: %v", err)
	}
	if dec.Decision != "require_reauthentication" || dec.PolicyID != "pol_private_app_reauth_without_session_001" {
		t.Fatalf("decision=%q policy=%q, want require_reauthentication product policy", dec.Decision, dec.PolicyID)
	}
}

func TestMockCallbackDisabledOutsideLabMode(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	handler := newServerWithConfig(serverConfig{
		Evaluator: testEvaluator(),
		Writer:    writer,
		LabMode:   boolPtr(false),
	})

	req := httptest.NewRequest(http.MethodGet, "/auth/mock/callback?session_id=sess_mock_disabled_001", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusNotFound, rec.Body.String())
	}
}

func TestConnectorRoutingSupportsSSHApplication(t *testing.T) {
	logDir := t.TempDir()
	writer, err := logs.NewWriter(logDir)
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	evaluator := testEvaluatorWithPolicies([]model.Policy{
		{
			ID:       "pol_lab_ssh_allow_001",
			TenantID: "tenant_lab_001",
			Priority: 100,
			Conditions: map[string]any{
				"actor_type":       "human",
				"application_id":   "app_dummy_ssh",
				"service_family":   "ssh",
				"destination_port": "22",
			},
			Action: model.PolicyAction{Decision: "allow"},
			Status: "active",
		},
	})
	handler := newServerWithClient(evaluator, writer, connector.NewRegistry(), &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Path != "/private-app/dummy-ssh" {
			t.Fatalf("path = %s, want /private-app/dummy-ssh", req.URL.Path)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"content-type": []string{"application/json"}},
			Body:       io.NopCloser(bytes.NewBufferString(`{"status":"ssh_banner_reachable","banner":"SSH-2.0-Dsse-Lab"}`)),
		}, nil
	})})
	registerReq := httptest.NewRequest(http.MethodPost, "/connectors/register", strings.NewReader(`{
		"id":"conn_lab_001",
		"tenant_id":"tenant_lab_001",
		"connector_group_id":"cgrp_lab_001",
		"name":"Lab Connector",
		"edge_region_id":"local",
		"edge_cluster_id":"local-edge-001",
		"application_ids":["app_dummy_https","app_dummy_ssh"],
		"private_base_url":"http://connector.local",
		"status":"registered",
		"metadata":{}
	}`))
	registerReq.Header.Set(connectorSecretHeader, defaultConnectorSecret)
	registerRec := httptest.NewRecorder()
	handler.ServeHTTP(registerRec, registerReq)
	if registerRec.Code != http.StatusCreated {
		t.Fatalf("register status = %d, want %d, body=%s", registerRec.Code, http.StatusCreated, registerRec.Body.String())
	}

	proxyReq := httptest.NewRequest(http.MethodGet, "/apps/app_dummy_ssh?connector_id=conn_lab_001&service_family=https&destination_port=443&destination=dummy-private-app.local", nil)
	proxyRec := httptest.NewRecorder()
	handler.ServeHTTP(proxyRec, proxyReq)
	if proxyRec.Code != http.StatusOK {
		t.Fatalf("proxy status = %d, want %d, body=%s", proxyRec.Code, http.StatusOK, proxyRec.Body.String())
	}
	if !strings.Contains(proxyRec.Body.String(), "ssh_banner_reachable") {
		t.Fatalf("proxy body = %s", proxyRec.Body.String())
	}

	accessLog, err := os.ReadFile(filepath.Join(logDir, "access.log.jsonl"))
	if err != nil {
		t.Fatalf("read access log: %v", err)
	}
	if !strings.Contains(string(accessLog), `"service_family":"ssh"`) {
		t.Fatalf("access log = %s, want ssh service_family", string(accessLog))
	}
	traceLog, err := os.ReadFile(filepath.Join(logDir, "access.log.jsonl"))
	if err != nil {
		t.Fatalf("read access log: %v", err)
	}
	if !strings.Contains(string(traceLog), "pol_lab_ssh_allow_001") {
		t.Fatalf("access log = %s, want ssh policy", string(traceLog))
	}
	connectorLog, err := os.ReadFile(filepath.Join(logDir, "connector.log.jsonl"))
	if err != nil {
		t.Fatalf("read connector log: %v", err)
	}
	if !strings.Contains(string(connectorLog), `"service_family":"ssh"`) || !strings.Contains(string(connectorLog), `"destination_port":22`) {
		t.Fatalf("connector log = %s, want ssh route details", string(connectorLog))
	}
}

func TestConnectorRoutingReturnsDecisionForSSHReauthentication(t *testing.T) {
	logDir := t.TempDir()
	writer, err := logs.NewWriter(logDir)
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	evaluator := testEvaluatorWithPolicies([]model.Policy{
		{
			ID:       "pol_lab_ssh_reauth_required_001",
			TenantID: "tenant_lab_001",
			Priority: 50,
			Conditions: map[string]any{
				"actor_type":     "human",
				"application_id": "app_dummy_ssh",
				"service_family": "ssh",
				"auth_age_seconds": map[string]any{
					"op":    "gte",
					"value": 901,
				},
			},
			Action: model.PolicyAction{Decision: "require_reauthentication"},
			Status: "active",
			Metadata: map[string]any{
				"reauth_interval_seconds": 900,
			},
		},
		{
			ID:       "pol_lab_ssh_allow_001",
			TenantID: "tenant_lab_001",
			Priority: 100,
			Conditions: map[string]any{
				"actor_type":     "human",
				"application_id": "app_dummy_ssh",
				"service_family": "ssh",
			},
			Action: model.PolicyAction{Decision: "allow"},
			Status: "active",
		},
	})
	handler := newServerWithClient(evaluator, writer, connector.NewRegistry(), &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		t.Fatalf("proxy client was called for reauth decision")
		return nil, nil
	})})
	registerReq := httptest.NewRequest(http.MethodPost, "/connectors/register", strings.NewReader(`{
		"id":"conn_lab_001",
		"tenant_id":"tenant_lab_001",
		"connector_group_id":"cgrp_lab_001",
		"name":"Lab Connector",
		"edge_region_id":"local",
		"edge_cluster_id":"local-edge-001",
		"application_ids":["app_dummy_ssh"],
		"private_base_url":"http://connector.local",
		"status":"registered",
		"metadata":{}
	}`))
	registerReq.Header.Set(connectorSecretHeader, defaultConnectorSecret)
	registerRec := httptest.NewRecorder()
	handler.ServeHTTP(registerRec, registerReq)
	if registerRec.Code != http.StatusCreated {
		t.Fatalf("register status = %d, want %d, body=%s", registerRec.Code, http.StatusCreated, registerRec.Body.String())
	}

	authBody := fmt.Sprintf(`{
		"id":"auth_ssh_stale_001",
		"tenant_id":"tenant_lab_001",
		"user_id":"user_lab_001",
		"subject_user_id":"user_lab_001",
		"session_id":"sess_ssh_stale_001",
		"idp_id":"idp_keycloak_lab",
		"method":"oidc_authorization_code",
		"amr":["pwd","otp"],
		"acr":"urn:mfa:fresh",
		"mfa_state":"fresh",
		"auth_time":%q,
		"expires_at":%q,
		"device_id":"dev_lab_001",
		"result":"success",
		"timestamp":%q,
		"metadata":{}
	}`, time.Now().Add(-20*time.Minute).UTC().Format(time.RFC3339), time.Now().Add(time.Hour).UTC().Format(time.RFC3339), time.Now().UTC().Format(time.RFC3339))
	authReq := httptest.NewRequest(http.MethodPost, "/auth/events", strings.NewReader(authBody))
	authRec := httptest.NewRecorder()
	handler.ServeHTTP(authRec, authReq)
	if authRec.Code != http.StatusCreated {
		t.Fatalf("auth status = %d, want %d, body=%s", authRec.Code, http.StatusCreated, authRec.Body.String())
	}

	proxyReq := httptest.NewRequest(http.MethodGet, "/apps/app_dummy_ssh?connector_id=conn_lab_001", nil)
	proxyReq.AddCookie(&http.Cookie{Name: "session_id", Value: "sess_ssh_stale_001"})
	proxyRec := httptest.NewRecorder()
	handler.ServeHTTP(proxyRec, proxyReq)
	if proxyRec.Code != http.StatusUnauthorized {
		t.Fatalf("proxy status = %d, want %d, body=%s", proxyRec.Code, http.StatusUnauthorized, proxyRec.Body.String())
	}
	var dec model.AccessDecision
	if err := json.NewDecoder(proxyRec.Body).Decode(&dec); err != nil {
		t.Fatalf("decode decision: %v", err)
	}
	if dec.Decision != "require_reauthentication" {
		t.Fatalf("decision = %q, want require_reauthentication", dec.Decision)
	}
	if len(dec.Actions) != 1 || dec.Actions[0].Type != "prompt_reauthentication" {
		t.Fatalf("actions = %#v, want prompt_reauthentication", dec.Actions)
	}
	if dec.Actions[0].TTLSeconds == nil || *dec.Actions[0].TTLSeconds != 900 {
		t.Fatalf("action ttl = %#v, want 900", dec.Actions[0].TTLSeconds)
	}
}

func TestEdgeTCPConnectTargetUsesRouteProfileAuthority(t *testing.T) {
	routeProfiles := map[string]edgeplane.ApplicationRouteProfile{
		"app_dummy_https": {
			Destination:     "route-profile.internal",
			DestinationPort: 8443,
			ServiceFamily:   "https",
		},
	}
	target, err := edgeplane.EdgeTCPConnectTargetForApplication("app_dummy_https", "ROUTE-PROFILE.INTERNAL", 8443, routeProfiles)
	if err != nil {
		t.Fatalf("edgeplane.EdgeTCPConnectTargetForApplication returned error: %v", err)
	}
	if target.Host != "route-profile.internal" || target.Port != 8443 || target.ApplicationID != "app_dummy_https" || target.ServiceFamily != "https" {
		t.Fatalf("target = %+v, want route profile authority", target)
	}
}

func TestDecisionPermitsConnectorRouteForNonBlockingVerdicts(t *testing.T) {
	for _, decision := range []string{"allow", "warn", "audit_only"} {
		if !decisionPermitsConnectorRoute(decision) {
			t.Fatalf("decisionPermitsConnectorRoute(%q) = false, want true", decision)
		}
	}
	// "observe" is in the refused set now: Policy Learning was the only producer and it is gone (2026-08-05).
	// An unknown verdict must not open a route.
	for _, decision := range []string{"deny", "observe", "require_reauthentication", "require_workload_attestation"} {
		if decisionPermitsConnectorRoute(decision) {
			t.Fatalf("decisionPermitsConnectorRoute(%q) = true, want false", decision)
		}
	}
}

func TestEdgeConnectPolicyDecisionTakeoverBlocksDeniedBeforeTCPOpenAndAllowsOpen(t *testing.T) {
	logDir := t.TempDir()
	writer, err := logs.NewWriter(logDir)
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	registry := connector.NewRegistry()
	if _, err := registry.Register(model.ConnectorRegistration{
		ID:               "conn_lab_001",
		TenantID:         "tenant_lab_001",
		ConnectorGroupID: "cgrp_lab_001",
		Name:             "Lab Connector",
		EdgeRegionID:     "local",
		EdgeClusterID:    "local-edge-001",
		ApplicationIDs:   []string{"app_denied_https", "app_allowed_https"},
		PrivateBaseURL:   "http://connector.local",
		Status:           "registered",
		Metadata:         map[string]any{},
	}, time.Now()); err != nil {
		t.Fatalf("Register returned error: %v", err)
	}

	clientRaw, serverRaw := net.Pipe()
	defer clientRaw.Close()
	defer serverRaw.Close()
	clientTunnelConn := tunnel.NewInProcessConn(clientRaw, true)
	serverTunnelConn := tunnel.NewInProcessConn(serverRaw, false)
	tunnelManager := tunnel.NewManagerWithRequestTimeout(500 * time.Millisecond)
	session, _ := tunnelManager.Register("conn_lab_001", "tun_lab_001", clientTunnelConn)
	runDone := make(chan error, 1)
	go func() {
		runDone <- session.Run()
	}()

	routeProfiles := map[string]edgeplane.ApplicationRouteProfile{
		"app_denied_https": {
			Destination:            "denied-route.internal",
			DestinationPort:        8443,
			Protocol:               "tcp",
			ServiceFamily:          "https",
			DestinationRole:        "private_app",
			ApplicationSensitivity: "high",
		},
		"app_allowed_https": {
			Destination:            "allowed-route.internal",
			DestinationPort:        8443,
			Protocol:               "tcp",
			ServiceFamily:          "https",
			DestinationRole:        "private_app",
			ApplicationSensitivity: "high",
		},
	}
	evaluator := testEvaluatorWithPolicies([]model.Policy{
		{
			ID:       "pol_lab_denied_https_001",
			TenantID: "tenant_lab_001",
			Priority: 10,
			Conditions: map[string]any{
				"actor_type":     "human",
				"application_id": "app_denied_https",
				"service_family": "https",
			},
			Action: model.PolicyAction{Decision: "deny"},
			Status: "active",
		},
		{
			ID:       "pol_lab_allowed_https_001",
			TenantID: "tenant_lab_001",
			Priority: 100,
			Conditions: map[string]any{
				"actor_type":     "human",
				"application_id": "app_allowed_https",
				"service_family": "https",
			},
			Action: model.PolicyAction{Decision: "allow"},
			Status: "active",
		},
	})
	handler := newServerWithConfig(serverConfig{
		Evaluator:     evaluator,
		Writer:        writer,
		Registry:      registry,
		TunnelManager: tunnelManager,
		RouteProfiles: routeProfiles,
		ProxyClient: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			t.Fatalf("proxy client was called for CONNECT decision takeover")
			return nil, nil
		})},
	})

	denyReq := httptest.NewRequest(http.MethodConnect, "/apps/app_denied_https?connector_id=conn_lab_001", nil)
	denyReq.Header.Set(edgeplane.ConnectAuthorityHeader, "denied-route.internal:8443")
	denyRec := httptest.NewRecorder()
	handler.ServeHTTP(denyRec, denyReq)
	if denyRec.Code != http.StatusForbidden {
		t.Fatalf("deny status = %d, want %d, body=%s", denyRec.Code, http.StatusForbidden, denyRec.Body.String())
	}
	var deniedDecision model.AccessDecision
	if err := json.NewDecoder(denyRec.Body).Decode(&deniedDecision); err != nil {
		t.Fatalf("decode denied decision: %v", err)
	}
	if deniedDecision.Decision != "deny" || deniedDecision.PolicyID != "pol_lab_denied_https_001" {
		t.Fatalf("denied decision = %+v, want explicit deny policy", deniedDecision)
	}
	if err := serverRaw.SetReadDeadline(time.Now().Add(75 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline returned error: %v", err)
	}
	var unexpectedOpen tunnel.Frame
	err = serverTunnelConn.ReadJSON(&unexpectedOpen)
	if err == nil {
		t.Fatalf("denied CONNECT emitted tunnel frame %+v, want no tcp_open", unexpectedOpen)
	}
	if netErr, ok := err.(net.Error); !ok || !netErr.Timeout() {
		t.Fatalf("denied CONNECT tunnel read error = %v, want timeout with no frame", err)
	}
	if err := serverRaw.SetReadDeadline(time.Time{}); err != nil {
		t.Fatalf("clearing read deadline returned error: %v", err)
	}

	allowReq := httptest.NewRequest(http.MethodConnect, "/apps/app_allowed_https?connector_id=conn_lab_001", nil)
	allowReq.Header.Set(edgeplane.ConnectAuthorityHeader, "allowed-route.internal:8443")
	allowDone := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		allowRec := httptest.NewRecorder()
		handler.ServeHTTP(allowRec, allowReq)
		allowDone <- allowRec
	}()

	var openFrame tunnel.Frame
	if err := serverTunnelConn.ReadJSON(&openFrame); err != nil {
		t.Fatalf("ReadJSON allowed tcp_open returned error: %v", err)
	}
	if openFrame.Type != tunnel.FrameTCPOpen || openFrame.ApplicationID != "app_allowed_https" || openFrame.Host != "allowed-route.internal" || openFrame.Port != 8443 || openFrame.TunnelID != "tun_lab_001" {
		t.Fatalf("openFrame = %+v, want allowed route tcp_open", openFrame)
	}
	if openFrame.RequestID == "" || !strings.HasPrefix(openFrame.RequestID, "req_tcp_") {
		t.Fatalf("openFrame request_id = %q, want req_tcp_ prefix", openFrame.RequestID)
	}
	if err := serverTunnelConn.WriteJSON(tunnel.Frame{Type: tunnel.FrameTCPOpenResult, RequestID: openFrame.RequestID}); err != nil {
		t.Fatalf("WriteJSON tcp_open_result returned error: %v", err)
	}
	var closeFrame tunnel.Frame
	if err := serverTunnelConn.ReadJSON(&closeFrame); err != nil {
		t.Fatalf("ReadJSON post-open tcp_close returned error: %v", err)
	}
	if closeFrame.Type != tunnel.FrameTCPClose || closeFrame.RequestID != openFrame.RequestID || closeFrame.Direction != tunnel.TCPDirectionLocal || closeFrame.CloseReason != tunnel.TCPCloseReasonError {
		t.Fatalf("closeFrame = %+v, want local error close after hijack limitation", closeFrame)
	}
	select {
	case allowRec := <-allowDone:
		if allowRec.Code != http.StatusInternalServerError || !strings.Contains(allowRec.Body.String(), "response writer does not support CONNECT hijack") {
			t.Fatalf("allow status/body = %d/%s, want post-open hijack limitation", allowRec.Code, allowRec.Body.String())
		}
	case <-time.After(time.Second):
		t.Fatal("allowed CONNECT handler did not return after tcp_open_result")
	}

	connectorLog, err := os.ReadFile(filepath.Join(logDir, "connector.log.jsonl"))
	if err != nil {
		t.Fatalf("read connector log: %v", err)
	}
	logText := string(connectorLog)
	for _, want := range []string{"connector_route_denied", "private_app_tcp_session_started", `"decision":"allow"`, `"tcp_request_id":"` + openFrame.RequestID + `"`} {
		if !strings.Contains(logText, want) {
			t.Fatalf("connector log = %s, want %s", logText, want)
		}
	}
	connectorRows, err := writer.ReadJSONL("connector.log.jsonl")
	if err != nil {
		t.Fatalf("read connector log rows: %v", err)
	}
	startedRows := []map[string]any{}
	for _, row := range connectorRows {
		if row["event_type"] == "private_app_tcp_session_started" {
			startedRows = append(startedRows, row)
		}
	}
	if len(startedRows) != 1 {
		t.Fatalf("private_app_tcp_session_started rows = %#v, want exactly one", startedRows)
	}
	startedRow := startedRows[0]
	if startedRow["tcp_request_id"] != closeFrame.RequestID {
		t.Fatalf("started audit tcp_request_id = %#v, want local error close request_id %q", startedRow["tcp_request_id"], closeFrame.RequestID)
	}
	if startedRow["private_app_session_audit_event"] != "tcp_session_started" || startedRow["transport_path"] != "edge_connector_tcp_tunnel" || startedRow["network_extension_runtime_used"] != false {
		t.Fatalf("started audit row = %#v, want metadata-only pre-hijack tcp session start", startedRow)
	}
	if startedRow["tunnel_id"] != "tun_lab_001" || startedRow["application_id"] != "app_allowed_https" || startedRow["decision"] != "allow" {
		t.Fatalf("started audit row = %#v, want allowed app tunnel scope", startedRow)
	}
	for _, forbidden := range []string{"private-response", "password="} {
		if strings.Contains(logText, forbidden) {
			t.Fatalf("connector log leaked forbidden marker %q: %s", forbidden, logText)
		}
	}

	_ = serverRaw.Close()
	_ = clientRaw.Close()
	select {
	case err := <-runDone:
		if err != nil && !strings.Contains(err.Error(), "closed pipe") {
			t.Fatalf("session Run returned error after cleanup: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("session Run did not stop after tunnel close")
	}
}

func TestPhase3PolicyDrivenDefaultDenyInProcessAllowsTunnelAndClosesDefaultDeny(t *testing.T) {
	logDir := t.TempDir()
	writer, err := logs.NewWriter(logDir)
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	registry := connector.NewRegistry()
	if _, err := registry.Register(model.ConnectorRegistration{
		ID:               "conn_lab_phase3",
		TenantID:         "tenant_lab_001",
		ConnectorGroupID: "cgrp_lab_phase3",
		Name:             "Phase3 Connector",
		EdgeRegionID:     "local",
		EdgeClusterID:    "local-edge-001",
		ApplicationIDs:   []string{"app_phase3_allow_https", "app_phase3_default_deny_https"},
		PrivateBaseURL:   "http://connector.local",
		Status:           "registered",
		Metadata:         map[string]any{},
	}, time.Now()); err != nil {
		t.Fatalf("Register returned error: %v", err)
	}

	clientRaw, serverRaw := net.Pipe()
	defer clientRaw.Close()
	defer serverRaw.Close()
	clientTunnelConn := tunnel.NewInProcessConn(clientRaw, true)
	serverTunnelConn := tunnel.NewInProcessConn(serverRaw, false)
	tunnelManager := tunnel.NewManagerWithRequestTimeout(500 * time.Millisecond)
	session, _ := tunnelManager.Register("conn_lab_phase3", "tun_lab_phase3", clientTunnelConn)
	runDone := make(chan error, 1)
	go func() {
		runDone <- session.Run()
	}()

	routeProfiles := map[string]edgeplane.ApplicationRouteProfile{
		"app_phase3_allow_https": {
			Destination:            "phase3-allow.internal",
			DestinationPort:        8443,
			Protocol:               "tcp",
			ServiceFamily:          "https",
			DestinationRole:        "private_app",
			ApplicationSensitivity: "high",
		},
		"app_phase3_default_deny_https": {
			Destination:            "phase3-default-deny.internal",
			DestinationPort:        8443,
			Protocol:               "tcp",
			ServiceFamily:          "https",
			DestinationRole:        "private_app",
			ApplicationSensitivity: "high",
		},
	}
	evaluator := testEvaluatorWithPolicies([]model.Policy{
		{
			ID:       "pol_phase3_allow_https_001",
			TenantID: "tenant_lab_001",
			Priority: 10,
			Conditions: map[string]any{
				"actor_type":     "human",
				"application_id": "app_phase3_allow_https",
				"service_family": "https",
			},
			Action: model.PolicyAction{Decision: "allow"},
			Status: "active",
		},
	})
	handler := newServerWithConfig(serverConfig{
		Evaluator:     evaluator,
		Writer:        writer,
		Registry:      registry,
		TunnelManager: tunnelManager,
		RouteProfiles: routeProfiles,
		ProxyClient: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			t.Fatalf("proxy client was called for Phase3 CONNECT integration")
			return nil, nil
		})},
	})

	denyReq := httptest.NewRequest(http.MethodConnect, "/apps/app_phase3_default_deny_https?connector_id=conn_lab_phase3", nil)
	denyReq.Header.Set(edgeplane.ConnectAuthorityHeader, "phase3-default-deny.internal:8443")
	denyRec := httptest.NewRecorder()
	handler.ServeHTTP(denyRec, denyReq)
	if denyRec.Code != http.StatusForbidden {
		t.Fatalf("default-deny status = %d, want %d, body=%s", denyRec.Code, http.StatusForbidden, denyRec.Body.String())
	}
	var deniedDecision model.AccessDecision
	if err := json.NewDecoder(denyRec.Body).Decode(&deniedDecision); err != nil {
		t.Fatalf("decode default-deny decision: %v", err)
	}
	if deniedDecision.Decision != "deny" || !stringSliceContains(deniedDecision.ReasonCodes, "no_policy_match") || stringSliceContains(deniedDecision.ReasonCodes, "policy_matched") {
		t.Fatalf("default-deny decision = %+v, want no-policy-match deny", deniedDecision)
	}
	if err := serverRaw.SetReadDeadline(time.Now().Add(75 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline returned error: %v", err)
	}
	var unexpectedOpen tunnel.Frame
	err = serverTunnelConn.ReadJSON(&unexpectedOpen)
	if err == nil {
		t.Fatalf("default-deny CONNECT emitted tunnel frame %+v, want no tcp_open", unexpectedOpen)
	}
	if netErr, ok := err.(net.Error); !ok || !netErr.Timeout() {
		t.Fatalf("default-deny tunnel read error = %v, want timeout with no frame", err)
	}
	if err := serverRaw.SetReadDeadline(time.Time{}); err != nil {
		t.Fatalf("clearing read deadline returned error: %v", err)
	}

	allowReq := httptest.NewRequest(http.MethodConnect, "/apps/app_phase3_allow_https?connector_id=conn_lab_phase3", nil)
	allowReq.Header.Set(edgeplane.ConnectAuthorityHeader, "phase3-allow.internal:8443")
	allowWriter := newHijackableCONNECTResponseWriter()
	defer allowWriter.close()
	allowDone := make(chan struct{}, 1)
	go func() {
		handler.ServeHTTP(allowWriter, allowReq)
		allowDone <- struct{}{}
	}()

	var openFrame tunnel.Frame
	if err := serverTunnelConn.ReadJSON(&openFrame); err != nil {
		t.Fatalf("ReadJSON allowed tcp_open returned error: %v", err)
	}
	if openFrame.Type != tunnel.FrameTCPOpen || openFrame.ApplicationID != "app_phase3_allow_https" || openFrame.Host != "phase3-allow.internal" || openFrame.Port != 8443 || openFrame.TunnelID != "tun_lab_phase3" {
		t.Fatalf("openFrame = %+v, want Phase3 allowed route tcp_open", openFrame)
	}
	if openFrame.RequestID == "" || !strings.HasPrefix(openFrame.RequestID, "req_tcp_") {
		t.Fatalf("openFrame request_id = %q, want req_tcp_ prefix", openFrame.RequestID)
	}
	if err := serverTunnelConn.WriteJSON(tunnel.Frame{Type: tunnel.FrameTCPOpenResult, RequestID: openFrame.RequestID}); err != nil {
		t.Fatalf("WriteJSON tcp_open_result returned error: %v", err)
	}
	connectResponse := readCONNECTResponse(t, allowWriter.clientConn)
	if !strings.Contains(connectResponse, "200 Connection Established") {
		t.Fatalf("CONNECT response = %q, want 200 Connection Established", connectResponse)
	}

	clientPayload := []byte("phase3-allow-client-bytes")
	clientWriteDone := make(chan error, 1)
	go func() {
		_, err := allowWriter.clientConn.Write(clientPayload)
		clientWriteDone <- err
	}()
	var upstreamFrame tunnel.Frame
	if err := serverTunnelConn.ReadJSON(&upstreamFrame); err != nil {
		t.Fatalf("ReadJSON upstream tcp_data returned error: %v", err)
	}
	if upstreamFrame.Type != tunnel.FrameTCPData || upstreamFrame.RequestID != openFrame.RequestID || upstreamFrame.Direction != tunnel.TCPDirectionUp {
		t.Fatalf("upstreamFrame = %+v, want up tcp_data for allowed request", upstreamFrame)
	}
	upstreamPayload, err := tunnel.TCPDataFramePayload(upstreamFrame)
	if err != nil {
		t.Fatalf("decode upstream payload: %v", err)
	}
	if !bytes.Equal(upstreamPayload, clientPayload) {
		t.Fatalf("upstream payload = %q, want %q", upstreamPayload, clientPayload)
	}
	select {
	case err := <-clientWriteDone:
		if err != nil {
			t.Fatalf("client write returned error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("client write did not complete after upstream frame was read")
	}

	privateResponse := []byte("phase3-private-response-bytes")
	downstreamFrame, err := tunnel.NewTCPDataFrame(openFrame.RequestID, tunnel.TCPDirectionDown, privateResponse)
	if err != nil {
		t.Fatalf("NewTCPDataFrame downstream returned error: %v", err)
	}
	if err := serverTunnelConn.WriteJSON(downstreamFrame); err != nil {
		t.Fatalf("WriteJSON downstream tcp_data returned error: %v", err)
	}
	responseBuf := make([]byte, len(privateResponse))
	if err := allowWriter.clientConn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SetReadDeadline on CONNECT client returned error: %v", err)
	}
	if _, err := io.ReadFull(allowWriter.clientConn, responseBuf); err != nil {
		t.Fatalf("ReadFull CONNECT private response returned error: %v", err)
	}
	if err := allowWriter.clientConn.SetReadDeadline(time.Time{}); err != nil {
		t.Fatalf("clearing CONNECT client deadline returned error: %v", err)
	}
	if !bytes.Equal(responseBuf, privateResponse) {
		t.Fatalf("CONNECT private response = %q, want %q", responseBuf, privateResponse)
	}

	_ = allowWriter.clientConn.Close()
	if err := serverRaw.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SetReadDeadline for local close returned error: %v", err)
	}
	var localClose tunnel.Frame
	if err := serverTunnelConn.ReadJSON(&localClose); err != nil {
		t.Fatalf("ReadJSON local tcp_close returned error: %v", err)
	}
	if err := serverRaw.SetReadDeadline(time.Time{}); err != nil {
		t.Fatalf("clearing local close deadline returned error: %v", err)
	}
	if localClose.Type != tunnel.FrameTCPClose || localClose.RequestID != openFrame.RequestID || localClose.Direction != tunnel.TCPDirectionLocal {
		t.Fatalf("localClose = %+v, want local tcp_close for allowed request", localClose)
	}
	if localClose.CloseReason != tunnel.TCPCloseReasonEOF && localClose.CloseReason != tunnel.TCPCloseReasonError {
		t.Fatalf("localClose = %+v, want eof/error close after CONNECT client close", localClose)
	}
	select {
	case <-allowDone:
	case <-time.After(time.Second):
		t.Fatal("allowed CONNECT handler did not return after client close")
	}

	connectorRows, err := writer.ReadJSONL("connector.log.jsonl")
	if err != nil {
		t.Fatalf("read connector log rows: %v", err)
	}
	deniedRows := []map[string]any{}
	allowedRows := []map[string]any{}
	startedRows := []map[string]any{}
	for _, row := range connectorRows {
		switch row["event_type"] {
		case "connector_route_denied":
			if row["application_id"] == "app_phase3_default_deny_https" {
				deniedRows = append(deniedRows, row)
			}
		case "connector_route_allowed":
			if row["application_id"] == "app_phase3_allow_https" {
				allowedRows = append(allowedRows, row)
			}
		case "private_app_tcp_session_started":
			startedRows = append(startedRows, row)
		}
	}
	if len(deniedRows) != 1 || deniedRows[0]["decision"] != "deny" {
		t.Fatalf("default-deny connector rows = %#v, want one metadata-only deny row", deniedRows)
	}
	if len(allowedRows) != 1 || allowedRows[0]["decision"] != "allow" {
		t.Fatalf("allow connector rows = %#v, want one metadata-only allow row", allowedRows)
	}
	if len(startedRows) != 1 {
		t.Fatalf("private_app_tcp_session_started rows = %#v, want exactly one allowed start row", startedRows)
	}
	startedRow := startedRows[0]
	if startedRow["tcp_request_id"] != openFrame.RequestID || startedRow["application_id"] != "app_phase3_allow_https" || startedRow["decision"] != "allow" || startedRow["transport_path"] != "edge_connector_tcp_tunnel" {
		t.Fatalf("started audit row = %#v, want allowed tunnel session metadata", startedRow)
	}
	if startedRow["network_extension_runtime_used"] != false || startedRow["raw_payload_logged"] != false || startedRow["credential_material_logged"] != false {
		t.Fatalf("started audit row = %#v, want metadata-only audit booleans false", startedRow)
	}
	connectorLog, err := os.ReadFile(filepath.Join(logDir, "connector.log.jsonl"))
	if err != nil {
		t.Fatalf("read connector log: %v", err)
	}
	logText := string(connectorLog)
	for _, forbidden := range []string{string(clientPayload), string(privateResponse), "password=", "credentials"} {
		if strings.Contains(logText, forbidden) {
			t.Fatalf("connector log leaked forbidden marker %q: %s", forbidden, logText)
		}
	}

	_ = serverRaw.Close()
	_ = clientRaw.Close()
	select {
	case err := <-runDone:
		if err != nil && !strings.Contains(err.Error(), "closed pipe") {
			t.Fatalf("session Run returned error after cleanup: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("session Run did not stop after tunnel close")
	}
}

func TestEdgeConnectClientSuppliedNHIContextIgnoredBeforeTCPOpen(t *testing.T) {
	logDir := t.TempDir()
	writer, err := logs.NewWriter(logDir)
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	registry := connector.NewRegistry()
	if _, err := registry.Register(model.ConnectorRegistration{
		ID:               "conn_lab_001",
		TenantID:         "tenant_lab_001",
		ConnectorGroupID: "cgrp_lab_001",
		Name:             "Lab Connector",
		EdgeRegionID:     "local",
		EdgeClusterID:    "local-edge-001",
		ApplicationIDs:   []string{"app_nhi_blocked_https"},
		PrivateBaseURL:   "http://connector.local",
		Status:           "registered",
		Metadata:         map[string]any{},
	}, time.Now()); err != nil {
		t.Fatalf("Register returned error: %v", err)
	}

	clientRaw, serverRaw := net.Pipe()
	defer clientRaw.Close()
	defer serverRaw.Close()
	clientTunnelConn := tunnel.NewInProcessConn(clientRaw, true)
	serverTunnelConn := tunnel.NewInProcessConn(serverRaw, false)
	tunnelManager := tunnel.NewManagerWithRequestTimeout(500 * time.Millisecond)
	session, _ := tunnelManager.Register("conn_lab_001", "tun_lab_001", clientTunnelConn)
	runDone := make(chan error, 1)
	go func() {
		runDone <- session.Run()
	}()

	routeProfiles := map[string]edgeplane.ApplicationRouteProfile{
		"app_nhi_blocked_https": {
			Destination:            "nhi-blocked-route.internal",
			DestinationPort:        8443,
			Protocol:               "tcp",
			ServiceFamily:          "https",
			DestinationRole:        "private_app",
			ApplicationSensitivity: "high",
		},
	}
	evaluator := testEvaluatorWithPolicies([]model.Policy{
		{
			ID:       "pol_lab_nhi_connect_allow_001",
			TenantID: "tenant_lab_001",
			Priority: 50,
			Conditions: map[string]any{
				"actor_type":                "delegated_agent",
				"actor_nhi_id":              "nhi_limited_001",
				"delegated_access_grant_id": "dag_lab_001",
				"application_id":            "app_nhi_blocked_https",
				"service_family":            "https",
				"tool_action_type":          "ticket:create",
			},
			Action: model.PolicyAction{Decision: "allow"},
			Status: "active",
		},
	})
	now := time.Now().UTC()
	nhiRegistry := nhi.NewStore()
	if _, err := nhiRegistry.Upsert(context.Background(), model.NonHumanIdentity{
		ID:                    "nhi_limited_001",
		Name:                  "Limited NHI",
		NHIType:               "ai_agent",
		OwnerUserID:           "user_owner_001",
		Status:                "active",
		AllowedApplicationIDs: []string{"app_allowed_001"},
		AllowedScopes:         []string{"ticket:create"},
	}, "tenant_lab_001", now); err != nil {
		t.Fatalf("upsert NHI returned error: %v", err)
	}
	handler := newServerWithConfig(serverConfig{
		Evaluator:          evaluator,
		Writer:             writer,
		Registry:           registry,
		TunnelManager:      tunnelManager,
		RouteProfiles:      routeProfiles,
		DelegatedGrants:    newDelegatedAccessGrantStore(),
		NonHumanIdentities: nhiRegistry,
		ProxyClient: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			t.Fatalf("proxy client was called for spoofed NHI CONNECT deny")
			return nil, nil
		})},
	})

	query := url.Values{}
	query.Set("connector_id", "conn_lab_001")
	query.Set("user_id", "user_lab_001")
	query.Set("subject_user_id", "user_lab_001")
	query.Set("actor_nhi_id", "nhi_limited_001")
	query.Set("delegated_access_grant_id", "dag_lab_001")
	query.Set("agent_task_session_id", "ats_lab_001")
	query.Set("tool_id", "tool_ticket_create_001")
	query.Set("tool_action_type", "ticket:create")
	query.Set("tool_signature_state", "signed")
	query.Set("mcp_server_id", "mcp_soc_lab_001")
	query.Set("mcp_token_passthrough_policy", "blocked")
	query.Set("runtime_environment_id", "runtime_managed_cloud_lab_001")
	denyReq := httptest.NewRequest(http.MethodConnect, "/apps/app_nhi_blocked_https?"+query.Encode(), nil)
	denyReq.Header.Set(edgeplane.ConnectAuthorityHeader, "nhi-blocked-route.internal:8443")
	denyRec := httptest.NewRecorder()
	handler.ServeHTTP(denyRec, denyReq)
	if denyRec.Code != http.StatusForbidden {
		t.Fatalf("deny status = %d, want %d, body=%s", denyRec.Code, http.StatusForbidden, denyRec.Body.String())
	}
	var deniedDecision model.AccessDecision
	if err := json.NewDecoder(denyRec.Body).Decode(&deniedDecision); err != nil {
		t.Fatalf("decode denied decision: %v", err)
	}
	if deniedDecision.Decision != "deny" {
		t.Fatalf("denied decision = %#v, want deny", deniedDecision)
	}
	if stringSliceContains(deniedDecision.ReasonCodes, "policy_matched") || stringSliceContains(deniedDecision.ReasonCodes, "nhi_application_not_allowed") || !stringSliceContains(deniedDecision.ReasonCodes, "no_policy_match") {
		t.Fatalf("denied decision = %#v, want spoofed NHI context ignored before NHI policy/evidence", deniedDecision)
	}
	if deniedDecision.ActorType != "human" || deniedDecision.ActorNHIID != nil {
		t.Fatalf("denied decision actor = %#v/%#v, want client-supplied NHI context ignored", deniedDecision.ActorType, deniedDecision.ActorNHIID)
	}
	if _, ok := deniedDecision.Metadata["runtime_evidence_result"]; ok {
		t.Fatalf("denied decision metadata = %#v, want no runtime evidence from client-supplied NHI context", deniedDecision.Metadata)
	}
	if _, ok := deniedDecision.Metadata["nhi_registry_last_used_result"]; ok {
		t.Fatalf("denied decision metadata = %#v, want no last-used marker", deniedDecision.Metadata)
	}

	if err := serverRaw.SetReadDeadline(time.Now().Add(75 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline returned error: %v", err)
	}
	var unexpectedOpen tunnel.Frame
	err = serverTunnelConn.ReadJSON(&unexpectedOpen)
	if err == nil {
		t.Fatalf("spoofed NHI CONNECT emitted tunnel frame %+v, want no tcp_open", unexpectedOpen)
	}
	if netErr, ok := err.(net.Error); !ok || !netErr.Timeout() {
		t.Fatalf("spoofed NHI CONNECT tunnel read error = %v, want timeout with no frame", err)
	}
	if err := serverRaw.SetReadDeadline(time.Time{}); err != nil {
		t.Fatalf("clearing read deadline returned error: %v", err)
	}

	connectorRows, err := writer.ReadJSONL("connector.log.jsonl")
	if err != nil {
		t.Fatalf("read connector log: %v", err)
	}
	deniedRows := []map[string]any{}
	startedRows := []map[string]any{}
	for _, row := range connectorRows {
		switch row["event_type"] {
		case "connector_route_denied":
			deniedRows = append(deniedRows, row)
		case "private_app_tcp_session_started":
			startedRows = append(startedRows, row)
		}
	}
	if len(deniedRows) != 1 || deniedRows[0]["decision"] != "deny" || deniedRows[0]["application_id"] != "app_nhi_blocked_https" {
		t.Fatalf("connector denied rows = %#v, want one denied connector route", deniedRows)
	}
	if len(startedRows) != 0 {
		t.Fatalf("private_app_tcp_session_started rows = %#v, want none before tcp_open", startedRows)
	}

	accessRows, err := writer.ReadJSONL("access.log.jsonl")
	if err != nil {
		t.Fatalf("read access log: %v", err)
	}
	if len(accessRows) != 1 || accessRows[0]["decision"] != "deny" || accessRows[0]["actor_type"] != "human" || accessRows[0]["actor_nhi_id"] != nil || accessRows[0]["subject_user_id"] != nil || accessRows[0]["delegated_access_grant_id"] != nil {
		t.Fatalf("access rows = %#v, want spoofed NHI context ignored in CONNECT deny", accessRows)
	}
	accessMetadata, ok := accessRows[0]["metadata"].(map[string]any)
	if !ok {
		t.Fatalf("access metadata = %#v, want metadata map", accessRows[0]["metadata"])
	}
	if _, ok := accessMetadata["runtime_evidence_result"]; ok {
		t.Fatalf("access metadata = %#v, want no runtime evidence from client-supplied NHI context", accessMetadata)
	}
	if _, ok := accessMetadata["nhi_registry_last_used_result"]; ok {
		t.Fatalf("access metadata = %#v, want no last-used marker", accessMetadata)
	}

	identities, err := nhiRegistry.List(context.Background(), "tenant_lab_001")
	if err != nil {
		t.Fatalf("list NHI registry: %v", err)
	}
	if len(identities) != 1 || identities[0].LastUsedAt != nil {
		t.Fatalf("NHI registry identities = %#v, want last_used_at unchanged on CONNECT deny", identities)
	}

	_ = serverRaw.Close()
	_ = clientRaw.Close()
	select {
	case err := <-runDone:
		if err != nil && !strings.Contains(err.Error(), "closed pipe") {
			t.Fatalf("session Run returned error after cleanup: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("session Run did not stop after tunnel close")
	}
}

func TestEdgeConnectClientSuppliedHumanContextCannotSatisfySessionPolicyBeforeTCPOpen(t *testing.T) {
	logDir := t.TempDir()
	writer, err := logs.NewWriter(logDir)
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	registry := connector.NewRegistry()
	if _, err := registry.Register(model.ConnectorRegistration{
		ID:               "conn_lab_001",
		TenantID:         "tenant_lab_001",
		ConnectorGroupID: "cgrp_lab_001",
		Name:             "Lab Connector",
		EdgeRegionID:     "local",
		EdgeClusterID:    "local-edge-001",
		ApplicationIDs:   []string{"app_human_mfa_group_https"},
		PrivateBaseURL:   "http://connector.local",
		Status:           "registered",
		Metadata:         map[string]any{},
	}, time.Now()); err != nil {
		t.Fatalf("Register returned error: %v", err)
	}

	clientRaw, serverRaw := net.Pipe()
	defer clientRaw.Close()
	defer serverRaw.Close()
	clientTunnelConn := tunnel.NewInProcessConn(clientRaw, true)
	serverTunnelConn := tunnel.NewInProcessConn(serverRaw, false)
	tunnelManager := tunnel.NewManagerWithRequestTimeout(500 * time.Millisecond)
	session, _ := tunnelManager.Register("conn_lab_001", "tun_lab_001", clientTunnelConn)
	runDone := make(chan error, 1)
	go func() {
		runDone <- session.Run()
	}()

	routeProfiles := map[string]edgeplane.ApplicationRouteProfile{
		"app_human_mfa_group_https": {
			Destination:            "human-mfa-group-route.internal",
			DestinationPort:        8443,
			Protocol:               "tcp",
			ServiceFamily:          "https",
			DestinationRole:        "private_app",
			ApplicationSensitivity: "high",
		},
	}
	evaluator := testEvaluatorWithPolicies([]model.Policy{
		{
			ID:       "pol_lab_human_mfa_group_connect_allow_001",
			TenantID: "tenant_lab_001",
			Priority: 50,
			Conditions: map[string]any{
				"actor_type":     "human",
				"application_id": "app_human_mfa_group_https",
				"service_family": "https",
				"mfa_state":      "fresh",
				"user_groups": map[string]any{
					"op":    "contains",
					"value": "security-admins",
				},
			},
			Action: model.PolicyAction{Decision: "allow"},
			Status: "active",
		},
	})
	handler := newServerWithConfig(serverConfig{
		Evaluator:     evaluator,
		Writer:        writer,
		Registry:      registry,
		TunnelManager: tunnelManager,
		RouteProfiles: routeProfiles,
		ProxyClient: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			t.Fatalf("proxy client was called for spoofed human CONNECT deny")
			return nil, nil
		})},
	})

	query := url.Values{}
	query.Set("connector_id", "conn_lab_001")
	query.Set("user_id", "evil_user")
	query.Set("subject_user_id", "evil_subject")
	query.Set("user_groups", "security-admins")
	query.Set("mfa_state", "fresh")
	query.Set("acr", "urn:mfa:fresh")
	query.Set("device_id", "dev_evil_001")
	query.Set("device_trust_level", "trusted")
	denyReq := httptest.NewRequest(http.MethodConnect, "/apps/app_human_mfa_group_https?"+query.Encode(), nil)
	denyReq.Header.Set(edgeplane.ConnectAuthorityHeader, "human-mfa-group-route.internal:8443")
	denyRec := httptest.NewRecorder()
	handler.ServeHTTP(denyRec, denyReq)
	if denyRec.Code != http.StatusForbidden {
		t.Fatalf("deny status = %d, want %d, body=%s", denyRec.Code, http.StatusForbidden, denyRec.Body.String())
	}
	var deniedDecision model.AccessDecision
	if err := json.NewDecoder(denyRec.Body).Decode(&deniedDecision); err != nil {
		t.Fatalf("decode denied decision: %v", err)
	}
	if deniedDecision.Decision != "deny" {
		t.Fatalf("denied decision = %#v, want deny", deniedDecision)
	}
	if stringSliceContains(deniedDecision.ReasonCodes, "policy_matched") || !stringSliceContains(deniedDecision.ReasonCodes, "no_policy_match") {
		t.Fatalf("denied decision = %#v, want query human context ignored before policy match", deniedDecision)
	}
	if deniedDecision.ActorType != "human" || deniedDecision.UserID != nil || deniedDecision.SubjectUserID != nil || deniedDecision.SessionID != nil || deniedDecision.DeviceID != nil {
		t.Fatalf("denied decision identity = %#v, want no client-supplied human/session/device identity", deniedDecision)
	}
	for _, forbidden := range []string{"mfa_state", "acr", "subject_user_id", "device_trust_level"} {
		if _, ok := deniedDecision.Metadata[forbidden]; ok {
			t.Fatalf("denied metadata = %#v, want no client-supplied %s", deniedDecision.Metadata, forbidden)
		}
	}

	if err := serverRaw.SetReadDeadline(time.Now().Add(75 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline returned error: %v", err)
	}
	var unexpectedOpen tunnel.Frame
	err = serverTunnelConn.ReadJSON(&unexpectedOpen)
	if err == nil {
		t.Fatalf("spoofed human CONNECT emitted tunnel frame %+v, want no tcp_open", unexpectedOpen)
	}
	if netErr, ok := err.(net.Error); !ok || !netErr.Timeout() {
		t.Fatalf("spoofed human CONNECT tunnel read error = %v, want timeout with no frame", err)
	}
	if err := serverRaw.SetReadDeadline(time.Time{}); err != nil {
		t.Fatalf("clearing read deadline returned error: %v", err)
	}

	accessRows, err := writer.ReadJSONL("access.log.jsonl")
	if err != nil {
		t.Fatalf("read access log: %v", err)
	}
	if len(accessRows) != 1 || accessRows[0]["decision"] != "deny" || accessRows[0]["actor_type"] != "human" || accessRows[0]["user_id"] != nil || accessRows[0]["subject_user_id"] != nil || accessRows[0]["session_id"] != nil || accessRows[0]["device_id"] != nil {
		t.Fatalf("access rows = %#v, want spoofed human context ignored in CONNECT deny", accessRows)
	}
	accessMetadata, ok := accessRows[0]["metadata"].(map[string]any)
	if !ok {
		t.Fatalf("access metadata = %#v, want metadata map", accessRows[0]["metadata"])
	}
	for _, forbidden := range []string{"mfa_state", "acr", "subject_user_id", "device_trust_level"} {
		if _, ok := accessMetadata[forbidden]; ok {
			t.Fatalf("access metadata = %#v, want no client-supplied %s", accessMetadata, forbidden)
		}
	}

	traceRows, err := writer.ReadJSONL("access.log.jsonl")
	if err != nil {
		t.Fatalf("read access log: %v", err)
	}
	if len(traceRows) != 1 {
		t.Fatalf("access rows = %#v, want one no-match record", traceRows)
	}
	matchedConditions, ok := traceRows[0]["matched_conditions"].([]any)
	if !ok {
		t.Fatalf("trace matched_conditions = %#v, want array", traceRows[0]["matched_conditions"])
	}
	if len(matchedConditions) != 0 {
		t.Fatalf("trace matched_conditions = %#v, want no policy match from query human context", matchedConditions)
	}
	for _, condition := range matchedConditions {
		if condition == "mfa_state" || condition == "user_groups" {
			t.Fatalf("trace matched_conditions = %#v, want no query-derived human policy match", matchedConditions)
		}
	}
	traceMetadata, ok := traceRows[0]["metadata"].(map[string]any)
	if !ok || traceMetadata["actor_type"] != "human" {
		t.Fatalf("trace metadata = %#v, want human actor only", traceRows[0]["metadata"])
	}
	for _, forbidden := range []string{"mfa_state", "acr", "subject_user_id", "device_trust_level"} {
		if _, ok := traceMetadata[forbidden]; ok {
			t.Fatalf("trace metadata = %#v, want no client-supplied %s", traceMetadata, forbidden)
		}
	}

	connectorRows, err := writer.ReadJSONL("connector.log.jsonl")
	if err != nil {
		t.Fatalf("read connector log: %v", err)
	}
	deniedRows := []map[string]any{}
	startedRows := []map[string]any{}
	for _, row := range connectorRows {
		switch row["event_type"] {
		case "connector_route_denied":
			deniedRows = append(deniedRows, row)
		case "private_app_tcp_session_started":
			startedRows = append(startedRows, row)
		}
	}
	if len(deniedRows) != 1 || deniedRows[0]["decision"] != "deny" || deniedRows[0]["application_id"] != "app_human_mfa_group_https" {
		t.Fatalf("connector denied rows = %#v, want one denied connector route", deniedRows)
	}
	if len(startedRows) != 0 {
		t.Fatalf("private_app_tcp_session_started rows = %#v, want none before tcp_open", startedRows)
	}

	_ = serverRaw.Close()
	_ = clientRaw.Close()
	select {
	case err := <-runDone:
		if err != nil && !strings.Contains(err.Error(), "closed pipe") {
			t.Fatalf("session Run returned error after cleanup: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("session Run did not stop after tunnel close")
	}
}

func TestEdgeConnectSessionCannotUpgradeHumanGroupMFAFromQueryBeforeTCPOpen(t *testing.T) {
	logDir := t.TempDir()
	writer, err := logs.NewWriter(logDir)
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	registry := connector.NewRegistry()
	if _, err := registry.Register(model.ConnectorRegistration{
		ID:               "conn_lab_001",
		TenantID:         "tenant_lab_001",
		ConnectorGroupID: "cgrp_lab_001",
		Name:             "Lab Connector",
		EdgeRegionID:     "local",
		EdgeClusterID:    "local-edge-001",
		ApplicationIDs:   []string{"app_session_strict_group_https"},
		PrivateBaseURL:   "http://connector.local",
		Status:           "registered",
		Metadata:         map[string]any{},
	}, time.Now()); err != nil {
		t.Fatalf("Register returned error: %v", err)
	}

	clientRaw, serverRaw := net.Pipe()
	defer clientRaw.Close()
	defer serverRaw.Close()
	clientTunnelConn := tunnel.NewInProcessConn(clientRaw, true)
	serverTunnelConn := tunnel.NewInProcessConn(serverRaw, false)
	tunnelManager := tunnel.NewManagerWithRequestTimeout(500 * time.Millisecond)
	session, _ := tunnelManager.Register("conn_lab_001", "tun_lab_001", clientTunnelConn)
	runDone := make(chan error, 1)
	go func() {
		runDone <- session.Run()
	}()

	routeProfiles := map[string]edgeplane.ApplicationRouteProfile{
		"app_session_strict_group_https": {
			Destination:            "session-strict-group-route.internal",
			DestinationPort:        8443,
			Protocol:               "tcp",
			ServiceFamily:          "https",
			DestinationRole:        "private_app",
			ApplicationSensitivity: "high",
		},
	}
	evaluator := testEvaluatorWithPolicies([]model.Policy{
		{
			ID:       "pol_lab_session_strict_group_connect_allow_001",
			TenantID: "tenant_lab_001",
			Priority: 50,
			Conditions: map[string]any{
				"actor_type":     "human",
				"application_id": "app_session_strict_group_https",
				"service_family": "https",
				"mfa_state":      "fresh",
				"user_groups": map[string]any{
					"op":    "contains",
					"value": "security-admins",
				},
			},
			Action: model.PolicyAction{Decision: "allow"},
			Status: "active",
		},
	})
	now := time.Now().UTC()
	sessionStore := sessionstore.NewStore()
	subjectUserID := "user_session_limited_subject_001"
	deviceID := "dev_session_limited_001"
	acr := "urn:mfa:stale"
	expiresAt := now.Add(time.Hour).Format(time.RFC3339)
	if _, err := sessionStore.CreateFromAuthenticationEvent(model.AuthenticationEvent{
		ID:            "auth_session_limited_connect_001",
		TenantID:      "tenant_lab_001",
		UserID:        "user_session_limited_001",
		SubjectUserID: &subjectUserID,
		SessionID:     "sess_connect_limited_human_001",
		IDPID:         "idp_keycloak_lab",
		Method:        "oidc_authorization_code",
		AMR:           []string{"pwd"},
		ACR:           &acr,
		MFAState:      "stale",
		ExpiresAt:     &expiresAt,
		DeviceID:      &deviceID,
		Result:        "success",
		Timestamp:     now.Format(time.RFC3339),
		Metadata: map[string]any{
			"groups": []string{"engineering"},
			"issuer": "https://idp.example.test",
		},
	}, "pb_lab_20260602_002", "tenant_lab_001", now); err != nil {
		t.Fatalf("create session returned error: %v", err)
	}
	handler := newServerWithConfig(serverConfig{
		Evaluator:     evaluator,
		Writer:        writer,
		Registry:      registry,
		TunnelManager: tunnelManager,
		RouteProfiles: routeProfiles,
		SessionStore:  sessionStore,
		ProxyClient: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			t.Fatalf("proxy client was called for session strict-group spoof deny")
			return nil, nil
		})},
	})

	query := url.Values{}
	query.Set("connector_id", "conn_lab_001")
	query.Set("user_id", "evil_user")
	query.Set("subject_user_id", "evil_subject")
	query.Set("user_groups", "security-admins")
	query.Set("mfa_state", "fresh")
	query.Set("acr", "urn:mfa:fresh")
	query.Set("device_id", "dev_evil_001")
	query.Set("device_trust_level", "trusted")
	denyReq := httptest.NewRequest(http.MethodConnect, "/apps/app_session_strict_group_https?"+query.Encode(), nil)
	denyReq.Header.Set(edgeplane.ConnectAuthorityHeader, "session-strict-group-route.internal:8443")
	denyReq.AddCookie(&http.Cookie{Name: "session_id", Value: "sess_connect_limited_human_001"})
	denyRec := httptest.NewRecorder()
	handler.ServeHTTP(denyRec, denyReq)
	if denyRec.Code != http.StatusForbidden {
		t.Fatalf("deny status = %d, want %d, body=%s", denyRec.Code, http.StatusForbidden, denyRec.Body.String())
	}
	var deniedDecision model.AccessDecision
	if err := json.NewDecoder(denyRec.Body).Decode(&deniedDecision); err != nil {
		t.Fatalf("decode denied decision: %v", err)
	}
	if deniedDecision.Decision != "deny" {
		t.Fatalf("denied decision = %#v, want deny", deniedDecision)
	}
	if stringSliceContains(deniedDecision.ReasonCodes, "policy_matched") || !stringSliceContains(deniedDecision.ReasonCodes, "no_policy_match") {
		t.Fatalf("denied decision = %#v, want session-derived strict group/MFA mismatch deny", deniedDecision)
	}
	if deniedDecision.UserID == nil || *deniedDecision.UserID != "user_session_limited_001" || deniedDecision.SubjectUserID == nil || *deniedDecision.SubjectUserID != "user_session_limited_subject_001" || deniedDecision.SessionID == nil || *deniedDecision.SessionID != "sess_connect_limited_human_001" {
		t.Fatalf("denied decision identity = %#v, want session-derived human identity", deniedDecision)
	}
	if deniedDecision.DeviceID == nil || *deniedDecision.DeviceID != "dev_session_limited_001" {
		t.Fatalf("denied decision device = %#v, want session-derived device", deniedDecision.DeviceID)
	}
	if deniedDecision.Metadata["mfa_state"] != "stale" || deniedDecision.Metadata["acr"] != "urn:mfa:stale" || deniedDecision.Metadata["subject_user_id"] != "user_session_limited_subject_001" {
		t.Fatalf("denied metadata = %#v, want session-derived stale MFA/ACR and subject", deniedDecision.Metadata)
	}
	for _, forbidden := range []string{"security-admins", "urn:mfa:fresh", "evil_subject", "dev_evil_001", "trusted"} {
		if strings.Contains(fmt.Sprint(deniedDecision.Metadata), forbidden) {
			t.Fatalf("denied metadata = %#v, want no query-derived marker %q", deniedDecision.Metadata, forbidden)
		}
	}

	if err := serverRaw.SetReadDeadline(time.Now().Add(75 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline returned error: %v", err)
	}
	var unexpectedOpen tunnel.Frame
	err = serverTunnelConn.ReadJSON(&unexpectedOpen)
	if err == nil {
		t.Fatalf("session strict-group spoof CONNECT emitted tunnel frame %+v, want no tcp_open", unexpectedOpen)
	}
	if netErr, ok := err.(net.Error); !ok || !netErr.Timeout() {
		t.Fatalf("session strict-group spoof CONNECT tunnel read error = %v, want timeout with no frame", err)
	}
	if err := serverRaw.SetReadDeadline(time.Time{}); err != nil {
		t.Fatalf("clearing read deadline returned error: %v", err)
	}

	accessRows, err := writer.ReadJSONL("access.log.jsonl")
	if err != nil {
		t.Fatalf("read access log: %v", err)
	}
	if len(accessRows) != 1 || accessRows[0]["decision"] != "deny" || accessRows[0]["actor_type"] != "human" || accessRows[0]["user_id"] != "user_session_limited_001" || accessRows[0]["subject_user_id"] != "user_session_limited_subject_001" || accessRows[0]["session_id"] != "sess_connect_limited_human_001" || accessRows[0]["device_id"] != "dev_session_limited_001" {
		t.Fatalf("access rows = %#v, want session-derived human deny row", accessRows)
	}
	accessMetadata, ok := accessRows[0]["metadata"].(map[string]any)
	if !ok {
		t.Fatalf("access metadata = %#v, want metadata map", accessRows[0]["metadata"])
	}
	if accessMetadata["mfa_state"] != "stale" || accessMetadata["acr"] != "urn:mfa:stale" || accessMetadata["subject_user_id"] != "user_session_limited_subject_001" {
		t.Fatalf("access metadata = %#v, want session-derived stale MFA/ACR and subject", accessMetadata)
	}
	for _, forbidden := range []string{"security-admins", "urn:mfa:fresh", "evil_subject", "dev_evil_001", "trusted"} {
		if strings.Contains(fmt.Sprint(accessMetadata), forbidden) {
			t.Fatalf("access metadata = %#v, want no query-derived marker %q", accessMetadata, forbidden)
		}
	}

	traceRows, err := writer.ReadJSONL("access.log.jsonl")
	if err != nil {
		t.Fatalf("read access log: %v", err)
	}
	if len(traceRows) != 1 {
		t.Fatalf("access rows = %#v, want one no-match record", traceRows)
	}
	matchedConditions, ok := traceRows[0]["matched_conditions"].([]any)
	if !ok {
		t.Fatalf("trace matched_conditions = %#v, want array", traceRows[0]["matched_conditions"])
	}
	if len(matchedConditions) != 0 {
		t.Fatalf("trace matched_conditions = %#v, want no strict group/MFA policy match from query context", matchedConditions)
	}
	traceMetadata, ok := traceRows[0]["metadata"].(map[string]any)
	if !ok || traceMetadata["actor_type"] != "human" || traceMetadata["subject_user_id"] != "user_session_limited_subject_001" {
		t.Fatalf("trace metadata = %#v, want session-derived human metadata", traceRows[0]["metadata"])
	}
	for _, forbidden := range []string{"security-admins", "urn:mfa:fresh", "evil_subject", "dev_evil_001", "trusted"} {
		if strings.Contains(fmt.Sprint(traceMetadata), forbidden) {
			t.Fatalf("trace metadata = %#v, want no query-derived marker %q", traceMetadata, forbidden)
		}
	}

	connectorRows, err := writer.ReadJSONL("connector.log.jsonl")
	if err != nil {
		t.Fatalf("read connector log: %v", err)
	}
	deniedRows := []map[string]any{}
	startedRows := []map[string]any{}
	for _, row := range connectorRows {
		switch row["event_type"] {
		case "connector_route_denied":
			deniedRows = append(deniedRows, row)
		case "private_app_tcp_session_started":
			startedRows = append(startedRows, row)
		}
	}
	if len(deniedRows) != 1 || deniedRows[0]["decision"] != "deny" || deniedRows[0]["application_id"] != "app_session_strict_group_https" {
		t.Fatalf("connector denied rows = %#v, want one denied connector route", deniedRows)
	}
	if len(startedRows) != 0 {
		t.Fatalf("private_app_tcp_session_started rows = %#v, want none before tcp_open", startedRows)
	}

	_ = serverRaw.Close()
	_ = clientRaw.Close()
	select {
	case err := <-runDone:
		if err != nil && !strings.Contains(err.Error(), "closed pipe") {
			t.Fatalf("session Run returned error after cleanup: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("session Run did not stop after tunnel close")
	}
}

func TestEdgeConnectSessionIdentityAllowsWhileIgnoringClientSuppliedNHIContext(t *testing.T) {
	logDir := t.TempDir()
	writer, err := logs.NewWriter(logDir)
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	registry := connector.NewRegistry()
	if _, err := registry.Register(model.ConnectorRegistration{
		ID:               "conn_lab_001",
		TenantID:         "tenant_lab_001",
		ConnectorGroupID: "cgrp_lab_001",
		Name:             "Lab Connector",
		EdgeRegionID:     "local",
		EdgeClusterID:    "local-edge-001",
		ApplicationIDs:   []string{"app_session_human_https"},
		PrivateBaseURL:   "http://connector.local",
		Status:           "registered",
		Metadata:         map[string]any{},
	}, time.Now()); err != nil {
		t.Fatalf("Register returned error: %v", err)
	}

	clientRaw, serverRaw := net.Pipe()
	defer clientRaw.Close()
	defer serverRaw.Close()
	clientTunnelConn := tunnel.NewInProcessConn(clientRaw, true)
	serverTunnelConn := tunnel.NewInProcessConn(serverRaw, false)
	tunnelManager := tunnel.NewManagerWithRequestTimeout(500 * time.Millisecond)
	session, _ := tunnelManager.Register("conn_lab_001", "tun_lab_001", clientTunnelConn)
	runDone := make(chan error, 1)
	go func() {
		runDone <- session.Run()
	}()

	routeProfiles := map[string]edgeplane.ApplicationRouteProfile{
		"app_session_human_https": {
			Destination:            "session-human-route.internal",
			DestinationPort:        8443,
			Protocol:               "tcp",
			ServiceFamily:          "https",
			DestinationRole:        "private_app",
			ApplicationSensitivity: "high",
		},
	}
	evaluator := testEvaluatorWithPolicies([]model.Policy{
		{
			ID:       "pol_lab_nhi_spoofed_connect_allow_001",
			TenantID: "tenant_lab_001",
			Priority: 10,
			Conditions: map[string]any{
				"actor_type":                "delegated_agent",
				"actor_nhi_id":              "nhi_spoofed_001",
				"delegated_access_grant_id": "dag_spoofed_001",
				"application_id":            "app_session_human_https",
				"service_family":            "https",
				"tool_action_type":          "ticket:create",
			},
			Action: model.PolicyAction{Decision: "allow"},
			Status: "active",
		},
		{
			ID:       "pol_lab_session_human_connect_allow_001",
			TenantID: "tenant_lab_001",
			Priority: 50,
			Conditions: map[string]any{
				"actor_type":     "human",
				"application_id": "app_session_human_https",
				"service_family": "https",
				"mfa_state":      "fresh",
				"user_groups": map[string]any{
					"op":    "contains",
					"value": "security-admins",
				},
			},
			Action: model.PolicyAction{Decision: "allow"},
			Status: "active",
		},
	})
	now := time.Now().UTC()
	nhiRegistry := nhi.NewStore()
	if _, err := nhiRegistry.Upsert(context.Background(), model.NonHumanIdentity{
		ID:                    "nhi_spoofed_001",
		Name:                  "Spoofed NHI",
		NHIType:               "ai_agent",
		OwnerUserID:           "user_owner_001",
		Status:                "active",
		AllowedApplicationIDs: []string{"app_session_human_https"},
		AllowedScopes:         []string{"ticket:create"},
	}, "tenant_lab_001", now); err != nil {
		t.Fatalf("upsert NHI returned error: %v", err)
	}
	sessionStore := sessionstore.NewStore()
	subjectUserID := "user_session_subject_001"
	deviceID := "dev_session_001"
	acr := "urn:mfa:fresh"
	expiresAt := now.Add(time.Hour).Format(time.RFC3339)
	if _, err := sessionStore.CreateFromAuthenticationEvent(model.AuthenticationEvent{
		ID:            "auth_session_connect_001",
		TenantID:      "tenant_lab_001",
		UserID:        "user_session_001",
		SubjectUserID: &subjectUserID,
		SessionID:     "sess_connect_human_001",
		IDPID:         "idp_keycloak_lab",
		Method:        "oidc_authorization_code",
		AMR:           []string{"pwd", "otp"},
		ACR:           &acr,
		MFAState:      "fresh",
		ExpiresAt:     &expiresAt,
		DeviceID:      &deviceID,
		Result:        "success",
		Timestamp:     now.Format(time.RFC3339),
		Metadata: map[string]any{
			"groups": []string{"security-admins"},
			"issuer": "https://idp.example.test",
		},
	}, "pb_lab_20260602_001", "tenant_lab_001", now); err != nil {
		t.Fatalf("create session returned error: %v", err)
	}
	handler := newServerWithConfig(serverConfig{
		Evaluator:          evaluator,
		Writer:             writer,
		Registry:           registry,
		TunnelManager:      tunnelManager,
		RouteProfiles:      routeProfiles,
		SessionStore:       sessionStore,
		DelegatedGrants:    newDelegatedAccessGrantStore(),
		NonHumanIdentities: nhiRegistry,
		ProxyClient: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			t.Fatalf("proxy client was called for CONNECT session identity test")
			return nil, nil
		})},
	})

	query := url.Values{}
	query.Set("connector_id", "conn_lab_001")
	query.Set("user_id", "evil_user")
	query.Set("subject_user_id", "evil_subject")
	query.Set("user_groups", "evil-admins")
	query.Set("actor_nhi_id", "nhi_spoofed_001")
	query.Set("delegated_access_grant_id", "dag_spoofed_001")
	query.Set("agent_task_session_id", "ats_spoofed_001")
	query.Set("tool_id", "tool_ticket_create_001")
	query.Set("tool_action_type", "ticket:create")
	query.Set("tool_signature_state", "signed")
	query.Set("mcp_server_id", "mcp_soc_lab_001")
	query.Set("mcp_token_passthrough_policy", "blocked")
	query.Set("runtime_environment_id", "runtime_managed_cloud_lab_001")
	allowReq := httptest.NewRequest(http.MethodConnect, "/apps/app_session_human_https?"+query.Encode(), nil)
	allowReq.Header.Set(edgeplane.ConnectAuthorityHeader, "session-human-route.internal:8443")
	allowReq.AddCookie(&http.Cookie{Name: "session_id", Value: "sess_connect_human_001"})
	allowDone := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		allowRec := httptest.NewRecorder()
		handler.ServeHTTP(allowRec, allowReq)
		allowDone <- allowRec
	}()

	var openFrame tunnel.Frame
	if err := serverTunnelConn.ReadJSON(&openFrame); err != nil {
		t.Fatalf("ReadJSON allowed tcp_open returned error: %v", err)
	}
	if openFrame.Type != tunnel.FrameTCPOpen || openFrame.ApplicationID != "app_session_human_https" || openFrame.Host != "session-human-route.internal" || openFrame.Port != 8443 {
		t.Fatalf("openFrame = %+v, want session human route tcp_open", openFrame)
	}
	if err := serverTunnelConn.WriteJSON(tunnel.Frame{Type: tunnel.FrameTCPOpenResult, RequestID: openFrame.RequestID}); err != nil {
		t.Fatalf("WriteJSON tcp_open_result returned error: %v", err)
	}
	var closeFrame tunnel.Frame
	if err := serverTunnelConn.ReadJSON(&closeFrame); err != nil {
		t.Fatalf("ReadJSON post-open tcp_close returned error: %v", err)
	}
	if closeFrame.Type != tunnel.FrameTCPClose || closeFrame.RequestID != openFrame.RequestID || closeFrame.Direction != tunnel.TCPDirectionLocal || closeFrame.CloseReason != tunnel.TCPCloseReasonError {
		t.Fatalf("closeFrame = %+v, want local error close after no-hijack test harness", closeFrame)
	}
	select {
	case allowRec := <-allowDone:
		if allowRec.Code != http.StatusInternalServerError || !strings.Contains(allowRec.Body.String(), "response writer does not support CONNECT hijack") {
			t.Fatalf("allow status/body = %d/%s, want post-open hijack limitation", allowRec.Code, allowRec.Body.String())
		}
	case <-time.After(time.Second):
		t.Fatal("allowed CONNECT handler did not return after tcp_open_result")
	}

	accessRows, err := writer.ReadJSONL("access.log.jsonl")
	if err != nil {
		t.Fatalf("read access log: %v", err)
	}
	if len(accessRows) != 1 {
		t.Fatalf("access rows = %#v, want one session-derived allow row", accessRows)
	}
	if accessRows[0]["decision"] != "allow" || accessRows[0]["actor_type"] != "human" || accessRows[0]["user_id"] != "user_session_001" || accessRows[0]["subject_user_id"] != "user_session_subject_001" || accessRows[0]["session_id"] != "sess_connect_human_001" {
		t.Fatalf("access rows = %#v, want session-derived human identity allow", accessRows)
	}
	if accessRows[0]["actor_nhi_id"] != nil || accessRows[0]["delegated_access_grant_id"] != nil || accessRows[0]["tool_id"] != nil || accessRows[0]["mcp_server_id"] != nil {
		t.Fatalf("access rows = %#v, want client-supplied NHI/tool/MCP context ignored", accessRows)
	}
	accessMetadata, ok := accessRows[0]["metadata"].(map[string]any)
	if !ok || accessMetadata["mfa_state"] != "fresh" {
		t.Fatalf("access metadata = %#v, want session metadata", accessRows[0]["metadata"])
	}
	for _, forbidden := range []string{"actor_nhi_id", "delegated_access_grant_id", "tool_id", "tool_action_type", "mcp_server_id", "runtime_evidence_result", "nhi_registry_last_used_result"} {
		if _, ok := accessMetadata[forbidden]; ok {
			t.Fatalf("access metadata = %#v, want no client-supplied %s", accessMetadata, forbidden)
		}
	}

	traceRows, err := writer.ReadJSONL("access.log.jsonl")
	if err != nil {
		t.Fatalf("read access log: %v", err)
	}
	if len(traceRows) != 1 || traceRows[0]["policy_id"] != "pol_lab_session_human_connect_allow_001" {
		t.Fatalf("access rows = %#v, want session human policy match", traceRows)
	}
	matchedConditions, ok := traceRows[0]["matched_conditions"].([]any)
	if !ok {
		t.Fatalf("trace matched_conditions = %#v, want array", traceRows[0]["matched_conditions"])
	}
	matchedSet := map[string]bool{}
	for _, condition := range matchedConditions {
		if value, ok := condition.(string); ok {
			matchedSet[value] = true
		}
	}
	if !matchedSet["actor_type"] || !matchedSet["mfa_state"] || !matchedSet["user_groups"] {
		t.Fatalf("trace matched_conditions = %#v, want session-derived actor_type/mfa_state/user_groups", matchedConditions)
	}
	traceMetadata, ok := traceRows[0]["metadata"].(map[string]any)
	if !ok || traceMetadata["actor_type"] != "human" || traceMetadata["subject_user_id"] != "user_session_subject_001" {
		t.Fatalf("trace metadata = %#v, want session-derived human metadata", traceRows[0]["metadata"])
	}
	for _, forbidden := range []string{"actor_nhi_id", "delegated_access_grant_id", "tool_id", "tool_action_type", "mcp_server_id", "runtime_evidence_result", "nhi_registry_last_used_result"} {
		if _, ok := traceMetadata[forbidden]; ok {
			t.Fatalf("trace metadata = %#v, want no client-supplied %s", traceMetadata, forbidden)
		}
	}

	connectorRows, err := writer.ReadJSONL("connector.log.jsonl")
	if err != nil {
		t.Fatalf("read connector log: %v", err)
	}
	routeAllowedRows := []map[string]any{}
	startedRows := []map[string]any{}
	deniedRows := []map[string]any{}
	for _, row := range connectorRows {
		switch row["event_type"] {
		case "connector_route_allowed":
			routeAllowedRows = append(routeAllowedRows, row)
		case "private_app_tcp_session_started":
			startedRows = append(startedRows, row)
		case "connector_route_denied":
			deniedRows = append(deniedRows, row)
		}
	}
	if len(routeAllowedRows) != 1 || len(startedRows) != 1 || len(deniedRows) != 0 {
		t.Fatalf("connector rows = %#v, want allowed route and one started session without deny", connectorRows)
	}
	if startedRows[0]["tcp_request_id"] != closeFrame.RequestID || startedRows[0]["decision"] != "allow" || startedRows[0]["network_extension_runtime_used"] != false {
		t.Fatalf("started rows = %#v, want metadata-only pre-hijack tcp session start", startedRows)
	}

	identities, err := nhiRegistry.List(context.Background(), "tenant_lab_001")
	if err != nil {
		t.Fatalf("list NHI registry: %v", err)
	}
	if len(identities) != 1 || identities[0].LastUsedAt != nil {
		t.Fatalf("NHI registry identities = %#v, want client-supplied NHI not marked used on human session CONNECT", identities)
	}

	_ = serverRaw.Close()
	_ = clientRaw.Close()
	select {
	case err := <-runDone:
		if err != nil && !strings.Contains(err.Error(), "closed pipe") {
			t.Fatalf("session Run returned error after cleanup: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("session Run did not stop after tunnel close")
	}
}

func TestEdgeTCPConnectTargetRejectsClientAuthorityMismatch(t *testing.T) {
	routeProfiles := map[string]edgeplane.ApplicationRouteProfile{
		"app_dummy_https": {
			Destination:     "route-profile.internal",
			DestinationPort: 8443,
			ServiceFamily:   "https",
		},
	}
	tests := []struct {
		name       string
		clientHost string
		clientPort int
		wantErr    string
	}{
		{name: "host mismatch", clientHost: "evil.internal", clientPort: 8443, wantErr: "host"},
		{name: "port mismatch", clientHost: "route-profile.internal", clientPort: 443, wantErr: "port"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := edgeplane.EdgeTCPConnectTargetForApplication("app_dummy_https", test.clientHost, test.clientPort, routeProfiles)
			if err == nil {
				t.Fatal("edgeplane.EdgeTCPConnectTargetForApplication returned nil error")
			}
			if !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("error = %q, want substring %q", err.Error(), test.wantErr)
			}
		})
	}
}

func TestEdgeTCPConnectTargetDoesNotAcceptClientSuppliedAuthority(t *testing.T) {
	routeProfiles := map[string]edgeplane.ApplicationRouteProfile{
		"app_dummy_https": {
			Destination:     "route-profile.internal",
			DestinationPort: 8443,
			ServiceFamily:   "https",
		},
	}
	target, err := edgeplane.EdgeTCPConnectTargetForApplication("app_dummy_https", "", 0, routeProfiles)
	if err != nil {
		t.Fatalf("edgeplane.EdgeTCPConnectTargetForApplication returned error: %v", err)
	}
	if target.Host != "route-profile.internal" || target.Port != 8443 {
		t.Fatalf("target = %+v, want route profile authority", target)
	}
}

func TestEdgeTCPConnectTargetDeniesUnprofiledApplication(t *testing.T) {
	routeProfiles := map[string]edgeplane.ApplicationRouteProfile{
		"app_other": {
			Destination:     "other.internal",
			DestinationPort: 443,
			ServiceFamily:   "https",
		},
	}
	_, err := edgeplane.EdgeTCPConnectTargetForApplication("app_dummy_https", "dummy-private-app.local", 443, routeProfiles)
	if err == nil {
		t.Fatal("edgeplane.EdgeTCPConnectTargetForApplication returned nil error for unprofiled application")
	}
	if !strings.Contains(err.Error(), "explicit route profile") {
		t.Fatalf("error = %q, want explicit route profile", err.Error())
	}
}

func TestEdgeTCPOpenFrameForTargetIncludesDoSGuardLimits(t *testing.T) {
	frame, err := edgeplane.EdgeTCPOpenFrameForTarget("req_tcp_001", edgeplane.EdgeTCPConnectTarget{
		ApplicationID: "app_dummy_https",
		Host:          "route-profile.internal",
		Port:          8443,
		ServiceFamily: "https",
	}, validEdgeTCPConnectLimits())
	if err != nil {
		t.Fatalf("edgeplane.EdgeTCPOpenFrameForTarget returned error: %v", err)
	}
	if frame.Type != tunnel.FrameTCPOpen || frame.ApplicationID != "app_dummy_https" || frame.Host != "route-profile.internal" || frame.Port != 8443 {
		t.Fatalf("frame = %+v, want tcp_open route target", frame)
	}
	if frame.ConnectTimeoutMillis == 0 || frame.MaxConnectionLifetimeMillis == 0 || frame.IdleTimeoutMillis == 0 || frame.ByteCap == 0 || frame.ConcurrentConnectionCap == 0 {
		t.Fatalf("frame missing DoS guard limits: %+v", frame)
	}
}

func TestEdgeMajorProtocolRouteProfilesEmitHardenedTCPOpenFrames(t *testing.T) {
	routeProfiles, err := edgeplane.LoadApplicationRouteProfiles(filepath.Join("..", "..", "samples", "phase1", "protected_app_map_lab.json"))
	if err != nil {
		t.Fatalf("edgeplane.LoadApplicationRouteProfiles returned error: %v", err)
	}
	limits := validEdgeTCPConnectLimits()
	tests := []struct {
		applicationID string
		host          string
		port          int
		serviceFamily string
	}{
		{applicationID: "app_dummy_ssh", host: "dummy-ssh.local", port: 22, serviceFamily: "ssh"},
		{applicationID: "app_dummy_rdp", host: "dummy-rdp.local", port: 3389, serviceFamily: "rdp"},
		{applicationID: "app_dummy_postgres", host: "dummy-postgres.local", port: 5432, serviceFamily: "database"},
	}
	for _, test := range tests {
		t.Run(test.applicationID, func(t *testing.T) {
			target, err := edgeplane.EdgeTCPConnectTargetForApplication(test.applicationID, test.host, test.port, routeProfiles)
			if err != nil {
				t.Fatalf("edgeplane.EdgeTCPConnectTargetForApplication returned error: %v", err)
			}
			if target.Host != test.host || target.Port != test.port || target.ServiceFamily != test.serviceFamily {
				t.Fatalf("target = %+v, want %s:%d/%s", target, test.host, test.port, test.serviceFamily)
			}
			frame, err := edgeplane.EdgeTCPOpenFrameForTarget("req_tcp_"+test.applicationID, target, limits)
			if err != nil {
				t.Fatalf("edgeplane.EdgeTCPOpenFrameForTarget returned error: %v", err)
			}
			if frame.ApplicationID != test.applicationID || frame.Host != test.host || frame.Port != test.port {
				t.Fatalf("frame = %+v, want route-bound tcp_open for %s", frame, test.applicationID)
			}
			if frame.ConnectTimeoutMillis != limits.ConnectTimeoutMillis ||
				frame.MaxConnectionLifetimeMillis != limits.MaxConnectionLifetimeMillis ||
				frame.IdleTimeoutMillis != limits.IdleTimeoutMillis ||
				frame.ByteCap != limits.ByteCap ||
				frame.ConcurrentConnectionCap != limits.ConcurrentConnectionCap {
				t.Fatalf("frame limits = %+v, want %+v", frame, limits)
			}
			if err := tunnel.ValidateTCPOpenFrame(frame); err != nil {
				t.Fatalf("ValidateTCPOpenFrame returned error: %v", err)
			}
		})
	}
}

func TestDecisionRequestForApplicationConnectIgnoresClientSuppliedActorContext(t *testing.T) {
	routeProfiles := map[string]edgeplane.ApplicationRouteProfile{
		"app_dummy_https": {
			Destination:            "route-profile.internal",
			DestinationPort:        8443,
			Protocol:               "tcp",
			ServiceFamily:          "https",
			DestinationRole:        "private_app",
			ApplicationSensitivity: "high",
		},
	}
	req := httptest.NewRequest(http.MethodConnect, "/apps/app_dummy_https?tenant_id=evil_tenant&user_id=evil_user&subject_user_id=evil_subject&user_groups=admins&actor_nhi_id=nhi_evil&delegated_access_grant_id=grant_evil&agent_task_session_id=task_evil&tool_id=tool_evil&tool_action_type=delete&context_boundary_id=ctx_evil&data_classification=secret&token_binding_state=missing&human_approval_event_id=approval_evil&device_id=device_evil&device_trust_level=trusted", nil)
	req.RemoteAddr = "192.0.2.10:55123"
	req.Header.Set("x-session-id", "sess_lab_001")
	conn := model.ConnectorRegistration{ID: "conn_lab_001", TenantID: "tenant_lab_001"}

	decisionReq := decisionRequestForApplicationConnect(req, conn, "app_dummy_https", routeProfiles)
	if decisionReq.TenantID != "tenant_lab_001" {
		t.Fatalf("tenant_id = %q, want connector tenant", decisionReq.TenantID)
	}
	if decisionReq.UserID != "" || decisionReq.SubjectUserID != "" || len(decisionReq.UserGroups) != 0 || decisionReq.ActorNHIID != "" || decisionReq.DelegatedAccessGrantID != "" || decisionReq.AgentTaskSessionID != "" || decisionReq.ToolID != "" || decisionReq.ToolActionType != "" || decisionReq.ContextBoundaryID != "" || decisionReq.DataClassification != "" || decisionReq.TokenBindingState != "" || decisionReq.HumanApprovalEventID != "" || decisionReq.DeviceID != "" || decisionReq.DeviceTrustLevel != "" {
		t.Fatalf("CONNECT decision request accepted client-supplied actor context: %+v", decisionReq)
	}
	if decisionReq.SessionID != "sess_lab_001" || decisionReq.ConnectorID != "conn_lab_001" || decisionReq.Destination != "route-profile.internal" || decisionReq.DestinationPort != 8443 {
		t.Fatalf("decision request = %+v, want session and route profile context", decisionReq)
	}
}

func TestCopyEdgeTCPTunnelToClientWritesDownstreamPayload(t *testing.T) {
	clientConn, edgeConn := net.Pipe()
	defer clientConn.Close()
	defer edgeConn.Close()
	streamCh := make(chan tunnel.Frame, 2)
	dataFrame, err := tunnel.NewTCPDataFrame("req_tcp_001", tunnel.TCPDirectionDown, []byte("private-response"))
	if err != nil {
		t.Fatalf("NewTCPDataFrame returned error: %v", err)
	}
	streamCh <- dataFrame
	streamCh <- tunnel.Frame{Type: tunnel.FrameTCPClose, RequestID: "req_tcp_001", Direction: tunnel.TCPDirectionRemote, CloseReason: tunnel.TCPCloseReasonEOF}
	close(streamCh)

	done := make(chan error, 1)
	go func() {
		done <- edgeplane.CopyEdgeTCPTunnelToClient(streamCh, edgeConn)
	}()
	buffer := make([]byte, len("private-response"))
	if _, err := io.ReadFull(clientConn, buffer); err != nil {
		t.Fatalf("ReadFull returned error: %v", err)
	}
	if string(buffer) != "private-response" {
		t.Fatalf("buffer = %q, want private-response", string(buffer))
	}
	if err := <-done; err != nil && !errors.Is(err, io.EOF) {
		t.Fatalf("edgeplane.CopyEdgeTCPTunnelToClient returned error: %v", err)
	}
}

func TestEdgeTCPInProcessByteRoundTripUsesOpenTCPAndCopyHelpers(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	clientRaw, serverRaw := net.Pipe()
	defer clientRaw.Close()
	defer serverRaw.Close()
	clientTunnelConn := tunnel.NewInProcessConn(clientRaw, true)
	serverTunnelConn := tunnel.NewInProcessConn(serverRaw, false)

	manager := tunnel.NewManagerWithRequestTimeout(time.Second)
	session, _ := manager.Register("conn_lab_001", "tun_lab_001", clientTunnelConn)
	runDone := make(chan error, 1)
	go func() {
		runDone <- session.Run()
	}()

	requestID := "req_tcp_edge_inprocess_roundtrip"
	clientPayload := []byte("client-request")
	privateResponse := []byte("private-response")
	serverDone := make(chan error, 1)
	go func() {
		var openFrame tunnel.Frame
		if err := serverTunnelConn.ReadJSON(&openFrame); err != nil {
			serverDone <- err
			return
		}
		if openFrame.Type != tunnel.FrameTCPOpen || openFrame.RequestID != requestID || openFrame.TunnelID != "tun_lab_001" || openFrame.ApplicationID != "app_dummy_https" || openFrame.Host != "dummy-private-app.local" || openFrame.Port != 443 {
			serverDone <- fmt.Errorf("openFrame = %+v, want route-profile tcp_open", openFrame)
			return
		}
		if err := serverTunnelConn.WriteJSON(tunnel.Frame{Type: tunnel.FrameTCPOpenResult, RequestID: openFrame.RequestID}); err != nil {
			serverDone <- err
			return
		}

		var upFrame tunnel.Frame
		if err := serverTunnelConn.ReadJSON(&upFrame); err != nil {
			serverDone <- err
			return
		}
		if upFrame.Type != tunnel.FrameTCPData || upFrame.RequestID != requestID || upFrame.Direction != tunnel.TCPDirectionUp {
			serverDone <- fmt.Errorf("upFrame = %+v, want upstream tcp_data", upFrame)
			return
		}
		upPayload, err := tunnel.TCPDataFramePayload(upFrame)
		if err != nil {
			serverDone <- err
			return
		}
		if string(upPayload) != string(clientPayload) {
			serverDone <- fmt.Errorf("upPayload = %q, want %q", string(upPayload), string(clientPayload))
			return
		}

		downFrame, err := tunnel.NewTCPDataFrame(openFrame.RequestID, tunnel.TCPDirectionDown, privateResponse)
		if err != nil {
			serverDone <- err
			return
		}
		if err := serverTunnelConn.WriteJSON(downFrame); err != nil {
			serverDone <- err
			return
		}
		serverDone <- serverTunnelConn.WriteJSON(tunnel.Frame{
			Type:        tunnel.FrameTCPClose,
			RequestID:   openFrame.RequestID,
			Direction:   tunnel.TCPDirectionRemote,
			CloseReason: tunnel.TCPCloseReasonEOF,
			BytesUp:     int64(len(clientPayload)),
			BytesDown:   int64(len(privateResponse)),
		})
	}()

	openFrame, err := edgeplane.EdgeTCPOpenFrameForTarget(requestID, edgeplane.EdgeTCPConnectTarget{
		ApplicationID: "app_dummy_https",
		Host:          "dummy-private-app.local",
		Port:          443,
		ServiceFamily: "https",
	}, validEdgeTCPConnectLimits())
	if err != nil {
		t.Fatalf("edgeplane.EdgeTCPOpenFrameForTarget returned error: %v", err)
	}
	streamCh, cleanup, openResponse, err := session.OpenTCP(ctx, openFrame)
	if err != nil {
		t.Fatalf("OpenTCP returned error: %v", err)
	}
	defer cleanup()
	if openResponse.Type != tunnel.FrameTCPOpenResult || openResponse.RequestID != requestID || openResponse.Error != "" {
		t.Fatalf("openResponse = %+v, want successful tcp_open_result", openResponse)
	}

	appConn, edgeConn := net.Pipe()
	defer appConn.Close()
	defer edgeConn.Close()
	copyCtx, cancelCopy := context.WithCancel(ctx)
	defer cancelCopy()

	upstreamDone := make(chan error, 1)
	go func() {
		upstreamDone <- edgeplane.CopyEdgeTCPClientToTunnel(copyCtx, session, requestID, edgeConn)
	}()
	downstreamDone := make(chan error, 1)
	go func() {
		downstreamDone <- edgeplane.CopyEdgeTCPTunnelToClient(streamCh, edgeConn)
	}()

	writeDone := make(chan error, 1)
	go func() {
		_, err := appConn.Write(clientPayload)
		writeDone <- err
	}()
	select {
	case err := <-writeDone:
		if err != nil {
			t.Fatalf("client payload write returned error: %v", err)
		}
	case <-ctx.Done():
		t.Fatalf("client payload write timed out: %v", ctx.Err())
	}

	if err := appConn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SetReadDeadline returned error: %v", err)
	}
	received := make([]byte, len(privateResponse))
	if _, err := io.ReadFull(appConn, received); err != nil {
		t.Fatalf("ReadFull downstream response returned error: %v", err)
	}
	if string(received) != string(privateResponse) {
		t.Fatalf("received downstream response = %q, want %q", string(received), string(privateResponse))
	}
	if err := appConn.SetReadDeadline(time.Time{}); err != nil {
		t.Fatalf("clearing read deadline returned error: %v", err)
	}

	select {
	case err := <-serverDone:
		if err != nil {
			t.Fatalf("in-process tunnel server returned error: %v", err)
		}
	case <-ctx.Done():
		t.Fatalf("in-process tunnel server timed out: %v", ctx.Err())
	}
	select {
	case err := <-downstreamDone:
		if err != nil && !errors.Is(err, io.EOF) {
			t.Fatalf("edgeplane.CopyEdgeTCPTunnelToClient returned error: %v", err)
		}
	case <-ctx.Done():
		t.Fatalf("downstream copy timed out: %v", ctx.Err())
	}

	cancelCopy()
	_ = serverRaw.Close()
	_ = appConn.Close()
	_ = edgeConn.Close()
	select {
	case err := <-upstreamDone:
		if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, context.Canceled) && !strings.Contains(err.Error(), "closed pipe") {
			t.Fatalf("edgeplane.CopyEdgeTCPClientToTunnel returned unexpected error after cleanup: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("edgeplane.CopyEdgeTCPClientToTunnel did not stop after cleanup")
	}

	_ = clientRaw.Close()
	select {
	case err := <-runDone:
		if err != nil && !strings.Contains(err.Error(), "closed pipe") {
			t.Fatalf("session Run returned error after cleanup: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("session Run did not stop after tunnel close")
	}
}

func TestPrivateAppTCPSessionAuditDetailsForDatabaseRedactsQueryMetadata(t *testing.T) {
	openFrame, err := edgeplane.EdgeTCPOpenFrameForTarget("req_tcp_001", edgeplane.EdgeTCPConnectTarget{
		ApplicationID: "app_dummy_postgres",
		Host:          "dummy-postgres.local",
		Port:          5432,
		ServiceFamily: "database",
	}, validEdgeTCPConnectLimits())
	if err != nil {
		t.Fatalf("edgeplane.EdgeTCPOpenFrameForTarget returned error: %v", err)
	}
	dec := model.AccessDecision{ID: "dec_tcp_001", Decision: "allow"}
	req := model.DecisionRequest{
		ApplicationID:          "app_dummy_postgres",
		ApplicationSensitivity: "high",
		DestinationPort:        5432,
		DestinationRole:        "database_server",
		Protocol:               "tcp",
		ServiceFamily:          "database",
	}
	details := edgeplane.PrivateAppTCPSessionAuditDetails(dec, req, openFrame, edgeplane.ApplicationRouteProfile{
		DatabaseProtocol: "postgresql",
	}, "tun_lab_001")

	if details["private_app_session_audit"] != true || details["private_app_session_audit_version"] != "m813.v1" {
		t.Fatalf("session audit details = %#v, want m813 audit marker", details)
	}
	if details["database_protocol"] != "postgresql" || details["database_query_metadata_mode"] != "category_only" {
		t.Fatalf("database metadata = %#v, want category-only postgresql metadata", details)
	}
	for _, key := range []string{"raw_payload_logged", "credential_material_logged", "database_query_text_logged", "database_parameter_values_logged", "network_extension_runtime_used"} {
		if details[key] != false {
			t.Fatalf("%s = %#v, want false in %#v", key, details[key], details)
		}
	}
	encoded, err := json.Marshal(details)
	if err != nil {
		t.Fatalf("Marshal returned error: %v", err)
	}
	for _, forbidden := range []string{"SELECT * FROM", "password=", "private-response"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("audit details leaked forbidden payload/query marker %q: %s", forbidden, string(encoded))
		}
	}
}

func TestPrivateAppTCPSessionAuditDetailsAllowlistsDatabaseProtocol(t *testing.T) {
	openFrame, err := edgeplane.EdgeTCPOpenFrameForTarget("req_tcp_002", edgeplane.EdgeTCPConnectTarget{
		ApplicationID: "app_dummy_postgres",
		Host:          "dummy-postgres.local",
		Port:          5432,
		ServiceFamily: "database",
	}, validEdgeTCPConnectLimits())
	if err != nil {
		t.Fatalf("edgeplane.EdgeTCPOpenFrameForTarget returned error: %v", err)
	}
	details := edgeplane.PrivateAppTCPSessionAuditDetails(
		model.AccessDecision{ID: "dec_tcp_002", Decision: "allow"},
		model.DecisionRequest{ApplicationID: "app_dummy_postgres", DestinationPort: 5432, DestinationRole: "database_server", Protocol: "tcp", ServiceFamily: "database"},
		openFrame,
		edgeplane.ApplicationRouteProfile{DatabaseProtocol: "postgresql password=secret"},
		"tun_lab_001",
	)
	if details["database_protocol"] != "database" {
		t.Fatalf("database_protocol = %#v, want generic database for non-allowlisted value", details["database_protocol"])
	}
	encoded, err := json.Marshal(details)
	if err != nil {
		t.Fatalf("Marshal returned error: %v", err)
	}
	if strings.Contains(string(encoded), "secret") || strings.Contains(string(encoded), "password") {
		t.Fatalf("audit details leaked database protocol input: %s", string(encoded))
	}
}

func TestPrivateAppTCPSessionAuditWritesConnectorLogWithoutPayload(t *testing.T) {
	logDir := t.TempDir()
	writer, err := logs.NewWriter(logDir)
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	openFrame, err := edgeplane.EdgeTCPOpenFrameForTarget("req_tcp_003", edgeplane.EdgeTCPConnectTarget{
		ApplicationID: "app_dummy_ssh",
		Host:          "dummy-ssh.local",
		Port:          22,
		ServiceFamily: "ssh",
	}, validEdgeTCPConnectLimits())
	if err != nil {
		t.Fatalf("edgeplane.EdgeTCPOpenFrameForTarget returned error: %v", err)
	}
	conn := model.ConnectorRegistration{
		ID:               "conn_lab_001",
		TenantID:         "tenant_lab_001",
		ConnectorGroupID: "cgrp_lab_001",
		EdgeRegionID:     "local",
		EdgeClusterID:    "local-edge-001",
		Status:           "registered",
	}
	details := edgeplane.PrivateAppTCPSessionAuditDetails(
		model.AccessDecision{ID: "dec_tcp_003", Decision: "allow"},
		model.DecisionRequest{ApplicationID: "app_dummy_ssh", ApplicationSensitivity: "high", DestinationPort: 22, DestinationRole: "ssh_server", Protocol: "tcp", ServiceFamily: "ssh"},
		openFrame,
		edgeplane.ApplicationRouteProfile{},
		"tun_lab_001",
	)
	if err := appendConnectorLog(context.Background(), writer, nil, connectorAudit("private_app_tcp_session_started", conn, details), time.Now()); err != nil {
		t.Fatalf("appendConnectorLog returned error: %v", err)
	}
	connectorLog, err := os.ReadFile(filepath.Join(logDir, "connector.log.jsonl"))
	if err != nil {
		t.Fatalf("read connector log: %v", err)
	}
	logText := string(connectorLog)
	for _, want := range []string{`"event_type":"private_app_tcp_session_started"`, `"private_app_session_audit":true`, `"service_family":"ssh"`, `"tcp_request_id":"req_tcp_003"`} {
		if !strings.Contains(logText, want) {
			t.Fatalf("connector log = %s, want %s", logText, want)
		}
	}
	for _, forbidden := range []string{"SSH-2.0-Dsse-Lab", "private-response", "password="} {
		if strings.Contains(logText, forbidden) {
			t.Fatalf("connector log leaked forbidden payload marker %q: %s", forbidden, logText)
		}
	}
}

func validEdgeTCPConnectLimits() edgeplane.EdgeTCPConnectLimits {
	return edgeplane.EdgeTCPConnectLimits{
		ConnectTimeoutMillis:        int((5 * time.Second) / time.Millisecond),
		MaxConnectionLifetimeMillis: int((5 * time.Minute) / time.Millisecond),
		IdleTimeoutMillis:           int((30 * time.Second) / time.Millisecond),
		ByteCap:                     64 << 20,
		ConcurrentConnectionCap:     32,
	}
}

func TestConnectorRoutingSupportsDatabaseApplication(t *testing.T) {
	logDir := t.TempDir()
	writer, err := logs.NewWriter(logDir)
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	evaluator := testEvaluatorWithPolicies([]model.Policy{
		{
			ID:       "pol_lab_postgres_allow_001",
			TenantID: "tenant_lab_001",
			Priority: 100,
			Conditions: map[string]any{
				"actor_type":       "human",
				"application_id":   "app_dummy_postgres",
				"service_family":   "database",
				"destination_port": "5432",
			},
			Action: model.PolicyAction{Decision: "allow"},
			Status: "active",
		},
	})
	handler := newServerWithClient(evaluator, writer, connector.NewRegistry(), &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Path != "/private-app/dummy-postgres" {
			t.Fatalf("path = %s, want /private-app/dummy-postgres", req.URL.Path)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"content-type": []string{"application/json"}},
			Body:       io.NopCloser(bytes.NewBufferString(`{"status":"database_probe_reachable"}`)),
		}, nil
	})})
	registerReq := httptest.NewRequest(http.MethodPost, "/connectors/register", strings.NewReader(`{
		"id":"conn_lab_001",
		"tenant_id":"tenant_lab_001",
		"connector_group_id":"cgrp_lab_001",
		"name":"Lab Connector",
		"edge_region_id":"local",
		"edge_cluster_id":"local-edge-001",
		"application_ids":["app_dummy_postgres"],
		"private_base_url":"http://connector.local",
		"status":"registered",
		"metadata":{}
	}`))
	registerReq.Header.Set(connectorSecretHeader, defaultConnectorSecret)
	registerRec := httptest.NewRecorder()
	handler.ServeHTTP(registerRec, registerReq)
	if registerRec.Code != http.StatusCreated {
		t.Fatalf("register status = %d, want %d, body=%s", registerRec.Code, http.StatusCreated, registerRec.Body.String())
	}

	proxyReq := httptest.NewRequest(http.MethodGet, "/apps/app_dummy_postgres?connector_id=conn_lab_001", nil)
	proxyRec := httptest.NewRecorder()
	handler.ServeHTTP(proxyRec, proxyReq)
	if proxyRec.Code != http.StatusOK {
		t.Fatalf("proxy status = %d, want %d, body=%s", proxyRec.Code, http.StatusOK, proxyRec.Body.String())
	}
	if !strings.Contains(proxyRec.Body.String(), "database_probe_reachable") {
		t.Fatalf("proxy body = %s", proxyRec.Body.String())
	}

	connectorLog, err := os.ReadFile(filepath.Join(logDir, "connector.log.jsonl"))
	if err != nil {
		t.Fatalf("read connector log: %v", err)
	}
	if !strings.Contains(string(connectorLog), `"service_family":"database"`) || !strings.Contains(string(connectorLog), `"destination_port":5432`) {
		t.Fatalf("connector log = %s, want database route details", string(connectorLog))
	}
}

func TestConnectorRoutingSupportsRDPApplication(t *testing.T) {
	logDir := t.TempDir()
	writer, err := logs.NewWriter(logDir)
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	evaluator := testEvaluatorWithPolicies([]model.Policy{
		{
			ID:       "pol_lab_rdp_allow_001",
			TenantID: "tenant_lab_001",
			Priority: 100,
			Conditions: map[string]any{
				"actor_type":       "human",
				"application_id":   "app_dummy_rdp",
				"service_family":   "rdp",
				"destination_port": "3389",
			},
			Action: model.PolicyAction{Decision: "allow"},
			Status: "active",
		},
	})
	handler := newServerWithClient(evaluator, writer, connector.NewRegistry(), &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Path != "/private-app/dummy-rdp" {
			t.Fatalf("path = %s, want /private-app/dummy-rdp", req.URL.Path)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"content-type": []string{"application/json"}},
			Body:       io.NopCloser(bytes.NewBufferString(`{"status":"rdp_probe_reachable"}`)),
		}, nil
	})})
	registerReq := httptest.NewRequest(http.MethodPost, "/connectors/register", strings.NewReader(`{
		"id":"conn_lab_001",
		"tenant_id":"tenant_lab_001",
		"connector_group_id":"cgrp_lab_001",
		"name":"Lab Connector",
		"edge_region_id":"local",
		"edge_cluster_id":"local-edge-001",
		"application_ids":["app_dummy_rdp"],
		"private_base_url":"http://connector.local",
		"status":"registered",
		"metadata":{}
	}`))
	registerReq.Header.Set(connectorSecretHeader, defaultConnectorSecret)
	registerRec := httptest.NewRecorder()
	handler.ServeHTTP(registerRec, registerReq)
	if registerRec.Code != http.StatusCreated {
		t.Fatalf("register status = %d, want %d, body=%s", registerRec.Code, http.StatusCreated, registerRec.Body.String())
	}

	proxyReq := httptest.NewRequest(http.MethodGet, "/apps/app_dummy_rdp?connector_id=conn_lab_001", nil)
	proxyRec := httptest.NewRecorder()
	handler.ServeHTTP(proxyRec, proxyReq)
	if proxyRec.Code != http.StatusOK {
		t.Fatalf("proxy status = %d, want %d, body=%s", proxyRec.Code, http.StatusOK, proxyRec.Body.String())
	}
	if !strings.Contains(proxyRec.Body.String(), "rdp_probe_reachable") {
		t.Fatalf("proxy body = %s", proxyRec.Body.String())
	}

	connectorLog, err := os.ReadFile(filepath.Join(logDir, "connector.log.jsonl"))
	if err != nil {
		t.Fatalf("read connector log: %v", err)
	}
	if !strings.Contains(string(connectorLog), `"service_family":"rdp"`) || !strings.Contains(string(connectorLog), `"destination_port":3389`) {
		t.Fatalf("connector log = %s, want rdp route details", string(connectorLog))
	}
}

func TestConnectorRoutingUsesSessionCookie(t *testing.T) {
	logDir := t.TempDir()
	writer, err := logs.NewWriter(logDir)
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	evaluator := testEvaluatorWithPolicies([]model.Policy{
		{
			ID:       "pol_lab_connector_mfa_allow_001",
			TenantID: "tenant_lab_001",
			Priority: 50,
			Conditions: map[string]any{
				"actor_type":     "human",
				"application_id": "app_dummy_https",
				"service_family": "https",
				"mfa_state":      "fresh",
				"amr": map[string]any{
					"op":    "contains",
					"value": "otp",
				},
			},
			Action: model.PolicyAction{Decision: "allow"},
			Status: "active",
		},
	})
	store := sessionStoreForTest()
	handler := newServerWithClientSecretTunnelSessionAndOIDC(evaluator, writer, connector.NewRegistry(), &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"content-type": []string{"application/json"}},
			Body:       io.NopCloser(bytes.NewBufferString(`{"status":"reachable_via_connector"}`)),
		}, nil
	})}, defaultConnectorSecret, tunnel.NewManager(), store, oidcConfig{})

	createReq := httptest.NewRequest(http.MethodPost, "/auth/events", strings.NewReader(`{
		"id":"auth_cookie_001",
		"tenant_id":"tenant_lab_001",
		"user_id":"user_cookie_001",
		"subject_user_id":"user_cookie_001",
		"session_id":"sess_cookie_001",
		"idp_id":"idp_keycloak_lab",
		"method":"oidc_authorization_code",
		"amr":["pwd","otp"],
		"acr":"urn:mfa:fresh",
		"mfa_state":"fresh",
		"auth_time":"2026-05-22T00:00:00Z",
		"expires_at":"2026-05-22T01:00:00Z",
		"device_id":"dev_cookie_001",
		"result":"success",
		"timestamp":"2026-05-22T00:00:00Z",
		"metadata":{}
	}`))
	createRec := httptest.NewRecorder()
	handler.ServeHTTP(createRec, createReq)
	if createRec.Code != http.StatusCreated {
		t.Fatalf("create session status = %d, want %d, body=%s", createRec.Code, http.StatusCreated, createRec.Body.String())
	}

	registerReq := httptest.NewRequest(http.MethodPost, "/connectors/register", strings.NewReader(`{
		"id":"conn_lab_001",
		"tenant_id":"tenant_lab_001",
		"connector_group_id":"cgrp_lab_001",
		"name":"Lab Connector",
		"edge_region_id":"local",
		"edge_cluster_id":"local-edge-001",
		"application_ids":["app_dummy_https"],
		"private_base_url":"http://connector.local",
		"status":"registered",
		"metadata":{}
	}`))
	registerReq.Header.Set(connectorSecretHeader, defaultConnectorSecret)
	registerRec := httptest.NewRecorder()
	handler.ServeHTTP(registerRec, registerReq)
	if registerRec.Code != http.StatusCreated {
		t.Fatalf("register status = %d, want %d, body=%s", registerRec.Code, http.StatusCreated, registerRec.Body.String())
	}

	proxyReq := httptest.NewRequest(http.MethodGet, "/apps/app_dummy_https?connector_id=conn_lab_001", nil)
	proxyReq.AddCookie(&http.Cookie{Name: "session_id", Value: "sess_cookie_001"})
	proxyRec := httptest.NewRecorder()
	handler.ServeHTTP(proxyRec, proxyReq)
	if proxyRec.Code != http.StatusOK {
		t.Fatalf("proxy status = %d, want %d, body=%s", proxyRec.Code, http.StatusOK, proxyRec.Body.String())
	}
	traceLog, err := os.ReadFile(filepath.Join(logDir, "access.log.jsonl"))
	if err != nil {
		t.Fatalf("read access log: %v", err)
	}
	if !strings.Contains(string(traceLog), "pol_lab_connector_mfa_allow_001") {
		t.Fatalf("access log = %s, want connector MFA policy", string(traceLog))
	}
}

func TestConnectorListAndHealthRequireAdminAuth(t *testing.T) {
	// Drives an admin route with the shared break-glass token, which is off by default now.
	armBreakGlassForTest(t)
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	registry := connector.NewRegistry()
	handler := newServerWithConfig(serverConfig{
		Evaluator:       testEvaluator(),
		Writer:          writer,
		Registry:        registry,
		ConnectorSecret: defaultConnectorSecret,
		AdminToken:      "legacy-admin-token",
	})
	registerBody := `{
		"id":"conn_lab_001",
		"tenant_id":"tenant_lab_001",
		"connector_group_id":"cgrp_lab_001",
		"name":"Lab Connector",
		"edge_region_id":"local",
		"edge_cluster_id":"local-edge-001",
		"application_ids":["app_dummy_https"],
		"private_base_url":"http://connector.local",
		"status":"registered",
		"metadata":{}
	}`
	registerReq := httptest.NewRequest(http.MethodPost, "/connectors/register", strings.NewReader(registerBody))
	registerReq.Header.Set(connectorSecretHeader, defaultConnectorSecret)
	registerRec := httptest.NewRecorder()
	handler.ServeHTTP(registerRec, registerReq)
	if registerRec.Code != http.StatusCreated {
		t.Fatalf("register status = %d, want %d, body=%s", registerRec.Code, http.StatusCreated, registerRec.Body.String())
	}

	listReq := httptest.NewRequest(http.MethodGet, "/connectors", nil)
	listRec := httptest.NewRecorder()
	handler.ServeHTTP(listRec, listReq)
	if listRec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated connector list status = %d, want %d", listRec.Code, http.StatusUnauthorized)
	}
	listReq = httptest.NewRequest(http.MethodGet, "/connectors", nil)
	listReq.Header.Set("authorization", "Bearer legacy-admin-token")
	listRec = httptest.NewRecorder()
	handler.ServeHTTP(listRec, listReq)
	if listRec.Code != http.StatusOK {
		t.Fatalf("authenticated connector list status = %d, want %d, body=%s", listRec.Code, http.StatusOK, listRec.Body.String())
	}

	healthReq := httptest.NewRequest(http.MethodGet, "/connectors/conn_lab_001/health", nil)
	healthRec := httptest.NewRecorder()
	handler.ServeHTTP(healthRec, healthReq)
	if healthRec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated connector health status = %d, want %d", healthRec.Code, http.StatusUnauthorized)
	}
	healthReq = httptest.NewRequest(http.MethodGet, "/connectors/conn_lab_001/health", nil)
	healthReq.Header.Set("authorization", "Bearer legacy-admin-token")
	healthRec = httptest.NewRecorder()
	handler.ServeHTTP(healthRec, healthReq)
	if healthRec.Code != http.StatusOK {
		t.Fatalf("authenticated connector health status = %d, want %d, body=%s", healthRec.Code, http.StatusOK, healthRec.Body.String())
	}
}

func TestConnectorAdminEndpointsAreTenantScoped(t *testing.T) {
	// Drives an admin route with the shared break-glass token, which is off by default now.
	armBreakGlassForTest(t)
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	registry := connector.NewRegistry()
	now := time.Now()
	if _, err := registry.Register(model.ConnectorRegistration{
		ID:               "conn_lab_001",
		TenantID:         "tenant_lab_001",
		ConnectorGroupID: "cgrp_lab_001",
		Name:             "Lab Connector",
		EdgeRegionID:     "local",
		EdgeClusterID:    "local-edge-001",
		ApplicationIDs:   []string{"app_dummy_https"},
		PrivateBaseURL:   "http://connector.local",
		Status:           "registered",
		Metadata:         map[string]any{},
	}, now); err != nil {
		t.Fatalf("register lab connector returned error: %v", err)
	}
	if _, err := registry.Register(model.ConnectorRegistration{
		ID:               "conn_other_001",
		TenantID:         "tenant_other",
		ConnectorGroupID: "cgrp_other_001",
		Name:             "Other Connector",
		EdgeRegionID:     "local",
		EdgeClusterID:    "local-edge-001",
		ApplicationIDs:   []string{"app_dummy_https"},
		PrivateBaseURL:   "http://other-connector.local",
		Status:           "registered",
		Metadata:         map[string]any{"owner": "other"},
	}, now); err != nil {
		t.Fatalf("register other connector returned error: %v", err)
	}
	handler := newServerWithConfig(serverConfig{
		Evaluator:       testEvaluator(),
		Writer:          writer,
		Registry:        registry,
		ConnectorSecret: defaultConnectorSecret,
		AdminToken:      "legacy-admin-token",
		LabMode:         boolPtr(false),
	})

	listReq := httptest.NewRequest(http.MethodGet, "/connectors", nil)
	listReq.Header.Set("authorization", "Bearer legacy-admin-token")
	listRec := httptest.NewRecorder()
	handler.ServeHTTP(listRec, listReq)
	if listRec.Code != http.StatusOK {
		t.Fatalf("connector list status = %d, want %d, body=%s", listRec.Code, http.StatusOK, listRec.Body.String())
	}
	var connectors []model.ConnectorRegistration
	if err := json.NewDecoder(listRec.Body).Decode(&connectors); err != nil {
		t.Fatalf("decode connectors: %v", err)
	}
	if len(connectors) != 1 || connectors[0].ID != "conn_lab_001" {
		t.Fatalf("connectors = %#v, want only conn_lab_001", connectors)
	}

	healthReq := httptest.NewRequest(http.MethodGet, "/connectors/conn_other_001/health", nil)
	healthReq.Header.Set("authorization", "Bearer legacy-admin-token")
	healthRec := httptest.NewRecorder()
	handler.ServeHTTP(healthRec, healthReq)
	if healthRec.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant health status = %d, want %d, body=%s", healthRec.Code, http.StatusNotFound, healthRec.Body.String())
	}

	rotateReq := httptest.NewRequest(http.MethodPost, "/connectors/conn_other_001/runtime-secret/rotate", strings.NewReader(`{"runtime_secret":"cross-tenant-runtime-secret-0001"}`))
	rotateReq.Header.Set("authorization", "Bearer legacy-admin-token")
	rotateRec := httptest.NewRecorder()
	handler.ServeHTTP(rotateRec, rotateReq)
	if rotateRec.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant rotate status = %d, want %d, body=%s", rotateRec.Code, http.StatusNotFound, rotateRec.Body.String())
	}
	other, ok := registry.Get("conn_other_001")
	if !ok {
		t.Fatal("other connector disappeared")
	}
	if connectorRuntimeSecretHashFromMetadata(other.Metadata) != "" || other.Metadata["runtime_secret_rotated_at"] != nil {
		t.Fatalf("other connector metadata = %#v, want no rotation metadata", other.Metadata)
	}
}

func TestConnectorForApplicationIsTenantScoped(t *testing.T) {
	registry := connector.NewRegistry()
	now := time.Now()
	if _, err := registry.Register(model.ConnectorRegistration{
		ID:               "conn_other_001",
		TenantID:         "tenant_other",
		ConnectorGroupID: "cgrp_other_001",
		ApplicationIDs:   []string{"app_dummy_https"},
		PrivateBaseURL:   "http://other-connector.local",
		Status:           "registered",
		Metadata:         map[string]any{},
	}, now); err != nil {
		t.Fatalf("register other connector returned error: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/apps/app_dummy_https", nil)
	if conn, ok, err := connectorForApplication(req.Context(), req, registry, nil, "tenant_lab_001", "app_dummy_https"); err != nil || ok {
		t.Fatalf("connectorForApplication returned cross-tenant connector %#v", conn)
	}

	if _, err := registry.Register(model.ConnectorRegistration{
		ID:               "conn_lab_001",
		TenantID:         "tenant_lab_001",
		ConnectorGroupID: "cgrp_lab_001",
		ApplicationIDs:   []string{"app_dummy_https"},
		PrivateBaseURL:   "http://connector.local",
		Status:           "registered",
		Metadata:         map[string]any{},
	}, now); err != nil {
		t.Fatalf("register lab connector returned error: %v", err)
	}
	conn, ok, err := connectorForApplication(req.Context(), req, registry, nil, "tenant_lab_001", "app_dummy_https")
	if err != nil {
		t.Fatalf("connectorForApplication returned error: %v", err)
	}
	if !ok || conn.ID != "conn_lab_001" {
		t.Fatalf("connectorForApplication returned %#v ok=%v, want conn_lab_001", conn, ok)
	}

	if _, err := registry.Heartbeat(model.ConnectorHeartbeat{
		ID:       "conn_lab_001",
		TenantID: "tenant_lab_001",
		Status:   "offline",
	}, now.Add(time.Minute)); err != nil {
		t.Fatalf("offline heartbeat returned error: %v", err)
	}
	if conn, ok, err := connectorForApplication(req.Context(), req, registry, nil, "tenant_lab_001", "app_dummy_https"); err != nil || ok {
		t.Fatalf("connectorForApplication returned offline connector %#v ok=%v err=%v", conn, ok, err)
	}
	offlineReq := httptest.NewRequest(http.MethodGet, "/apps/app_dummy_https?connector_id=conn_lab_001", nil)
	if conn, ok, err := connectorForApplication(offlineReq.Context(), offlineReq, registry, nil, "tenant_lab_001", "app_dummy_https"); err != nil || ok {
		t.Fatalf("connectorForApplication with connector_id returned offline connector %#v ok=%v err=%v", conn, ok, err)
	}

	crossTenantReq := httptest.NewRequest(http.MethodGet, "/apps/app_dummy_https?connector_id=conn_other_001", nil)
	if conn, ok, err := connectorForApplication(crossTenantReq.Context(), crossTenantReq, registry, nil, "tenant_lab_001", "app_dummy_https"); err != nil || ok {
		t.Fatalf("connectorForApplication with connector_id returned cross-tenant connector %#v", conn)
	}
}

func TestConnectorAdminReadRedactsRuntimeSecretHash(t *testing.T) {
	// Drives an admin route with the shared break-glass token, which is off by default now.
	armBreakGlassForTest(t)
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	handler := newServerWithConfig(serverConfig{
		Evaluator:       testEvaluator(),
		Writer:          writer,
		Registry:        connector.NewRegistry(),
		ConnectorSecret: defaultConnectorSecret,
		AdminToken:      "legacy-admin-token",
	})
	registerBody := fmt.Sprintf(`{
		"id":"conn_lab_001",
		"tenant_id":"tenant_lab_001",
		"connector_group_id":"cgrp_lab_001",
		"name":"Lab Connector",
		"edge_region_id":"local",
		"edge_cluster_id":"local-edge-001",
		"application_ids":["app_dummy_https"],
		"private_base_url":"http://connector.local",
		"status":"registered",
		"metadata":{"runtime_secret_hash":%q,"identity_sync":{"configured":true}}
	}`, connectorRuntimeSecretHash("runtime-secret"))
	registerReq := httptest.NewRequest(http.MethodPost, "/connectors/register", strings.NewReader(registerBody))
	registerReq.Header.Set(connectorSecretHeader, defaultConnectorSecret)
	registerRec := httptest.NewRecorder()
	handler.ServeHTTP(registerRec, registerReq)
	if registerRec.Code != http.StatusCreated {
		t.Fatalf("register status = %d, want %d, body=%s", registerRec.Code, http.StatusCreated, registerRec.Body.String())
	}

	listReq := httptest.NewRequest(http.MethodGet, "/connectors", nil)
	listReq.Header.Set("authorization", "Bearer legacy-admin-token")
	listRec := httptest.NewRecorder()
	handler.ServeHTTP(listRec, listReq)
	if listRec.Code != http.StatusOK {
		t.Fatalf("connector list status = %d, want %d, body=%s", listRec.Code, http.StatusOK, listRec.Body.String())
	}
	body := listRec.Body.String()
	if strings.Contains(body, "runtime_secret_hash") || strings.Contains(body, connectorRuntimeSecretHash("runtime-secret")) {
		t.Fatalf("connector list leaked runtime hash: %s", body)
	}
	if !strings.Contains(body, `"runtime_secret_configured":true`) || !strings.Contains(body, "identity_sync") {
		t.Fatalf("connector list body = %s, want redacted runtime flag and metadata", body)
	}

	healthReq := httptest.NewRequest(http.MethodGet, "/connectors/conn_lab_001/health", nil)
	healthReq.Header.Set("authorization", "Bearer legacy-admin-token")
	healthRec := httptest.NewRecorder()
	handler.ServeHTTP(healthRec, healthReq)
	if healthRec.Code != http.StatusOK {
		t.Fatalf("connector health status = %d, want %d, body=%s", healthRec.Code, http.StatusOK, healthRec.Body.String())
	}
	healthBody := healthRec.Body.String()
	if strings.Contains(healthBody, "runtime_secret_hash") || strings.Contains(healthBody, connectorRuntimeSecretHash("runtime-secret")) {
		t.Fatalf("connector health leaked runtime hash: %s", healthBody)
	}
	if !strings.Contains(healthBody, `"runtime_secret_configured":true`) {
		t.Fatalf("connector health body = %s, want redacted runtime flag", healthBody)
	}
}

func TestDeviceRegistrationHeartbeatAndPolicyBundleFetch(t *testing.T) {
	logDir := t.TempDir()
	writer, err := logs.NewWriter(logDir)
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	domainOutbox := &recordingDomainEventOutbox{}
	handler := newServerWithConfig(serverConfig{
		Evaluator:         testEvaluator(),
		Writer:            writer,
		Registry:          connector.NewRegistry(),
		DomainEventOutbox: domainOutbox,
		TrustedKeyring: model.TrustedKeyring{
			TenantID: "tenant_lab_001",
			Version:  "2026.05.22.001",
			Keys: []model.TrustedKeyringKey{
				{ID: "pbsign_lab_2026_01", PublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", Status: "active"},
			},
			Metadata: map[string]any{"source": "test"},
		},
		AgentTargetVersion:  "0.1.2",
		AgentReleaseChannel: "lab",
	})
	registerReq := httptest.NewRequest(http.MethodPost, "/devices/register", strings.NewReader(`{
		"id":"dev_lab_001",
		"tenant_id":"tenant_lab_001",
		"user_id":"user_lab_001",
		"hostname":"macbook-lab",
		"os":"macos",
		"os_version":"15.5",
		"agent_version":"0.1.0",
		"device_trust_level":"managed",
		"status":"registered",
		"metadata":{"serial_hash":"sha256:lab"}
	}`))
	registerRec := httptest.NewRecorder()
	handler.ServeHTTP(registerRec, registerReq)
	if registerRec.Code != http.StatusCreated {
		t.Fatalf("register status = %d, want %d, body=%s", registerRec.Code, http.StatusCreated, registerRec.Body.String())
	}
	var dev model.Device
	if err := json.NewDecoder(registerRec.Body).Decode(&dev); err != nil {
		t.Fatalf("decode device: %v", err)
	}
	if dev.PolicyBundleID != "pb_lab_20260522_001" || dev.PolicyBundleVersion != "2026.05.22.001" {
		t.Fatalf("device policy bundle = %s/%s", dev.PolicyBundleID, dev.PolicyBundleVersion)
	}

	heartbeatReq := httptest.NewRequest(http.MethodPost, "/devices/dev_lab_001/heartbeat", strings.NewReader(`{
		"tenant_id":"tenant_lab_001",
		"agent_version":"0.1.1",
		"device_trust_level":"managed",
		"status":"healthy",
		"metadata":{"network":"lab"}
	}`))
	heartbeatRec := httptest.NewRecorder()
	handler.ServeHTTP(heartbeatRec, heartbeatReq)
	if heartbeatRec.Code != http.StatusAccepted {
		t.Fatalf("heartbeat status = %d, want %d, body=%s", heartbeatRec.Code, http.StatusAccepted, heartbeatRec.Body.String())
	}
	var updated model.Device
	if err := json.NewDecoder(heartbeatRec.Body).Decode(&updated); err != nil {
		t.Fatalf("decode updated device: %v", err)
	}
	if updated.AgentVersion != "0.1.1" || updated.Status != "healthy" {
		t.Fatalf("updated device = %#v", updated)
	}

	bundleReq := httptest.NewRequest(http.MethodGet, "/devices/dev_lab_001/policy-bundle", nil)
	bundleRec := httptest.NewRecorder()
	handler.ServeHTTP(bundleRec, bundleReq)
	if bundleRec.Code != http.StatusOK {
		t.Fatalf("policy bundle status = %d, want %d, body=%s", bundleRec.Code, http.StatusOK, bundleRec.Body.String())
	}
	if !strings.Contains(bundleRec.Body.String(), `"policy_bundle"`) || !strings.Contains(bundleRec.Body.String(), `"pb_lab_20260522_001"`) {
		t.Fatalf("policy bundle body = %s", bundleRec.Body.String())
	}

	keyringReq := httptest.NewRequest(http.MethodGet, "/devices/dev_lab_001/trusted-keyring", nil)
	keyringRec := httptest.NewRecorder()
	handler.ServeHTTP(keyringRec, keyringReq)
	if keyringRec.Code != http.StatusOK {
		t.Fatalf("trusted keyring status = %d, want %d, body=%s", keyringRec.Code, http.StatusOK, keyringRec.Body.String())
	}
	if !strings.Contains(keyringRec.Body.String(), `"pbsign_lab_2026_01"`) {
		t.Fatalf("trusted keyring body = %s", keyringRec.Body.String())
	}
	updateReq := httptest.NewRequest(http.MethodPost, "/devices/dev_lab_001/agent-updates", strings.NewReader(`{
		"id":"aue_lab_20260522_001",
		"tenant_id":"tenant_lab_001",
		"device_id":"dev_lab_001",
		"user_id":"user_lab_001",
		"current_agent_version":"0.1.0",
		"target_agent_version":"0.1.1",
		"release_channel":"lab",
		"update_status":"available",
		"update_source":"mdm",
		"timestamp":"2026-05-22T00:00:00Z",
		"metadata":{"rollout_batch":"lab-001"}
	}`))
	updateRec := httptest.NewRecorder()
	handler.ServeHTTP(updateRec, updateReq)
	if updateRec.Code != http.StatusAccepted {
		t.Fatalf("agent update status = %d, want %d, body=%s", updateRec.Code, http.StatusAccepted, updateRec.Body.String())
	}
	if !strings.Contains(updateRec.Body.String(), `"update_status":"available"`) {
		t.Fatalf("agent update body = %s", updateRec.Body.String())
	}
	statusReq := httptest.NewRequest(http.MethodPost, "/devices/dev_lab_001/agent-status", strings.NewReader(`{
		"tenant_id":"tenant_lab_001",
		"device_id":"dev_lab_001",
		"policy_bundle_id":"pb_lab_20260522_001",
		"policy_bundle_version":"2026.05.22.001",
		"bundle_source":"remote",
		"device_trust_level":"managed",
		"status":"healthy",
		"timestamp":"2026-05-22T00:06:00Z",
		"metadata":{"crash_count":0,"steering_attempted":3,"steering_succeeded":3,"steering_failed":0}
	}`))
	statusRec := httptest.NewRecorder()
	handler.ServeHTTP(statusRec, statusReq)
	if statusRec.Code != http.StatusAccepted {
		t.Fatalf("agent status status = %d, want %d, body=%s", statusRec.Code, http.StatusAccepted, statusRec.Body.String())
	}
	if !strings.Contains(statusRec.Body.String(), `"status":"healthy"`) {
		t.Fatalf("agent status body = %s", statusRec.Body.String())
	}
	rolloutReq := httptest.NewRequest(http.MethodGet, "/devices/dev_lab_001/agent-rollout", nil)
	rolloutRec := httptest.NewRecorder()
	handler.ServeHTTP(rolloutRec, rolloutReq)
	if rolloutRec.Code != http.StatusOK {
		t.Fatalf("agent rollout status = %d, want %d, body=%s", rolloutRec.Code, http.StatusOK, rolloutRec.Body.String())
	}
	if !strings.Contains(rolloutRec.Body.String(), `"target_agent_version":"0.1.2"`) || !strings.Contains(rolloutRec.Body.String(), `"update_required":true`) {
		t.Fatalf("agent rollout body = %s", rolloutRec.Body.String())
	}
	auditLog, err := os.ReadFile(filepath.Join(logDir, "audit.log.jsonl"))
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	if !strings.Contains(string(auditLog), "device_registered") || !strings.Contains(string(auditLog), "device_heartbeat") || !strings.Contains(string(auditLog), "agent_update_event_recorded") || !strings.Contains(string(auditLog), "agent_status_reported") {
		t.Fatalf("audit log = %s, want device events", string(auditLog))
	}
	domainEvents := domainOutbox.insertedEvents()
	counts := map[string]int{}
	for _, event := range domainEvents {
		counts[event.Stream]++
	}
	if counts["device_events"] != 2 || counts["agent_update_events"] != 1 {
		t.Fatalf("domain event counts = %#v from events %#v", counts, domainEvents)
	}
}

func TestAgentRuntimeReportsDefaultTelemetryFields(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	evaluator := testEvaluator()
	devices := devicestore.NewStore()
	now := time.Now().UTC()
	if _, err := devices.Register(model.Device{
		ID:                  "dev_agent_defaults",
		TenantID:            evaluator.PolicyBundle.TenantID,
		UserID:              "user_lab_001",
		Hostname:            "agent-defaults",
		OS:                  "macos",
		AgentVersion:        "0.1.0",
		DeviceTrustLevel:    "managed",
		Status:              "registered",
		RegisteredAt:        now.Format(time.RFC3339),
		LastSeenAt:          now.Format(time.RFC3339),
		PolicyBundleID:      evaluator.PolicyBundle.ID,
		PolicyBundleVersion: evaluator.PolicyBundle.Version,
	}, evaluator.PolicyBundle, now); err != nil {
		t.Fatalf("Register device returned error: %v", err)
	}
	telemetry := agenttelemetry.NewStore()
	handler := newServerWithConfig(serverConfig{
		Evaluator:           evaluator,
		Writer:              writer,
		DeviceStore:         devices,
		AgentTelemetry:      telemetry,
		AgentTargetVersion:  "0.1.1",
		AgentReleaseChannel: "pilot",
	})

	updateReq := httptest.NewRequest(http.MethodPost, "/devices/dev_agent_defaults/agent-updates", strings.NewReader(`{}`))
	updateRec := httptest.NewRecorder()
	handler.ServeHTTP(updateRec, updateReq)
	if updateRec.Code != http.StatusAccepted {
		t.Fatalf("agent update status = %d, want %d, body=%s", updateRec.Code, http.StatusAccepted, updateRec.Body.String())
	}
	var update model.AgentUpdateEvent
	if err := json.NewDecoder(updateRec.Body).Decode(&update); err != nil {
		t.Fatalf("decode agent update response: %v", err)
	}
	if !strings.HasPrefix(update.ID, "aue_") || update.TenantID != evaluator.PolicyBundle.TenantID || update.DeviceID != "dev_agent_defaults" || update.UserID != "user_lab_001" {
		t.Fatalf("agent update identity defaults = %#v", update)
	}
	if update.CurrentAgentVersion != "0.1.0" || update.TargetAgentVersion != "0.1.1" || update.ReleaseChannel != "pilot" || update.UpdateStatus != "available" || update.UpdateSource != "control_plane" || update.Timestamp == "" {
		t.Fatalf("agent update lifecycle defaults = %#v", update)
	}

	statusReq := httptest.NewRequest(http.MethodPost, "/devices/dev_agent_defaults/agent-status", strings.NewReader(`{}`))
	statusRec := httptest.NewRecorder()
	handler.ServeHTTP(statusRec, statusReq)
	if statusRec.Code != http.StatusAccepted {
		t.Fatalf("agent status status = %d, want %d, body=%s", statusRec.Code, http.StatusAccepted, statusRec.Body.String())
	}
	var status model.AgentStatus
	if err := json.NewDecoder(statusRec.Body).Decode(&status); err != nil {
		t.Fatalf("decode agent status response: %v", err)
	}
	if status.TenantID != evaluator.PolicyBundle.TenantID || status.DeviceID != "dev_agent_defaults" || status.PolicyBundleID != evaluator.PolicyBundle.ID || status.PolicyBundleVersion != evaluator.PolicyBundle.Version {
		t.Fatalf("agent status identity defaults = %#v", status)
	}
	// DeviceTrustLevel is "unknown": the device was registered without posture signals, and a client-claimed
	// trust string ("managed" in the Register call above) is no longer honored — trust is derived only from
	// real posture signals (review #18). The agent-status telemetry reports the stored, derived value.
	if status.BundleSource != "remote" || status.DeviceTrustLevel != "unknown" || status.Status != "healthy" || status.Timestamp == "" {
		t.Fatalf("agent status lifecycle defaults = %#v", status)
	}

	updateSummary, err := telemetry.UpdateSummary(context.Background(), evaluator.PolicyBundle.TenantID)
	if err != nil {
		t.Fatalf("UpdateSummary returned error: %v", err)
	}
	if updateSummary["total"] != 1 || updateSummary["status_counts"].(map[string]int)["available"] != 1 {
		t.Fatalf("update summary = %#v", updateSummary)
	}
	statusSummary, err := telemetry.StatusSummary(context.Background(), evaluator.PolicyBundle.TenantID)
	if err != nil {
		t.Fatalf("StatusSummary returned error: %v", err)
	}
	if statusSummary["total"] != 1 || statusSummary["status_counts"].(map[string]int)["healthy"] != 1 {
		t.Fatalf("status summary = %#v", statusSummary)
	}
}

func TestDeviceRuntimeEndpointsScopeDeviceLookupToTenant(t *testing.T) {
	logDir := t.TempDir()
	writer, err := logs.NewWriter(logDir)
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	evaluator := testEvaluator()
	store := devicestore.NewStore()
	now := time.Date(2026, 5, 25, 1, 2, 3, 0, time.UTC)
	if _, err := store.Register(model.Device{
		ID:               "dev_other_tenant",
		TenantID:         "tenant_other",
		UserID:           "user_other",
		Hostname:         "other-device",
		OS:               "macos",
		AgentVersion:     "0.1.0",
		DeviceTrustLevel: "managed",
		PolicyBundleID:   "pb_other",
	}, model.PolicyBundle{ID: "pb_other", TenantID: "tenant_other", Version: "2026.05.25.001"}, now); err != nil {
		t.Fatalf("Register other tenant device returned error: %v", err)
	}
	handler := newServerWithConfig(serverConfig{
		Evaluator:   evaluator,
		Writer:      writer,
		DeviceStore: store,
	})

	getReq := httptest.NewRequest(http.MethodGet, "/devices/dev_other_tenant", nil)
	getRec := httptest.NewRecorder()
	handler.ServeHTTP(getRec, getReq)
	if getRec.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant device get status = %d, want %d, body=%s", getRec.Code, http.StatusNotFound, getRec.Body.String())
	}

	rolloutReq := httptest.NewRequest(http.MethodGet, "/devices/dev_other_tenant/agent-rollout", nil)
	rolloutRec := httptest.NewRecorder()
	handler.ServeHTTP(rolloutRec, rolloutReq)
	if rolloutRec.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant rollout status = %d, want %d, body=%s", rolloutRec.Code, http.StatusNotFound, rolloutRec.Body.String())
	}

	statusReq := httptest.NewRequest(http.MethodPost, "/devices/dev_other_tenant/agent-status", strings.NewReader(`{
		"device_id":"dev_other_tenant",
		"status":"healthy"
	}`))
	statusRec := httptest.NewRecorder()
	handler.ServeHTTP(statusRec, statusReq)
	if statusRec.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant agent status = %d, want %d, body=%s", statusRec.Code, http.StatusNotFound, statusRec.Body.String())
	}

	updateReq := httptest.NewRequest(http.MethodPost, "/devices/dev_other_tenant/agent-updates", strings.NewReader(`{
		"device_id":"dev_other_tenant",
		"current_agent_version":"0.1.0",
		"target_agent_version":"0.1.1",
		"release_channel":"lab",
		"update_status":"available",
		"update_source":"mdm"
	}`))
	updateRec := httptest.NewRecorder()
	handler.ServeHTTP(updateRec, updateReq)
	if updateRec.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant agent update = %d, want %d, body=%s", updateRec.Code, http.StatusNotFound, updateRec.Body.String())
	}

	ownDevice, err := store.Register(model.Device{
		ID:               "dev_lab_scoped",
		TenantID:         evaluator.PolicyBundle.TenantID,
		UserID:           "user_lab_001",
		Hostname:         "lab-device",
		OS:               "macos",
		AgentVersion:     "0.1.0",
		DeviceTrustLevel: "managed",
	}, evaluator.PolicyBundle, now)
	if err != nil {
		t.Fatalf("Register own tenant device returned error: %v", err)
	}
	if ownDevice.TenantID != evaluator.PolicyBundle.TenantID {
		t.Fatalf("own device tenant = %s, want %s", ownDevice.TenantID, evaluator.PolicyBundle.TenantID)
	}
	ownReq := httptest.NewRequest(http.MethodGet, "/devices/dev_lab_scoped", nil)
	ownRec := httptest.NewRecorder()
	handler.ServeHTTP(ownRec, ownReq)
	if ownRec.Code != http.StatusOK {
		t.Fatalf("own tenant device get status = %d, want %d, body=%s", ownRec.Code, http.StatusOK, ownRec.Body.String())
	}
}

func TestInspectionEventWriterAndLookup(t *testing.T) {
	logDir := t.TempDir()
	writer, err := logs.NewWriter(logDir)
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	decisionStore := newAccessDecisionStore()
	decisionStore.Upsert(model.AccessDecision{
		ID:                  "dec_inspection_lab_001",
		TenantID:            "tenant_lab_001",
		ActorType:           "delegated_agent",
		ApplicationID:       "app_dummy_https",
		PolicyID:            "pol_lab_nhi_tool_allow_001",
		PolicyBundleID:      "pb_lab_20260522_001",
		PolicyBundleVersion: "2026.05.22.001",
		Decision:            "allow",
		ReasonCodes:         []string{"policy_matched"},
		Actions:             []model.DecisionAction{},
		CacheStatus:         "miss",
		TTLSeconds:          60,
		Metadata:            map[string]any{},
	})
	domainOutbox := &recordingDomainEventOutbox{}
	handler := newServerWithConfig(serverConfig{
		Evaluator:         testEvaluator(),
		Writer:            writer,
		Registry:          connector.NewRegistry(),
		DecisionStore:     decisionStore,
		DomainEventOutbox: domainOutbox,
	})
	body := `{
		"id":"ie_lab_001",
		"tenant_id":"tenant_lab_001",
		"access_decision_id":"dec_inspection_lab_001",
		"application_id":"app_dummy_https",
		"inspection_profile_id":"ip_metadata_only_lab",
		"inspection_mode":"metadata_only",
		"content_type":"application/json",
		"finding_type":"none",
		"severity":"info",
		"payload_stored":false,
		"masked":true,
		"metadata":{"payload_policy":"metadata_only"}
	}`
	req := httptest.NewRequest(http.MethodPost, "/inspection/events", strings.NewReader(body))
	req.RemoteAddr = "192.0.2.30:55000"
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusAccepted, rec.Body.String())
	}
	var event model.InspectionEvent
	if err := json.NewDecoder(rec.Body).Decode(&event); err != nil {
		t.Fatalf("decode inspection response: %v", err)
	}
	if event.RetentionPolicy == nil || *event.RetentionPolicy != "metadata_30d" {
		t.Fatalf("event = %#v, want metadata_30d retention", event)
	}
	rows, err := writer.ReadJSONL("inspection_events.log.jsonl")
	if err != nil {
		t.Fatalf("read inspection log: %v", err)
	}
	if len(rows) != 1 || rows[0]["id"] != "ie_lab_001" || rows[0]["access_decision_id"] != "dec_inspection_lab_001" {
		t.Fatalf("inspection rows = %#v", rows)
	}
	domainEvents := domainOutbox.insertedEvents()
	if len(domainEvents) != 1 || domainEvents[0].Stream != "inspection_events" || domainEvents[0].Payload["id"] != "ie_lab_001" {
		t.Fatalf("domain events = %#v", domainEvents)
	}
	auditRows, err := readAuditRowsExcludingWrapper(writer)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	if len(auditRows) != 1 || auditRows[0]["event_type"] != "inspection_event_recorded" {
		t.Fatalf("audit rows = %#v", auditRows)
	}
	if auditRows[0]["source_ip"] != nil || auditRows[0]["actor_user_id"] != nil || auditRows[0]["session_id"] != nil {
		t.Fatalf("inspection audit included raw source/user/session fields: %#v", auditRows[0])
	}
	if metadata, ok := auditRows[0]["metadata"].(map[string]any); !ok || metadata["inspection_metadata_recorded_scope"] != "none" {
		t.Fatalf("inspection audit metadata = %#v, want scope none", auditRows[0]["metadata"])
	}
	if encoded, err := json.Marshal(auditRows[0]); err != nil {
		t.Fatalf("marshal inspection audit row: %v", err)
	} else {
		for _, leaked := range []string{"user_inspection_lab_001", "dev_inspection_lab_001", "payload-ref-lab-001"} {
			if strings.Contains(string(encoded), leaked) {
				t.Fatalf("inspection audit leaked %q: %s", leaked, string(encoded))
			}
		}
	}

	getReq := httptest.NewRequest(http.MethodGet, "/inspection/events/ie_lab_001", nil)
	getRec := httptest.NewRecorder()
	handler.ServeHTTP(getRec, getReq)
	if getRec.Code != http.StatusOK {
		t.Fatalf("lookup status = %d, want %d, body=%s", getRec.Code, http.StatusOK, getRec.Body.String())
	}
}

func TestDeriveDecisionRequestActorIgnoresActorTypeClaim(t *testing.T) {
	now := time.Date(2026, 5, 24, 12, 0, 0, 0, time.UTC)
	grants := newDelegatedAccessGrantStore()
	if _, err := grants.Upsert(model.DelegatedAccessGrant{
		ID:            "dag_lab_001",
		TenantID:      "tenant_lab_001",
		SubjectUserID: "user_lab_001",
		ActorNHIID:    "nhi_soc_agent_001",
		ExpiresAt:     now.Add(time.Hour).Format(time.RFC3339),
		Status:        "active",
		Metadata:      map[string]any{},
	}); err != nil {
		t.Fatalf("upsert delegated grant returned error: %v", err)
	}

	derived := deriveDecisionRequestActor(model.DecisionRequest{
		TenantID:               "tenant_lab_001",
		ActorType:              "human",
		DelegatedAccessGrantID: "dag_lab_001",
		ApplicationID:          "app_dummy_https",
	}, grants)
	if derived.ActorType != "delegated_agent" || derived.ActorNHIID != "nhi_soc_agent_001" || derived.SubjectUserID != "user_lab_001" {
		t.Fatalf("derived request = %#v, want delegated agent fields from grant", derived)
	}

	ignoredClaim := deriveDecisionRequestActor(model.DecisionRequest{
		TenantID:      "tenant_lab_001",
		ActorType:     "nhi",
		ApplicationID: "app_dummy_https",
	}, grants)
	if ignoredClaim.ActorType != "human" {
		t.Fatalf("ignored claim actor_type = %q, want human without runtime evidence", ignoredClaim.ActorType)
	}

	directNHI := deriveDecisionRequestActor(model.DecisionRequest{
		TenantID:      "tenant_lab_001",
		ActorNHIID:    "nhi_service_account_001",
		ApplicationID: "app_dummy_https",
	}, grants)
	if directNHI.ActorType != "nhi" {
		t.Fatalf("direct NHI actor_type = %q, want nhi from actor_nhi_id", directNHI.ActorType)
	}
}

func TestNHIDecisionRequiresActiveGrantAndApproval(t *testing.T) {
	evaluator := testEvaluatorWithPolicies([]model.Policy{
		{
			ID:       "pol_lab_nhi_tool_allow_001",
			TenantID: "tenant_lab_001",
			Priority: 80,
			Conditions: map[string]any{
				"actor_type":                "delegated_agent",
				"actor_nhi_id":              "nhi_soc_agent_001",
				"delegated_access_grant_id": "dag_lab_001",
				"tool_id":                   "tool_ticket_create_001",
				"tool_action_type":          "ticket:create",
				"human_approval_event_id":   "hae_lab_001",
				"data_classification":       "confidential",
			},
			Action:                model.PolicyAction{Decision: "allow"},
			RequiredTokenBinding:  true,
			RequiredHumanApproval: true,
			Status:                "active",
		},
	})
	logDir := t.TempDir()
	writer, err := logs.NewWriter(logDir)
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	handler := newServerWithConfig(serverConfig{
		Evaluator: evaluator,
		Writer:    writer,
		Registry:  connector.NewRegistry(),
	})
	decisionBody := `{
		"tenant_id":"tenant_lab_001",
		"user_id":"user_lab_001",
		"subject_user_id":"user_lab_001",
		"actor_type":"human",
		"actor_nhi_id":"nhi_soc_agent_001",
		"delegated_access_grant_id":"dag_lab_001",
		"agent_task_session_id":"ats_lab_001",
		"tool_id":"tool_ticket_create_001",
		"tool_action_type":"ticket:create",
		"tool_permission_profile":"write_ticket_only",
		"tool_version":"0.1.0",
		"tool_signature_state":"signed",
		"mcp_server_id":"mcp_soc_lab_001",
		"mcp_resource_uri":"https://mcp.local/soc",
		"mcp_audience":"https://mcp.local/soc",
		"mcp_token_passthrough_policy":"blocked",
		"runtime_environment_id":"runtime_managed_cloud_lab_001",
		"context_boundary_id":"ctx_incident_lab_001",
		"data_classification":"confidential",
		"device_id":"dev_lab_001",
		"application_id":"app_dummy_https",
		"source_ip":"127.0.0.1",
		"destination":"mcp.local:443",
		"destination_port":443,
		"protocol":"tcp",
		"service_family":"https",
		"token_binding_state":"bound",
		"human_approval_event_id":"hae_lab_001"
	}`

	req := httptest.NewRequest(http.MethodPost, "/decisions/evaluate", strings.NewReader(decisionBody))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("initial decision status = %d, body=%s", rec.Code, rec.Body.String())
	}
	var dec model.AccessDecision
	if err := json.NewDecoder(rec.Body).Decode(&dec); err != nil {
		t.Fatalf("decode initial decision: %v", err)
	}
	if dec.Decision != "deny" || !stringSliceContains(dec.ReasonCodes, "delegated_grant_absent") {
		t.Fatalf("initial decision = %#v, want delegated grant absent deny", dec)
	}

	approvalBody := `{
		"id":"hae_lab_001",
		"tenant_id":"tenant_lab_001",
		"approval_source":"admin_console",
		"approver_user_id":"approver_lab_001",
		"subject_user_id":"user_lab_001",
		"actor_nhi_id":"nhi_soc_agent_001",
		"delegated_access_grant_id":"dag_lab_001",
		"application_id":"app_dummy_https",
		"action_type":"ticket:create",
		"approval_result":"approved",
		"metadata":{"approval_ttl_seconds":120}
	}`
	approvalReq := httptest.NewRequest(http.MethodPost, "/human-approvals/events", strings.NewReader(approvalBody))
	approvalRec := httptest.NewRecorder()
	handler.ServeHTTP(approvalRec, approvalReq)
	if approvalRec.Code != http.StatusAccepted {
		t.Fatalf("approval status = %d, body=%s", approvalRec.Code, approvalRec.Body.String())
	}

	grantBody := `{
		"id":"dag_lab_001",
		"tenant_id":"tenant_lab_001",
		"subject_user_id":"user_lab_001",
		"actor_nhi_id":"nhi_soc_agent_001",
		"device_id":"dev_lab_001",
		"application_id":"app_dummy_https",
		"scopes":["incident:read","ticket:create"],
		"tool_ids":["tool_ticket_create_001"],
		"approval_event_id":"hae_lab_001",
		"token_binding_required":true,
		"max_session_duration":120,
		"metadata":{"grant_type":"human_delegated_agent_task"}
	}`
	grantReq := httptest.NewRequest(http.MethodPost, "/delegated-grants", strings.NewReader(grantBody))
	grantRec := httptest.NewRecorder()
	handler.ServeHTTP(grantRec, grantReq)
	if grantRec.Code != http.StatusAccepted {
		t.Fatalf("grant status = %d, body=%s", grantRec.Code, grantRec.Body.String())
	}

	req = httptest.NewRequest(http.MethodPost, "/decisions/evaluate", strings.NewReader(decisionBody))
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("active decision status = %d, body=%s", rec.Code, rec.Body.String())
	}
	if err := json.NewDecoder(rec.Body).Decode(&dec); err != nil {
		t.Fatalf("decode active decision: %v", err)
	}
	if dec.Decision != "allow" || dec.ActorType != "delegated_agent" || dec.Metadata["runtime_evidence_result"] != "valid" {
		t.Fatalf("active decision = %#v, want allow with valid runtime evidence", dec)
	}

	revokeReq := httptest.NewRequest(http.MethodPost, "/delegated-grants/dag_lab_001/revoke", strings.NewReader(`{"revocation_reason":"test"}`))
	revokeRec := httptest.NewRecorder()
	handler.ServeHTTP(revokeRec, revokeReq)
	if revokeRec.Code != http.StatusOK {
		t.Fatalf("revoke status = %d, body=%s", revokeRec.Code, revokeRec.Body.String())
	}

	req = httptest.NewRequest(http.MethodPost, "/decisions/evaluate", strings.NewReader(decisionBody))
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("revoked decision status = %d, body=%s", rec.Code, rec.Body.String())
	}
	if err := json.NewDecoder(rec.Body).Decode(&dec); err != nil {
		t.Fatalf("decode revoked decision: %v", err)
	}
	if dec.Decision != "deny" || !stringSliceContains(dec.ReasonCodes, "delegated_grant_revoked") {
		t.Fatalf("revoked decision = %#v, want revoked delegated grant deny", dec)
	}
}

func TestNHIDecisionWritesSeparatedAccessTraceAndAuditMetadata(t *testing.T) {
	evaluator := testEvaluatorWithPolicies([]model.Policy{
		{
			ID:       "pol_lab_nhi_tool_allow_001",
			TenantID: "tenant_lab_001",
			Priority: 80,
			Conditions: map[string]any{
				"actor_type":                "delegated_agent",
				"actor_nhi_id":              "nhi_soc_agent_001",
				"delegated_access_grant_id": "dag_lab_001",
				"tool_id":                   "tool_ticket_create_001",
				"tool_action_type":          "ticket:create",
				"human_approval_event_id":   "hae_lab_001",
			},
			Action:                model.PolicyAction{Decision: "allow"},
			RequiredHumanApproval: true,
			Status:                "active",
		},
	})
	logDir := t.TempDir()
	writer, err := logs.NewWriter(logDir)
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	now := time.Now().UTC()
	expiresAt := now.Add(time.Hour).Format(time.RFC3339)
	humanApprovals := newHumanApprovalEventStore()
	if _, err := humanApprovals.Upsert(model.HumanApprovalEvent{
		ID:                     "hae_lab_001",
		TenantID:               "tenant_lab_001",
		ApprovalSource:         "admin_console",
		ApproverUserID:         stringPtr("approver_lab_001"),
		SubjectUserID:          stringPtr("user_lab_001"),
		ActorNHIID:             stringPtr("nhi_soc_agent_001"),
		DelegatedAccessGrantID: stringPtr("dag_lab_001"),
		ActionType:             stringPtr("ticket:create"),
		ApprovalResult:         "approved",
		ExpiresAt:              &expiresAt,
		CreatedAt:              now.Format(time.RFC3339),
		Metadata:               map[string]any{},
	}); err != nil {
		t.Fatalf("upsert human approval returned error: %v", err)
	}
	delegatedGrants := newDelegatedAccessGrantStore()
	if _, err := delegatedGrants.Upsert(model.DelegatedAccessGrant{
		ID:              "dag_lab_001",
		TenantID:        "tenant_lab_001",
		SubjectUserID:   "user_lab_001",
		ActorNHIID:      "nhi_soc_agent_001",
		ToolIDs:         []string{"tool_ticket_create_001"},
		ApprovalEventID: stringPtr("hae_lab_001"),
		ExpiresAt:       expiresAt,
		Status:          "active",
		Metadata:        map[string]any{},
	}); err != nil {
		t.Fatalf("upsert delegated grant returned error: %v", err)
	}
	handler := newServerWithConfig(serverConfig{
		Evaluator:       evaluator,
		Writer:          writer,
		Registry:        connector.NewRegistry(),
		HumanApprovals:  humanApprovals,
		DelegatedGrants: delegatedGrants,
	})
	body := `{
		"tenant_id":"tenant_lab_001",
		"user_id":"user_lab_001",
		"subject_user_id":"user_lab_001",
		"actor_type":"human",
		"actor_nhi_id":"nhi_soc_agent_001",
		"delegated_access_grant_id":"dag_lab_001",
		"agent_task_session_id":"ats_lab_001",
		"tool_id":"tool_ticket_create_001",
		"tool_action_type":"ticket:create",
		"tool_permission_profile":"write_ticket_only",
		"tool_version":"0.1.0",
		"tool_signature_state":"signed",
		"mcp_server_id":"mcp_soc_lab_001",
		"mcp_resource_uri":"https://mcp.local/soc",
		"mcp_audience":"https://mcp.local/soc",
		"mcp_token_passthrough_policy":"blocked",
		"runtime_environment_id":"runtime_managed_cloud_lab_001",
		"context_boundary_id":"ctx_incident_lab_001",
		"data_classification":"confidential",
		"application_id":"app_dummy_https",
		"service_family":"https",
		"human_approval_event_id":"hae_lab_001"
	}`
	req := httptest.NewRequest(http.MethodPost, "/decisions/evaluate", strings.NewReader(body))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	var dec model.AccessDecision
	if err := json.NewDecoder(rec.Body).Decode(&dec); err != nil {
		t.Fatalf("decode decision: %v", err)
	}
	if dec.Decision != "allow" || dec.ActorType != "delegated_agent" || dec.UserID == nil || *dec.UserID != "user_lab_001" || dec.SubjectUserID == nil || *dec.SubjectUserID != "user_lab_001" || dec.ActorNHIID == nil || *dec.ActorNHIID != "nhi_soc_agent_001" {
		t.Fatalf("decision identity split = %#v", dec)
	}
	accessRows, err := writer.ReadJSONL("access.log.jsonl")
	if err != nil {
		t.Fatalf("read access log: %v", err)
	}
	if len(accessRows) != 1 || accessRows[0]["subject_user_id"] != "user_lab_001" || accessRows[0]["actor_type"] != "delegated_agent" || accessRows[0]["actor_nhi_id"] != "nhi_soc_agent_001" || accessRows[0]["delegated_access_grant_id"] != "dag_lab_001" || accessRows[0]["human_approval_event_id"] != "hae_lab_001" {
		t.Fatalf("access rows = %#v, want separated subject user and actor NHI", accessRows)
	}
	if accessRows[0]["tool_id"] != "tool_ticket_create_001" || accessRows[0]["tool_action_type"] != "ticket:create" || accessRows[0]["mcp_server_id"] != "mcp_soc_lab_001" || accessRows[0]["runtime_environment_id"] != "runtime_managed_cloud_lab_001" {
		t.Fatalf("access rows = %#v, want top-level tool/mcp evidence", accessRows)
	}
	traceRows, err := writer.ReadJSONL("access.log.jsonl")
	if err != nil {
		t.Fatalf("read access log: %v", err)
	}
	if len(traceRows) != 1 {
		t.Fatalf("access rows = %#v, want one delegated access record", traceRows)
	}
	traceMetadata, ok := traceRows[0]["metadata"].(map[string]any)
	if !ok || traceMetadata["subject_user_id"] != "user_lab_001" || traceMetadata["actor_nhi_id"] != "nhi_soc_agent_001" || traceMetadata["runtime_evidence_result"] != "valid" || traceMetadata["mcp_server_id"] != "mcp_soc_lab_001" || traceMetadata["tool_payload_recorded"] != false {
		t.Fatalf("trace rows = %#v, want delegated access metadata", traceRows)
	}
	auditRows, err := readAuditRowsExcludingWrapper(writer)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	if len(auditRows) != 1 || auditRows[0]["event_type"] != "nhi_delegated_access_decision_evaluated" || auditRows[0]["actor_user_id"] != nil || auditRows[0]["actor_nhi_id"] != "nhi_soc_agent_001" {
		t.Fatalf("audit rows = %#v, want NHI actor audit row without treating subject as actor_user", auditRows)
	}
	auditMetadata, ok := auditRows[0]["metadata"].(map[string]any)
	if !ok || auditMetadata["subject_user_id"] != "user_lab_001" || auditMetadata["delegated_access_grant_id"] != "dag_lab_001" || auditMetadata["human_approval_event_id"] != "hae_lab_001" || auditMetadata["runtime_evidence_result"] != "valid" || auditMetadata["mcp_server_id"] != "mcp_soc_lab_001" || auditMetadata["tool_payload_recorded"] != false || auditMetadata["tool_secret_recorded"] != false || auditMetadata["tool_credentials_recorded"] != false {
		t.Fatalf("audit metadata = %#v, want non-secret delegated access metadata", auditRows[0]["metadata"])
	}
}

func TestNHIDecisionRequiresRegisteredActiveNHIWhenRegistryPopulated(t *testing.T) {
	evaluator := testEvaluatorWithPolicies([]model.Policy{
		{
			ID:       "pol_lab_nhi_tool_allow_001",
			TenantID: "tenant_lab_001",
			Priority: 80,
			Conditions: map[string]any{
				"actor_type":                "delegated_agent",
				"actor_nhi_id":              "nhi_soc_agent_001",
				"delegated_access_grant_id": "dag_lab_001",
				"tool_id":                   "tool_ticket_create_001",
				"tool_action_type":          "ticket:create",
				"human_approval_event_id":   "hae_lab_001",
			},
			Action:                model.PolicyAction{Decision: "allow"},
			RequiredTokenBinding:  true,
			RequiredHumanApproval: true,
			Status:                "active",
		},
	})
	now := time.Now().UTC()
	activeExpiresAt := now.Add(time.Minute).Format(time.RFC3339)
	decisionBody := `{
		"tenant_id":"tenant_lab_001",
		"user_id":"user_lab_001",
		"subject_user_id":"user_lab_001",
		"actor_type":"human",
		"actor_nhi_id":"nhi_soc_agent_001",
		"delegated_access_grant_id":"dag_lab_001",
		"tool_id":"tool_ticket_create_001",
		"tool_action_type":"ticket:create",
		"application_id":"app_dummy_https",
		"service_family":"https",
		"token_binding_state":"bound",
		"human_approval_event_id":"hae_lab_001"
	}`

	newHandler := func(t *testing.T, registryItems ...model.NonHumanIdentity) http.Handler {
		t.Helper()
		writer, err := logs.NewWriter(t.TempDir())
		if err != nil {
			t.Fatalf("NewWriter returned error: %v", err)
		}
		humanApprovals := newHumanApprovalEventStore()
		if _, err := humanApprovals.Upsert(model.HumanApprovalEvent{
			ID:                     "hae_lab_001",
			TenantID:               "tenant_lab_001",
			ApprovalSource:         "admin_console",
			ApproverUserID:         stringPtr("approver_lab_001"),
			SubjectUserID:          stringPtr("user_lab_001"),
			ActorNHIID:             stringPtr("nhi_soc_agent_001"),
			DelegatedAccessGrantID: stringPtr("dag_lab_001"),
			ActionType:             stringPtr("ticket:create"),
			ApprovalResult:         "approved",
			ExpiresAt:              &activeExpiresAt,
			CreatedAt:              now.Format(time.RFC3339),
			Metadata:               map[string]any{},
		}); err != nil {
			t.Fatalf("upsert approval returned error: %v", err)
		}
		delegatedGrants := newDelegatedAccessGrantStore()
		if _, err := delegatedGrants.Upsert(model.DelegatedAccessGrant{
			ID:              "dag_lab_001",
			TenantID:        "tenant_lab_001",
			SubjectUserID:   "user_lab_001",
			ActorNHIID:      "nhi_soc_agent_001",
			ToolIDs:         []string{"tool_ticket_create_001"},
			ApprovalEventID: stringPtr("hae_lab_001"),
			ExpiresAt:       activeExpiresAt,
			Status:          "active",
			Metadata:        map[string]any{},
		}); err != nil {
			t.Fatalf("upsert grant returned error: %v", err)
		}
		nhiRegistry := nhi.NewStore()
		for _, item := range registryItems {
			if _, err := nhiRegistry.Upsert(context.Background(), item, "tenant_lab_001", now); err != nil {
				t.Fatalf("upsert NHI returned error: %v", err)
			}
		}
		return newServerWithConfig(serverConfig{
			Evaluator:          evaluator,
			Writer:             writer,
			Registry:           connector.NewRegistry(),
			HumanApprovals:     humanApprovals,
			DelegatedGrants:    delegatedGrants,
			NonHumanIdentities: nhiRegistry,
		})
	}

	absentHandler := newHandler(t, model.NonHumanIdentity{
		ID:          "nhi_other_001",
		Name:        "Other Agent",
		NHIType:     "ai_agent",
		OwnerUserID: "user_owner_001",
		Status:      "active",
	})
	req := httptest.NewRequest(http.MethodPost, "/decisions/evaluate", strings.NewReader(decisionBody))
	rec := httptest.NewRecorder()
	absentHandler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("absent status = %d, body=%s", rec.Code, rec.Body.String())
	}
	var dec model.AccessDecision
	if err := json.NewDecoder(rec.Body).Decode(&dec); err != nil {
		t.Fatalf("decode absent decision: %v", err)
	}
	if dec.Decision != "deny" || !stringSliceContains(dec.ReasonCodes, "nhi_registry_absent") || dec.Metadata["runtime_evidence_result"] != "nhi_registry_absent" {
		t.Fatalf("absent decision = %#v, want nhi_registry_absent deny", dec)
	}

	inactiveHandler := newHandler(t, model.NonHumanIdentity{
		ID:          "nhi_soc_agent_001",
		Name:        "Suspended Agent",
		NHIType:     "ai_agent",
		OwnerUserID: "user_owner_001",
		Status:      "suspended",
	})
	req = httptest.NewRequest(http.MethodPost, "/decisions/evaluate", strings.NewReader(decisionBody))
	rec = httptest.NewRecorder()
	inactiveHandler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("inactive status = %d, body=%s", rec.Code, rec.Body.String())
	}
	if err := json.NewDecoder(rec.Body).Decode(&dec); err != nil {
		t.Fatalf("decode inactive decision: %v", err)
	}
	if dec.Decision != "deny" || !stringSliceContains(dec.ReasonCodes, "nhi_inactive") || dec.Metadata["runtime_evidence_result"] != "nhi_inactive" {
		t.Fatalf("inactive decision = %#v, want nhi_inactive deny", dec)
	}

	wrongAppHandler := newHandler(t, model.NonHumanIdentity{
		ID:                    "nhi_soc_agent_001",
		Name:                  "Wrong App Agent",
		NHIType:               "ai_agent",
		OwnerUserID:           "user_owner_001",
		Status:                "active",
		AllowedApplicationIDs: []string{"app_other"},
	})
	req = httptest.NewRequest(http.MethodPost, "/decisions/evaluate", strings.NewReader(decisionBody))
	rec = httptest.NewRecorder()
	wrongAppHandler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("wrong app status = %d, body=%s", rec.Code, rec.Body.String())
	}
	if err := json.NewDecoder(rec.Body).Decode(&dec); err != nil {
		t.Fatalf("decode wrong app decision: %v", err)
	}
	if dec.Decision != "deny" || !stringSliceContains(dec.ReasonCodes, "nhi_application_not_allowed") || dec.Metadata["runtime_evidence_result"] != "nhi_application_not_allowed" {
		t.Fatalf("wrong app decision = %#v, want nhi_application_not_allowed deny", dec)
	}

	wrongScopeHandler := newHandler(t, model.NonHumanIdentity{
		ID:                    "nhi_soc_agent_001",
		Name:                  "Wrong Scope Agent",
		NHIType:               "ai_agent",
		OwnerUserID:           "user_owner_001",
		Status:                "active",
		AllowedApplicationIDs: []string{"app_dummy_https"},
		AllowedScopes:         []string{"incident:read"},
	})
	req = httptest.NewRequest(http.MethodPost, "/decisions/evaluate", strings.NewReader(decisionBody))
	rec = httptest.NewRecorder()
	wrongScopeHandler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("wrong scope status = %d, body=%s", rec.Code, rec.Body.String())
	}
	if err := json.NewDecoder(rec.Body).Decode(&dec); err != nil {
		t.Fatalf("decode wrong scope decision: %v", err)
	}
	if dec.Decision != "deny" || !stringSliceContains(dec.ReasonCodes, "nhi_scope_not_allowed") || dec.Metadata["runtime_evidence_result"] != "nhi_scope_not_allowed" {
		t.Fatalf("wrong scope decision = %#v, want nhi_scope_not_allowed deny", dec)
	}

	allowedHandler := newHandler(t, model.NonHumanIdentity{
		ID:                    "nhi_soc_agent_001",
		Name:                  "Allowed Agent",
		NHIType:               "ai_agent",
		OwnerUserID:           "user_owner_001",
		Status:                "active",
		AllowedApplicationIDs: []string{"app_dummy_https"},
		AllowedScopes:         []string{"ticket:create"},
	})
	req = httptest.NewRequest(http.MethodPost, "/decisions/evaluate", strings.NewReader(decisionBody))
	rec = httptest.NewRecorder()
	allowedHandler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("allowed status = %d, body=%s", rec.Code, rec.Body.String())
	}
	if err := json.NewDecoder(rec.Body).Decode(&dec); err != nil {
		t.Fatalf("decode allowed decision: %v", err)
	}
	if dec.Decision != "allow" || dec.Metadata["runtime_evidence_result"] != "valid" {
		t.Fatalf("allowed decision = %#v, want allow", dec)
	}
}

func TestRuntimeDecisionNHIEvidenceDenyDoesNotMarkLastUsed(t *testing.T) {
	evaluator := testEvaluatorWithPolicies([]model.Policy{
		{
			ID:       "pol_lab_direct_nhi_allow_001",
			TenantID: "tenant_lab_001",
			Priority: 90,
			Conditions: map[string]any{
				"actor_type":       "delegated_agent",
				"actor_nhi_id":     "nhi_limited_001",
				"application_id":   "app_blocked_001",
				"service_family":   "https",
				"tool_action_type": "ticket:create",
			},
			Action: model.PolicyAction{Decision: "allow"},
			Status: "active",
		},
	})
	now := time.Now().UTC()
	nhiRegistry := nhi.NewStore()
	if _, err := nhiRegistry.Upsert(context.Background(), model.NonHumanIdentity{
		ID:                    "nhi_limited_001",
		Name:                  "Limited NHI",
		NHIType:               "ai_agent",
		OwnerUserID:           "user_owner_001",
		Status:                "active",
		AllowedApplicationIDs: []string{"app_allowed_001"},
		AllowedScopes:         []string{"ticket:create"},
	}, "tenant_lab_001", now); err != nil {
		t.Fatalf("upsert NHI returned error: %v", err)
	}
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	handler := newServerWithConfig(serverConfig{
		Evaluator:          evaluator,
		Writer:             writer,
		Registry:           connector.NewRegistry(),
		NonHumanIdentities: nhiRegistry,
	})

	body := `{
		"tenant_id":"tenant_lab_001",
		"actor_nhi_id":"nhi_limited_001",
		"application_id":"app_blocked_001",
		"service_family":"https",
		"tool_action_type":"ticket:create"
	}`
	req := httptest.NewRequest(http.MethodPost, "/decisions/evaluate", strings.NewReader(body))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	var dec model.AccessDecision
	if err := json.NewDecoder(rec.Body).Decode(&dec); err != nil {
		t.Fatalf("decode decision: %v", err)
	}
	if dec.Decision != "deny" || !stringSliceContains(dec.ReasonCodes, "policy_matched") || !stringSliceContains(dec.ReasonCodes, "nhi_application_not_allowed") {
		t.Fatalf("decision = %#v, want runtime NHI application evidence deny", dec)
	}
	if dec.ActorType != "delegated_agent" || dec.ActorNHIID == nil || *dec.ActorNHIID != "nhi_limited_001" {
		t.Fatalf("decision actor = %#v/%#v, want delegated NHI actor", dec.ActorType, dec.ActorNHIID)
	}
	if dec.Metadata["runtime_evidence_result"] != "nhi_application_not_allowed" {
		t.Fatalf("decision metadata = %#v, want nhi_application_not_allowed evidence", dec.Metadata)
	}
	if _, ok := dec.Metadata["nhi_registry_last_used_result"]; ok {
		t.Fatalf("decision metadata = %#v, want no last_used marker on deny", dec.Metadata)
	}
	if _, ok := dec.Metadata["nhi_registry_last_used_at"]; ok {
		t.Fatalf("decision metadata = %#v, want no last_used timestamp on deny", dec.Metadata)
	}
	identities, err := nhiRegistry.List(context.Background(), "tenant_lab_001")
	if err != nil {
		t.Fatalf("list NHI registry: %v", err)
	}
	if len(identities) != 1 || identities[0].LastUsedAt != nil {
		t.Fatalf("NHI registry identities = %#v, want last_used_at unchanged on deny", identities)
	}
}

func TestRuntimeDecisionNHIEvidenceDenyWritesMetadataOnlyAccessTraceAudit(t *testing.T) {
	evaluator := testEvaluatorWithPolicies([]model.Policy{
		{
			ID:       "pol_lab_direct_nhi_allow_001",
			TenantID: "tenant_lab_001",
			Priority: 90,
			Conditions: map[string]any{
				"actor_type":                "delegated_agent",
				"actor_nhi_id":              "nhi_limited_001",
				"delegated_access_grant_id": "dag_lab_001",
				"application_id":            "app_blocked_001",
				"service_family":            "https",
				"tool_action_type":          "ticket:create",
			},
			Action: model.PolicyAction{Decision: "allow"},
			Status: "active",
		},
	})
	now := time.Now().UTC()
	nhiRegistry := nhi.NewStore()
	if _, err := nhiRegistry.Upsert(context.Background(), model.NonHumanIdentity{
		ID:                    "nhi_limited_001",
		Name:                  "Limited NHI",
		NHIType:               "ai_agent",
		OwnerUserID:           "user_owner_001",
		Status:                "active",
		AllowedApplicationIDs: []string{"app_allowed_001"},
		AllowedScopes:         []string{"ticket:create"},
	}, "tenant_lab_001", now); err != nil {
		t.Fatalf("upsert NHI returned error: %v", err)
	}
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	handler := newServerWithConfig(serverConfig{
		Evaluator:          evaluator,
		Writer:             writer,
		Registry:           connector.NewRegistry(),
		NonHumanIdentities: nhiRegistry,
	})

	body := `{
		"tenant_id":"tenant_lab_001",
		"user_id":"user_lab_001",
		"subject_user_id":"user_lab_001",
		"actor_nhi_id":"nhi_limited_001",
		"delegated_access_grant_id":"dag_lab_001",
		"agent_task_session_id":"ats_lab_001",
		"tool_id":"tool_ticket_create_001",
		"tool_action_type":"ticket:create",
		"tool_permission_profile":"write_ticket_only",
		"tool_version":"0.1.0",
		"tool_signature_state":"signed",
		"mcp_server_id":"mcp_soc_lab_001",
		"mcp_resource_uri":"https://mcp.local/soc",
		"mcp_audience":"https://mcp.local/soc",
		"mcp_token_passthrough_policy":"blocked",
		"runtime_environment_id":"runtime_managed_cloud_lab_001",
		"context_boundary_id":"ctx_incident_lab_001",
		"data_classification":"confidential",
		"application_id":"app_blocked_001",
		"service_family":"https"
	}`
	req := httptest.NewRequest(http.MethodPost, "/decisions/evaluate", strings.NewReader(body))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	var dec model.AccessDecision
	if err := json.NewDecoder(rec.Body).Decode(&dec); err != nil {
		t.Fatalf("decode decision: %v", err)
	}
	if dec.Decision != "deny" || !stringSliceContains(dec.ReasonCodes, "nhi_application_not_allowed") {
		t.Fatalf("decision = %#v, want NHI evidence deny", dec)
	}

	accessRows, err := writer.ReadJSONL("access.log.jsonl")
	if err != nil {
		t.Fatalf("read access log: %v", err)
	}
	if len(accessRows) != 1 || accessRows[0]["decision"] != "deny" || accessRows[0]["actor_type"] != "delegated_agent" || accessRows[0]["actor_nhi_id"] != "nhi_limited_001" || accessRows[0]["subject_user_id"] != "user_lab_001" {
		t.Fatalf("access rows = %#v, want separated delegated NHI deny", accessRows)
	}
	accessMetadata, ok := accessRows[0]["metadata"].(map[string]any)
	if !ok || accessMetadata["runtime_evidence_result"] != "nhi_application_not_allowed" || accessMetadata["tool_payload_recorded"] != false || accessMetadata["tool_secret_recorded"] != false || accessMetadata["tool_credentials_recorded"] != false {
		t.Fatalf("access metadata = %#v, want metadata-only NHI evidence deny", accessRows[0]["metadata"])
	}
	if _, ok := accessMetadata["nhi_registry_last_used_result"]; ok {
		t.Fatalf("access metadata = %#v, want no last_used result on deny", accessMetadata)
	}
	if _, ok := accessMetadata["nhi_registry_last_used_at"]; ok {
		t.Fatalf("access metadata = %#v, want no last_used timestamp on deny", accessMetadata)
	}

	traceRows, err := writer.ReadJSONL("access.log.jsonl")
	if err != nil {
		t.Fatalf("read access log: %v", err)
	}
	if len(traceRows) != 1 {
		t.Fatalf("access rows = %#v, want one record", traceRows)
	}
	traceMetadata, ok := traceRows[0]["metadata"].(map[string]any)
	if !ok || traceMetadata["runtime_evidence_result"] != "nhi_application_not_allowed" || traceMetadata["actor_nhi_id"] != "nhi_limited_001" || traceMetadata["subject_user_id"] != "user_lab_001" {
		t.Fatalf("trace metadata = %#v, want NHI evidence deny metadata", traceRows[0]["metadata"])
	}
	if _, ok := traceMetadata["nhi_registry_last_used_result"]; ok {
		t.Fatalf("trace metadata = %#v, want no last_used result on deny", traceMetadata)
	}
	if _, ok := traceMetadata["nhi_registry_last_used_at"]; ok {
		t.Fatalf("trace metadata = %#v, want no last_used timestamp on deny", traceMetadata)
	}

	auditRows, err := readAuditRowsExcludingWrapper(writer)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	if len(auditRows) != 1 || auditRows[0]["event_type"] != "nhi_delegated_access_decision_evaluated" || auditRows[0]["result"] != "deny" || auditRows[0]["actor_user_id"] != nil || auditRows[0]["actor_nhi_id"] != "nhi_limited_001" {
		t.Fatalf("audit rows = %#v, want NHI actor deny audit row", auditRows)
	}
	auditMetadata, ok := auditRows[0]["metadata"].(map[string]any)
	if !ok || auditMetadata["runtime_evidence_result"] != "nhi_application_not_allowed" || auditMetadata["subject_user_id"] != "user_lab_001" || auditMetadata["tool_payload_recorded"] != false || auditMetadata["tool_secret_recorded"] != false || auditMetadata["tool_credentials_recorded"] != false {
		t.Fatalf("audit metadata = %#v, want metadata-only NHI evidence deny", auditRows[0]["metadata"])
	}
	if _, ok := auditMetadata["nhi_registry_last_used_result"]; ok {
		t.Fatalf("audit metadata = %#v, want no last_used result on deny", auditMetadata)
	}
	if _, ok := auditMetadata["nhi_registry_last_used_at"]; ok {
		t.Fatalf("audit metadata = %#v, want no last_used timestamp on deny", auditMetadata)
	}
}

func TestToolCallEventWriter(t *testing.T) {
	logDir := t.TempDir()
	writer, err := logs.NewWriter(logDir)
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	now := time.Now().UTC()
	activeExpiresAt := now.Add(time.Minute).Format(time.RFC3339)
	humanApprovals := newHumanApprovalEventStore()
	if _, err := humanApprovals.Upsert(model.HumanApprovalEvent{
		ID:                     "hae_lab_001",
		TenantID:               "tenant_lab_001",
		ApprovalSource:         "admin_console",
		ApproverUserID:         stringPtr("approver_lab_001"),
		ActorNHIID:             stringPtr("nhi_soc_agent_001"),
		DelegatedAccessGrantID: stringPtr("dag_lab_001"),
		ActionType:             stringPtr("ticket:create"),
		ApprovalResult:         "approved",
		ExpiresAt:              &activeExpiresAt,
		CreatedAt:              now.Format(time.RFC3339),
		Metadata:               map[string]any{},
	}); err != nil {
		t.Fatalf("upsert human approval returned error: %v", err)
	}
	delegatedGrants := newDelegatedAccessGrantStore()
	if _, err := delegatedGrants.Upsert(model.DelegatedAccessGrant{
		ID:              "dag_lab_001",
		TenantID:        "tenant_lab_001",
		SubjectUserID:   "user_lab_001",
		ActorNHIID:      "nhi_soc_agent_001",
		ToolIDs:         []string{"tool_ticket_create_001"},
		ApprovalEventID: stringPtr("hae_lab_001"),
		ExpiresAt:       activeExpiresAt,
		Status:          "active",
		Metadata:        map[string]any{},
	}); err != nil {
		t.Fatalf("upsert delegated grant returned error: %v", err)
	}
	decisionStore := newAccessDecisionStore()
	decisionStore.Upsert(model.AccessDecision{
		ID:                     "dec_nhi_tool_lab_001",
		TenantID:               "tenant_lab_001",
		ActorType:              "delegated_agent",
		ActorNHIID:             stringPtr("nhi_soc_agent_001"),
		DelegatedAccessGrantID: stringPtr("dag_lab_001"),
		ToolID:                 stringPtr("tool_ticket_create_001"),
		ToolActionType:         stringPtr("ticket:create"),
		HumanApprovalEventID:   stringPtr("hae_lab_001"),
		ApplicationID:          "app_dummy_https",
		PolicyID:               "pol_lab_nhi_tool_allow_001",
		PolicyBundleID:         "pb_lab_20260522_001",
		PolicyBundleVersion:    "2026.05.22.001",
		Decision:               "allow",
		ReasonCodes:            []string{"policy_matched", "delegated_grant_valid", "approval_valid", "tool_allowed"},
		Actions:                []model.DecisionAction{},
		CacheStatus:            "miss",
		TTLSeconds:             60,
		Timestamp:              now.Format(time.RFC3339),
		Metadata:               map[string]any{},
	})
	inspectionEvents := newInspectionEventStore()
	inspectionEvents.Upsert(model.InspectionEvent{
		ID:               "ie_lab_001",
		TenantID:         "tenant_lab_001",
		AccessDecisionID: stringPtr("dec_nhi_tool_lab_001"),
		ApplicationID:    stringPtr("app_dummy_https"),
		PayloadStored:    false,
		Masked:           true,
		RetentionPolicy:  stringPtr("metadata_30d"),
		Timestamp:        now.Format(time.RFC3339),
		Metadata:         map[string]any{},
	})
	domainOutbox := &recordingDomainEventOutbox{}
	handler := newServerWithConfig(serverConfig{
		Evaluator:         testEvaluator(),
		Writer:            writer,
		Registry:          connector.NewRegistry(),
		HumanApprovals:    humanApprovals,
		DelegatedGrants:   delegatedGrants,
		DecisionStore:     decisionStore,
		InspectionEvents:  inspectionEvents,
		DomainEventOutbox: domainOutbox,
	})
	body := `{
		"id":"tce_lab_001",
		"tenant_id":"tenant_lab_001",
		"agent_task_session_id":"ats_lab_001",
		"actor_nhi_id":"nhi_soc_agent_001",
		"subject_user_id":"user_lab_001",
		"delegated_access_grant_id":"dag_lab_001",
		"tool_id":"tool_ticket_create_001",
		"mcp_server_id":"mcp_soc_lab_001",
		"action_type":"ticket:create",
		"application_id":"app_dummy_https",
		"human_approval_event_id":"hae_lab_001",
		"access_decision_id":"dec_nhi_tool_lab_001",
		"inspection_event_id":"ie_lab_001",
		"policy_id":"pol_lab_nhi_tool_allow_001",
		"decision":"allow",
		"result_summary":"ticket_created",
		"result_summary_scope":"metadata_only",
		"masked":true,
		"retention_policy":"metadata_30d",
		"timestamp":"2026-05-22T00:01:00Z",
		"status":"success",
		"metadata":{"ticket_id":"TICKET-20260522-001"}
	}`
	req := httptest.NewRequest(http.MethodPost, "/tools/events", strings.NewReader(body))
	req.RemoteAddr = "192.0.2.10:53000"
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusAccepted, rec.Body.String())
	}
	rows, err := writer.ReadJSONL("tool_call_events.log.jsonl")
	if err != nil {
		t.Fatalf("read tool call log: %v", err)
	}
	if len(rows) != 1 || rows[0]["id"] != "tce_lab_001" || rows[0]["actor_nhi_id"] != "nhi_soc_agent_001" {
		t.Fatalf("tool call rows = %#v", rows)
	}
	domainEvents := domainOutbox.insertedEvents()
	if len(domainEvents) != 1 || domainEvents[0].Stream != "tool_call_events" || domainEvents[0].Metadata["dedup_key"] != "tenant_lab_001:tool_call_events:tce_lab_001" {
		t.Fatalf("domain events = %#v", domainEvents)
	}
	auditRows, err := readAuditRowsExcludingWrapper(writer)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	if len(auditRows) != 1 {
		t.Fatalf("audit row count = %d, want 1", len(auditRows))
	}
	if auditRows[0]["event_type"] != "tool_call_event_recorded" {
		t.Fatalf("audit row = %#v", auditRows[0])
	}
	if auditRows[0]["source_ip"] != nil || auditRows[0]["actor_nhi_id"] != nil {
		t.Fatalf("tool call audit included raw source/actor fields: %#v", auditRows[0])
	}
	metadata, ok := auditRows[0]["metadata"].(map[string]any)
	if !ok {
		t.Fatalf("audit metadata = %#v", auditRows[0]["metadata"])
	}
	if metadata["tool_call_metadata_recorded_scope"] != "none" || metadata["result_summary_scope"] != "metadata_only" || metadata["masked"] != true || metadata["inspection_event_id_present"] != true {
		t.Fatalf("audit metadata = %#v, want metadata-only masked event", metadata)
	}
	if metadata["tool_id_present"] != true || metadata["tool_action_type_present"] != true || metadata["agent_tool_metadata_scope"] != "none" || metadata["mcp_server_id_present"] != true || metadata["mcp_metadata_scope"] != "none" {
		t.Fatalf("audit metadata = %#v, want agent tool and MCP metadata", metadata)
	}
	if metadata["tool_payload_recorded"] != false || metadata["tool_secret_recorded"] != false || metadata["tool_credentials_recorded"] != false {
		t.Fatalf("audit metadata = %#v, want no payload/secret/credential recording", metadata)
	}
	if encoded, err := json.Marshal(auditRows[0]); err != nil {
		t.Fatalf("marshal tool call audit row: %v", err)
	} else {
		for _, leaked := range []string{"nhi_soc_agent_001", "user_lab_001", "ats_lab_001", "mcp_soc_lab_001", "ie_lab_001", "ticket_created", "TICKET-20260522-001"} {
			if strings.Contains(string(encoded), leaked) {
				t.Fatalf("tool call audit leaked %q: %s", leaked, string(encoded))
			}
		}
	}
}

func TestToolCallEventRejectsPayloadOrSecretMetadata(t *testing.T) {
	handler := newTestHandler(t)
	body := `{
		"id":"tce_secret_metadata_001",
		"tenant_id":"tenant_lab_001",
		"actor_nhi_id":"nhi_soc_agent_001",
		"tool_id":"tool_ticket_create_001",
		"action_type":"ticket:create",
		"timestamp":"2026-05-22T00:01:00Z",
		"metadata":{"api_token":"redacted"}
	}`
	req := httptest.NewRequest(http.MethodPost, "/tools/events", strings.NewReader(body))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

func TestToolCallEventRejectsMissingInspectionEvent(t *testing.T) {
	handler := newTestHandler(t)
	body := `{
		"id":"tce_missing_inspection_001",
		"tenant_id":"tenant_lab_001",
		"actor_nhi_id":"nhi_soc_agent_001",
		"tool_id":"tool_ticket_create_001",
		"action_type":"ticket:create",
		"inspection_event_id":"ie_absent_001",
		"timestamp":"2026-05-22T00:01:00Z",
		"metadata":{}
	}`
	req := httptest.NewRequest(http.MethodPost, "/tools/events", strings.NewReader(body))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusNotFound, rec.Body.String())
	}
}

func TestToolCallEventRejectsMissingAccessDecision(t *testing.T) {
	handler := newTestHandler(t)
	body := `{
		"id":"tce_missing_decision_001",
		"tenant_id":"tenant_lab_001",
		"actor_nhi_id":"nhi_soc_agent_001",
		"tool_id":"tool_ticket_create_001",
		"action_type":"ticket:create",
		"access_decision_id":"dec_absent_001",
		"timestamp":"2026-05-22T00:01:00Z",
		"metadata":{}
	}`
	req := httptest.NewRequest(http.MethodPost, "/tools/events", strings.NewReader(body))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusNotFound, rec.Body.String())
	}
}

func TestToolCallEventRejectsTenantMismatch(t *testing.T) {
	handler := newTestHandler(t)
	body := `{
		"id":"tce_other_001",
		"tenant_id":"tenant_other",
		"actor_nhi_id":"nhi_soc_agent_001",
		"tool_id":"tool_ticket_create_001",
		"action_type":"ticket:create",
		"timestamp":"2026-05-22T00:01:00Z",
		"metadata":{}
	}`
	req := httptest.NewRequest(http.MethodPost, "/tools/events", strings.NewReader(body))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusForbidden, rec.Body.String())
	}
}

func TestLoadEdgeTrustedKeyringRejectsTenantMismatch(t *testing.T) {
	path := filepath.Join(t.TempDir(), "trusted_keys.json")
	data := []byte(`{
		"tenant_id":"tenant_other",
		"version":"2026.05.22.001",
		"keys":[{"id":"pbsign_lab_001","public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","status":"active"}]
	}`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}

	_, err := loadEdgeTrustedKeyring(path, "tenant_lab_001")
	if err == nil {
		t.Fatal("loadEdgeTrustedKeyring returned nil, want tenant mismatch error")
	}
	if !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("error = %q", err.Error())
	}
}

func TestLabBypassRequiresExplicitLabMode(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	handler := newServerWithConfig(serverConfig{
		Evaluator: testEvaluator(),
		Writer:    writer,
		LabMode:   boolPtr(false),
	})

	req := httptest.NewRequest(http.MethodGet, "/admin/state", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusUnauthorized, rec.Body.String())
	}

	labHandler := newServerWithConfig(serverConfig{
		Evaluator: testEvaluator(),
		Writer:    writer,
		LabMode:   boolPtr(true),
	})
	req = httptest.NewRequest(http.MethodGet, "/admin/state", nil)
	rec = httptest.NewRecorder()
	labHandler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("lab status = %d, want %d, body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
}

func TestRuntimeDecisionEndpointRequiresConnectorSecretWhenLabModeDisabled(t *testing.T) {
	relaxConnectorMTLSPresentationForTest(t)
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	handler := newServerWithConfig(serverConfig{
		Evaluator: testEvaluator(),
		Writer:    writer,
		LabMode:   boolPtr(false),
	})
	body := `{"tenant_id":"tenant_lab_001","user_id":"user_lab_001","application_id":"app_dummy_https","service_family":"https"}`

	req := httptest.NewRequest(http.MethodPost, "/decisions/evaluate", strings.NewReader(body))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusUnauthorized, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodPost, "/decisions/evaluate", strings.NewReader(body))
	req.Header.Set(connectorSecretHeader, defaultConnectorSecret)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("authorized status = %d, want %d, body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
}

func TestRuntimeJSONEndpointsRejectOversizedBody(t *testing.T) {
	relaxConnectorMTLSPresentationForTest(t)
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	handler := newServerWithConfig(serverConfig{
		Evaluator:       testEvaluator(),
		Writer:          writer,
		Registry:        connector.NewRegistry(),
		ConnectorSecret: defaultConnectorSecret,
		LabMode:         boolPtr(false),
	})
	oversized := `{"tenant_id":"tenant_lab_001","user_id":"user_lab_001","application_id":"app_dummy_https","service_family":"https","padding":"` + strings.Repeat("x", maxEdgeRuntimeJSONBodyBytes) + `"}`
	req := httptest.NewRequest(http.MethodPost, "/decisions/evaluate", strings.NewReader(oversized))
	req.Header.Set(connectorSecretHeader, defaultConnectorSecret)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "request body too large") {
		t.Fatalf("oversized decision status=%d body=%s, want bad request size error", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodPost, "/logs/access", strings.NewReader(oversized))
	req.Header.Set(connectorSecretHeader, defaultConnectorSecret)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "request body too large") {
		t.Fatalf("oversized access log status=%d body=%s, want bad request size error", rec.Code, rec.Body.String())
	}
}

func TestAdminJSONEndpointsRejectOversizedBody(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	handler := newServerWithConfig(serverConfig{
		Evaluator: testEvaluator(),
		Writer:    writer,
	})
	oversized := `{"tenant_id":"tenant_lab_001","reason":"` + strings.Repeat("x", maxEdgeRuntimeJSONBodyBytes) + `"}`
	req := httptest.NewRequest(http.MethodPost, "/break-glass/requests", strings.NewReader(oversized))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "request body too large") {
		t.Fatalf("oversized break-glass status=%d body=%s, want bad request size error", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodPost, "/admin/export-jobs", strings.NewReader(oversized))
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "request body too large") {
		t.Fatalf("oversized export job status=%d body=%s, want bad request size error", rec.Code, rec.Body.String())
	}
}

func TestRuntimeDecisionEndpointDoesNotFallbackWhenConnectorRegistryLookupFails(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	handler := newServerWithConfig(serverConfig{
		Evaluator:       testEvaluator(),
		Writer:          writer,
		Registry:        postgresConnectorRegistryStore{},
		ConnectorSecret: "bootstrap-secret",
		LabMode:         boolPtr(false),
	})
	body := `{"tenant_id":"tenant_lab_001","user_id":"user_lab_001","application_id":"app_dummy_https","service_family":"https"}`
	req := httptest.NewRequest(http.MethodPost, "/decisions/evaluate", strings.NewReader(body))
	req.Header.Set(connectorIDHeader, "conn_runtime_001")
	req.Header.Set(connectorSecretHeader, "bootstrap-secret")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("registry failure decision status = %d, want %d, body=%s", rec.Code, http.StatusInternalServerError, rec.Body.String())
	}
}

func TestEdgeRuntimeSecretConfigRejectsLabDefaultOutsideLabMode(t *testing.T) {
	for name, tc := range map[string]struct {
		devMode         bool
		connectorSecret string
		wantErr         bool
	}{
		"lab mode allows default":       {devMode: true, connectorSecret: defaultConnectorSecret},
		"lab mode allows short":         {devMode: true, connectorSecret: "short"},
		"non lab rejects empty":         {connectorSecret: "", wantErr: true},
		"non lab rejects local default": {connectorSecret: defaultConnectorSecret, wantErr: true},
		"non lab rejects too short":     {connectorSecret: "tenant-specific-secret", wantErr: true}, // 22 chars < 32
		"non lab accepts long explicit": {connectorSecret: "tenant-specific-secret-long-enough-1234567"},
	} {
		t.Run(name, func(t *testing.T) {
			err := validateEdgeRuntimeSecretConfig(tc.devMode, tc.connectorSecret)
			if tc.wantErr && err == nil {
				t.Fatalf("validateEdgeRuntimeSecretConfig returned nil, want error")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("validateEdgeRuntimeSecretConfig returned error: %v", err)
			}
		})
	}
}

func TestLoadEdgeSWGRuntimeConfigInitializesOperatorManagedTenantRestrictionResolver(t *testing.T) {
	harnessConfig, err := swghttprewrite.LoadHarnessConfig(filepath.Join("..", "..", "swghttprewrite", "testdata", "swg_saas_tenant_enforcement_preflight.json"))
	if err != nil {
		t.Fatalf("load harness config: %v", err)
	}
	runtimeConfig, err := swg.LoadRuntimeConfig(swg.RuntimeConfigInput{
		TenantRestrictionOperatorConfigPath: filepath.Join("..", "..", "swghttprewrite", "testdata", "swg_tenant_restriction_operator_config.json"),
		PolicyBundle:                        harnessConfig.PolicyBundle,
	})
	if err != nil {
		t.Fatalf("load SWG runtime config: %v", err)
	}

	wantRefs := []string{
		"operator_config_ref:google_workspace_allowed_domains",
		"operator_config_ref:microsoft_365_allowed_tenants",
	}
	if !runtimeConfig.TenantRestrictionResolverConfigured ||
		runtimeConfig.TenantRestrictionOperatorConfigPath == "" ||
		!reflect.DeepEqual(runtimeConfig.TenantRestrictionOperatorConfigRefs, wantRefs) {
		t.Fatalf("runtime SWG resolver configured=%v path_present=%v refs=%v, want refs %v", runtimeConfig.TenantRestrictionResolverConfigured, runtimeConfig.TenantRestrictionOperatorConfigPath != "", runtimeConfig.TenantRestrictionOperatorConfigRefs, wantRefs)
	}
	for _, ref := range wantRefs {
		value, ok := runtimeConfig.TenantRestrictionResolver.ResolveHeaderValue(ref)
		if !ok || strings.TrimSpace(value) == "" {
			t.Fatalf("runtime SWG resolver did not resolve %s", ref)
		}
	}
	for field, value := range map[string]bool{
		"tenant_restriction_header_value_logged":      runtimeConfig.TenantRestrictionHeaderValueLogged,
		"tenant_restriction_header_value_in_decision": runtimeConfig.TenantRestrictionHeaderValueInDecision,
		"runtime_tls_decryption_observed":             runtimeConfig.RuntimeTLSDecryptionObserved,
		"runtime_header_injection_observed":           runtimeConfig.RuntimeHeaderInjectionObserved,
		"mac_ca_trust_observed":                       runtimeConfig.MacCATrustObserved,
		"network_extension_runtime_used":              runtimeConfig.NetworkExtensionRuntimeUsed,
		"productization_claims_made":                  runtimeConfig.ProductizationClaimsMade,
		"new_product_claims_made":                     runtimeConfig.NewProductClaimsMade,
	} {
		if value {
			t.Fatalf("%s = true, want false", field)
		}
	}
}

func TestLoadEdgeSWGRuntimeConfigRequiresOperatorConfigWhenTenantRestrictionRulesAreActive(t *testing.T) {
	harnessConfig, err := swghttprewrite.LoadHarnessConfig(filepath.Join("..", "..", "swghttprewrite", "testdata", "swg_saas_tenant_enforcement_preflight.json"))
	if err != nil {
		t.Fatalf("load harness config: %v", err)
	}
	_, err = swg.LoadRuntimeConfig(swg.RuntimeConfigInput{
		PolicyBundle: harnessConfig.PolicyBundle,
	})
	if err == nil || !strings.Contains(err.Error(), "operator config is required") {
		t.Fatalf("swg.LoadRuntimeConfig error = %v, want required operator config", err)
	}
}

func TestLoadEdgeSWGRuntimeConfigAllowsNoOperatorConfigWithoutSWGRules(t *testing.T) {
	runtimeConfig, err := swg.LoadRuntimeConfig(swg.RuntimeConfigInput{
		PolicyBundle: testEvaluator().PolicyBundle,
	})
	if err != nil {
		t.Fatalf("swg.LoadRuntimeConfig returned error: %v", err)
	}
	if runtimeConfig.TenantRestrictionResolverConfigured ||
		runtimeConfig.TenantRestrictionOperatorConfigPath != "" ||
		len(runtimeConfig.TenantRestrictionOperatorConfigRefs) != 0 {
		t.Fatalf("runtime SWG resolver configured=%v path_present=%v refs=%d, want disabled", runtimeConfig.TenantRestrictionResolverConfigured, runtimeConfig.TenantRestrictionOperatorConfigPath != "", len(runtimeConfig.TenantRestrictionOperatorConfigRefs))
	}
}

func TestSWGEdgeSWGHTTPEgressUsesRuntimeRewriteResolver(t *testing.T) {
	harnessConfig, err := swghttprewrite.LoadHarnessConfig(filepath.Join("..", "..", "swghttprewrite", "testdata", "swg_saas_tenant_enforcement_preflight.json"))
	if err != nil {
		t.Fatalf("load harness config: %v", err)
	}
	runtimeConfig, err := swg.LoadRuntimeConfig(swg.RuntimeConfigInput{
		TenantRestrictionOperatorConfigPath: filepath.Join("..", "..", "swghttprewrite", "testdata", "swg_tenant_restriction_operator_config.json"),
		PolicyBundle:                        harnessConfig.PolicyBundle,
	})
	if err != nil {
		t.Fatalf("load SWG runtime config: %v", err)
	}
	evaluator := decision.Evaluator{
		Policies:      harnessConfig.Policies,
		PolicyBundle:  harnessConfig.PolicyBundle,
		EdgeRegionID:  "local",
		EdgeClusterID: "local-edge-a",
	}

	for _, tc := range []struct {
		name             string
		targetURL        string
		wantPolicyID     string
		wantHeader       string
		wantRef          string
		wantGoogle       string
		wantMicrosoft    string
		wantTLSSuppress  string
		wantTLSRuleID    string
		wantHeaderAbsent bool
	}{
		{
			name:            "google workspace header from runtime resolver",
			targetURL:       "https://mail.google.com/lab/product-egress",
			wantPolicyID:    "pol_google_workspace_swg_allow_001",
			wantHeader:      swghttprewrite.GoogleWorkspaceTenantRestrictionHeader,
			wantRef:         "operator_config_ref:google_workspace_allowed_domains",
			wantGoogle:      "rewritten_by_operator_config_ref",
			wantMicrosoft:   "not_applicable",
			wantTLSSuppress: "not_applied",
		},
		{
			name:            "microsoft 365 header from runtime resolver",
			targetURL:       "https://www.office.com/lab/product-egress",
			wantPolicyID:    "pol_microsoft_365_swg_allow_001",
			wantHeader:      swghttprewrite.Microsoft365TenantRestrictionHeader,
			wantRef:         "operator_config_ref:microsoft_365_allowed_tenants",
			wantGoogle:      "not_applicable",
			wantMicrosoft:   "rewritten_by_operator_config_ref",
			wantTLSSuppress: "not_applied",
		},
		{
			name:             "pinned google tls bypass suppresses injection",
			targetURL:        "https://pinned-client.google.com/lab/product-egress",
			wantPolicyID:     "pol_google_workspace_swg_allow_001",
			wantHeader:       swghttprewrite.GoogleWorkspaceTenantRestrictionHeader,
			wantRef:          "operator_config_ref:google_workspace_allowed_domains",
			wantGoogle:       "suppressed_by_tls_bypass",
			wantMicrosoft:    "not_applicable",
			wantTLSSuppress:  "header_injection_suppressed",
			wantTLSRuleID:    "swg_tls_bypass_pinned_google_exact",
			wantHeaderAbsent: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			writer, err := logs.NewWriter(t.TempDir())
			if err != nil {
				t.Fatalf("new writer: %v", err)
			}
			captured := make(chan *http.Request, 1)
			decisions := newAccessDecisionStore()
			handler := newServerWithConfig(serverConfig{
				Evaluator: evaluator,
				Writer:    writer,
				ProxyClient: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
					clone := req.Clone(req.Context())
					clone.Header = req.Header.Clone()
					captured <- clone
					return &http.Response{
						StatusCode: http.StatusNoContent,
						Header:     make(http.Header),
						Body:       io.NopCloser(strings.NewReader("")),
						Request:    req,
					}, nil
				})},
				SWGRuntime:    runtimeConfig,
				DecisionStore: decisions,
				LabMode:       boolPtr(true),
			})

			req := httptest.NewRequest(http.MethodGet, edgeplane.EdgeSWGHTTPEgressPath, nil)
			req.Header.Set(edgeplane.EdgeSWGHTTPEgressTargetURLHeader, tc.targetURL)
			req.Header.Set(connectorSecretHeader, defaultConnectorSecret)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != http.StatusNoContent {
				t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusNoContent, rec.Body.String())
			}
			dec, ok := decisions.LatestForApplication(harnessConfig.PolicyBundle.TenantID, edgeplane.EdgeSWGEgressApplicationID)
			if !ok || dec.PolicyID != tc.wantPolicyID || dec.Decision != "allow" {
				t.Fatalf("decision = %v/%s/%s, want allow policy %s", ok, dec.Decision, dec.PolicyID, tc.wantPolicyID)
			}

			upstream := <-captured
			if upstream.Header.Get(connectorSecretHeader) != "" || upstream.Header.Get(edgeplane.EdgeSWGHTTPEgressTargetURLHeader) != "" {
				t.Fatalf("edge runtime control headers were forwarded upstream")
			}
			assertSWGSWGInspectionEventReadback(t, handler, writer, runtimeConfig, dec, tc.wantPolicyID, tc.wantHeader, tc.wantRef, tc.wantGoogle, tc.wantMicrosoft, tc.wantTLSSuppress, tc.wantTLSRuleID, !tc.wantHeaderAbsent, tc.wantHeaderAbsent)
			if tc.wantHeaderAbsent {
				if upstream.Header.Get(swghttprewrite.GoogleWorkspaceTenantRestrictionHeader) != "" ||
					upstream.Header.Get(swghttprewrite.Microsoft365TenantRestrictionHeader) != "" {
					t.Fatalf("tenant restriction header was injected for bypass destination")
				}
				return
			}
			wantValue, ok := runtimeConfig.TenantRestrictionResolver.ResolveHeaderValue(tc.wantRef)
			if !ok || strings.TrimSpace(wantValue) == "" {
				t.Fatalf("runtime resolver did not resolve %s", tc.wantRef)
			}
			if got := upstream.Header.Get(tc.wantHeader); got != wantValue {
				t.Fatalf("upstream request did not receive configured header value for %s", tc.wantRef)
			}
			if tc.wantHeader == swghttprewrite.GoogleWorkspaceTenantRestrictionHeader &&
				upstream.Header.Get(swghttprewrite.Microsoft365TenantRestrictionHeader) != "" {
				t.Fatalf("unexpected Microsoft 365 tenant restriction header on Google request")
			}
			if tc.wantHeader == swghttprewrite.Microsoft365TenantRestrictionHeader &&
				upstream.Header.Get(swghttprewrite.GoogleWorkspaceTenantRestrictionHeader) != "" {
				t.Fatalf("unexpected Google Workspace tenant restriction header on Microsoft request")
			}
		})
	}
}

func assertSWGSWGInspectionEventReadback(t *testing.T, handler http.Handler, writer *logs.Writer, runtimeConfig swg.RuntimeConfig, dec model.AccessDecision, wantPolicyID, wantHeader, wantRef, wantGoogle, wantMicrosoft, wantTLSSuppress, wantTLSRuleID string, wantApplied, wantSuppressed bool) {
	t.Helper()
	wantDefaultTLSObserved := runtimeConfig.RuntimeTLSDecryptionObserved
	wantDefaultTLSStatus := swg.TlsReadinessRequiredObservedStatus(true, wantDefaultTLSObserved)
	wantMacCATrustObserved := runtimeConfig.MacCATrustObserved
	wantMacCATrustStatus := swg.MacCATrustRequiredStatus(true, wantMacCATrustObserved)
	wantCurrentTLSBypass := strings.TrimSpace(wantTLSRuleID) != ""
	wantReadinessStatus, wantReadinessDependency := sWGExpectedPrecondition(runtimeConfig, true, wantCurrentTLSBypass)
	inspectionRows, err := writer.ReadJSONL("inspection_events.log.jsonl")
	if err != nil {
		t.Fatalf("read inspection events log: %v", err)
	}
	if len(inspectionRows) != 1 {
		t.Fatalf("inspection rows = %#v, want one SWG inspection event row", inspectionRows)
	}
	row := inspectionRows[0]
	if row["access_decision_id"] != dec.ID ||
		row["tenant_id"] != dec.TenantID ||
		row["application_id"] != dec.ApplicationID ||
		row["inspection_profile_id"] != stringPtrValue(dec.InspectionProfileID) ||
		row["inspection_mode"] != stringPtrValue(dec.InspectionMode) ||
		row["content_type"] != "application/vnd.dsse.swg-rewrite-metadata+json" ||
		row["finding_type"] != "saas_tenant_restriction_rewrite" ||
		row["severity"] != "info" ||
		row["payload_stored"] != false ||
		row["payload_ref"] != nil ||
		row["masked"] != true ||
		row["retention_policy"] != "metadata_30d" ||
		row["session_id"] != nil ||
		row["user_id"] != nil ||
		row["device_id"] != nil {
		t.Fatalf("inspection row = %#v, want non-secret SWG inspection event for decision %s", row, dec.ID)
	}
	metadata, ok := row["metadata"].(map[string]any)
	if !ok {
		t.Fatalf("inspection row metadata = %#v", row["metadata"])
	}
	for key, want := range map[string]any{
		"swg_inspection_event_version":                      "swg_inspection.v1",
		"swg_inspection_metadata_recorded_scope":            "non_secret",
		"source_audit_event_type":                           edgeplane.EdgeSWGHTTPEgressRewriteEvent,
		"edge_http_egress_handler_path":                     edgeplane.EdgeSWGHTTPEgressPath,
		"edge_runtime_rewrite_path_observed":                true,
		"local_http_rewrite_harness_observation":            false,
		"access_decision_id":                                dec.ID,
		"policy_id":                                         wantPolicyID,
		"saas_application_id":                               dec.SaaSContext.SaaSApplicationID,
		"header_name":                                       wantHeader,
		"operator_config_ref":                               wantRef,
		"google_workspace_rewrite_outcome":                  wantGoogle,
		"microsoft_365_rewrite_outcome":                     wantMicrosoft,
		"tls_bypass_suppression_outcome":                    wantTLSSuppress,
		"header_rewrite_applied":                            wantApplied,
		"header_injection_suppressed_by_bypass":             wantSuppressed,
		"header_value_material_logged":                      false,
		"header_value_material_in_inspection_event":         false,
		"header_value_material_in_api_readback":             false,
		"operator_config_value_material_logged":             false,
		"operator_config_value_material_in_inspection":      false,
		"operator_config_value_material_in_api_readback":    false,
		"runtime_tls_decryption_observed":                   wantDefaultTLSObserved,
		"runtime_header_injection_observed":                 runtimeConfig.RuntimeHeaderInjectionObserved,
		"network_extension_runtime_used":                    runtimeConfig.NetworkExtensionRuntimeUsed,
		"tls_readiness_precondition_checked":                true,
		"tls_readiness_precondition_status":                 wantReadinessStatus,
		"readiness_dependency":                              wantReadinessDependency,
		"egress_forwarded":                                  true,
		"lab_mode":                                          true,
		"tls_readiness_status_path":                         swg.EdgeSWGTLSReadinessStatusPath,
		"tls_readiness_status_version":                      "swg_tls_readiness_status.v1",
		"default_tls_decryption_required":                   true,
		"default_tls_decryption_observed":                   wantDefaultTLSObserved,
		"default_tls_decryption_status":                     wantDefaultTLSStatus,
		"mac_ca_trust_required":                             true,
		"mac_ca_trust_observed":                             wantMacCATrustObserved,
		"mac_ca_trust_status":                               wantMacCATrustStatus,
		"tenant_header_rewrite_dependency_count":            float64(2),
		"per_destination_tls_bypass_required":               true,
		"tls_bypass_rule_count":                             float64(2),
		"current_request_tls_bypass_applied":                wantCurrentTLSBypass,
		"current_request_tls_bypass_rule_id":                wantTLSRuleID,
		"tls_readiness_dependency_suppressed_by_tls_bypass": wantCurrentTLSBypass,
		"header_value_material_in_diagnostic":               false,
		"operator_config_value_material_in_diagnostic":      false,
		"real_tls_interception_runtime_executed":            false,
		"mac_ca_trust_mutated":                              false,
		"p4_packaging_mdm_signing_install_started":          false,
		"windows_work_started":                              false,
	} {
		if got := metadata[key]; got != want {
			t.Fatalf("inspection metadata[%s] = %#v, want %#v; metadata=%#v", key, got, want, metadata)
		}
	}
	assertSWGSWGRewriteAuditNoHeaderValues(t, runtimeConfig, row)

	inspectionID, ok := row["id"].(string)
	if !ok || strings.TrimSpace(inspectionID) == "" {
		t.Fatalf("inspection row id = %#v, want id", row["id"])
	}
	getReq := httptest.NewRequest(http.MethodGet, "/inspection/events/"+url.PathEscape(inspectionID), nil)
	getReq.Header.Set(connectorSecretHeader, defaultConnectorSecret)
	getRec := httptest.NewRecorder()
	handler.ServeHTTP(getRec, getReq)
	if getRec.Code != http.StatusOK {
		t.Fatalf("inspection event lookup status = %d, want %d, body=%s", getRec.Code, http.StatusOK, getRec.Body.String())
	}
	assertSWGSWGRewriteAuditNoHeaderValues(t, runtimeConfig, getRec.Body.String())

	searchReq := httptest.NewRequest(http.MethodGet, "/admin/logs/inspection_events?access_decision_id="+url.QueryEscape(dec.ID)+"&q="+url.QueryEscape(wantRef)+"&limit=5", nil)
	searchRec := httptest.NewRecorder()
	handler.ServeHTTP(searchRec, searchReq)
	if searchRec.Code != http.StatusOK {
		t.Fatalf("inspection log readback status = %d, want %d, body=%s", searchRec.Code, http.StatusOK, searchRec.Body.String())
	}
	var result map[string]any
	if err := json.NewDecoder(searchRec.Body).Decode(&result); err != nil {
		t.Fatalf("decode inspection log readback: %v", err)
	}
	if result["total_matches"] != float64(1) || result["returned"] != float64(1) || result["stream"] != "inspection_events" {
		t.Fatalf("inspection log readback result = %#v, want one matching inspection row", result)
	}
	assertSWGSWGRewriteAuditNoHeaderValues(t, runtimeConfig, result)

	detailReq := httptest.NewRequest(http.MethodGet, "/admin/access-decisions/"+url.PathEscape(dec.ID), nil)
	detailRec := httptest.NewRecorder()
	handler.ServeHTTP(detailRec, detailReq)
	if detailRec.Code != http.StatusOK {
		t.Fatalf("decision detail status = %d, want %d, body=%s", detailRec.Code, http.StatusOK, detailRec.Body.String())
	}
	var detail map[string]any
	if err := json.NewDecoder(detailRec.Body).Decode(&detail); err != nil {
		t.Fatalf("decode access decision detail for inspection: %v", err)
	}
	related, ok := detail["related_logs"].(map[string]any)
	if !ok {
		t.Fatalf("decision detail related_logs = %#v", detail["related_logs"])
	}
	inspectionRelated, ok := related["inspection_events"].([]any)
	if !ok || len(inspectionRelated) != 1 {
		t.Fatalf("decision detail inspection related rows = %#v", related["inspection_events"])
	}
	relatedInspection, ok := inspectionRelated[0].(map[string]any)
	if !ok || relatedInspection["id"] != inspectionID || relatedInspection["access_decision_id"] != dec.ID {
		t.Fatalf("decision detail inspection related row = %#v, want SWG inspection event", inspectionRelated[0])
	}
	assertSWGSWGRewriteAuditNoHeaderValues(t, runtimeConfig, detail)
	assertSWGSWGTLSReadinessStatusReadback(t, handler, runtimeConfig, dec, inspectionID, wantGoogle, wantMicrosoft, wantTLSSuppress)
}

func assertSWGSWGTLSReadinessStatusReadback(t *testing.T, handler http.Handler, runtimeConfig swg.RuntimeConfig, dec model.AccessDecision, inspectionID, wantGoogle, wantMicrosoft, wantTLSSuppress string) {
	t.Helper()
	wantDefaultTLSObserved := runtimeConfig.RuntimeTLSDecryptionObserved
	wantDefaultTLSStatus := swg.TlsReadinessRequiredObservedStatus(true, wantDefaultTLSObserved)
	wantVisibilityStatus := swg.TlsReadinessVisibilityStatus(true, wantDefaultTLSObserved)
	wantMacCATrustObserved := runtimeConfig.MacCATrustObserved
	wantMacCATrustStatus := swg.MacCATrustRequiredStatus(true, wantMacCATrustObserved)
	statusReq := httptest.NewRequest(http.MethodGet, swg.EdgeSWGTLSReadinessStatusPath, nil)
	statusReq.Header.Set(connectorSecretHeader, defaultConnectorSecret)
	statusRec := httptest.NewRecorder()
	handler.ServeHTTP(statusRec, statusReq)
	if statusRec.Code != http.StatusOK {
		t.Fatalf("TLS readiness status = %d, want %d, body=%s", statusRec.Code, http.StatusOK, statusRec.Body.String())
	}
	var status map[string]any
	if err := json.NewDecoder(statusRec.Body).Decode(&status); err != nil {
		t.Fatalf("decode TLS readiness status: %v", err)
	}
	for key, want := range map[string]any{
		"schema_version":                           "swg_tls_readiness_status.v1",
		"status":                                   wantVisibilityStatus,
		"tenant_id":                                "tenant_swg_lab",
		"policy_bundle_id":                         "pb_swg_preflight_m1583",
		"readback_path":                            swg.EdgeSWGTLSReadinessStatusPath,
		"edge_http_egress_handler_path":            edgeplane.EdgeSWGHTTPEgressPath,
		"default_tls_decryption_required":          true,
		"default_tls_decryption_observed":          wantDefaultTLSObserved,
		"default_tls_decryption_status":            wantDefaultTLSStatus,
		"tenant_header_rewrite_dependency_count":   float64(2),
		"per_destination_tls_bypass_required":      true,
		"tls_bypass_rule_count":                    float64(2),
		"mac_ca_trust_required":                    true,
		"mac_ca_trust_observed":                    wantMacCATrustObserved,
		"mac_ca_trust_mutated":                     false,
		"mac_ca_trust_status":                      wantMacCATrustStatus,
		"inspection_metadata_readback_observed":    true,
		"inspection_event_count":                   float64(1),
		"latest_inspection_event_id":               inspectionID,
		"latest_access_decision_id":                dec.ID,
		"runtime_tls_decryption_observed":          wantDefaultTLSObserved,
		"runtime_header_injection_observed":        runtimeConfig.RuntimeHeaderInjectionObserved,
		"network_extension_runtime_used":           runtimeConfig.NetworkExtensionRuntimeUsed,
		"swg_runtime_traffic_observed":             false,
		"real_tls_interception_runtime_executed":   false,
		"header_value_material_in_status":          false,
		"operator_config_value_material_in_status": false,
		"mac_ca_trust_mutation_started":            false,
		"p4_packaging_mdm_signing_install_started": false,
		"shipping_product_claimed":                 false,
		"production_scale_claimed":                 false,
		"mvp_pilot_success_claimed":                false,
		"windows_work_started":                     false,
		"productization_claims_made":               false,
		"new_product_claims_made":                  false,
		"secret_leak_gate":                         "ok",
		"no_secret_attestation":                    true,
	} {
		if got := status[key]; got != want {
			t.Fatalf("TLS readiness status[%s] = %#v, want %#v; status=%#v", key, got, want, status)
		}
	}
	profiles, ok := status["required_inspection_profile_ids"].([]any)
	if !ok || len(profiles) != 1 || profiles[0] != "ip_swg_default_tls_decrypt" {
		t.Fatalf("required inspection profiles = %#v", status["required_inspection_profile_ids"])
	}
	trustProfiles, ok := status["mac_trust_profile_ids"].([]any)
	if !ok || len(trustProfiles) != 1 || trustProfiles[0] != "tp_swg_mac_trust" {
		t.Fatalf("mac trust profiles = %#v", status["mac_trust_profile_ids"])
	}
	rootCAs, ok := status["tenant_root_ca_ids"].([]any)
	if !ok || len(rootCAs) != 1 || rootCAs[0] != "trca_swg_lab" {
		t.Fatalf("tenant root CAs = %#v", status["tenant_root_ca_ids"])
	}
	deps, ok := status["tenant_header_rewrite_dependencies"].([]any)
	if !ok || len(deps) != 2 {
		t.Fatalf("tenant header dependencies = %#v", status["tenant_header_rewrite_dependencies"])
	}
	assertSWGSWGTLSReadinessDependency(t, deps, swghttprewrite.GoogleWorkspaceTenantRestrictionHeader, "operator_config_ref:google_workspace_allowed_domains")
	assertSWGSWGTLSReadinessDependency(t, deps, swghttprewrite.Microsoft365TenantRestrictionHeader, "operator_config_ref:microsoft_365_allowed_tenants")
	bypassRules, ok := status["tls_bypass_rules"].([]any)
	if !ok || len(bypassRules) != 2 || !sWGTLSBypassRulePresent(bypassRules, "swg_tls_bypass_banking_category") || !sWGTLSBypassRulePresent(bypassRules, "swg_tls_bypass_pinned_google_exact") {
		t.Fatalf("TLS bypass rules = %#v", status["tls_bypass_rules"])
	}
	inspectionMetadata, ok := status["inspection_metadata"].(map[string]any)
	if !ok {
		t.Fatalf("inspection metadata = %#v", status["inspection_metadata"])
	}
	for key, want := range map[string]any{
		"latest_event_type":                              edgeplane.EdgeSWGHTTPEgressRewriteEvent,
		"latest_finding_type":                            "saas_tenant_restriction_rewrite",
		"google_workspace_rewrite_outcome":               wantGoogle,
		"microsoft_365_rewrite_outcome":                  wantMicrosoft,
		"tls_bypass_suppression_outcome":                 wantTLSSuppress,
		"header_value_material_in_inspection_event":      false,
		"header_value_material_in_api_readback":          false,
		"operator_config_value_material_in_inspection":   false,
		"operator_config_value_material_in_api_readback": false,
	} {
		if got := inspectionMetadata[key]; got != want {
			t.Fatalf("inspection metadata[%s] = %#v, want %#v; metadata=%#v", key, got, want, inspectionMetadata)
		}
	}
	assertSWGSWGRewriteAuditNoHeaderValues(t, runtimeConfig, status)
}

func TestSWGEdgeSWGHTTPEgressProductionModeShowsTLSReadinessDependency(t *testing.T) {
	relaxConnectorMTLSPresentationForTest(t)
	harnessConfig, err := swghttprewrite.LoadHarnessConfig(filepath.Join("..", "..", "swghttprewrite", "testdata", "swg_saas_tenant_enforcement_preflight.json"))
	if err != nil {
		t.Fatalf("load harness config: %v", err)
	}
	runtimeConfig, err := swg.LoadRuntimeConfig(swg.RuntimeConfigInput{
		TenantRestrictionOperatorConfigPath: filepath.Join("..", "..", "swghttprewrite", "testdata", "swg_tenant_restriction_operator_config.json"),
		PolicyBundle:                        harnessConfig.PolicyBundle,
	})
	if err != nil {
		t.Fatalf("load SWG runtime config: %v", err)
	}
	evaluator := decision.Evaluator{
		Policies:      harnessConfig.Policies,
		PolicyBundle:  harnessConfig.PolicyBundle,
		EdgeRegionID:  "local",
		EdgeClusterID: "local-edge-a",
	}
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("new writer: %v", err)
	}
	captured := make(chan *http.Request, 1)
	decisions := newAccessDecisionStore()
	handler := newServerWithConfig(serverConfig{
		Evaluator: evaluator,
		Writer:    writer,
		ProxyClient: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			captured <- req
			return &http.Response{
				StatusCode: http.StatusNoContent,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader("")),
				Request:    req,
			}, nil
		})},
		SWGRuntime:    runtimeConfig,
		DecisionStore: decisions,
		LabMode:       boolPtr(false),
	})

	req := httptest.NewRequest(http.MethodGet, edgeplane.EdgeSWGHTTPEgressPath, nil)
	req.Header.Set(edgeplane.EdgeSWGHTTPEgressTargetURLHeader, "https://mail.google.com/lab/product-egress")
	req.Header.Set(connectorSecretHeader, defaultConnectorSecret)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusPreconditionRequired {
		t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusPreconditionRequired, rec.Body.String())
	}
	select {
	case upstream := <-captured:
		t.Fatalf("upstream request was sent despite TLS readiness dependency: %#v", upstream.URL)
	default:
	}
	dec, ok := decisions.LatestForApplication(harnessConfig.PolicyBundle.TenantID, edgeplane.EdgeSWGEgressApplicationID)
	if !ok || dec.PolicyID != "pol_google_workspace_swg_allow_001" || dec.Decision != "allow" {
		t.Fatalf("decision = %v/%s/%s, want allow google workspace policy", ok, dec.Decision, dec.PolicyID)
	}
	var diagnostic map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&diagnostic); err != nil {
		t.Fatalf("decode readiness dependency diagnostic: %v", err)
	}
	for key, want := range map[string]any{
		"schema_version":                                    edgeplane.EdgeSWGHTTPEgressReadinessSchema,
		"status":                                            "readiness_dependency",
		"readiness_dependency":                              edgeplane.EdgeSWGHTTPEgressReadinessReason,
		"edge_http_egress_handler_path":                     edgeplane.EdgeSWGHTTPEgressPath,
		"tls_readiness_status_path":                         swg.EdgeSWGTLSReadinessStatusPath,
		"tls_readiness_status_version":                      "swg_tls_readiness_status.v1",
		"tenant_id":                                         harnessConfig.PolicyBundle.TenantID,
		"policy_bundle_id":                                  harnessConfig.PolicyBundle.ID,
		"policy_bundle_version":                             harnessConfig.PolicyBundle.Version,
		"access_decision_id":                                dec.ID,
		"policy_id":                                         dec.PolicyID,
		"application_id":                                    edgeplane.EdgeSWGEgressApplicationID,
		"saas_application_id":                               "saas_google_workspace",
		"lab_mode":                                          false,
		"egress_forwarded":                                  false,
		"default_tls_decryption_required":                   true,
		"default_tls_decryption_observed":                   false,
		"default_tls_decryption_status":                     "required_not_observed",
		"mac_ca_trust_required":                             true,
		"mac_ca_trust_observed":                             false,
		"mac_ca_trust_status":                               "required_not_mutated",
		"tenant_header_rewrite_dependency_count":            float64(2),
		"per_destination_tls_bypass_required":               true,
		"tls_bypass_rule_count":                             float64(2),
		"current_request_tls_bypass_applied":                false,
		"current_request_tls_bypass_rule_id":                "",
		"tls_readiness_dependency_suppressed_by_tls_bypass": false,
		"inspection_metadata_readback_observed":             false,
		"header_value_material_in_diagnostic":               false,
		"operator_config_value_material_in_diagnostic":      false,
		"real_tls_interception_runtime_executed":            false,
		"mac_ca_trust_mutation_started":                     false,
		"p4_packaging_mdm_signing_install_started":          false,
		"shipping_product_claimed":                          false,
		"production_scale_claimed":                          false,
		"mvp_pilot_success_claimed":                         false,
		"windows_work_started":                              false,
		"secret_leak_gate":                                  "ok",
		"no_secret_attestation":                             true,
	} {
		if got := diagnostic[key]; got != want {
			t.Fatalf("diagnostic[%s] = %#v, want %#v; diagnostic=%#v", key, got, want, diagnostic)
		}
	}
	headerNames, ok := diagnostic["header_names_visible"].([]any)
	if !ok || !sWGValuePresent(headerNames, swghttprewrite.GoogleWorkspaceTenantRestrictionHeader) || !sWGValuePresent(headerNames, swghttprewrite.Microsoft365TenantRestrictionHeader) {
		t.Fatalf("diagnostic header_names_visible = %#v", diagnostic["header_names_visible"])
	}
	configRefs, ok := diagnostic["operator_config_refs_visible"].([]any)
	if !ok || !sWGValuePresent(configRefs, "operator_config_ref:google_workspace_allowed_domains") || !sWGValuePresent(configRefs, "operator_config_ref:microsoft_365_allowed_tenants") {
		t.Fatalf("diagnostic operator_config_refs_visible = %#v", diagnostic["operator_config_refs_visible"])
	}
	assertSWGSWGRewriteAuditNoHeaderValues(t, runtimeConfig, diagnostic)

	auditRows, err := writer.ReadJSONL("inspection_events.log.jsonl")
	if err != nil {
		t.Fatalf("read inspection log: %v", err)
	}
	if len(auditRows) != 1 {
		t.Fatalf("inspection rows = %#v, want one diagnostic inspection row", auditRows)
	}
	auditMetadata, ok := auditRows[0]["metadata"].(map[string]any)
	if !ok {
		t.Fatalf("audit metadata = %#v", auditRows[0]["metadata"])
	}
	assertSWGSWGReadinessPreconditionMetadata(t, runtimeConfig, auditMetadata, false, "readiness_dependency", edgeplane.EdgeSWGHTTPEgressReadinessReason, false, false, "", false)
	inspectionRows, err := writer.ReadJSONL("inspection_events.log.jsonl")
	if err != nil {
		t.Fatalf("read inspection events log: %v", err)
	}
	if len(inspectionRows) != 1 {
		t.Fatalf("inspection rows = %#v, want one diagnostic inspection row", inspectionRows)
	}
	inspectionMetadata, ok := inspectionRows[0]["metadata"].(map[string]any)
	if !ok {
		t.Fatalf("inspection metadata = %#v", inspectionRows[0]["metadata"])
	}
	assertSWGSWGReadinessPreconditionMetadata(t, runtimeConfig, inspectionMetadata, false, "readiness_dependency", edgeplane.EdgeSWGHTTPEgressReadinessReason, false, false, "", false)
}

func TestSWGEdgeSWGHTTPEgressProductionModeBlocksWhenMacCATrustNotObserved(t *testing.T) {
	relaxConnectorMTLSPresentationForTest(t)
	harnessConfig, err := swghttprewrite.LoadHarnessConfig(filepath.Join("..", "..", "swghttprewrite", "testdata", "swg_saas_tenant_enforcement_preflight.json"))
	if err != nil {
		t.Fatalf("load harness config: %v", err)
	}
	runtimeConfig, err := swg.LoadRuntimeConfig(swg.RuntimeConfigInput{
		TenantRestrictionOperatorConfigPath: filepath.Join("..", "..", "swghttprewrite", "testdata", "swg_tenant_restriction_operator_config.json"),
		PolicyBundle:                        harnessConfig.PolicyBundle,
		RuntimeTLSDecryptionObserved:        true,
	})
	if err != nil {
		t.Fatalf("load SWG runtime config: %v", err)
	}
	evaluator := decision.Evaluator{
		Policies:      harnessConfig.Policies,
		PolicyBundle:  harnessConfig.PolicyBundle,
		EdgeRegionID:  "local",
		EdgeClusterID: "local-edge-a",
	}
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("new writer: %v", err)
	}
	captured := make(chan *http.Request, 1)
	decisions := newAccessDecisionStore()
	handler := newServerWithConfig(serverConfig{
		Evaluator: evaluator,
		Writer:    writer,
		ProxyClient: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			captured <- req
			return &http.Response{
				StatusCode: http.StatusNoContent,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader("")),
				Request:    req,
			}, nil
		})},
		SWGRuntime:    runtimeConfig,
		DecisionStore: decisions,
		LabMode:       boolPtr(false),
	})

	req := httptest.NewRequest(http.MethodGet, edgeplane.EdgeSWGHTTPEgressPath, nil)
	req.Header.Set(edgeplane.EdgeSWGHTTPEgressTargetURLHeader, "https://mail.google.com/lab/product-egress")
	req.Header.Set(connectorSecretHeader, defaultConnectorSecret)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusPreconditionRequired {
		t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusPreconditionRequired, rec.Body.String())
	}
	select {
	case upstream := <-captured:
		t.Fatalf("upstream request was sent despite Mac CA trust readiness dependency: %#v", upstream.URL)
	default:
	}
	dec, ok := decisions.LatestForApplication(harnessConfig.PolicyBundle.TenantID, edgeplane.EdgeSWGEgressApplicationID)
	if !ok || dec.PolicyID != "pol_google_workspace_swg_allow_001" || dec.Decision != "allow" {
		t.Fatalf("decision = %v/%s/%s, want allow google workspace policy", ok, dec.Decision, dec.PolicyID)
	}
	var diagnostic map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&diagnostic); err != nil {
		t.Fatalf("decode readiness dependency diagnostic: %v", err)
	}
	for key, want := range map[string]any{
		"schema_version":                                    edgeplane.EdgeSWGHTTPEgressReadinessSchema,
		"status":                                            "readiness_dependency",
		"readiness_dependency":                              edgeplane.EdgeSWGHTTPEgressMacCAReason,
		"edge_http_egress_handler_path":                     edgeplane.EdgeSWGHTTPEgressPath,
		"tls_readiness_status_path":                         swg.EdgeSWGTLSReadinessStatusPath,
		"tls_readiness_status_version":                      "swg_tls_readiness_status.v1",
		"tenant_id":                                         harnessConfig.PolicyBundle.TenantID,
		"policy_bundle_id":                                  harnessConfig.PolicyBundle.ID,
		"policy_bundle_version":                             harnessConfig.PolicyBundle.Version,
		"access_decision_id":                                dec.ID,
		"policy_id":                                         dec.PolicyID,
		"application_id":                                    edgeplane.EdgeSWGEgressApplicationID,
		"saas_application_id":                               "saas_google_workspace",
		"lab_mode":                                          false,
		"egress_forwarded":                                  false,
		"default_tls_decryption_required":                   true,
		"default_tls_decryption_observed":                   true,
		"default_tls_decryption_status":                     "required_observed",
		"mac_ca_trust_required":                             true,
		"mac_ca_trust_observed":                             false,
		"mac_ca_trust_status":                               "required_not_mutated",
		"current_request_tls_bypass_applied":                false,
		"current_request_tls_bypass_rule_id":                "",
		"tls_readiness_dependency_suppressed_by_tls_bypass": false,
		"inspection_metadata_readback_observed":             false,
		"header_value_material_in_diagnostic":               false,
		"operator_config_value_material_in_diagnostic":      false,
		"real_tls_interception_runtime_executed":            false,
		"mac_ca_trust_mutation_started":                     false,
		"p4_packaging_mdm_signing_install_started":          false,
		"shipping_product_claimed":                          false,
		"production_scale_claimed":                          false,
		"mvp_pilot_success_claimed":                         false,
		"windows_work_started":                              false,
		"secret_leak_gate":                                  "ok",
		"no_secret_attestation":                             true,
	} {
		if got := diagnostic[key]; got != want {
			t.Fatalf("diagnostic[%s] = %#v, want %#v; diagnostic=%#v", key, got, want, diagnostic)
		}
	}
	assertSWGSWGRewriteAuditNoHeaderValues(t, runtimeConfig, diagnostic)

	auditRows, err := writer.ReadJSONL("inspection_events.log.jsonl")
	if err != nil {
		t.Fatalf("read inspection log: %v", err)
	}
	if len(auditRows) != 1 {
		t.Fatalf("inspection rows = %#v, want one Mac CA diagnostic inspection row", auditRows)
	}
	auditMetadata, ok := auditRows[0]["metadata"].(map[string]any)
	if !ok {
		t.Fatalf("audit metadata = %#v", auditRows[0]["metadata"])
	}
	assertSWGSWGReadinessPreconditionMetadata(t, runtimeConfig, auditMetadata, false, "readiness_dependency", edgeplane.EdgeSWGHTTPEgressMacCAReason, false, false, "", false)
	inspectionRows, err := writer.ReadJSONL("inspection_events.log.jsonl")
	if err != nil {
		t.Fatalf("read inspection events log: %v", err)
	}
	if len(inspectionRows) != 1 {
		t.Fatalf("inspection rows = %#v, want one Mac CA diagnostic inspection row", inspectionRows)
	}
	inspectionMetadata, ok := inspectionRows[0]["metadata"].(map[string]any)
	if !ok {
		t.Fatalf("inspection metadata = %#v", inspectionRows[0]["metadata"])
	}
	assertSWGSWGReadinessPreconditionMetadata(t, runtimeConfig, inspectionMetadata, false, "readiness_dependency", edgeplane.EdgeSWGHTTPEgressMacCAReason, false, false, "", false)
}

func TestSWGEdgeSWGHTTPEgressProductionModeClearsReadinessWhenRuntimeTLSAndMacCATrustObserved(t *testing.T) {
	relaxConnectorMTLSPresentationForTest(t)
	harnessConfig, err := swghttprewrite.LoadHarnessConfig(filepath.Join("..", "..", "swghttprewrite", "testdata", "swg_saas_tenant_enforcement_preflight.json"))
	if err != nil {
		t.Fatalf("load harness config: %v", err)
	}
	runtimeConfig, err := swg.LoadRuntimeConfig(swg.RuntimeConfigInput{
		TenantRestrictionOperatorConfigPath: filepath.Join("..", "..", "swghttprewrite", "testdata", "swg_tenant_restriction_operator_config.json"),
		PolicyBundle:                        harnessConfig.PolicyBundle,
		RuntimeTLSDecryptionObserved:        true,
		MacCATrustObserved:                  true,
	})
	if err != nil {
		t.Fatalf("load SWG runtime config: %v", err)
	}
	evaluator := decision.Evaluator{
		Policies:      harnessConfig.Policies,
		PolicyBundle:  harnessConfig.PolicyBundle,
		EdgeRegionID:  "local",
		EdgeClusterID: "local-edge-a",
	}

	for _, tc := range []struct {
		name          string
		targetURL     string
		wantPolicyID  string
		wantSaaS      string
		wantHeader    string
		wantRef       string
		wantGoogle    string
		wantMicrosoft string
	}{
		{
			name:         "google workspace tenant header forwards after runtime TLS observed",
			targetURL:    "https://mail.google.com/lab/product-egress",
			wantPolicyID: "pol_google_workspace_swg_allow_001",
			wantSaaS:     "saas_google_workspace",
			wantHeader:   swghttprewrite.GoogleWorkspaceTenantRestrictionHeader,
			wantRef:      "operator_config_ref:google_workspace_allowed_domains",
			wantGoogle:   "rewritten_by_operator_config_ref",
		},
		{
			name:          "microsoft 365 tenant header forwards after runtime TLS observed",
			targetURL:     "https://www.office.com/lab/product-egress",
			wantPolicyID:  "pol_microsoft_365_swg_allow_001",
			wantSaaS:      "saas_microsoft_365",
			wantHeader:    swghttprewrite.Microsoft365TenantRestrictionHeader,
			wantRef:       "operator_config_ref:microsoft_365_allowed_tenants",
			wantMicrosoft: "rewritten_by_operator_config_ref",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			writer, err := logs.NewWriter(t.TempDir())
			if err != nil {
				t.Fatalf("new writer: %v", err)
			}
			captured := make(chan *http.Request, 1)
			decisions := newAccessDecisionStore()
			handler := newServerWithConfig(serverConfig{
				Evaluator: evaluator,
				Writer:    writer,
				ProxyClient: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
					clone := req.Clone(req.Context())
					clone.Header = req.Header.Clone()
					captured <- clone
					return &http.Response{
						StatusCode: http.StatusNoContent,
						Header:     make(http.Header),
						Body:       io.NopCloser(strings.NewReader("")),
						Request:    req,
					}, nil
				})},
				SWGRuntime:    runtimeConfig,
				DecisionStore: decisions,
				LabMode:       boolPtr(false),
			})

			req := httptest.NewRequest(http.MethodGet, edgeplane.EdgeSWGHTTPEgressPath, nil)
			req.Header.Set(edgeplane.EdgeSWGHTTPEgressTargetURLHeader, tc.targetURL)
			req.Header.Set(connectorSecretHeader, defaultConnectorSecret)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != http.StatusNoContent {
				t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusNoContent, rec.Body.String())
			}

			var upstream *http.Request
			select {
			case upstream = <-captured:
			default:
				t.Fatalf("upstream request was not sent after runtime TLS and Mac CA trust readiness")
			}
			if upstream.Header.Get(connectorSecretHeader) != "" || upstream.Header.Get(edgeplane.EdgeSWGHTTPEgressTargetURLHeader) != "" {
				t.Fatalf("edge runtime control headers were forwarded upstream")
			}
			wantValue, ok := runtimeConfig.TenantRestrictionResolver.ResolveHeaderValue(tc.wantRef)
			if !ok || strings.TrimSpace(wantValue) == "" {
				t.Fatalf("runtime resolver did not resolve %s", tc.wantRef)
			}
			if got := upstream.Header.Get(tc.wantHeader); got != wantValue {
				t.Fatalf("upstream request header %s = %q, want configured value", tc.wantHeader, got)
			}

			dec, ok := decisions.LatestForApplication(harnessConfig.PolicyBundle.TenantID, edgeplane.EdgeSWGEgressApplicationID)
			if !ok || dec.PolicyID != tc.wantPolicyID || dec.Decision != "allow" || dec.SaaSContext == nil || dec.SaaSContext.SaaSApplicationID != tc.wantSaaS {
				t.Fatalf("decision = %#v, want allow policy %s SaaS %s", dec, tc.wantPolicyID, tc.wantSaaS)
			}

			auditRows, err := writer.ReadJSONL("inspection_events.log.jsonl")
			if err != nil {
				t.Fatalf("read inspection log: %v", err)
			}
			if len(auditRows) != 1 {
				t.Fatalf("inspection rows = %#v, want one runtime TLS observed inspection row", auditRows)
			}
			auditMetadata, ok := auditRows[0]["metadata"].(map[string]any)
			if !ok {
				t.Fatalf("audit metadata = %#v", auditRows[0]["metadata"])
			}
			for key, want := range map[string]any{
				"runtime_tls_decryption_observed":        true,
				"runtime_header_injection_observed":      false,
				"network_extension_runtime_used":         false,
				"google_workspace_rewrite_outcome":       valueOrDefault(tc.wantGoogle, "not_applicable"),
				"microsoft_365_rewrite_outcome":          valueOrDefault(tc.wantMicrosoft, "not_applicable"),
				"tls_bypass_suppression_outcome":         "not_applied",
				"real_tls_interception_runtime_executed": false,
			} {
				if got := auditMetadata[key]; got != want {
					t.Fatalf("audit metadata[%s] = %#v, want %#v; metadata=%#v", key, got, want, auditMetadata)
				}
			}
			assertSWGSWGReadinessPreconditionMetadata(t, runtimeConfig, auditMetadata, false, "mac_ca_trust_observed", "none", true, false, "", false)

			inspectionRows, err := writer.ReadJSONL("inspection_events.log.jsonl")
			if err != nil {
				t.Fatalf("read inspection events log: %v", err)
			}
			if len(inspectionRows) != 1 {
				t.Fatalf("inspection rows = %#v, want one runtime TLS observed inspection row", inspectionRows)
			}
			inspectionMetadata, ok := inspectionRows[0]["metadata"].(map[string]any)
			if !ok {
				t.Fatalf("inspection metadata = %#v", inspectionRows[0]["metadata"])
			}
			for key, want := range map[string]any{
				"runtime_tls_decryption_observed":        true,
				"runtime_header_injection_observed":      false,
				"network_extension_runtime_used":         false,
				"google_workspace_rewrite_outcome":       valueOrDefault(tc.wantGoogle, "not_applicable"),
				"microsoft_365_rewrite_outcome":          valueOrDefault(tc.wantMicrosoft, "not_applicable"),
				"tls_bypass_suppression_outcome":         "not_applied",
				"real_tls_interception_runtime_executed": false,
			} {
				if got := inspectionMetadata[key]; got != want {
					t.Fatalf("inspection metadata[%s] = %#v, want %#v; metadata=%#v", key, got, want, inspectionMetadata)
				}
			}
			assertSWGSWGReadinessPreconditionMetadata(t, runtimeConfig, inspectionMetadata, false, "mac_ca_trust_observed", "none", true, false, "", false)
			inspectionID, ok := inspectionRows[0]["id"].(string)
			if !ok || strings.TrimSpace(inspectionID) == "" {
				t.Fatalf("inspection row id = %#v, want id", inspectionRows[0]["id"])
			}
			assertSWGSWGTLSReadinessStatusReadback(t, handler, runtimeConfig, dec, inspectionID, valueOrDefault(tc.wantGoogle, "not_applicable"), valueOrDefault(tc.wantMicrosoft, "not_applicable"), "not_applied")
			assertSWGSWGRewriteAuditNoHeaderValues(t, runtimeConfig, auditRows[0])
			assertSWGSWGRewriteAuditNoHeaderValues(t, runtimeConfig, inspectionRows[0])
		})
	}
}

func TestSWGEdgeSWGHTTPEgressProductionModeExemptsTLSBypassDestinations(t *testing.T) {
	relaxConnectorMTLSPresentationForTest(t)
	harnessConfig, err := swghttprewrite.LoadHarnessConfig(filepath.Join("..", "..", "swghttprewrite", "testdata", "swg_saas_tenant_enforcement_preflight.json"))
	if err != nil {
		t.Fatalf("load harness config: %v", err)
	}
	runtimeConfig, err := swg.LoadRuntimeConfig(swg.RuntimeConfigInput{
		TenantRestrictionOperatorConfigPath: filepath.Join("..", "..", "swghttprewrite", "testdata", "swg_tenant_restriction_operator_config.json"),
		PolicyBundle:                        harnessConfig.PolicyBundle,
	})
	if err != nil {
		t.Fatalf("load SWG runtime config: %v", err)
	}
	evaluator := decision.Evaluator{
		Policies:      harnessConfig.Policies,
		PolicyBundle:  harnessConfig.PolicyBundle,
		EdgeRegionID:  "local",
		EdgeClusterID: "local-edge-a",
	}

	for _, tc := range []struct {
		name            string
		targetURL       string
		wantPolicyID    string
		wantSaaS        string
		wantTLSRuleID   string
		wantGoogle      string
		wantMicrosoft   string
		wantTLSSuppress string
		wantSuppressed  bool
	}{
		{
			name:            "pinned Google endpoint bypass suppresses tenant header readiness dependency",
			targetURL:       "https://pinned-client.google.com/lab/product-egress",
			wantPolicyID:    "pol_google_workspace_swg_allow_001",
			wantSaaS:        "saas_google_workspace",
			wantTLSRuleID:   "swg_tls_bypass_pinned_google_exact",
			wantGoogle:      "suppressed_by_tls_bypass",
			wantMicrosoft:   "not_applicable",
			wantTLSSuppress: "header_injection_suppressed",
			wantSuppressed:  true,
		},
		{
			name:            "banking category bypass suppresses default TLS readiness dependency",
			targetURL:       "https://portal.bank.example/lab/product-egress",
			wantPolicyID:    "pol_sensitive_banking_bypass_allow_001",
			wantSaaS:        "saas_sensitive_banking",
			wantTLSRuleID:   "swg_tls_bypass_banking_category",
			wantGoogle:      "not_applicable",
			wantMicrosoft:   "not_applicable",
			wantTLSSuppress: "tls_bypass_without_tenant_header",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			writer, err := logs.NewWriter(t.TempDir())
			if err != nil {
				t.Fatalf("new writer: %v", err)
			}
			captured := make(chan *http.Request, 1)
			decisions := newAccessDecisionStore()
			handler := newServerWithConfig(serverConfig{
				Evaluator: evaluator,
				Writer:    writer,
				ProxyClient: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
					clone := req.Clone(req.Context())
					clone.Header = req.Header.Clone()
					captured <- clone
					return &http.Response{
						StatusCode: http.StatusNoContent,
						Header:     make(http.Header),
						Body:       io.NopCloser(strings.NewReader("")),
						Request:    req,
					}, nil
				})},
				SWGRuntime:    runtimeConfig,
				DecisionStore: decisions,
				LabMode:       boolPtr(false),
			})

			req := httptest.NewRequest(http.MethodGet, edgeplane.EdgeSWGHTTPEgressPath, nil)
			req.Header.Set(edgeplane.EdgeSWGHTTPEgressTargetURLHeader, tc.targetURL)
			req.Header.Set(connectorSecretHeader, defaultConnectorSecret)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != http.StatusNoContent {
				t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusNoContent, rec.Body.String())
			}
			upstream := <-captured
			if upstream.Header.Get(connectorSecretHeader) != "" || upstream.Header.Get(edgeplane.EdgeSWGHTTPEgressTargetURLHeader) != "" {
				t.Fatalf("edge runtime control headers were forwarded upstream")
			}
			if upstream.Header.Get(swghttprewrite.GoogleWorkspaceTenantRestrictionHeader) != "" ||
				upstream.Header.Get(swghttprewrite.Microsoft365TenantRestrictionHeader) != "" {
				t.Fatalf("tenant restriction header was injected for TLS bypass destination")
			}
			dec, ok := decisions.LatestForApplication(harnessConfig.PolicyBundle.TenantID, edgeplane.EdgeSWGEgressApplicationID)
			if !ok || dec.PolicyID != tc.wantPolicyID || dec.Decision != "allow" || dec.SaaSContext == nil || dec.SaaSContext.SaaSApplicationID != tc.wantSaaS {
				t.Fatalf("decision = %#v, want allow policy %s SaaS %s", dec, tc.wantPolicyID, tc.wantSaaS)
			}

			auditRows, err := writer.ReadJSONL("inspection_events.log.jsonl")
			if err != nil {
				t.Fatalf("read inspection log: %v", err)
			}
			if len(auditRows) != 1 {
				t.Fatalf("inspection rows = %#v, want one bypass inspection row", auditRows)
			}
			auditMetadata, ok := auditRows[0]["metadata"].(map[string]any)
			if !ok {
				t.Fatalf("audit metadata = %#v", auditRows[0]["metadata"])
			}
			for key, want := range map[string]any{
				"tls_bypass_applied":                    true,
				"tls_bypass_rule_id":                    tc.wantTLSRuleID,
				"header_injection_suppressed_by_bypass": tc.wantSuppressed,
				"google_workspace_rewrite_outcome":      tc.wantGoogle,
				"microsoft_365_rewrite_outcome":         tc.wantMicrosoft,
				"tls_bypass_suppression_outcome":        tc.wantTLSSuppress,
			} {
				if got := auditMetadata[key]; got != want {
					t.Fatalf("audit metadata[%s] = %#v, want %#v; metadata=%#v", key, got, want, auditMetadata)
				}
			}
			assertSWGSWGReadinessPreconditionMetadata(t, runtimeConfig, auditMetadata, false, "tls_bypass_exempted", "none", true, true, tc.wantTLSRuleID, true)

			inspectionRows, err := writer.ReadJSONL("inspection_events.log.jsonl")
			if err != nil {
				t.Fatalf("read inspection events log: %v", err)
			}
			if len(inspectionRows) != 1 {
				t.Fatalf("inspection rows = %#v, want one bypass inspection row", inspectionRows)
			}
			inspectionMetadata, ok := inspectionRows[0]["metadata"].(map[string]any)
			if !ok {
				t.Fatalf("inspection metadata = %#v", inspectionRows[0]["metadata"])
			}
			for key, want := range map[string]any{
				"tls_bypass_applied":                    true,
				"tls_bypass_rule_id":                    tc.wantTLSRuleID,
				"header_injection_suppressed_by_bypass": tc.wantSuppressed,
				"google_workspace_rewrite_outcome":      tc.wantGoogle,
				"microsoft_365_rewrite_outcome":         tc.wantMicrosoft,
				"tls_bypass_suppression_outcome":        tc.wantTLSSuppress,
			} {
				if got := inspectionMetadata[key]; got != want {
					t.Fatalf("inspection metadata[%s] = %#v, want %#v; metadata=%#v", key, got, want, inspectionMetadata)
				}
			}
			assertSWGSWGReadinessPreconditionMetadata(t, runtimeConfig, inspectionMetadata, false, "tls_bypass_exempted", "none", true, true, tc.wantTLSRuleID, true)
			assertSWGSWGRewriteAuditNoHeaderValues(t, runtimeConfig, auditRows[0])
			assertSWGSWGRewriteAuditNoHeaderValues(t, runtimeConfig, inspectionRows[0])
		})
	}
}

func assertSWGSWGTLSReadinessDependency(t *testing.T, deps []any, headerName, ref string) {
	t.Helper()
	for _, raw := range deps {
		dep, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if dep["header_name"] != headerName || dep["operator_config_ref"] != ref {
			continue
		}
		for key, want := range map[string]any{
			"operator_config_ref_resolved":      true,
			"rewrite_dependency":                "default_tls_decryption_required",
			"header_value_material_in_status":   false,
			"header_value_material_in_decision": false,
		} {
			if got := dep[key]; got != want {
				t.Fatalf("dependency %s[%s] = %#v, want %#v; dep=%#v", ref, key, got, want, dep)
			}
		}
		return
	}
	t.Fatalf("dependency for %s/%s not found in %#v", headerName, ref, deps)
}

func assertSWGSWGReadinessPreconditionMetadata(t *testing.T, runtimeConfig swg.RuntimeConfig, metadata map[string]any, devMode bool, wantStatus, wantDependency string, wantForwarded, wantCurrentTLSBypass bool, wantTLSRuleID string, wantSuppressedByTLSBypass bool) {
	t.Helper()
	wantDefaultTLSObserved := runtimeConfig.RuntimeTLSDecryptionObserved
	wantDefaultTLSStatus := swg.TlsReadinessRequiredObservedStatus(true, wantDefaultTLSObserved)
	wantMacCATrustObserved := runtimeConfig.MacCATrustObserved
	wantMacCATrustStatus := swg.MacCATrustRequiredStatus(true, wantMacCATrustObserved)
	for key, want := range map[string]any{
		"tls_readiness_precondition_checked":                true,
		"tls_readiness_precondition_status":                 wantStatus,
		"readiness_dependency":                              wantDependency,
		"egress_forwarded":                                  wantForwarded,
		"lab_mode":                                          devMode,
		"tls_readiness_status_path":                         swg.EdgeSWGTLSReadinessStatusPath,
		"tls_readiness_status_version":                      "swg_tls_readiness_status.v1",
		"default_tls_decryption_required":                   true,
		"default_tls_decryption_observed":                   wantDefaultTLSObserved,
		"default_tls_decryption_status":                     wantDefaultTLSStatus,
		"mac_ca_trust_required":                             true,
		"mac_ca_trust_observed":                             wantMacCATrustObserved,
		"mac_ca_trust_status":                               wantMacCATrustStatus,
		"tenant_header_rewrite_dependency_count":            float64(2),
		"per_destination_tls_bypass_required":               true,
		"tls_bypass_rule_count":                             float64(2),
		"current_request_tls_bypass_applied":                wantCurrentTLSBypass,
		"current_request_tls_bypass_rule_id":                wantTLSRuleID,
		"tls_readiness_dependency_suppressed_by_tls_bypass": wantSuppressedByTLSBypass,
		"header_value_material_in_diagnostic":               false,
		"operator_config_value_material_in_diagnostic":      false,
	} {
		if got := metadata[key]; got != want {
			t.Fatalf("readiness precondition metadata[%s] = %#v, want %#v; metadata=%#v", key, got, want, metadata)
		}
	}
	headerNames, ok := metadata["header_names_visible"].([]any)
	if !ok || !sWGValuePresent(headerNames, swghttprewrite.GoogleWorkspaceTenantRestrictionHeader) || !sWGValuePresent(headerNames, swghttprewrite.Microsoft365TenantRestrictionHeader) {
		t.Fatalf("metadata header_names_visible = %#v", metadata["header_names_visible"])
	}
	configRefs, ok := metadata["operator_config_refs_visible"].([]any)
	if !ok || !sWGValuePresent(configRefs, "operator_config_ref:google_workspace_allowed_domains") || !sWGValuePresent(configRefs, "operator_config_ref:microsoft_365_allowed_tenants") {
		t.Fatalf("metadata operator_config_refs_visible = %#v", metadata["operator_config_refs_visible"])
	}
	assertSWGSWGRewriteAuditNoHeaderValues(t, runtimeConfig, metadata)
}

func sWGExpectedPrecondition(runtimeConfig swg.RuntimeConfig, devMode, tlsBypass bool) (string, string) {
	if tlsBypass {
		return "tls_bypass_exempted", "none"
	}
	if !runtimeConfig.RuntimeTLSDecryptionObserved {
		if devMode {
			return "lab_mode_diagnostic_only", edgeplane.EdgeSWGHTTPEgressReadinessReason
		}
		return "readiness_dependency", edgeplane.EdgeSWGHTTPEgressReadinessReason
	}
	if !runtimeConfig.MacCATrustObserved {
		if devMode {
			return "lab_mode_diagnostic_only", edgeplane.EdgeSWGHTTPEgressMacCAReason
		}
		return "readiness_dependency", edgeplane.EdgeSWGHTTPEgressMacCAReason
	}
	return "mac_ca_trust_observed", "none"
}

func sWGValuePresent(values []any, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func sWGTLSBypassRulePresent(rules []any, ruleID string) bool {
	for _, raw := range rules {
		rule, ok := raw.(map[string]any)
		if ok && rule["rule_id"] == ruleID {
			return true
		}
	}
	return false
}

func assertSWGSWGRewriteAuditNoHeaderValues(t *testing.T, runtimeConfig swg.RuntimeConfig, value any) {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal audit value: %v", err)
	}
	body := string(encoded)
	for _, ref := range []string{
		"operator_config_ref:google_workspace_allowed_domains",
		"operator_config_ref:microsoft_365_allowed_tenants",
	} {
		if headerValue, ok := runtimeConfig.TenantRestrictionResolver.ResolveHeaderValue(ref); ok && strings.TrimSpace(headerValue) != "" && strings.Contains(body, headerValue) {
			t.Fatalf("SWG rewrite audit leaked configured header value for %s: %s", ref, body)
		}
	}
}

func TestSWGEdgeSWGHTTPRequestRewriteResultIsProductPathOnly(t *testing.T) {
	harnessConfig, err := swghttprewrite.LoadHarnessConfig(filepath.Join("..", "..", "swghttprewrite", "testdata", "swg_saas_tenant_enforcement_preflight.json"))
	if err != nil {
		t.Fatalf("load harness config: %v", err)
	}
	runtimeConfig, err := swg.LoadRuntimeConfig(swg.RuntimeConfigInput{
		TenantRestrictionOperatorConfigPath: filepath.Join("..", "..", "swghttprewrite", "testdata", "swg_tenant_restriction_operator_config.json"),
		PolicyBundle:                        harnessConfig.PolicyBundle,
	})
	if err != nil {
		t.Fatalf("load SWG runtime config: %v", err)
	}
	evaluator := decision.Evaluator{
		Policies:      harnessConfig.Policies,
		PolicyBundle:  harnessConfig.PolicyBundle,
		EdgeRegionID:  "local",
		EdgeClusterID: "local-edge-a",
	}
	req, err := http.NewRequest(http.MethodGet, "https://mail.google.com/lab/product-egress", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	dec := evaluator.Evaluate(model.DecisionRequest{
		TenantID:        harnessConfig.PolicyBundle.TenantID,
		ActorType:       "human",
		ApplicationID:   edgeplane.EdgeSWGEgressApplicationID,
		Destination:     "mail.google.com",
		DestinationPort: 443,
		Protocol:        "tcp",
		SteeringMode:    "network_extension",
		FQDN:            "mail.google.com",
		SNI:             "mail.google.com",
		ServiceFamily:   "https",
	})
	if dec.PolicyID != "pol_google_workspace_swg_allow_001" {
		t.Fatalf("policy_id = %s, want Google Workspace SWG policy", dec.PolicyID)
	}
	_, result, err := rewriteEdgeSWGHTTPRequest(req, dec, runtimeConfig)
	if err != nil {
		t.Fatalf("rewrite edge SWG request: %v", err)
	}
	if !result.EdgeRuntimeRewritePathObserved ||
		result.LocalHTTPRewriteHarnessObservation ||
		result.RuntimeTLSDecryptionObserved ||
		result.RuntimeHeaderInjectionObserved ||
		result.NetworkExtensionRuntimeUsed ||
		result.HeaderValueMaterialLogged {
		t.Fatalf("rewrite result has wrong observation/claim flags: %#v", result)
	}
	if !result.HeaderApplied || !result.HeaderValueResolved || result.HeaderValueRef != "operator_config_ref:google_workspace_allowed_domains" {
		t.Fatalf("rewrite result did not resolve/apply operator config ref: %#v", result)
	}
}

func TestConnectorSecretMatchesConstantTimeBoundary(t *testing.T) {
	for name, tc := range map[string]struct {
		candidate string
		expected  string
		want      bool
	}{
		"matches":       {candidate: "tenant-secret", expected: "tenant-secret", want: true},
		"trims spaces":  {candidate: " tenant-secret ", expected: "tenant-secret", want: true},
		"rejects empty": {candidate: "", expected: "tenant-secret"},
		"rejects wrong": {candidate: "tenant-secret-2", expected: "tenant-secret"},
	} {
		t.Run(name, func(t *testing.T) {
			if got := connectorSecretMatches(tc.candidate, tc.expected); got != tc.want {
				t.Fatalf("connectorSecretMatches(%q, %q) = %v, want %v", tc.candidate, tc.expected, got, tc.want)
			}
		})
	}
}

func newTestHandler(t *testing.T) http.Handler {
	t.Helper()
	return newTestHandlerWithClient(t, http.DefaultClient)
}

func newTestHandlerWithClient(t *testing.T, proxyClient *http.Client) http.Handler {
	t.Helper()
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	return newServerWithClient(testEvaluator(), writer, connector.NewRegistry(), proxyClient)
}

func testEvaluator() decision.Evaluator {
	return testEvaluatorWithPolicies([]model.Policy{
		{
			ID:       "pol_lab_https_allow_001",
			TenantID: "tenant_lab_001",
			Priority: 100,
			Conditions: map[string]any{
				"actor_type":     "human",
				"application_id": "app_dummy_https",
				"service_family": "https",
			},
			Action: model.PolicyAction{
				Decision: "allow",
			},
			Status: "active",
		},
	})
}

func testEvaluatorWithPolicies(policies []model.Policy) decision.Evaluator {
	return decision.Evaluator{
		Policies: policies,
		PolicyBundle: model.PolicyBundle{
			ID:       "pb_lab_20260522_001",
			TenantID: "tenant_lab_001",
			Version:  "2026.05.22.001",
		},
		EdgeRegionID:  "local",
		EdgeClusterID: "local-edge-001",
	}
}

func assertLogExists(t *testing.T, logDir, filename string) {
	t.Helper()
	info, err := os.Stat(filepath.Join(logDir, filename))
	if err != nil {
		t.Fatalf("stat %s: %v", filename, err)
	}
	if info.Size() == 0 {
		t.Fatalf("%s is empty", filename)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return fn(req)
}

func recorderCookie(rec *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name == name {
			return cookie
		}
	}
	return nil
}

func recorderHasCookie(rec *httptest.ResponseRecorder, name string) bool {
	return recorderCookie(rec, name) != nil
}

type hijackableCONNECTResponseWriter struct {
	header     http.Header
	body       bytes.Buffer
	statusCode int
	clientConn net.Conn
	serverConn net.Conn
	hijacked   bool
}

func newHijackableCONNECTResponseWriter() *hijackableCONNECTResponseWriter {
	clientConn, serverConn := net.Pipe()
	return &hijackableCONNECTResponseWriter{
		header:     http.Header{},
		clientConn: clientConn,
		serverConn: serverConn,
	}
}

func (w *hijackableCONNECTResponseWriter) Header() http.Header {
	return w.header
}

func (w *hijackableCONNECTResponseWriter) Write(payload []byte) (int, error) {
	return w.body.Write(payload)
}

func (w *hijackableCONNECTResponseWriter) WriteHeader(statusCode int) {
	w.statusCode = statusCode
}

func (w *hijackableCONNECTResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if w.hijacked {
		return nil, nil, fmt.Errorf("CONNECT response writer already hijacked")
	}
	w.hijacked = true
	rw := bufio.NewReadWriter(bufio.NewReader(w.serverConn), bufio.NewWriter(w.serverConn))
	return w.serverConn, rw, nil
}

func (w *hijackableCONNECTResponseWriter) close() {
	_ = w.clientConn.Close()
	_ = w.serverConn.Close()
}

func readCONNECTResponse(t *testing.T, conn net.Conn) string {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SetReadDeadline on CONNECT response returned error: %v", err)
	}
	defer conn.SetReadDeadline(time.Time{})
	var response bytes.Buffer
	buf := make([]byte, 1)
	for !strings.Contains(response.String(), "\r\n\r\n") {
		n, err := conn.Read(buf)
		if err != nil {
			t.Fatalf("read CONNECT response returned error: %v", err)
		}
		response.Write(buf[:n])
	}
	return response.String()
}

func sessionStoreForTest() *sessionstore.Store {
	return sessionstore.NewStore()
}

func mustRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey returned error: %v", err)
	}
	return key
}

func signedRS256JWT(t *testing.T, key *rsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	header := map[string]any{"alg": "RS256", "typ": "JWT", "kid": kid}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("marshal jwt header: %v", err)
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal jwt claims: %v", err)
	}
	signingInput := base64.RawURLEncoding.EncodeToString(headerJSON) + "." + base64.RawURLEncoding.EncodeToString(claimsJSON)
	digest := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("sign jwt: %v", err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func rsaPublicJWK(key *rsa.PrivateKey, kid string) map[string]string {
	exponent := big.NewInt(int64(key.PublicKey.E)).Bytes()
	return map[string]string{
		"kty": "RSA",
		"use": "sig",
		"alg": "RS256",
		"kid": kid,
		"n":   base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(exponent),
	}
}

func timeNowUnixPlus(seconds int64) int64 {
	return time.Now().UTC().Add(time.Duration(seconds) * time.Second).Unix()
}

func responseHasCookie(resp *http.Response, name string) bool {
	for _, cookie := range resp.Cookies() {
		if cookie.Name == name {
			return true
		}
	}
	return false
}

func jsonHTTPResponse(status int, value any) *http.Response {
	payload, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return &http.Response{
		StatusCode: status,
		Header:     http.Header{"content-type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewReader(payload)),
	}
}

func contextForTest() context.Context {
	return context.Background()
}
