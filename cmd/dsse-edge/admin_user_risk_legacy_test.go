package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lantern-networks/dsse-core/enrolledinventory"
	"github.com/lantern-networks/dsse-core/humanidentity"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/revocation"
)

func TestUnattributedLegacyRiskStartsAndReachesEdge(t *testing.T) {
	path := filepath.Join(t.TempDir(), "risk.json")
	if err := os.WriteFile(path, []byte(`{"schema_version":"high_risk_overlay_state.v1","devices":{"retired-id":"critical"}}`), 0600); err != nil {
		t.Fatal(err)
	}
	cp := revocation.NewHighRiskOverlay()
	if err := cp.SetStatePath(path); err != nil {
		t.Fatal(err)
	}
	if err := prepareUserRiskState(context.Background(), cp, enrolledinventory.NewLedger(), humanidentity.NewHumanIdentityDirectoryStore()); err != nil {
		t.Fatalf("CP did not start with unattributed v1 mark: %v", err)
	}
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	outbox := &recordingAdminAuditOutboxDeadReader{}
	revoked := revocation.NewAdmissionRevocations()
	revoked.Revoke("blocked-device", "operator")
	handler := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), AdminAuth: newAdminAuthStore(), AdmissionRevocations: revoked, HighRiskOverlay: cp, Writer: writer, AdminAuditOutbox: outbox})
	health := httptest.NewRecorder()
	handler.ServeHTTP(health, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	var healthBody map[string]any
	if health.Code != http.StatusOK || json.Unmarshal(health.Body.Bytes(), &healthBody) != nil || healthBody["legacy_unattributed_risk_count"] != float64(1) {
		t.Fatalf("unattributed risk not visible in healthy CP: status=%d body=%s", health.Code, health.Body.String())
	}
	response := doAdmin(t, handler, http.MethodGet, "/admin/revocations", "")
	var feed revocationFeed
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &feed) != nil ||
		feed.UserRiskVersion != 1 || feed.LegacyRiskVersion != 1 || feed.LegacyUnattributed["retired-id"] != "critical" || feed.HighRisk["retired-id"] != "critical" {
		t.Fatalf("CP feed dropped unresolved raw-ID risk: status=%d body=%s", response.Code, response.Body.String())
	}
	// Decode the actual response with the fields understood by main 603f981's
	// Edge. Its v1 guard runs before revocation application; a v2 feed would
	// discard the entire response, including the operator's device block.
	var oldEdgeFeed struct {
		Revoked         map[string]string     `json:"revoked"`
		HighRisk        map[string]string     `json:"high_risk"`
		UserRiskVersion int                   `json:"user_risk_version"`
		UserRisk        []revocation.UserRisk `json:"user_risk"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &oldEdgeFeed); err != nil || oldEdgeFeed.UserRiskVersion != 1 {
		t.Fatalf("old Edge cannot decode CP feed: %v", err)
	}
	oldEdgeRisk := revocation.NewHighRiskOverlay()
	if err := oldEdgeRisk.ReplaceSyncedUsers(oldEdgeFeed.UserRisk); err != nil {
		t.Fatal(err)
	}
	oldEdgeAdmission := revocation.NewAdmissionRevocations()
	oldEdgeAdmission.ReplaceSynced(oldEdgeFeed.Revoked)
	oldEdgeRisk.ReplaceSynced(oldEdgeFeed.HighRisk)
	if _, ok := oldEdgeAdmission.IsRevoked("blocked-device"); !ok {
		t.Fatal("old Edge lost operator device revocation after CP upgrade")
	}
	if severity, ok := oldEdgeRisk.IsHighRisk("retired-id"); !ok || severity != "critical" {
		t.Fatal("old Edge lost legacy raw-ID device match")
	}
	tenantAuth := seedAdminConnectorAPITokenAuth("tenant-risk-admin", "tenant-risk-token", []string{"admin.risk.read", "admin.risk.write"})
	tenantHandler := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), AdminAuth: tenantAuth, HighRiskOverlay: cp})
	tenantRequest := httptest.NewRequest(http.MethodPost, "/admin/risk-signals/legacy-unattributed/resolve", strings.NewReader(`{"id":"retired-id","expected_severity":"critical","reason":"unverified","confirm_discard":true}`))
	tenantRequest.Header.Set("Authorization", "Bearer tenant-risk-token")
	tenantResponse := httptest.NewRecorder()
	tenantHandler.ServeHTTP(tenantResponse, tenantRequest)
	if tenantResponse.Code != http.StatusForbidden || cp.LegacyUnattributedCount() != 1 {
		t.Fatalf("tenant principal resolved deployment-wide legacy mark: status=%d body=%s", tenantResponse.Code, tenantResponse.Body.String())
	}
	tenantRead := httptest.NewRequest(http.MethodGet, "/admin/risk-signals?entity_type=user", nil)
	tenantRead.Header.Set("Authorization", "Bearer tenant-risk-token")
	tenantReadResponse := httptest.NewRecorder()
	tenantHandler.ServeHTTP(tenantReadResponse, tenantRead)
	if tenantReadResponse.Code != http.StatusOK || strings.Contains(tenantReadResponse.Body.String(), "retired-id") {
		t.Fatalf("tenant principal saw unresolved deployment-wide ID: status=%d body=%s", tenantReadResponse.Code, tenantReadResponse.Body.String())
	}
	operatorRead := doAdmin(t, handler, http.MethodGet, "/admin/risk-signals?entity_type=user", "")
	if operatorRead.Code != http.StatusOK || !strings.Contains(operatorRead.Body.String(), `"retired-id":"critical"`) {
		t.Fatalf("operator cannot inspect unresolved mark: status=%d body=%s", operatorRead.Code, operatorRead.Body.String())
	}
	edge := revocation.NewHighRiskOverlay()
	if err := applyUserRiskFeed(edge, feed); err != nil {
		t.Fatal(err)
	}
	edge.ReplaceSynced(feed.HighRisk)
	if sev, ok := edge.IsHighRisk("retired-id"); !ok || sev != "critical" {
		t.Fatal("Edge lost raw device risk match")
	}
	req, err := enrichDecisionRequestWithDirectoryRisk(context.Background(), model.DecisionRequest{TenantID: "one", UserID: "retired-id"}, nil, edge)
	if err != nil || req.RiskStateSeverity != "critical" || !req.AdminHighRisk {
		t.Fatalf("Edge lost raw user risk match: req=%+v err=%v", req, err)
	}
	if err := applyUserRiskFeed(edge, revocationFeed{UserRiskVersion: 1, LegacyUnattributed: map[string]string{"other": "high"}}); err == nil {
		t.Fatal("old feed version accepted unresolved marks")
	}
	if err := applyUserRiskFeed(edge, revocationFeed{UserRiskVersion: 1, Authoritative: true}); err != nil || edge.LegacyUnattributedCount() != 1 {
		t.Fatal("older authority cleared existing unresolved marks or blocked revocations")
	}
	if err := applyUserRiskFeed(edge, revocationFeed{UserRiskVersion: 1, LegacyRiskVersion: 1, Authoritative: true}); err != nil || edge.LegacyUnattributedCount() != 0 {
		t.Fatal("new authority could not explicitly clear unresolved marks")
	}
	if err := applyUserRiskFeed(edge, feed); err != nil {
		t.Fatal(err)
	}
	if err := applyUserRiskFeed(edge, revocationFeed{UserRiskVersion: 2, LegacyUnattributed: map[string]string{"bad ": "high"}}); err == nil {
		t.Fatal("invalid raw-ID mark accepted")
	}
	if edge.LegacyUnattributedCount() != 1 || edge.LegacySeverity("retired-id") != "critical" {
		t.Fatal("bad feed changed confirmed risk")
	}
	if _, err := cp.SetUserRisk(revocation.UserRisk{TenantID: "one", ID: "alice", Severity: "high"}); err != nil {
		t.Fatal(err)
	}
	reloaded := revocation.NewHighRiskOverlay()
	if err := reloaded.SetStatePath(path); err != nil || reloaded.LegacyUnattributedCount() != 1 || reloaded.CountUsers("one") != 1 {
		t.Fatalf("normal risk edit erased unresolved v1 mark: %v", err)
	}
	reloaded.Clear("retired-id") // an ordinary device clear must not resolve an unattributed raw mark
	afterClear := revocation.NewHighRiskOverlay()
	if err := afterClear.SetStatePath(path); err != nil || afterClear.LegacyUnattributedCount() != 1 || afterClear.CountUsers("one") != 1 {
		t.Fatalf("device clear erased unresolved risk: %v", err)
	}
	stale := doAdmin(t, handler, http.MethodPost, "/admin/risk-signals/legacy-unattributed/resolve", `{"id":"retired-id","expected_severity":"high","reason":"verified","confirm_discard":true}`)
	if stale.Code != http.StatusConflict || cp.LegacyUnattributedCount() != 1 {
		t.Fatalf("stale resolution changed risk: status=%d body=%s", stale.Code, stale.Body.String())
	}
	missingConfirmation := doAdmin(t, handler, http.MethodPost, "/admin/risk-signals/legacy-unattributed/resolve", `{"id":"retired-id","expected_severity":"critical","reason":"verified"}`)
	if missingConfirmation.Code != http.StatusBadRequest || cp.LegacyUnattributedCount() != 1 {
		t.Fatalf("unconfirmed resolution changed risk: status=%d body=%s", missingConfirmation.Code, missingConfirmation.Body.String())
	}
	resolved := doAdmin(t, handler, http.MethodPost, "/admin/risk-signals/legacy-unattributed/resolve", `{"id":"retired-id","expected_severity":"critical","reason":"verified","confirm_discard":true}`)
	if resolved.Code != http.StatusOK || cp.LegacyUnattributedCount() != 0 {
		t.Fatalf("operator could not resolve risk: status=%d body=%s", resolved.Code, resolved.Body.String())
	}
	var foundAudit bool
	for _, audit := range outbox.insertedAudits {
		if audit.EventType != "legacy_unattributed_risk_discarded" {
			continue
		}
		foundAudit = true
		data, _ := json.Marshal(audit)
		if strings.Contains(string(data), "retired-id") || strings.Contains(string(data), "verified") || audit.TargetID == nil || len(*audit.TargetID) != 64 {
			t.Fatalf("resolution audit exposed raw ID or reason: %s", data)
		}
	}
	if !foundAudit {
		t.Fatal("resolution produced no audit record")
	}
	final := revocation.NewHighRiskOverlay()
	if err := final.SetStatePath(path); err != nil || final.LegacyUnattributedCount() != 0 || final.CountUsers("one") != 1 {
		t.Fatalf("resolution did not persist: %v", err)
	}
}

func TestLegacyRiskStartsWithoutLocalDirectoryOrLedger(t *testing.T) {
	path := filepath.Join(t.TempDir(), "risk.json")
	if err := os.WriteFile(path, []byte(`{"schema_version":"high_risk_overlay_state.v1","devices":{"edge-only-id":"high"}}`), 0600); err != nil {
		t.Fatal(err)
	}
	overlay := revocation.NewHighRiskOverlay()
	if err := overlay.SetStatePath(path); err != nil {
		t.Fatal(err)
	}
	if err := prepareUserRiskState(context.Background(), overlay, nil, nil); err != nil || overlay.Health() != nil || overlay.LegacySeverity("edge-only-id") != "high" {
		t.Fatalf("Edge failed startup without stale local attribution data: %v", err)
	}
}
