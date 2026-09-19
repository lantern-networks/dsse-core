package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/enrolledinventory"
	"github.com/lantern-networks/dsse-core/humanidentity"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/revocation"
)

func TestUserRiskHTTPStateAuditAndTenantScope(t *testing.T) {
	directory := humanidentity.NewHumanIdentityDirectoryStore(model.HumanIdentity{TenantID: "tenant_lab_001", ID: "shared", Subject: "alice-subject"}, model.HumanIdentity{TenantID: "tenant_other", ID: "shared", Subject: "alice-subject"}, model.HumanIdentity{TenantID: "tenant_other", ID: "only-other", Subject: "only-other"})
	overlay := revocation.NewHighRiskOverlay()
	gate := &humanIdentityFailSave{base: blobstore.FilePersister{Path: filepath.Join(t.TempDir(), "risk.json")}}
	overlay.SetPersister(gate)
	auth := seedAdminConnectorAPITokenAuth("risk-admin", "risk-admin-bearer", []string{"admin.risk.read", "admin.risk.write"})
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	outbox := &recordingAdminAuditOutboxDeadReader{}
	handler := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), AdminAuth: auth, Writer: writer, AdminAuditOutbox: outbox, HumanIdentities: directory, HighRiskOverlay: overlay})
	send := func(method, path, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer risk-admin-bearer")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, r)
		return rec
	}
	for _, sev := range []string{"medium", "high", "critical", "none"} {
		rec := send("POST", "/admin/risk-signals", `{"entity_type":"user","entity_id":"shared","severity":"`+sev+`","raw_evidence_reference":"do-not-audit"}`)
		if rec.Code != 200 {
			t.Fatalf("%d %s", rec.Code, rec.Body.String())
		}
		own := enrichDecisionRequestWithDeviceRisk(model.DecisionRequest{TenantID: "tenant_lab_001", UserID: "alice-subject"}, nil, overlay)
		want := sev
		if sev == "none" {
			want = ""
		}
		if own.RiskStateSeverity != want {
			t.Fatalf("decision=%s want=%s", own.RiskStateSeverity, want)
		}
		for _, req := range []model.DecisionRequest{{TenantID: "tenant_other", UserID: "shared"}, {TenantID: "tenant_lab_001", DeviceID: "shared"}} {
			if next := enrichDecisionRequestWithDeviceRisk(req, nil, overlay); next.RiskStateSeverity != "" || next.AdminHighRisk {
				t.Fatalf("risk escaped scope: %#v", next)
			}
		}
		get := send("GET", "/admin/risk-signals?entity_type=user", "")
		var b struct {
			HighRisk map[string]string `json:"high_risk"`
		}
		json.Unmarshal(get.Body.Bytes(), &b)
		if get.Code != 200 || b.HighRisk["shared"] != want {
			t.Fatalf("read %d %s", get.Code, get.Body.String())
		}
	}
	before := overlay.ConfigGeneration()
	gate.fail = true
	rec := send("POST", "/admin/risk-signals", `{"entity_type":"user","entity_id":"shared","severity":"high"}`)
	if rec.Code != 503 || strings.Contains(rec.Body.String(), "secret-directory-path") || overlay.ConfigGeneration() != before {
		t.Fatalf("failure %d %s", rec.Code, rec.Body.String())
	}
	gate.fail = false
	// Alias input resolves to the stored canonical ID; opaque wrong-case IDs refuse.
	rec = send("POST", "/admin/risk-signals", `{"entity_type":"human","entity_id":"alice-subject","severity":"high"}`)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"entity_id":"shared"`) {
		t.Fatalf("alias: %d %s", rec.Code, rec.Body.String())
	}
	rec = send("POST", "/admin/risk-signals", `{"entity_type":"user","entity_id":"SHARED","severity":"high"}`)
	if rec.Code != 404 {
		t.Fatalf("wrong case accepted: %d", rec.Code)
	}
	for _, id := range []string{"only-other", "missing"} {
		rec = send("POST", "/admin/risk-signals", `{"entity_type":"user","tenant_id":"tenant_other","entity_id":"`+id+`","severity":"high"}`)
		if rec.Code != 404 {
			t.Fatalf("foreign or missing ID: %d", rec.Code)
		}
	}
	if len(outbox.insertedAudits) != 5 {
		t.Fatalf("domain count %d", len(outbox.insertedAudits))
	}
	for _, a := range outbox.insertedAudits {
		if a.EventType != "user_risk_changed" || a.ActorUserID == nil || *a.ActorUserID != "risk-admin" || a.TargetID == nil || *a.TargetID != "shared" || a.TenantID != "tenant_lab_001" || a.Result == nil || *a.Result != "success" {
			t.Fatalf("audit %#v", a)
		}
		b, _ := json.Marshal(a)
		if strings.Contains(string(b), "do-not-audit") || strings.Contains(string(b), "alice-subject") || strings.Contains(string(b), "risk-admin-bearer") {
			t.Fatal("audit copied request or subject")
		}
	}
}
func TestUserRiskPreservesStrongerSignal(t *testing.T) {
	overlay := revocation.NewHighRiskOverlay()
	overlay.Mark("device", "medium")
	overlay.SetUserRisk(revocation.UserRisk{TenantID: "tenant", ID: "alice", Severity: "critical"})
	req := enrichDecisionRequestWithDeviceRisk(model.DecisionRequest{TenantID: "tenant", DeviceID: "device", UserID: "alice", RiskStateSeverity: "high"}, nil, overlay)
	if req.RiskStateSeverity != "critical" || !req.AdminHighRisk {
		t.Fatalf("severity downgraded: %#v", req)
	}
}
func TestLegacyRiskMigrationAttributionAndRejectedSaves(t *testing.T) {
	for _, scenario := range []string{"person", "device", "two-tenants", "person-and-device", "unknown", "save-failure"} {
		t.Run(scenario, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "risk.json")
			raw := `{"schema_version":"high_risk_overlay_state.v1","devices":{"shared":"high"}}`
			os.WriteFile(path, []byte(raw), 0600)
			gate := &humanIdentityFailSave{base: blobstore.FilePersister{Path: path}, fail: scenario == "save-failure"}
			overlay := revocation.NewHighRiskOverlay()
			overlay.SetPersister(gate)
			directory := humanidentity.NewHumanIdentityDirectoryStore()
			ledger := enrolledinventory.NewLedger()
			if scenario != "unknown" && scenario != "device" {
				directory.Upsert(context.Background(), model.HumanIdentity{ID: "shared", Subject: "subject"}, "one", time.Now())
			}
			if scenario == "two-tenants" {
				directory.Upsert(context.Background(), model.HumanIdentity{ID: "shared", Subject: "subject"}, "two", time.Now())
			}
			if scenario == "device" || scenario == "person-and-device" {
				ledger.Enroll("shared", "one", "", time.Now().Format(time.RFC3339))
			}
			err := prepareUserRiskState(context.Background(), overlay, ledger, directory)
			if scenario == "person" || scenario == "device" {
				if err != nil {
					t.Fatal(err)
				}
				if overlay.Health() != nil {
					t.Fatal("migration unhealthy")
				}
				again := revocation.NewHighRiskOverlay()
				again.SetStatePath(path)
				if again.Health() != nil {
					t.Fatal("restart unhealthy")
				}
				if scenario == "person" {
					if sev, _ := again.UserSeverity("one", "subject"); sev != "high" {
						t.Fatal("migration lost user mark")
					}
					if _, ok := again.IsHighRisk("shared"); ok {
						t.Fatal("user remained in device set")
					}
				} else {
					if sev, _ := again.IsHighRisk("shared"); sev != "high" {
						t.Fatal("device migration lost mark")
					}
				}
			} else {
				if err == nil {
					t.Fatal("ambiguous or rejected migration accepted")
				}
				after, _ := os.ReadFile(path)
				if string(after) != raw || !reflect.DeepEqual(overlay.Snapshot(), map[string]string{"shared": "high"}) {
					t.Fatal("rejected migration modified state")
				}
			}
		})
	}
}

func TestUserRiskFeedRejectsBeforeClearingOtherState(t *testing.T) {
	for _, scenario := range []string{"typed", "clear", "empty-unconfirmed", "old", "invalid", "unknown-version", "missing-version"} {
		t.Run(scenario, func(t *testing.T) {
			overlay := revocation.NewHighRiskOverlay()
			overlay.Mark("device", "high")
			overlay.SetUserRisk(revocation.UserRisk{TenantID: "one", ID: "alice", Severity: "high"})
			admission := revocation.NewAdmissionRevocations()
			admission.ReplaceSynced(map[string]string{"blocked": "admin"})
			feed := revocationFeed{Generation: 10, Epoch: "new", UserRiskVersion: 1, Authoritative: true}
			switch scenario {
			case "typed":
				feed.UserRisk = []revocation.UserRisk{{TenantID: "two", ID: "alice", Subjects: []string{"subject"}, Severity: "critical"}}
			case "empty-unconfirmed":
				feed.Authoritative = false
			case "old":
				feed.UserRiskVersion = 0
			case "invalid":
				feed.UserRisk = []revocation.UserRisk{{ID: "alice", Severity: "high"}}
			case "unknown-version":
				feed.UserRiskVersion = 2
			case "missing-version":
				feed.UserRiskVersion = 0
				feed.UserRisk = []revocation.UserRisk{{TenantID: "two", ID: "alice", Severity: "high"}}
			}
			cp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { json.NewEncoder(w).Encode(feed) }))
			defer cp.Close()
			status := &revocationSyncStatus{}
			source := revocationSource{url: cp.URL, client: cp.Client(), interval: time.Hour, status: status}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan struct{})
			go func() { defer close(done); source.run(ctx, admission, overlay) }()
			deadline := time.Now().Add(5 * time.Second)
			for time.Now().Before(deadline) {
				snap := status.snapshot()
				if snap["have_applied"] == true || snap["consecutive_failures"].(int) > 0 {
					break
				}
				time.Sleep(time.Millisecond)
			}
			cancel()
			<-done
			rejected := scenario == "invalid" || scenario == "unknown-version" || scenario == "missing-version"
			snap := status.snapshot()
			if rejected {
				if snap["have_applied"] != false || snap["consecutive_failures"].(int) != 1 {
					t.Fatalf("invalid feed reported success: %#v", snap)
				}
				if admission.SyncedCount() != 1 {
					t.Fatal("invalid user feed cleared admission")
				}
				if sev, _ := overlay.IsHighRisk("device"); sev != "high" {
					t.Fatal("invalid feed changed device risk")
				}
			} else if snap["have_applied"] != true {
				t.Fatalf("feed not applied: %#v", snap)
			}
			want := "high"
			if scenario == "typed" || scenario == "clear" {
				want = ""
			}
			if sev, _ := overlay.UserSeverity("one", "alice"); sev != want {
				t.Fatalf("cached user=%q want=%q", sev, want)
			}
			if scenario == "typed" {
				if sev, _ := overlay.UserSeverity("two", "subject"); sev != "critical" {
					t.Fatal("typed subject not propagated")
				}
				if _, ok := overlay.IsHighRisk("alice"); ok {
					t.Fatal("user escaped into device namespace")
				}
			}
		})
	}
}

func TestUserRiskWeakSaveAuditAndScopedRead(t *testing.T) {
	directory := humanidentity.NewHumanIdentityDirectoryStore(model.HumanIdentity{TenantID: "tenant_lab_001", ID: "alice", Subject: "alice"})
	overlay := revocation.NewHighRiskOverlay() // deliberately volatile: report partial
	overlay.SetUserRisk(revocation.UserRisk{TenantID: "other", ID: "other-secret", Severity: "critical"})
	auth := seedAdminConnectorAPITokenAuth("risk-admin", "risk-admin-bearer", []string{"admin.risk.read", "admin.risk.write", "admin.endpoints.read"})
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	outbox := &recordingAdminAuditOutboxDeadReader{}
	handler := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), AdminAuth: auth, Writer: writer, AdminAuditOutbox: outbox, HumanIdentities: directory, HighRiskOverlay: overlay})
	request := func(method, path, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer risk-admin-bearer")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	w := request("POST", "/admin/risk-signals", `{"entity_type":"user","entity_id":"alice","severity":"high"}`)
	var response adminRiskSignalResponse
	json.Unmarshal(w.Body.Bytes(), &response)
	if w.Code != 200 || response.NotStoredDurably == "" || response.TenantID != "tenant_lab_001" {
		t.Fatalf("volatile save hidden: %d %s", w.Code, w.Body.String())
	}
	if len(outbox.insertedAudits) != 1 || *outbox.insertedAudits[0].Result != "partial" || outbox.insertedAudits[0].Metadata["user_persistence_warning"] != true {
		t.Fatalf("partial audit missing: %#v", outbox.insertedAudits)
	}
	w = request("GET", "/admin/risk-signals?entity_type=user", "")
	if w.Code != 200 || strings.Contains(w.Body.String(), "other-secret") || !strings.Contains(w.Body.String(), `"alice":"high"`) {
		t.Fatalf("scoped GET: %d %s", w.Code, w.Body.String())
	}
	w = request("GET", "/admin/risk-signals", "")
	if strings.Contains(w.Body.String(), "alice") || strings.Contains(w.Body.String(), "other-secret") {
		t.Fatal("user leaked through device query")
	}
	w = request("GET", "/admin/revocations", "")
	var feed revocationFeed
	json.Unmarshal(w.Body.Bytes(), &feed)
	if w.Code != 200 || feed.UserRiskVersion != 1 || len(feed.UserRisk) != 2 || len(feed.HighRisk) != 0 {
		t.Fatalf("typed feed: %d %s", w.Code, w.Body.String())
	}
}

func TestUserRiskTenantPurgeCountsBothKindsAndRetainsOtherTenants(t *testing.T) {
	path := filepath.Join(t.TempDir(), "risk.json")
	gate := &humanIdentityFailSave{base: blobstore.FilePersister{Path: path}}
	risk := revocation.NewHighRiskOverlay()
	risk.SetPersister(gate)
	risk.Mark("device", "high")
	for _, tenant := range []string{"one", "two"} {
		if _, err := risk.SetUserRisk(revocation.UserRisk{TenantID: tenant, ID: "same", Severity: "high"}); err != nil {
			t.Fatal(err)
		}
	}
	stores := adminTenantExtraStores{HighRisk: risk, DeviceIDs: []string{"device"}}
	footprint := adminTenantFootprint{TenantID: "one"}
	stores.count(&footprint)
	found := false
	for _, row := range footprint.Stores {
		if row.Store == "high_risk_marks" {
			found = true
			if row.Count != 2 {
				t.Fatalf("risk footprint=%d", row.Count)
			}
		}
	}
	if !found {
		t.Fatal("risk footprint missing")
	}
	before, _ := os.ReadFile(path)
	gate.fail = true
	rejected := adminTenantPurgeResult{TenantID: "one"}
	stores.erase(&rejected)
	if len(rejected.Failures) == 0 || risk.CountUsers("one") != 1 {
		t.Fatal("failed purge was not retained")
	}
	saved, _ := os.ReadFile(path)
	if string(saved) != string(before) {
		t.Fatal("failed purge changed saved risk")
	}
	gate.fail = false
	result := adminTenantPurgeResult{TenantID: "one"}
	stores.erase(&result)
	if len(result.Failures) > 0 {
		t.Fatalf("purge failed: %#v", result)
	}
	again := revocation.NewHighRiskOverlay()
	again.SetStatePath(path)
	if again.CountUsers("one") != 0 || again.CountUsers("two") != 1 || len(again.Snapshot()) != 0 {
		t.Fatal("tenant purge erased another tenant or left its own marks")
	}
}
