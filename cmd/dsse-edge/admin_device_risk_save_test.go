package main

import (
	"encoding/json"
	"errors"
	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/device"
	"github.com/lantern-networks/dsse-core/enrolledinventory"
	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/revocation"
	"net/http"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

type deviceOverlaySavePersister struct {
	base   blobstore.Persister
	err    error
	retain bool
}

func (p *deviceOverlaySavePersister) Load() ([]byte, error) { return p.base.Load() }
func (p *deviceOverlaySavePersister) Save(b []byte) error {
	if p.err != nil && !p.retain {
		return p.err
	}
	if err := p.base.Save(b); err != nil {
		return err
	}
	return p.err
}
func TestDeviceRiskOverlaySavePrecedesRuntimeAndAudit(t *testing.T) {
	for _, mode := range []string{"no_write", "bridge", "in_place"} {
		for _, severity := range []string{"critical", "medium", "none"} {
			t.Run(mode+"/"+severity, func(t *testing.T) {
				handler, writer, overlay, _, runtime, runtimePersistence := deviceRiskAuditHandler(t)
				p := &deviceOverlaySavePersister{base: blobstore.FilePersister{Path: filepath.Join(t.TempDir(), "risk.json")}}
				overlay.SetPersister(p)
				overlay.Mark("owned-device", "high")
				overlay.Mark("other-device", "critical")
				if _, err := overlay.SetUserRisk(revocation.UserRisk{TenantID: "tenant_other", ID: "owned-device", Severity: "medium"}); err != nil {
					t.Fatal(err)
				}
				if _, _, _, err := runtime.ApplyRiskSignal("owned-device", model.RiskSignal{EntityType: "device", EntityID: "owned-device", Severity: "high"}, time.Now()); err != nil {
					t.Fatal(err)
				}
				beforeRuntime, _ := runtime.Get("owned-device")
				savedRuntime, _ := runtimePersistence.Load()
				gen := overlay.ConfigGeneration()
				p.err = errors.New("private-overlay-location")
				if mode == "bridge" {
					p.err = errors.Join(blobstore.ErrSavedWithoutAtomicity, blobstore.ErrDurabilityUnconfirmed)
					p.retain = true
				}
				if mode == "in_place" {
					p.err = blobstore.ErrSavedWithoutAtomicity
					p.retain = true
				}
				body := `{"entity_type":"device","entity_id":"owned-device","severity":"` + severity + `","evidence_ref":"private-request"}`
				r := deviceRiskRequest(handler, body, transportAuditBearer)
				accepted := mode == "in_place"
				if r.Code != map[bool]int{true: 200, false: 503}[accepted] {
					t.Fatal(r.Code, r.Body.String())
				}
				if strings.Contains(r.Body.String(), "private-overlay-location") {
					t.Fatal("private error escaped")
				}
				current, _ := runtime.Get("owned-device")
				disk, _ := runtimePersistence.Load()
				if !accepted && (!reflect.DeepEqual(beforeRuntime, current) || string(disk) != string(savedRuntime) || overlay.Snapshot()["owned-device"] != "high" || overlay.ConfigGeneration() != gen) {
					t.Fatal("refused operation touched runtime or overlay")
				}
				rows := readTransportAudits(t, writer)
				if !accepted {
					if len(rows) != 2 {
						t.Fatal("missing failure audits")
					}
					failed := false
					for _, a := range rows {
						if stringPtrValue(a.Result) != "error" {
							t.Fatal("failure reported success")
						}
						if a.EventType == "device_risk_change_failed" {
							failed = true
							if stringPtrValue(a.TargetID) != "owned-device" || a.Metadata["applied"] != false || a.Metadata["requested_severity"] != severity {
								t.Fatal("failure context missing")
							}
						}
					}
					if !failed {
						t.Fatal("no device failure audit")
					}
				} else {
					var resp adminRiskSignalResponse
					if err := json.Unmarshal(r.Body.Bytes(), &resp); err != nil {
						t.Fatal(err)
					}
					if !resp.OverlayPersistenceWarning || resp.RuntimePersistenceWarning || resp.NotStoredDurably == "" {
						t.Fatal("wrong warning source")
					}
					if len(rows) != 2 {
						t.Fatal("missing accepted audits")
					}
					var domain bool
					for _, a := range rows {
						if a.EventType == "device_risk_changed" {
							domain = true
							if stringPtrValue(a.Result) != "partial" || a.Metadata["overlay_persistence_warning"] != true || a.Metadata["runtime_persistence_warning"] != false {
								t.Fatal("warning attribution")
							}
						}
					}
					if !domain {
						t.Fatal("no domain audit")
					}
				}
				for _, a := range rows {
					if stringPtrValue(a.ActorUserID) != "transport-admin" || a.TenantID != "tenant_lab_001" {
						t.Fatal("wrong actor/tenant")
					}
				}
				p.err = nil
				r = deviceRiskRequest(handler, body, transportAuditBearer)
				if r.Code != 200 {
					t.Fatal("retry failed", r.Code, r.Body)
				}
				if overlay.ConfigGeneration() != gen+1 {
					t.Fatal("same-value retry generation churn")
				}
				reload := revocation.NewHighRiskOverlay()
				reload.SetPersister(p)
				restoredRuntime := device.NewStore()
				if err := restoredRuntime.SetPersister(runtimePersistence); err != nil {
					t.Fatal(err)
				}
				effective := enrichDecisionRequestWithDeviceRisk(model.DecisionRequest{DeviceID: "owned-device", TenantID: "tenant_lab_001"}, restoredRuntime, reload)
				if effective.RiskStateSeverity != severity || effective.AdminHighRisk != (severity == "critical") {
					t.Fatal("restored effective risk differs", effective.RiskStateSeverity, effective.AdminHighRisk)
				}
				if reload.Snapshot()["other-device"] != "critical" || reload.CountUsers("tenant_other") != 1 {
					t.Fatal("foreign changed")
				}
			})
		}
	}
}
func TestDeviceRiskMissingOverlayDoesNotApplyRuntime(t *testing.T) {
	store := device.NewStore()
	_, err := store.Register(model.Device{ID: "device", TenantID: "tenant_lab_001"}, testEvaluator().PolicyBundle, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	handler := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), DeviceStore: store})
	r := deviceRiskRequest(handler, `{"entity_type":"device","entity_id":"device","severity":"high"}`, "")
	if r.Code != http.StatusServiceUnavailable {
		t.Fatal(r.Code, r.Body.String())
	}
	dev, _ := store.Get("device")
	if dev.Metadata["risk_state_severity"] != nil {
		t.Fatal("runtime changed without overlay")
	}
}

func TestDeviceRiskReportsBothSaveWarnings(t *testing.T) {
	handler, writer, overlay, _, _, runtimeSave := deviceRiskAuditHandler(t)
	p := &deviceOverlaySavePersister{base: blobstore.FilePersister{Path: filepath.Join(t.TempDir(), "risk.json")}, err: blobstore.ErrSavedWithoutAtomicity, retain: true}
	overlay.SetPersister(p)
	runtimeSave.fail.Store(true)
	body := `{"entity_type":"device","entity_id":"owned-device","severity":"high"}`
	r := deviceRiskRequest(handler, body, transportAuditBearer)
	if r.Code != 200 {
		t.Fatal(r.Code, r.Body.String())
	}
	var resp adminRiskSignalResponse
	if err := json.Unmarshal(r.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if !resp.OverlayPersistenceWarning || !resp.RuntimePersistenceWarning || resp.NotStoredDurably == "" {
		t.Fatal("lost one partial save outcome")
	}
	rows := readTransportAudits(t, writer)
	if len(rows) != 2 {
		t.Fatal("audit count")
	}
	for _, a := range rows {
		if a.EventType == "device_risk_changed" && (stringPtrValue(a.Result) != "partial" || a.Metadata["runtime_persistence_warning"] != true || a.Metadata["overlay_persistence_warning"] != true) {
			t.Fatal("wrong warning sources")
		}
	}
	p.err = nil
	runtimeSave.fail.Store(false)
	r = deviceRiskRequest(handler, body, transportAuditBearer)
	if r.Code != 200 || strings.Contains(r.Body.String(), "not_stored_durably") {
		t.Fatal("retry still partial", r.Code, r.Body.String())
	}
}
func TestDeviceRiskWithoutRuntimeReportStillUsesCheckedOverlay(t *testing.T) {
	now := time.Now().UTC()
	runtime := device.NewStore()
	overlay := revocation.NewHighRiskOverlay()
	overlay.SetStatePath(filepath.Join(t.TempDir(), "risk.json"))
	ledger := enrolledinventory.NewLedger()
	if _, err := ledger.Enroll("owned", "tenant_lab_001", "", now.Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	auth := newAdminAuthStore()
	auth.UpsertPrincipal(adminPrincipal{ID: "review-admin", TenantID: "tenant_lab_001", Roles: []string{"admin"}, Status: "active"})
	auth.UpsertAPIToken(adminAPIToken{ID: "review-token", TenantID: "tenant_lab_001", CreatedByAdminPrincipalID: "review-admin", Roles: []string{"admin"}, Scopes: []string{"*"}, Status: "active", TokenHash: adminTokenHash("synthetic-cold-runtime"), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339)})
	handler := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), DeviceStore: runtime, HighRiskOverlay: overlay, EnrolledLedger: ledger, AdminAuth: auth})
	r := deviceRiskRequest(handler, `{"entity_type":"device","entity_id":"owned","severity":"critical"}`, "synthetic-cold-runtime")
	if r.Code != 200 || overlay.Snapshot()["owned"] != "critical" {
		t.Fatal(r.Code, r.Body.String())
	}
	if _, exists := runtime.Get("owned"); exists {
		t.Fatal("fabricated runtime report")
	}
	if strings.Contains(r.Body.String(), "not_stored_durably") {
		t.Fatal("false save warning")
	}
}

func TestDeviceRiskRuntimeUnconfirmedSaveProducesPartialAudit(t *testing.T) {
	for _, tc := range []struct {
		name    string
		err     error
		warning bool
	}{
		{"synced_nonatomic", blobstore.ErrSavedWithoutAtomicity, false},
		{"unconfirmed", blobstore.ErrDurabilityUnconfirmed, true},
		{"joined", errors.Join(blobstore.ErrSavedWithoutAtomicity, blobstore.ErrDurabilityUnconfirmed), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, w, overlay, _, runtime, _ := deviceRiskAuditHandler(t)
			p := &deviceOverlaySavePersister{base: blobstore.FilePersister{Path: filepath.Join(t.TempDir(), "runtime.json")}, err: tc.err, retain: true}
			if err := runtime.SetPersister(p); err != nil {
				t.Fatal(err)
			}
			r := deviceRiskRequest(h, `{"entity_type":"device","entity_id":"owned-device","severity":"high"}`, transportAuditBearer)
			if r.Code != 200 {
				t.Fatal(r.Code, r.Body)
			}
			var out adminRiskSignalResponse
			if err := json.Unmarshal(r.Body.Bytes(), &out); err != nil {
				t.Fatal(err)
			}
			if !out.Applied || out.RuntimePersistenceWarning != tc.warning || out.OverlayPersistenceWarning || (out.NotStoredDurably != "") != tc.warning {
				t.Fatalf("wrong partial outcome: %+v", out)
			}
			if overlay.Snapshot()["owned-device"] != "high" {
				t.Fatal("durable overlay lost")
			}
			restored := device.NewStore()
			if err := restored.SetPersister(p.base); err != nil {
				t.Fatal(err)
			}
			d, _ := restored.Get("owned-device")
			if d.Metadata["risk_state_severity"] != "high" {
				t.Fatal("candidate not written before error")
			}
			rows := readTransportAudits(t, w)
			if len(rows) != 2 {
				t.Fatal("audit count", len(rows))
			}
			domain := false
			for _, a := range rows {
				if a.EventType == "device_risk_changed" {
					domain = true
					want := "success"
					if tc.warning {
						want = "partial"
					}
					if stringPtrValue(a.Result) != want || a.Metadata["runtime_persistence_warning"] != tc.warning {
						t.Fatal("audit does not explain runtime persistence", a)
					}
				}
			}
			if !domain {
				t.Fatal("domain audit absent")
			}
			p.err = nil
			r = deviceRiskRequest(h, `{"entity_type":"device","entity_id":"owned-device","severity":"high"}`, transportAuditBearer)
			if r.Code != 200 {
				t.Fatal("retry", r.Code)
			}
			out = adminRiskSignalResponse{}
			if err := json.Unmarshal(r.Body.Bytes(), &out); err != nil {
				t.Fatal(err)
			}
			if out.RuntimePersistenceWarning {
				t.Fatal("confirmed retry still warns")
			}
		})
	}
}
