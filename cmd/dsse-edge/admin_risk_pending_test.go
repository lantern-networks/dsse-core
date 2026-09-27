package main

import (
	"encoding/json"
	"errors"
	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/revocation"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"
)

func riskPendingRead(t *testing.T, h http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		r := httptest.NewRequest("GET", path, nil)
		r.Header.Set("Authorization", "Bearer "+transportAuditBearer)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		done <- w
	}()
	select {
	case w := <-done:
		return w
	case <-time.After(2 * time.Second):
		t.Fatal("risk read waited on storage")
		return nil
	}
}
func assertPendingRiskReads(t *testing.T, h http.Handler, severity string) {
	t.Helper()
	for _, query := range []string{"", "?entity_type=user"} {
		w := riskPendingRead(t, h, "/admin/risk-signals"+query)
		if w.Code != 200 {
			t.Fatal(w.Code, w.Body.String())
		}
		var b struct {
			Risk map[string]string `json:"high_risk"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &b); err != nil {
			t.Fatal(err)
		}
		id, want := "owned-device", severity
		if query != "" {
			id, want = "alice", "high"
		}
		if len(b.Risk) != 1 || b.Risk[id] != want {
			t.Fatal("wrong scoped risk", b)
		}
	}
	w := riskPendingRead(t, h, "/admin/enrolled-devices")
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var b struct {
		Devices []struct {
			ID   string `json:"identity"`
			Risk string `json:"effective_risk"`
		} `json:"devices"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &b); err != nil {
		t.Fatal(err)
	}
	if len(b.Devices) != 1 || b.Devices[0].ID != "owned-device" || b.Devices[0].Risk != severity {
		t.Fatal("wrong effective risk", b)
	}
}
func TestDeviceRiskReadsAndDecisionContinueDuringPendingSave(t *testing.T) {
	for _, severity := range []string{"critical", "medium", "none"} {
		for _, failed := range []bool{false, true} {
			name := severity + "/ok"
			if failed {
				name = severity + "/failed"
			}
			t.Run(name, func(t *testing.T) {
				h, w, o, _, runtime, _ := deviceRiskAuditHandler(t)
				o.Mark("owned-device", "high")
				o.Mark("other-device", "critical")
				for _, mark := range []revocation.UserRisk{{TenantID: "tenant_lab_001", ID: "alice", Severity: "high"}, {TenantID: "tenant_other", ID: "alice", Severity: "critical"}} {
					if _, err := o.SetUserRisk(mark); err != nil {
						t.Fatal(err)
					}
				}
				beforeRuntime := runtime.List()
				gen := o.ConfigGeneration()
				p := &pendingAdmissionPersister{entered: make(chan struct{}), release: make(chan struct{})}
				if failed {
					p.err = errors.New("private delayed backend")
				}
				var once sync.Once
				release := func() { once.Do(func() { close(p.release) }) }
				t.Cleanup(release)
				if err := o.SetPersister(p); err != nil {
					t.Fatal(err)
				}
				done := make(chan *httptest.ResponseRecorder, 1)
				go func() {
					done <- deviceRiskRequest(h, `{"entity_type":"device","entity_id":"owned-device","severity":"`+severity+`"}`, transportAuditBearer)
				}()
				select {
				case <-p.entered:
				case <-time.After(2 * time.Second):
					t.Fatal("save not reached")
				}
				assertPendingRiskReads(t, h, "high")
				decision := make(chan model.DecisionRequest, 1)
				go func() {
					decision <- enrichDecisionRequestWithDeviceRisk(model.DecisionRequest{DeviceID: "owned-device", TenantID: "tenant_lab_001"}, runtime, o)
				}()
				select {
				case d := <-decision:
					if d.RiskStateSeverity != "high" {
						t.Fatal("pending decision risk", d)
					}
				case <-time.After(2 * time.Second):
					t.Fatal("decision waited for saving")
				}
				if !reflect.DeepEqual(beforeRuntime, runtime.List()) || o.ConfigGeneration() != gen {
					t.Fatal("pending operation published state")
				}
				select {
				case <-done:
					t.Fatal("early POST acknowledgement")
				default:
				}
				if b, err := os.ReadFile(filepath.Join(w.Dir(), "audit.log.jsonl")); err != nil && !os.IsNotExist(err) {
					t.Fatal(err)
				} else if len(b) > 0 {
					t.Fatal("pending operation logged completed audit")
				}
				release()
				var resp *httptest.ResponseRecorder
				select {
				case resp = <-done:
				case <-time.After(2 * time.Second):
					t.Fatal("POST did not finish")
				}
				want := 200
				if failed {
					want = 503
				}
				if resp.Code != want {
					t.Fatal(resp.Code, resp.Body.String())
				}
				if failed && (!reflect.DeepEqual(beforeRuntime, runtime.List()) || o.Snapshot()["owned-device"] != "high" || o.ConfigGeneration() != gen) {
					t.Fatal("failed write published change")
				}
				audits := readTransportAudits(t, w)
				if len(audits) != 2 {
					t.Fatal("audit count", len(audits))
				}
				for _, a := range audits {
					result := "success"
					if failed {
						result = "error"
					}
					if stringPtrValue(a.Result) != result || stringPtrValue(a.ActorUserID) != "transport-admin" || a.TenantID != "tenant_lab_001" {
						t.Fatal("audit attribution/result", a)
					}
				}
			})
		}
	}
}

type riskPendingLoad struct {
	entered, release chan struct{}
	data             []byte
	err              error
}

func (p *riskPendingLoad) Load() ([]byte, error) { close(p.entered); <-p.release; return p.data, p.err }
func (p *riskPendingLoad) Save([]byte) error     { return nil }
func TestRiskHTTPReadsDuringExplicitRestoration(t *testing.T) {
	for _, failed := range []bool{false, true} {
		t.Run(map[bool]string{false: "ok", true: "failed"}[failed], func(t *testing.T) {
			h, _, o, _, _, _ := deviceRiskAuditHandler(t)
			o.Mark("owned-device", "high")
			if _, err := o.SetUserRisk(revocation.UserRisk{TenantID: "tenant_lab_001", ID: "alice", Severity: "high"}); err != nil {
				t.Fatal(err)
			}
			p := &riskPendingLoad{entered: make(chan struct{}), release: make(chan struct{}), data: []byte(`{"schema_version":"high_risk_overlay_state.v2","devices":{"owned-device":"medium"},"users":{"tenant_lab_001\u0000alice":{"tenant_id":"tenant_lab_001","id":"alice","severity":"high"}}}`)}
			if failed {
				p.err = errors.New("private load error")
			}
			var once sync.Once
			release := func() { once.Do(func() { close(p.release) }) }
			t.Cleanup(release)
			done := make(chan error, 1)
			go func() { done <- o.SetPersister(p) }()
			select {
			case <-p.entered:
			case <-time.After(2 * time.Second):
				t.Fatal("load not entered")
			}
			assertPendingRiskReads(t, h, "high")
			release()
			select {
			case err := <-done:
				if (err != nil) != failed {
					t.Fatal(err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("restore did not finish")
			}
			if failed {
				for _, query := range []string{"", "?entity_type=user"} {
					if r := riskPendingRead(t, h, "/admin/risk-signals"+query); r.Code != 503 {
						t.Fatal("failed restoration read healthy", r.Code)
					}
				}
			} else {
				assertPendingRiskReads(t, h, "medium")
			}
		})
	}
}
