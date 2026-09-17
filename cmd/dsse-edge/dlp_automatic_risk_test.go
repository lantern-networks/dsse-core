package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/hotstore"
	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/revocation"
	"io"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type automaticDLPTestPersister struct {
	data    []byte
	err     error
	loadErr error
	writes  int
}

func (p *automaticDLPTestPersister) Load() ([]byte, error) { return bytes.Clone(p.data), p.loadErr }
func (p *automaticDLPTestPersister) Save(b []byte) error {
	p.writes++
	if p.err != nil {
		if errors.Is(p.err, blobstore.ErrSavedWithoutAtomicity) && !errors.Is(p.err, blobstore.ErrDurabilityUnconfirmed) {
			p.data = bytes.Clone(b)
		}
		return p.err
	}
	p.data = bytes.Clone(b)
	return nil
}
func automaticDLPTestPolicies(t *testing.T, tenant string) *dlpPolicyObjectStore {
	t.Helper()
	s := newDLPPolicyObjectStore()
	if e := s.Upsert(model.DLPPolicyObject{ID: "risk-policy", TenantID: tenant, OnMatch: "observe", Identifiers: []string{"credit_card", "email"}, DeviceRisk: []model.DLPDeviceRiskCondition{{MinCount: 1, Severity: "medium"}, {MinCount: 1, MinDistinctTypes: 2, Severity: "high"}}}); e != nil {
		t.Fatal(e)
	}
	return s
}
func runAutomaticDLPTestUpload(t *testing.T, config edgeSWGHTTPEgressHandlerConfig, tenant, id string) {
	t.Helper()
	dec := dlpDecWithInspect(id, tenant, "app", "observe", "email", "credit_card")
	dec.DeviceID = stringPtr("risk-device")
	dec.Actions[0].Metadata["dlp_policy_id"] = "risk-policy"
	body := `{"card":"4111111111111111","email":"PRIVATE@example.test"}`
	req := httptest.NewRequest("POST", "https://upload.example.invalid/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	hook := installEdgeSWGHTTPEgressDLP(req, config, dec)
	if hook == nil {
		t.Fatal("no hook")
	}
	sent, e := io.ReadAll(req.Body)
	if e != nil || string(sent) != body {
		t.Fatal("observe changed body", e)
	}
	hook.finalizeObserve(context.Background())
}
func TestAutomaticDLPRiskDiagnosticsAndFindings(t *testing.T) {
	for _, tc := range []struct {
		name             string
		saveErr, loadErr error
		status, result   string
		applied          bool
	}{
		{"saved", nil, nil, "saved", "success", true}, {"save_failed", errors.New("PRIVATE-save"), nil, "unconfirmed", "partial", true},
		{"flush_unknown", errors.Join(blobstore.ErrSavedWithoutAtomicity, blobstore.ErrDurabilityUnconfirmed), nil, "unconfirmed", "partial", true},
		{"in_place", blobstore.ErrSavedWithoutAtomicity, nil, "saved_non_atomic", "partial", true},
		{"unavailable", nil, errors.New("PRIVATE-load"), "not_attempted", "error", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config, events := newDLPTestConfig(t)
			tenant := testEvaluator().PolicyBundle.TenantID
			p := &automaticDLPTestPersister{err: tc.saveErr, loadErr: tc.loadErr}
			risk := revocation.NewHighRiskOverlay()
			_ = risk.SetPersister(p)
			config.DLPDeviceRisk = newDLPDeviceRiskAggregator(risk)
			config.DLPPolicies = automaticDLPTestPolicies(t, tenant)
			runAutomaticDLPTestUpload(t, config, tenant, "first")
			rows := events.ListByTenant(tenant)
			if len(rows) != 2 {
				t.Fatalf("got %d events", len(rows))
			}
			ev := dlpEventByFindingType(rows, "dlp_device_risk")
			match := dlpEventByFindingType(rows, "dlp_match")
			if ev == nil || match == nil || ev.Metadata["condition_severity"] != "high" || ev.Metadata["persistence"] != tc.status || ev.Metadata["applied"] != tc.applied || ev.Metadata["result"] != tc.result {
				t.Fatalf("%+v", ev)
			}
			if *ev.AccessDecisionID != "first" || *ev.DeviceID != "risk-device" || ev.PayloadStored || !ev.Masked || match.Metadata["dlp_action"] != "observe" {
				t.Fatal("event identity or detection changed")
			}
			encoded, _ := json.Marshal(rows)
			for _, secret := range []string{"4111111111111111", "PRIVATE@example.test", "PRIVATE-save", "PRIVATE-load"} {
				if bytes.Contains(encoded, []byte(secret)) {
					t.Fatal("secret leaked")
				}
			}
			p.err, p.loadErr = nil, nil
			if !tc.applied {
				p.data = []byte(`{"schema_version":"high_risk_overlay_state.v2","devices":{}}`)
				if e := risk.SetPersister(p); e != nil {
					t.Fatal(e)
				}
			}
			runAutomaticDLPTestUpload(t, config, tenant, "retry")
			var retry *model.InspectionEvent
			for _, e := range events.ListByTenant(tenant) {
				if e.FindingType != nil && *e.FindingType == "dlp_device_risk" && *e.AccessDecisionID == "retry" {
					copy := e
					retry = &copy
				}
			}
			expected := "saved"
			if tc.status == "saved" || tc.status == "saved_non_atomic" {
				expected = "not_attempted"
			}
			if retry == nil || retry.Metadata["result"] != "success" || retry.Metadata["persistence"] != expected {
				t.Fatalf("retry %+v", retry)
			}
			for _, aggregate := range []bool{false, true} {
				var hot hotstore.Store
				if aggregate {
					hot = hotstore.NewJSONLStore(config.Writer, adminLogStreamFilenameMap())
				}
				h := findingsTestHandler(t, config.Writer, hot, events)
				reply := findingsTestRead(h, "")
				var body struct {
					Findings []any `json:"findings"`
					Summary  struct {
						Total int `json:"total"`
					} `json:"summary"`
				}
				if e := json.Unmarshal(reply.Body.Bytes(), &body); e != nil || reply.Code != 200 || len(body.Findings) != 2 || body.Summary.Total != 2 {
					t.Fatalf("findings double counted %s", reply.Body.String())
				}
			}
		})
	}
}
func TestAutomaticDLPNoMarkerIsNotApplied(t *testing.T) {
	config, events := newDLPTestConfig(t)
	tenant := testEvaluator().PolicyBundle.TenantID
	config.DLPPolicies = automaticDLPTestPolicies(t, tenant)
	config.DLPDeviceRisk = newDLPDeviceRiskAggregator(nil)
	runAutomaticDLPTestUpload(t, config, tenant, "nil-marker")
	ev := dlpEventByFindingType(events.ListByTenant(tenant), "dlp_device_risk")
	if ev == nil || ev.Metadata["applied"] != false || ev.Metadata["result"] != "error" {
		t.Fatal(ev)
	}
}

type automaticDLPDelayedPersister struct{ entered, release chan struct{} }

func (p *automaticDLPDelayedPersister) Load() ([]byte, error) { return nil, nil }
func (p *automaticDLPDelayedPersister) Save([]byte) error {
	close(p.entered)
	<-p.release
	return errors.New("private save failed")
}
func TestAutomaticDLPDetectionPrecedesPendingRiskSave(t *testing.T) {
	config, events := newDLPTestConfig(t)
	tenant := testEvaluator().PolicyBundle.TenantID
	p := &automaticDLPDelayedPersister{make(chan struct{}), make(chan struct{})}
	risk := revocation.NewHighRiskOverlay()
	if e := risk.SetPersister(p); e != nil {
		t.Fatal(e)
	}
	config.DLPDeviceRisk = newDLPDeviceRiskAggregator(risk)
	config.DLPPolicies = automaticDLPTestPolicies(t, tenant)
	done := make(chan struct{})
	go func() { defer close(done); runAutomaticDLPTestUpload(t, config, tenant, "pending") }()
	defer func() {
		close(p.release)
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("upload remained blocked")
		}
	}()
	select {
	case <-p.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("save not entered")
	}
	rows := events.ListByTenant(tenant)
	if len(rows) != 1 || dlpEventByFindingType(rows, "dlp_match") == nil {
		t.Fatal("finding not recorded before save")
	}
	if severity, ok := risk.IsHighRisk("risk-device"); !ok || severity != "high" {
		t.Fatal("pending risk invisible")
	}
	select {
	case <-done:
		t.Fatal("early outcome")
	default:
	}
}
