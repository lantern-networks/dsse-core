package main

import (
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/enrolledinventory"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/policy"
)

func TestIncomingPartialUpdatePreservesRestrictions(t *testing.T) {
	tenant := testEvaluator().PolicyBundle.TenantID
	s := policy.NewStore(nil)
	path := filepath.Join(t.TempDir(), "state.json")
	if err := s.SetRuntimeStatePersister(blobstore.FilePersister{Path: path}); err != nil {
		t.Fatal(err)
	}
	w, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	h := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), PolicyStore: s, Writer: w, AdminAuth: newAdminAuthStore()})
	call := func(body string, status int) model.LegacyException {
		t.Helper()
		r := httptest.NewRecorder()
		h.ServeHTTP(r, httptest.NewRequest("POST", "/admin/legacy-exceptions", strings.NewReader(body)))
		if r.Code != status {
			t.Fatalf("%d: %s", r.Code, r.Body)
		}
		var ex model.LegacyException
		if status == 200 {
			if err := json.Unmarshal(r.Body.Bytes(), &ex); err != nil {
				t.Fatal(err)
			}
		}
		return ex
	}
	before := call(`{"id":"same","business_owner":"owner","expires_at":"2027-01-01T12:34:56Z","source_server":"10.0.0.1","device_group":"QA","service_family":"ssh","protocol":"tcp","port":22,"approval_required":true,"max_session_seconds":60,"mode":"deny","status":"disabled"}`, 200)
	after := call(`{"id":"same","business_owner":"changed"}`, 200)
	want := before
	want.BusinessOwner = "changed"
	if !reflect.DeepEqual(after, want) {
		t.Fatalf("constraints lost: %+v", after)
	}
	for _, body := range []string{`{"id":"same","port":null}`, `{"id":"same","status":"active"}`, `{"id":"same","protocol":"udp"}`, `{"id":"same","port":65536}`, `{"id":"same","status":"unknown"}`, `{"id":"same","mode":"typo"}`, `{"id":"same","expires_at":"bad"}`, `{"id":"same","protcol":"tcp"}`} {
		gen := s.ConfigGeneration()
		call(body, 400)
		if !reflect.DeepEqual(s.LegacyExceptionsFor(tenant), []model.LegacyException{want}) || s.ConfigGeneration() != gen {
			t.Fatal("refusal mutated record")
		}
	}
	fresh := policy.NewStore(nil)
	if err := fresh.SetRuntimeStatePersister(blobstore.FilePersister{Path: path}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(fresh.LegacyExceptionsFor(tenant), []model.LegacyException{want}) {
		t.Fatal("restart lost fields")
	}
	explicit := call(`{"id":"same","source_server":"","device_group":"","service_family":"","protocol":"","port":0,"approval_required":false,"max_session_seconds":0,"mode":"allow","status":"active"}`, 200)
	if explicit.SourceServer != "" || explicit.Port != 0 || explicit.ApprovalRequired || explicit.Status != "active" || explicit.ExpiresAt != want.ExpiresAt {
		t.Fatalf("explicit reset failed: %+v", explicit)
	}
	rows := readTransportAudits(t, w)
	success, failure := 0, 0
	for _, a := range rows {
		if a.EventType == "admin_incoming_changed" {
			if stringPtrValue(a.Result) == "success" {
				success++
			} else {
				failure++
			}
		}
	}
	if success != 3 || failure != 8 {
		t.Fatalf("audits success=%d failure=%d", success, failure)
	}
}

func TestIncomingExportRefusesUnsupportedWholePolicy(t *testing.T) {
	now := time.Now()
	good := model.LegacyException{ID: "wide-allow", Status: "active", Mode: "allow", ExpiresAt: now.Add(time.Hour).UTC().Format(time.RFC3339)}
	for name, change := range map[string]func(*model.LegacyException){
		"unknown-family": func(x *model.LegacyException) { x.ServiceFamily = "udp" },
		"udp":            func(x *model.LegacyException) { x.Protocol = "udp"; x.Port = 53 },
		"expiry":         func(x *model.LegacyException) { x.ExpiresAt = "bad" },
		"missing-expiry": func(x *model.LegacyException) { x.ExpiresAt = "" },
		"mode":           func(x *model.LegacyException) { x.Mode = "typo" },
		"status":         func(x *model.LegacyException) { x.Status = "typo" },
		"port":           func(x *model.LegacyException) { x.Port = 65536 },
		"unscoped-port":  func(x *model.LegacyException) { x.Port = 22 },
		"approval":       func(x *model.LegacyException) { x.ApprovalRequired = true },
		"session-limit":  func(x *model.LegacyException) { x.MaxSessionSeconds = 60 },
	} {
		t.Run(name, func(t *testing.T) {
			bad := good
			bad.ID = "restricted-deny"
			bad.Mode = "deny"
			change(&bad)
			exp, err := buildServerInitiatedExport([]model.LegacyException{good, bad}, now)
			if err == nil || exp.RuleCount != 0 || len(exp.Rules) != 0 {
				t.Fatalf("partial or widened export: %+v %v", exp, err)
			}
		})
	}
	for _, status := range []string{"disabled", "expired"} {
		bad := good
		bad.ID = "inactive-udp"
		bad.Protocol = "udp"
		if status == "expired" {
			bad.ExpiresAt = now.Add(-time.Hour).UTC().Format(time.RFC3339)
		} else {
			bad.Status = status
		}
		exp, err := buildServerInitiatedExport([]model.LegacyException{good, bad}, now)
		if err != nil || len(exp.Rules) != 1 {
			t.Fatalf("inactive: %+v %v", exp, err)
		}
	}
}

func TestIncomingExportAdminAndDeviceRefuseSameUnsafeState(t *testing.T) {
	tenant := testEvaluator().PolicyBundle.TenantID
	s := policy.NewStore(nil)
	s.UpsertLegacyException(tenant, model.LegacyException{ID: "bad", Status: "active", Mode: "allow", Protocol: "udp", Port: 53, ExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339)})
	if err := s.SetServerInitiatedEnabledConfirmed(tenant, true); err != nil {
		t.Fatal(err)
	}
	ledger := enrolledinventory.NewLedger()
	if _, err := ledger.Enroll("local-device", tenant, "", time.Now().UTC().Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	h := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), PolicyStore: s, EnrolledLedger: ledger, AdminAuth: newAdminAuthStore()})
	for _, enabled := range []bool{true, false} {
		if err := s.SetServerInitiatedEnabledConfirmed(tenant, enabled); err != nil {
			t.Fatal(err)
		}
		a := httptest.NewRecorder()
		h.ServeHTTP(a, httptest.NewRequest("GET", "/admin/legacy-exceptions/export", nil))
		d := asVerifiedDevice(t, h, "local-device", "/steer/server-initiated-export")
		for _, r := range []*httptest.ResponseRecorder{a, d} {
			if enabled {
				if r.Code != 503 || strings.Contains(r.Body.String(), `"rules"`) {
					t.Fatalf("unsafe output %d %s", r.Code, r.Body)
				}
			} else {
				if r.Code != 200 {
					t.Fatal(r.Body)
				}
				var exp serverInitiatedExport
				if err := json.Unmarshal(r.Body.Bytes(), &exp); err != nil {
					t.Fatal(err)
				}
				if exp.DefaultAction != "allow" || len(exp.Rules) != 0 {
					t.Fatal("off did not withdraw")
				}
			}
		}
	}
}

func TestIncomingLegacyUnsupportedRecordCanBeDisabled(t *testing.T) {
	s := policy.NewStore(nil)
	tenant := testEvaluator().PolicyBundle.TenantID
	old := model.LegacyException{ID: "old", TenantID: tenant, BusinessOwner: "owner", Status: "active", Protocol: "udp", Mode: "allow", Port: 53, ExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339)}
	if err := s.UpsertLegacyExceptionConfirmed(tenant, old); err != nil {
		t.Fatal(err)
	}
	h := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), PolicyStore: s, AdminAuth: newAdminAuthStore()})
	r := httptest.NewRecorder()
	h.ServeHTTP(r, httptest.NewRequest("POST", "/admin/legacy-exceptions", strings.NewReader(`{"id":"old","status":"disabled"}`)))
	if r.Code != 200 {
		t.Fatalf("cannot disable old unsupported record: %s", r.Body)
	}
	got := s.LegacyExceptionsFor(tenant)[0]
	if got.Protocol != "udp" || got.Port != 53 || got.Status != "disabled" {
		t.Fatalf("lost condition: %+v", got)
	}
	r = httptest.NewRecorder()
	h.ServeHTTP(r, httptest.NewRequest("POST", "/admin/legacy-exceptions", strings.NewReader(`{"id":"old","status":"active"}`)))
	if r.Code != 400 || s.LegacyExceptionsFor(tenant)[0].Status != "disabled" {
		t.Fatal("reactivated unsupported record")
	}
}
