package main

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/lantern-networks/dsse-core/revocation"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func runRiskFeedOnce(t *testing.T, body map[string]any, risk *revocation.HighRiskOverlay, admission *revocation.AdmissionRevocations) map[string]any {
	t.Helper()
	cp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/admin/revocations" || r.Header.Get("Authorization") != "Bearer synthetic-feed-token" {
			w.WriteHeader(403)
			return
		}
		json.NewEncoder(w).Encode(body)
	}))
	defer cp.Close()
	status := &revocationSyncStatus{}
	source := revocationSource{url: cp.URL, token: "synthetic-feed-token", client: cp.Client(), interval: time.Hour, status: status}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { defer close(done); source.run(ctx, admission, risk) }()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		v := status.snapshot()
		if v["have_applied"] == true || v["consecutive_failures"].(int) > 0 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("sync did not stop")
	}
	state := status.snapshot()
	if state["have_applied"] != true && state["consecutive_failures"].(int) == 0 {
		t.Fatal("feed never processed")
	}
	return state
}
func seedRiskFeedTest(t *testing.T) (*revocation.HighRiskOverlay, *revocation.AdmissionRevocations) {
	t.Helper()
	risk := revocation.NewHighRiskOverlay()
	risk.Mark("Device", "critical")
	risk.Mark("device", "high")
	if _, e := risk.SetUserRisk(revocation.UserRisk{TenantID: "one", ID: "Device", Subjects: []string{"alias"}, Severity: "medium"}); e != nil {
		t.Fatal(e)
	}
	admission := revocation.NewAdmissionRevocations()
	admission.ReplaceSynced(map[string]string{"blocked": "admin"})
	return risk, admission
}
func TestDeviceRiskFeedEmptyDeclaration(t *testing.T) {
	for _, shape := range []string{"omitted", "empty", "null"} {
		for _, authoritative := range []bool{false, true} {
			name := shape + "/retained"
			if authoritative {
				name = shape + "/cleared"
			}
			t.Run(name, func(t *testing.T) {
				risk, admission := seedRiskFeedTest(t)
				before, users := risk.Snapshot(), risk.UserSnapshot()
				generation := risk.ConfigGeneration()
				body := map[string]any{"generation": 99, "epoch": "cp", "revoked": map[string]string{}, "authoritative": authoritative}
				if shape == "empty" {
					body["high_risk"] = map[string]string{}
				}
				if shape == "null" {
					body["high_risk"] = nil
				}
				status := runRiskFeedOnce(t, body, risk, admission)
				if status["have_applied"] != true {
					t.Fatal(status)
				}
				if authoritative {
					if len(risk.Snapshot()) != 0 || admission.SyncedCount() != 0 {
						t.Fatal("complete empty did not release")
					}
				} else {
					if !reflect.DeepEqual(risk.Snapshot(), before) || admission.SyncedCount() != 1 {
						t.Fatal("undeclared blank cleared state")
					}
				}
				if !reflect.DeepEqual(users, risk.UserSnapshot()) || generation != risk.ConfigGeneration() {
					t.Fatal("legacy user preservation or pulled-generation contract changed")
				}
			})
		}
	}
}
func TestDeviceRiskFeedNonEmptyAndTypedUsers(t *testing.T) {
	for _, authoritative := range []bool{false, true} {
		risk, admission := seedRiskFeedTest(t)
		body := map[string]any{"generation": 99, "epoch": "cp", "authoritative": authoritative, "revoked": map[string]string{"new": "admin"}, "high_risk": map[string]string{"Device": "medium", "new": "critical"}, "user_risk_version": 1, "user_risk": []revocation.UserRisk{{TenantID: "two", ID: "user", Subjects: []string{"subject"}, Severity: "high"}}}
		status := runRiskFeedOnce(t, body, risk, admission)
		if status["have_applied"] != true || risk.Snapshot()["Device"] != "medium" || risk.Snapshot()["new"] != "critical" || len(risk.Snapshot()) != 2 {
			t.Fatal("valid replacement failed", status, risk.Snapshot())
		}
		if s, ok := risk.UserSeverity("two", "subject"); !ok || s != "high" {
			t.Fatal("user feed not applied")
		}
		if _, ok := admission.IsRevoked("new"); !ok {
			t.Fatal("admission not applied")
		}
	}
}
func TestDeviceRiskFeedLocalUnavailableRefusesLegacyAndTyped(t *testing.T) {
	for _, version := range []int{0, 1} {
		for _, kind := range []string{"load", "legacy"} {
			t.Run(kind+string(rune('0'+version)), func(t *testing.T) {
				risk, admission := seedRiskFeedTest(t)
				if kind == "load" {
					_ = risk.SetPersister(&automaticDLPTestPersister{loadErr: errors.New("PRIVATE load path")})
				} else {
					if e := risk.SetPersister(&automaticDLPTestPersister{data: []byte(`{"schema_version":"high_risk_overlay_state.v1","devices":{"Device":"critical"}}`)}); e != nil {
						t.Fatal(e)
					}
				}
				before, users, gen := risk.Snapshot(), risk.UserSnapshot(), risk.ConfigGeneration()
				body := map[string]any{"generation": 99, "epoch": "cp", "revoked": map[string]string{}, "authoritative": true, "user_risk_version": version}
				status := runRiskFeedOnce(t, body, risk, admission)
				if status["have_applied"] != false || status["consecutive_failures"].(int) != 1 || !reflect.DeepEqual(before, risk.Snapshot()) || !reflect.DeepEqual(users, risk.UserSnapshot()) || gen != risk.ConfigGeneration() || admission.SyncedCount() != 1 {
					t.Fatal("unavailable local risk was replaced", status)
				}
				if strings.Contains(status["last_error"].(string), "PRIVATE") {
					t.Fatal("private error exposed")
				}
			})
		}
	}
}
func TestDeviceRiskFeedAuthorityPromotionAtSameGeneration(t *testing.T) {
	risk, admission := seedRiskFeedTest(t)
	var mu sync.Mutex
	generation := uint64(99)
	authoritative := false
	cp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		json.NewEncoder(w).Encode(revocationFeed{Generation: generation, Epoch: "same", Authoritative: authoritative, Revoked: map[string]string{}})
	}))
	defer cp.Close()
	status := &revocationSyncStatus{}
	source := revocationSource{url: cp.URL, client: cp.Client(), interval: 10 * time.Millisecond, status: status}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); source.run(ctx, admission, risk) }()
	defer func() { cancel(); <-done }()
	waitUntil(t, 3*time.Second, func() bool { return status.snapshot()["have_applied"] == true }, "first ambiguous feed")
	if len(risk.Snapshot()) != 2 || admission.SyncedCount() != 1 {
		t.Fatal("ambiguous feed erased state")
	}
	prior := status.snapshot()["last_poll_at"]
	mu.Lock()
	generation = 98
	authoritative = true
	mu.Unlock()
	waitUntil(t, 3*time.Second, func() bool { return status.snapshot()["last_poll_at"] != prior }, "older complete poll")
	if len(risk.Snapshot()) != 2 || admission.SyncedCount() != 1 {
		t.Fatal("older complete feed rolled back state")
	}
	mu.Lock()
	generation = 99
	mu.Unlock()
	waitUntil(t, 3*time.Second, func() bool { return len(risk.Snapshot()) == 0 && admission.SyncedCount() == 0 }, "same-generation complete release")
}
func TestUnavailableAuthorityRefusesRevocationFeed(t *testing.T) {
	for _, kind := range []string{"load", "legacy"} {
		t.Run(kind, func(t *testing.T) {
			h, w, risk, _, _, _ := deviceRiskAuditHandler(t)
			defer w.Close()
			old := edgeIsControlPlane
			edgeIsControlPlane = true
			defer func() { edgeIsControlPlane = old }()
			risk.Mark("owned-device", "critical")
			if kind == "load" {
				_ = risk.SetPersister(&automaticDLPTestPersister{loadErr: errors.New("PRIVATE path")})
			} else {
				if e := risk.SetPersister(&automaticDLPTestPersister{data: []byte(`{"schema_version":"high_risk_overlay_state.v1","devices":{"owned-device":"critical"}}`)}); e != nil {
					t.Fatal(e)
				}
			}
			response := riskPendingRead(t, h, "/admin/revocations")
			if response.Code != 503 || strings.Contains(response.Body.String(), "PRIVATE") || strings.Contains(response.Body.String(), "authoritative") {
				t.Fatal("unavailable feed claimed completeness", response.Code, response.Body.String())
			}
			if e := risk.SetPersister(&automaticDLPTestPersister{data: []byte(`{"schema_version":"high_risk_overlay_state.v2","devices":{"owned-device":"high"},"users":{"tenant_lab_001\u0000user":{"tenant_id":"tenant_lab_001","id":"user","severity":"medium","subjects":["user"]}}}`)}); e != nil {
				t.Fatal(e)
			}
			response = riskPendingRead(t, h, "/admin/revocations")
			var feed revocationFeed
			if e := json.Unmarshal(response.Body.Bytes(), &feed); e != nil || response.Code != 200 || !feed.Authoritative || feed.HighRisk["owned-device"] != "high" || len(feed.UserRisk) != 1 {
				t.Fatal("recovery failed", response.Code, response.Body.String(), e)
			}
		})
	}
}

func TestDeviceRiskFeedUnchangedPollDoesNotHideLocalFailure(t *testing.T) {
	risk, admission := seedRiskFeedTest(t)
	cp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(revocationFeed{Generation: 99, Epoch: "cp", Authoritative: true, HighRisk: map[string]string{"Device": "high"}})
	}))
	defer cp.Close()
	status := &revocationSyncStatus{}
	source := revocationSource{url: cp.URL, client: cp.Client(), interval: 10 * time.Millisecond, status: status}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); source.run(ctx, admission, risk) }()
	defer func() { cancel(); <-done }()
	waitUntil(t, 3*time.Second, func() bool { return status.snapshot()["have_applied"] == true }, "initial feed")
	if e := risk.SetPersister(&automaticDLPTestPersister{loadErr: errors.New("PRIVATE")}); e == nil {
		t.Fatal("fixture did not fail")
	}
	before := risk.Snapshot()
	waitUntil(t, 3*time.Second, func() bool { return status.snapshot()["consecutive_failures"].(int) > 0 }, "unchanged feed reported local failure")
	if !reflect.DeepEqual(before, risk.Snapshot()) || status.snapshot()["last_error"] != "local risk state is not ready" {
		t.Fatal("unchanged poll hid local failure")
	}
}
