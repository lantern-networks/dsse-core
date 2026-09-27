package main

import (
	"context"
	"errors"
	"github.com/lantern-networks/dsse-core/device"
	"github.com/lantern-networks/dsse-core/enrolledinventory"
	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/revocation"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func TestPostgresDeviceRequestsCannotOutliveLeadership(t *testing.T) {
	for _, kind := range []string{"restore", "revoke", "risk"} {
		t.Run(kind, func(t *testing.T) {
			a, b := postgresFailureElectors(t)
			db, err := newCPStateBlobDB(os.Getenv("POSTGRES_QUEUE_E2E_DSN"), "../../migrations", true)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			pa, pr := postgresBlobPersister{db: db, key: "test_device_request_admission"}, postgresBlobPersister{db: db, key: "test_device_request_risk"}
			for _, p := range []postgresBlobPersister{pa, pr} {
				db.Exec("DELETE FROM cp_state_blobs WHERE store_key=$1", p.key)
				defer db.Exec("DELETE FROM cp_state_blobs WHERE store_key=$1", p.key)
			}
			ad := revocation.NewAdmissionRevocations()
			if err := ad.SetPersister(pa); err != nil {
				t.Fatal(err)
			}
			risk := revocation.NewHighRiskOverlay()
			if err := risk.SetPersister(pr); err != nil {
				t.Fatal(err)
			}
			if err := ad.RevokeChecked("target-device", "initial"); err != nil {
				t.Fatal(err)
			}
			if _, err := risk.SetDeviceRisk("target-device", "high"); err != nil {
				t.Fatal(err)
			}
			ledger := enrolledinventory.NewLedger()
			ledger.Enroll("target-device", "tenant_lab_001", "", "now")
			runtime := device.NewStore()
			runtime.Register(model.Device{ID: "target-device", TenantID: "tenant_lab_001"}, testEvaluator().PolicyBundle, time.Now())
			old := cpLeaderElectorInstance
			cpLeaderElectorInstance = a
			defer func() { cpLeaderElectorInstance = old }()
			a.tick()
			auth := newAdminAuthStore()
			auth.UpsertPrincipal(adminPrincipal{ID: "review", TenantID: "tenant_lab_001", Roles: []string{"admin"}, Status: "active"})
			auth.UpsertSession(adminSession{ID: "device-session", TenantID: "tenant_lab_001", AdminPrincipalID: "review", Roles: []string{"admin"}, Status: "active", ExpiresAt: time.Now().Add(time.Hour).Format(time.RFC3339), Metadata: map[string]any{adminCSRFTokenKey: "device-csrf"}})
			handler := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), AdminAuth: auth, EnrolledLedger: ledger, AdmissionRevocations: ad, HighRiskOverlay: risk, DeviceStore: runtime})
			path, raw := "/admin/transport-admission/"+kind, `{"identity":"target-device","reason":"stale"}`
			if kind == "risk" {
				path = "/admin/risk-signals"
				raw = `{"entity_type":"device","entity_id":"target-device","severity":"medium"}`
			}
			body := &pausedSeatBody{Reader: strings.NewReader(raw), entered: make(chan struct{}), resume: make(chan struct{})}
			req := httptest.NewRequest("POST", path, body)
			req.AddCookie(&http.Cookie{Name: "admin_session", Value: "device-session"})
			req.Header.Set("X-CSRF-Token", "device-csrf")
			rec := httptest.NewRecorder()
			done := make(chan struct{})
			go func() { defer close(done); handler.ServeHTTP(rec, req) }()
			select {
			case <-body.entered:
			case <-done:
				t.Fatalf("body not reached: %d %s", rec.Code, rec.Body)
			case <-time.After(5 * time.Second):
				t.Fatal("body timeout")
			}
			a.release()
			b.tick()
			if !b.IsLeader() {
				close(body.resume)
				<-done
				t.Fatal("peer takeover failed")
			}
			peer := revocation.NewAdmissionRevocations()
			peer.SetPersister(pa)
			peer.RevokeChecked("foreign-device", "new peer block")
			peer.RevokeChecked("target-device", "new peer block")
			peerRisk := revocation.NewHighRiskOverlay()
			peerRisk.SetPersister(pr)
			peerRisk.SetDeviceRisk("target-device", "critical")
			peerRisk.SetDeviceRisk("foreign-device", "critical")
			callbackCount := 0
			ad.SetOnRevoked(func(string, string) { callbackCount++ })
			beforeGeneration := ad.ConfigGeneration()
			beforeA, _ := pa.Load()
			beforeR, _ := pr.Load()
			close(body.resume)
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("response timeout")
			}
			if callbackCount != 0 || ad.ConfigGeneration() != beforeGeneration {
				t.Fatal("rejected authority changed live admission or fired callback")
			}
			afterA, _ := pa.Load()
			afterR, _ := pr.Load()
			if rec.Code != 503 || string(beforeA) != string(afterA) || string(beforeR) != string(afterR) {
				t.Fatalf("stale %s accepted: HTTP %d admission_same=%t risk_same=%t body=%s", kind, rec.Code, string(beforeA) == string(afterA), string(beforeR) == string(afterR), rec.Body)
			}
		})
	}
}

func TestPostgresDeviceContextMutationsPreserveSharedState(t *testing.T) {
	a, b := postgresFailureElectors(t)
	db, err := newCPStateBlobDB(os.Getenv("POSTGRES_QUEUE_E2E_DSN"), "../../migrations", true)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	stores := map[string]postgresBlobPersister{}
	for _, key := range []string{"admission", "risk", "inventory"} {
		p := postgresBlobPersister{db: db, key: "test_context_" + key}
		stores[key] = p
		db.Exec("DELETE FROM cp_state_blobs WHERE store_key=$1", p.key)
		defer db.Exec("DELETE FROM cp_state_blobs WHERE store_key=$1", p.key)
	}
	ad, peerAd := revocation.NewAdmissionRevocations(), revocation.NewAdmissionRevocations()
	risk, peerRisk := revocation.NewHighRiskOverlay(), revocation.NewHighRiskOverlay()
	ledger, peerLedger := enrolledinventory.NewLedger(), enrolledinventory.NewLedger()
	for _, s := range []*revocation.AdmissionRevocations{ad, peerAd} {
		if err := s.SetPersister(stores["admission"]); err != nil {
			t.Fatal(err)
		}
	}
	for _, s := range []*revocation.HighRiskOverlay{risk, peerRisk} {
		if err := s.SetPersister(stores["risk"]); err != nil {
			t.Fatal(err)
		}
	}
	for _, s := range []*enrolledinventory.Ledger{ledger, peerLedger} {
		if err := s.SetPersisterChecked(stores["inventory"]); err != nil {
			t.Fatal(err)
		}
	}
	if err := peerAd.RevokeChecked("foreign", "keep"); err != nil {
		t.Fatal(err)
	}
	if _, err := peerAd.RevokeFromMeshChecked("mesh", "mesh block"); err != nil {
		t.Fatal(err)
	}
	if _, err := peerRisk.SetDeviceRisk("foreign", "critical"); err != nil {
		t.Fatal(err)
	}
	if _, err := peerRisk.SetUserRisk(revocation.UserRisk{TenantID: "other", ID: "person", Severity: "high"}); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"target", "foreign"} {
		if _, err := peerLedger.Enroll(id, "tenant_a", "", "now"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := peerLedger.CreateGroup("retained", "tenant_a", "", "high", "now"); err != nil {
		t.Fatal(err)
	}
	old := cpLeaderElectorInstance
	cpLeaderElectorInstance = a
	defer func() { cpLeaderElectorInstance = old }()
	a.tick()
	ctx := captureCPWriteLease(context.Background())
	if applied, err := ad.RevokeCheckedContext(ctx, "target", "block"); err != nil || !applied {
		t.Fatal(applied, err)
	}
	if err := ad.RestoreCheckedContext(ctx, "target"); err != nil {
		t.Fatal(err)
	}
	if _, ok := ad.IsRevoked("foreign"); !ok {
		t.Fatal("foreign admission lost")
	}
	if _, ok := ad.IsRevoked("mesh"); !ok {
		t.Fatal("mesh lost")
	}
	if _, err := risk.SetDeviceRiskContext(ctx, "target", "medium"); err != nil {
		t.Fatal(err)
	}
	if _, err := risk.SetUserRiskContext(ctx, revocation.UserRisk{TenantID: "tenant_a", ID: "person", Severity: "critical"}); err != nil {
		t.Fatal(err)
	}
	if risk.Snapshot()["foreign"] != "critical" {
		t.Fatal("foreign device risk lost")
	}
	if sev, _ := risk.UserSeverity("other", "person"); sev != "high" {
		t.Fatal("foreign user risk lost")
	}
	if _, err := ledger.SetEnabledContext(ctx, "target", "tenant_a", false, "later"); err != nil {
		t.Fatal(err)
	}
	if !ledger.IsAdmitted("foreign") || len(ledger.ListGroups()) != 1 {
		t.Fatal("other inventory lost")
	}
	before, _ := stores["inventory"].Load()
	if _, err := ledger.SetEnabledContext(ctx, "target", "other", true, "later"); !errors.Is(err, enrolledinventory.ErrIdentityNotFound) {
		t.Fatal("foreign ownership accepted", err)
	}
	after, _ := stores["inventory"].Load()
	if string(before) != string(after) {
		t.Fatal("ownership refusal changed snapshot")
	}
	a.release()
	b.tick()
	if !b.IsLeader() {
		t.Fatal("peer takeover failed")
	}
	if _, err := ledger.SetEnabledContext(ctx, "target", "tenant_a", true, "stale"); err == nil {
		t.Fatal("stale enable accepted")
	}
	if _, err := risk.SetUserRiskContext(ctx, revocation.UserRisk{TenantID: "tenant_a", ID: "person", Severity: "none"}); err == nil {
		t.Fatal("stale user risk accepted")
	}
	fresh := enrolledinventory.NewLedger()
	if err := fresh.SetPersisterChecked(stores["inventory"]); err != nil {
		t.Fatal(err)
	}
	if fresh.IsAdmitted("target") || !fresh.IsAdmitted("foreign") || len(fresh.ListGroups()) != 1 {
		t.Fatal("fresh store mismatch")
	}
	freshAd := revocation.NewAdmissionRevocations()
	if err := freshAd.SetPersister(stores["admission"]); err != nil {
		t.Fatal(err)
	}
	if _, ok := freshAd.IsRevoked("target"); ok {
		t.Fatal("restore not persisted")
	}
	freshRisk := revocation.NewHighRiskOverlay()
	if err := freshRisk.SetPersister(stores["risk"]); err != nil {
		t.Fatal(err)
	}
	if sev, _ := freshRisk.UserSeverity("tenant_a", "person"); sev != "critical" {
		t.Fatal("user risk not retained")
	}
}
