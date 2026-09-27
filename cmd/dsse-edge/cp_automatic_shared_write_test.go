package main

import (
	"context"
	"github.com/lantern-networks/dsse-core/revocation"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func TestPostgresAutomaticWritersPreservePeerState(t *testing.T) {
	if os.Getenv("POSTGRES_QUEUE_E2E_DSN") == "" {
		t.Skip("POSTGRES_QUEUE_E2E_DSN required")
	}
	db, err := newCPStateBlobDB(os.Getenv("POSTGRES_QUEUE_E2E_DSN"), "../../migrations", true)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	pr, pa := postgresBlobPersister{db: db, key: "test_auto_risk"}, postgresBlobPersister{db: db, key: "test_auto_admission"}
	for _, p := range []postgresBlobPersister{pr, pa} {
		if _, err := db.Exec("DELETE FROM cp_state_blobs WHERE store_key=$1", p.key); err != nil {
			t.Fatal(err)
		}
		defer db.Exec("DELETE FROM cp_state_blobs WHERE store_key=$1", p.key)
	}
	risk, peer := revocation.NewHighRiskOverlay(), revocation.NewHighRiskOverlay()
	for _, o := range []*revocation.HighRiskOverlay{risk, peer} {
		if err := o.SetPersister(pr); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := peer.SetDeviceRiskContext(context.Background(), "foreign", "critical"); err != nil {
		t.Fatal(err)
	}
	if _, err := peer.SetDeviceRiskContext(context.Background(), "risk-device", "critical"); err != nil {
		t.Fatal(err)
	}
	if _, err := peer.SetUserRiskContext(context.Background(), revocation.UserRisk{TenantID: "tenant_other", ID: "person", Severity: "high"}); err != nil {
		t.Fatal(err)
	}
	cfg, events := newDLPTestConfig(t)
	tenant := testEvaluator().PolicyBundle.TenantID
	cfg.DLPDeviceRisk = newDLPDeviceRiskAggregator(risk)
	cfg.DLPPolicies = automaticDLPTestPolicies(t, tenant)
	runAutomaticDLPTestUpload(t, cfg, tenant, "shared-first")
	reloaded := revocation.NewHighRiskOverlay()
	if err := reloaded.SetPersister(pr); err != nil {
		t.Fatal(err)
	}
	if reloaded.Snapshot()["foreign"] != "critical" || reloaded.Snapshot()["risk-device"] != "critical" || len(reloaded.UserSnapshot()) != 1 {
		t.Error("automatic DLP writer erased or lowered peer state")
	}
	finding := dlpEventByFindingType(events.ListByTenant(tenant), "dlp_device_risk")
	if finding == nil || finding.Metadata["persistence"] != "saved" {
		t.Fatal("missing persisted DLP outcome", finding)
	}
	ad, peerAd := revocation.NewAdmissionRevocations(), revocation.NewAdmissionRevocations()
	for _, o := range []*revocation.AdmissionRevocations{ad, peerAd} {
		if err := o.SetPersister(pa); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := peerAd.RevokeCheckedContext(context.Background(), "foreign", "peer origin"); err != nil {
		t.Fatal(err)
	}
	if _, err := peerAd.RevokeFromMeshChecked("older-received", "peer mesh"); err != nil {
		t.Fatal(err)
	}
	ad.SetMeshReporter(func(string, string) { t.Error("received item re-pushed") })
	h := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), AdmissionRevocations: ad, RevocationMeshSecret: meshSaveSecret})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, meshSaveRequest([]byte(`{"identity":"target","reason":"new mesh"}`)))
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	ar := revocation.NewAdmissionRevocations()
	if err := ar.SetPersister(pa); err != nil {
		t.Fatal(err)
	}
	if ar.Snapshot()["foreign"] != "peer origin" || ar.FeedSnapshot()["older-received"] != "peer mesh" || ar.FeedSnapshot()["target"] != "new mesh" {
		t.Error("mesh writer erased peer origin or received blocks")
	}
}

func TestPostgresMeshRequestCannotOutliveLeadership(t *testing.T) {
	a, b := postgresFailureElectors(t)
	db, err := newCPStateBlobDB(os.Getenv("POSTGRES_QUEUE_E2E_DSN"), "../../migrations", true)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	p := postgresBlobPersister{db: db, key: "test_mesh_authority"}
	db.Exec("DELETE FROM cp_state_blobs WHERE store_key=$1", p.key)
	defer db.Exec("DELETE FROM cp_state_blobs WHERE store_key=$1", p.key)
	ad := revocation.NewAdmissionRevocations()
	if err := ad.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	old := cpLeaderElectorInstance
	cpLeaderElectorInstance = a
	defer func() { cpLeaderElectorInstance = old }()
	a.tick()
	h := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), AdmissionRevocations: ad, RevocationMeshSecret: meshSaveSecret})
	raw := []byte(`{"identity":"target","reason":"stale"}`)
	r := meshSaveRequest(raw)
	body := &pausedSeatBody{Reader: strings.NewReader(string(raw)), entered: make(chan struct{}), resume: make(chan struct{})}
	r.Body = body
	w := httptest.NewRecorder()
	done := make(chan struct{})
	go func() { defer close(done); h.ServeHTTP(w, r) }()
	select {
	case <-body.entered:
	case <-done:
		t.Fatalf("body not reached: %d", w.Code)
	case <-time.After(5 * time.Second):
		t.Fatal("body timeout")
	}
	a.release()
	b.tick()
	if !b.IsLeader() {
		close(body.resume)
		<-done
		t.Fatal("peer not leader")
	}
	b.release()
	a.tick()
	calls := 0
	ad.SetOnRevoked(func(string, string) { calls++ })
	close(body.resume)
	<-done
	if w.Code != 503 || strings.Contains(w.Body.String(), "applied locally") || calls != 0 {
		t.Fatal(w.Code, w.Body, calls)
	}
	if raw, err := p.Load(); err != nil || raw != nil {
		t.Fatal("stale request saved", err)
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, meshSaveRequest(raw))
	if w.Code != 200 || calls != 1 {
		t.Fatal("fresh retry failed", w.Code, w.Body, calls)
	}
}
