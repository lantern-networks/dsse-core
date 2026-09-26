package main

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/lantern-networks/dsse-core/vendorlicense"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

type licenseUnreadableStore struct {
	raw []byte
	err error
}

func (p *licenseUnreadableStore) Load() ([]byte, error) { return p.raw, p.err }
func (p *licenseUnreadableStore) Save(b []byte) error   { p.raw = b; return nil }
func TestLicenseUnreadableStateCannotResetSerial(t *testing.T) {
	_, key, _, _, d := licenceAdminFixture(t)
	for _, raw := range [][]byte{nil, {}, []byte(`{`), []byte(`{}`), []byte(`{"schema_version":"unknown"}`)} {
		t.Run(string(raw), func(t *testing.T) {
			p := &licenseUnreadableStore{raw: raw}
			if raw == nil {
				p.err = errors.New("private failure")
			}
			s := newLicenseStore()
			s.SetPersister(p)
			env, err := vendorlicense.Sign(testLicence(20), "test", key, licenceNow())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := s.Apply(env, d.acceptedKeys, d.msspID, "test", licenceNow().Format(time.RFC3339)); err == nil {
				t.Error("load failure allowed new write and reset serial floor")
			}
		})
	}
}
func TestPostgresLicenseApplyUsesLatestSerial(t *testing.T) {
	if os.Getenv("POSTGRES_QUEUE_E2E_DSN") == "" {
		t.Skip("POSTGRES_QUEUE_E2E_DSN required")
	}
	db, err := newCPStateBlobDB(os.Getenv("POSTGRES_QUEUE_E2E_DSN"), "../../migrations", true)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	p := postgresBlobPersister{db: db, key: "test_license_serial"}
	db.Exec("DELETE FROM cp_state_blobs WHERE store_key=$1", p.key)
	defer db.Exec("DELETE FROM cp_state_blobs WHERE store_key=$1", p.key)
	_, key, _, _, d := licenceAdminFixture(t)
	stale, peer := newLicenseStore(), newLicenseStore()
	stale.SetPersister(p)
	peer.SetPersister(p)
	sign := func(serial int64) vendorlicense.Envelope {
		payload := testLicence(30)
		payload.Serial = serial
		env, err := vendorlicense.Sign(payload, "test", key, licenceNow())
		if err != nil {
			t.Fatal(err)
		}
		return env
	}
	if _, err := peer.Apply(sign(3), d.acceptedKeys, d.msspID, "peer", licenceNow().Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	before, _ := p.Load()
	if _, err := stale.Apply(sign(2), d.acceptedKeys, d.msspID, "stale", licenceNow().Format(time.RFC3339)); err == nil {
		t.Error("stale writer accepted old serial")
	}
	after, _ := p.Load()
	if string(before) != string(after) {
		t.Error("shared serial floor rolled back")
	}
}

func TestPostgresLicensePromotionAndStaleRequest(t *testing.T) {
	a, b := postgresFailureElectors(t)
	db, err := newCPStateBlobDB(os.Getenv("POSTGRES_QUEUE_E2E_DSN"), "../../migrations", true)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	p := postgresBlobPersister{db: db, key: "test_license_promotion"}
	db.Exec("DELETE FROM cp_state_blobs WHERE store_key=$1", p.key)
	defer db.Exec("DELETE FROM cp_state_blobs WHERE store_key=$1", p.key)
	_, key, ledger, seats, d := licenceAdminFixture(t)
	s, peer := newLicenseStore(), newLicenseStore()
	s.SetPersister(p)
	peer.SetPersister(p)
	sign := func(serial int64) vendorlicense.Envelope {
		payload := testLicence(30)
		payload.Serial = serial
		env, err := vendorlicense.Sign(payload, "test", key, licenceNow())
		if err != nil {
			t.Fatal(err)
		}
		return env
	}
	gate := newEnrolmentLicensing(seats, ledger, true, false)
	configureLicensePromotion(a, "postgres+import:unused", s, gate, d.acceptedKeys, d.msspID)
	old, oldCP := cpLeaderElectorInstance, edgeIsControlPlane
	cpLeaderElectorInstance = a
	edgeIsControlPlane = true
	defer func() { cpLeaderElectorInstance = old; edgeIsControlPlane = oldCP }()
	a.tick()
	ctx := captureCPWriteLease(context.Background())
	a.release()
	b.tick()
	if !b.IsLeader() {
		t.Fatal("peer election")
	}
	if _, err := peer.Apply(sign(5), d.acceptedKeys, d.msspID, "peer", "now"); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	d.licence = s
	registerAdminLicenseEndpoints(mux, d, func(_ string, h http.HandlerFunc) http.HandlerFunc { return h })
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest("GET", "/admin/license", nil))
	if w.Code != 409 {
		t.Fatal("standby returned licensing", w.Code)
	}
	b.release()
	a.tick()
	if !a.IsLeader() || s.LastAcceptedSerial() != 5 {
		t.Fatal("promotion did not refresh serial")
	}
	if applied, ok := gate.Current(); !ok || applied.Serial != 5 {
		t.Fatal("gate stale")
	}
	before, _ := p.Load()
	if _, err := s.ApplyContext(ctx, sign(6), d.acceptedKeys, d.msspID, "old", "now"); !errors.Is(err, errLicensePersistence) {
		t.Fatal("old term accepted", err)
	}
	after, _ := p.Load()
	if string(before) != string(after) || s.LastAcceptedSerial() != 5 {
		t.Fatal("old term changed state")
	}
	a.release()
	p.Save([]byte(`{`))
	a.tick()
	if a.IsLeader() {
		t.Fatal("corrupt license allowed promotion")
	}
	p.Save(before)
	a.tick()
	if !a.IsLeader() {
		t.Fatal("repair did not recover promotion")
	}
	if _, err := s.ApplyContext(captureCPWriteLease(context.Background()), sign(6), d.acceptedKeys, d.msspID, "new", "now"); err != nil {
		t.Fatal(err)
	}
}
func TestLicenseRestorePreservesStateAndSerialConsistency(t *testing.T) {
	_, key, _, _, d := licenceAdminFixture(t)
	s := newLicenseStore()
	p := &licenseUnreadableStore{}
	s.SetPersister(p)
	payload := testLicence(20)
	payload.Serial = 4
	env, _ := vendorlicense.Sign(payload, "test", key, licenceNow())
	if _, err := s.Apply(env, d.acceptedKeys, d.msspID, "x", "now"); err != nil {
		t.Fatal(err)
	}
	original := append([]byte(nil), p.raw...)
	var st licenseState
	json.Unmarshal(original, &st)
	st.LastAcceptedSerial = 1
	p.raw, _ = json.Marshal(st)
	if err := s.ReloadFromStore(); err == nil || s.LastAcceptedSerial() != 4 {
		t.Fatal("serial mismatch accepted")
	}
	if _, ok, _ := s.CurrentWithReason(d.acceptedKeys, d.msspID); ok {
		t.Fatal("failed load remained available")
	}
	p.raw = original
	if err := s.ReloadFromStore(); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Current(d.acceptedKeys, d.msspID); !ok {
		t.Fatal("recovery unavailable")
	}
}
