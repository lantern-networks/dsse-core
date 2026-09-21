package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestPostgresTransportTrustAcceptedTermAndRead(t *testing.T) {
	leader, peer := postgresFailureElectors(t)
	db, err := newCPStateBlobDB(os.Getenv("POSTGRES_QUEUE_E2E_DSN"), "../../migrations", true)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	p := postgresBlobPersister{db: db, key: "transport_trust"}
	saved, err := p.Load()
	if err != nil {
		t.Fatal(err)
	}
	db.Exec("DELETE FROM cp_state_blobs WHERE store_key=$1", p.key)
	defer func() {
		if saved == nil {
			db.Exec("DELETE FROM cp_state_blobs WHERE store_key=$1", p.key)
		} else {
			p.Save(saved)
		}
	}()
	oldE, oldTrust := cpLeaderElectorInstance, transportTrust
	defer func() { cpLeaderElectorInstance = oldE; transportTrust = oldTrust }()
	cpLeaderElectorInstance = nil
	seed := string(testCertPEM(t, "seed"))
	other := string(testCertPEM(t, "other"))
	gate := &runtimeLeaseGate{postgresBlobPersister: p}
	store, err := openSharedTransportTrustStore(gate, "", seed, 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	transportTrust = store
	mux := http.NewServeMux()
	registerTransportTrustAnchorsEndpoint(mux, serverConfig{}, "tenant", func(_ string, h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) { h(w, r.WithContext(captureCPWriteLease(r.Context()))) }
	}, nil)
	cpLeaderElectorInstance = leader
	leader.tick()
	if !leader.IsLeader() {
		t.Fatal("leader")
	}
	flip := func() {
		leader.release()
		peer.tick()
		if !peer.IsLeader() {
			t.Fatal("peer")
		}
		peer.release()
		leader.tick()
	}
	request := func(method, path string, body []byte) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest(method, path, bytes.NewReader(body)))
		return w
	}
	before, _ := p.Load()
	gate.before = flip
	body, _ := json.Marshal(map[string]string{"certificate_pem": other})
	w := request("POST", "/admin/transport-trust-anchors", body)
	if w.Code != 503 {
		t.Fatal(w.Code, w.Body)
	}
	gate.before = nil
	after, _ := p.Load()
	if !bytes.Equal(before, after) || len(store.Anchors()) != 1 {
		t.Fatal("old request applied")
	}
	w = request("POST", "/admin/transport-trust-anchors", body)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	before, _ = p.Load()
	fp := certFingerprint(parseAllCerts([]byte(seed))[0])
	for _, op := range []string{"withdraw", "announce"} {
		ctx := captureCPWriteLease(context.Background())
		gate.before = flip
		if op == "withdraw" {
			_, _, err = store.WithdrawIfContext(ctx, fp, nil)
		} else {
			_, _, err = store.AdvanceForAnnouncementContext(ctx, []string{"root=changed"}, "test")
		}
		if err == nil {
			t.Fatal("old term accepted", op)
		}
		gate.before = nil
		after, _ = p.Load()
		if !bytes.Equal(before, after) {
			t.Fatal("old term changed row", op)
		}
	}
	// A separate CP preserves the latest row and the restarted CP sees the withdrawal.
	cpLeaderElectorInstance = nil
	second, err := openSharedTransportTrustStore(p, "", seed, 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = second.Add(string(testCertPEM(t, "peer"))); err != nil {
		t.Fatal(err)
	}
	if _, n, err := store.Withdraw(fp); err != nil || n != 4 {
		t.Fatal(n, err)
	}
	restarted, err := openSharedTransportTrustStore(p, "", seed, 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(restarted.Anchors()) != 2 {
		t.Fatal("restart lost peer")
	}
	for _, bad := range [][]byte{[]byte(`{}`), nil} {
		if bad == nil {
			db.Exec("DELETE FROM cp_state_blobs WHERE store_key=$1", p.key)
		} else {
			p.Save(bad)
		}
		w = request("GET", "/admin/transport-trust-anchors", nil)
		if w.Code != 503 {
			t.Fatal("stale GET", w.Code, w.Body)
		}
	}
}
