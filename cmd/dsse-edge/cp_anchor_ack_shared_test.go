package main

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"
)

func TestPostgresACKAcceptedTermAndConcurrentWriters(t *testing.T) {
	leader, peer := postgresFailureElectors(t)
	db, err := newCPStateBlobDB(os.Getenv("POSTGRES_QUEUE_E2E_DSN"), "../../migrations", true)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	p := postgresBlobPersister{db: db, key: "test_anchor_acks"}
	db.Exec("DELETE FROM cp_state_blobs WHERE store_key=$1", p.key)
	defer db.Exec("DELETE FROM cp_state_blobs WHERE store_key=$1", p.key)
	oldE, oldA := cpLeaderElectorInstance, transportAnchorAcks
	defer func() { cpLeaderElectorInstance = oldE; transportAnchorAcks = oldA }()
	cpLeaderElectorInstance = nil
	gate := &runtimeLeaseGate{postgresBlobPersister: p}
	a := newSharedTransportAnchorAcknowledgements(gate)
	b := newSharedTransportAnchorAcknowledgements(p)
	var wg sync.WaitGroup
	for _, v := range []struct {
		s  *transportAnchorAcknowledgements
		id string
	}{{a, "one"}, {b, "two"}} {
		wg.Add(1)
		go func(s *transportAnchorAcknowledgements, id string) {
			defer wg.Done()
			if err := s.Acknowledge("abc", id, "checked", "admin", time.Now()); err != nil {
				t.Error(err)
			}
		}(v.s, v.id)
	}
	wg.Wait()
	if len(a.For("abc")) != 2 {
		t.Fatal("concurrent peer lost")
	}
	transportAnchorAcks = a
	mux := http.NewServeMux()
	var actions []string
	registerTransportTrustAnchorsEndpoint(mux, serverConfig{}, "tenant", func(_ string, h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			ctx := captureCPWriteLease(r.Context())
			ctx = context.WithValue(ctx, adminIdentityContextKey{}, adminIdentity{PrincipalID: "admin"})
			h(w, r.WithContext(ctx))
		}
	}, func(_ *http.Request, action, _, _ string, m map[string]any) {
		actions = append(actions, action)
		if action == "transport_trust_acknowledge_failed" || action == "transport_trust_acknowledgement_withdraw_failed" {
			if m["durable"] != false {
				t.Error("failure marked durable")
			}
		}
	})
	request := func(method, path, body string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest(method, path, bytes.NewBufferString(body)))
		return w
	}
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
	for _, method := range []string{"POST", "DELETE"} {
		before, _ := p.Load()
		gate.before = flip
		path := "/admin/transport-trust-anchors/abc/acknowledge"
		if method == "DELETE" {
			path += "/one"
		}
		w := request(method, path, `{"identity":"one","reason":"checked"}`)
		gate.before = nil
		after, _ := p.Load()
		if w.Code != 503 || !bytes.Equal(before, after) {
			t.Fatal("old term changed row", method, w.Code, w.Body)
		}
		w = request(method, path, `{"identity":"one","reason":"checked"}`)
		if w.Code != 200 {
			t.Fatal(w.Code, w.Body)
		}
	}
	if len(actions) != 4 || actions[0] != "transport_trust_acknowledge_failed" || actions[1] != "transport_trust_acknowledged" || actions[2] != "transport_trust_acknowledgement_withdraw_failed" || actions[3] != "transport_trust_acknowledgement_withdrawn" {
		t.Fatal("missing audit", actions)
	}
	if got := b.For("abc"); len(got) != 1 || got[0].Identity != "two" {
		t.Fatal("peer stale", got)
	}
	if got := newSharedTransportAnchorAcknowledgements(p).For("abc"); len(got) != 1 {
		t.Fatal("restart", got)
	}
	p.Save([]byte(`{}`))
	if w := request("GET", "/admin/transport-trust-anchors", ""); w.Code != 503 {
		t.Fatal("read failure hidden", w.Code)
	}
}
