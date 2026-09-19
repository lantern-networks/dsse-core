package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/revocation"
)

// The errors are injected around a real file save; this does not simulate power loss.
type meshSaveStore struct {
	base   blobstore.Persister
	mode   atomic.Int32
	writes atomic.Int64
}

func (p *meshSaveStore) Load() ([]byte, error) { return p.base.Load() }
func (p *meshSaveStore) Save(b []byte) error {
	p.writes.Add(1)
	if p.mode.Load() == 1 {
		return errors.New("private receiver path unavailable")
	}
	if err := p.base.Save(b); err != nil {
		return err
	}
	switch p.mode.Load() {
	case 2:
		return blobstore.ErrDurabilityUnconfirmed
	case 3:
		return errors.Join(blobstore.ErrSavedWithoutAtomicity, blobstore.ErrDurabilityUnconfirmed)
	case 4:
		return blobstore.ErrSavedWithoutAtomicity
	}
	return nil
}

const meshSaveSecret = "synthetic-mesh-save-secret"

func meshSaveRequest(body []byte) *http.Request {
	r := httptest.NewRequest("POST", "/revocation-mesh/admission", bytes.NewReader(body))
	r.Header.Set("x-revocation-mesh-secret", meshSaveSecret)
	signMeshRequest(r.Header, meshSaveSecret, body, time.Now().UTC())
	return r
}

func meshSaveFixture(t *testing.T) (*revocation.AdmissionRevocations, *meshSaveStore, http.Handler) {
	t.Helper()
	p := &meshSaveStore{base: blobstore.FilePersister{Path: filepath.Join(t.TempDir(), "receiver.json")}}
	a := revocation.NewAdmissionRevocations()
	if err := a.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	a.Revoke("foreign", "keep")
	h := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), AdmissionRevocations: a, RevocationMeshSecret: meshSaveSecret})
	return a, p, h
}

func TestRevocationMeshSaveResponseAndFreshRetry(t *testing.T) {
	for _, mode := range []int32{0, 1, 2, 3, 4} {
		t.Run([]string{"atomic", "no_write", "unconfirmed", "bridge", "synced_in_place"}[mode], func(t *testing.T) {
			a, p, h := meshSaveFixture(t)
			gen := a.ConfigGeneration()
			var calls atomic.Int64
			a.SetOnRevoked(func(string, string) { calls.Add(1) })
			a.SetMeshReporter(func(string, string) { t.Error("received item was re-pushed") })
			p.mode.Store(mode)
			body := []byte(`{"identity":" TARGET ","reason":" incident ","origin_region":"claimed-region"}`)
			firstHeaders := make(http.Header)
			for attempt := 0; attempt < 2; attempt++ {
				r := meshSaveRequest(body)
				if attempt == 0 {
					firstHeaders = r.Header.Clone()
				}
				w := httptest.NewRecorder()
				h.ServeHTTP(w, r)
				want := 200
				if mode > 0 && mode < 4 {
					want = 503
				}
				if w.Code != want {
					t.Fatalf("attempt %d: %d %s", attempt, w.Code, w.Body.String())
				}
				if want == 200 {
					var result struct {
						Applied bool `json:"applied"`
					}
					if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
						t.Fatal(err)
					}
					if result.Applied != (attempt == 0) {
						t.Fatal("changed response differs from state")
					}
				} else if !strings.Contains(w.Body.String(), "applied locally") {
					t.Fatal("missing partial outcome")
				}
				for _, secret := range []string{meshSaveSecret, "private receiver path"} {
					if strings.Contains(w.Body.String(), secret) {
						t.Fatal("private error escaped")
					}
				}
				if p.writes.Load() != int64(attempt+2) || a.ConfigGeneration() != gen+1 || calls.Load() != 1 {
					t.Fatal("retry did not save or repeated state change")
				}
				if reason, ok := a.IsRevoked("target"); !ok || reason != "incident" {
					t.Fatal("block missing during save failure")
				}
			}
			// Even a failed save consumed the nonce. Only a freshly signed retry is accepted.
			replay := meshSaveRequest(body)
			replay.Header = firstHeaders
			w := httptest.NewRecorder()
			h.ServeHTTP(w, replay)
			if w.Code != 401 || p.writes.Load() != 3 {
				t.Fatal("captured request replay changed state")
			}
			p.mode.Store(0)
			w = httptest.NewRecorder()
			h.ServeHTTP(w, meshSaveRequest(body))
			if w.Code != 200 || !strings.Contains(w.Body.String(), `"applied":false`) || p.writes.Load() != 4 {
				t.Fatal("healthy duplicate was not saved and acknowledged")
			}
			reopened := revocation.NewAdmissionRevocations()
			if err := reopened.SetPersister(p); err != nil {
				t.Fatal(err)
			}
			if reason, ok := reopened.IsRevoked("target"); !ok || reason != "incident" {
				t.Fatal("acknowledged item was not restored")
			}
			if reason, ok := reopened.IsRevoked("foreign"); !ok || reason != "keep" {
				t.Fatal("foreign state changed")
			}
			if a.ConfigGeneration() != gen+1 || calls.Load() != 1 {
				t.Fatal("healthy retry caused churn")
			}
		})
	}
}

func TestRevocationMeshRejectedDeliveryDoesNotSave(t *testing.T) {
	for _, kind := range []string{"missing_auth", "wrong_secret", "bad_signature", "stale", "empty_identity", "bad_json", "allowlist_no_fallback", "disabled"} {
		t.Run(kind, func(t *testing.T) {
			a, p, h := meshSaveFixture(t)
			body := []byte(`{"identity":"target","reason":"incident"}`)
			want := 401
			if kind == "empty_identity" {
				body = []byte(`{"identity":" "}`)
				want = 400
			}
			if kind == "bad_json" {
				body = []byte(`{`)
				want = 400
			}
			r := meshSaveRequest(body)
			switch kind {
			case "missing_auth":
				r.Header.Del("x-revocation-mesh-secret")
			case "wrong_secret":
				r.Header.Set("x-revocation-mesh-secret", "wrong")
			case "bad_signature":
				r.Header.Set(meshSignatureHeader, "invalid")
			case "stale":
				signMeshRequest(r.Header, meshSaveSecret, body, time.Now().Add(-10*time.Minute))
			case "allowlist_no_fallback":
				h = newServerWithConfig(serverConfig{Evaluator: testEvaluator(), AdmissionRevocations: a, RevocationMeshSecret: meshSaveSecret, MeshIngressAllowedPeers: map[string]bool{"peer-a": true}})
			case "disabled":
				want = 404
				h = newServerWithConfig(serverConfig{Evaluator: testEvaluator(), AdmissionRevocations: a})
			}
			gen := a.ConfigGeneration()
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != want || p.writes.Load() != 1 || a.ConfigGeneration() != gen {
				t.Fatalf("rejected delivery %d: %s", w.Code, w.Body.String())
			}
			if _, ok := a.IsRevoked("target"); ok {
				t.Fatal("rejected delivery applied")
			}
		})
	}
}

func TestRevocationMeshSenderRetainsPendingUntilReceiverSave(t *testing.T) {
	a, p, h := meshSaveFixture(t)
	responses := make(chan int, 16)
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		recorded := httptest.NewRecorder()
		h.ServeHTTP(recorded, r)
		for key, values := range recorded.Header() {
			w.Header()[key] = values
		}
		w.WriteHeader(recorded.Code)
		_, _ = w.Write(recorded.Body.Bytes())
		responses <- recorded.Code
	}))
	defer peer.Close()
	file := blobstore.FilePersister{Path: filepath.Join(t.TempDir(), "outbox.json")}
	outbox, err := newRevocationMeshOutbox(file)
	if err != nil {
		t.Fatal(err)
	}
	src := revocationMeshSource{originRegion: "region-a", secret: meshSaveSecret, client: peer.Client(), outbox: outbox}
	// Use the real sender worker and receiver routes. On any early test failure,
	// heal the store while the server is still alive so its retry worker can finish.
	target := revocationMeshPeer{region: "region-b", url: peer.URL}
	defer func() {
		p.mode.Store(0)
		waitUntil(t, 5*time.Second, func() bool { return len(outbox.snapshot()) == 0 }, "sender worker cleanup")
	}()
	p.mode.Store(1)
	gen := a.ConfigGeneration()
	src.deliverToPeer(target, revocationMeshItem{Identity: "target", Reason: "incident", OriginRegion: "region-a"})
	select {
	case status := <-responses:
		if status != 503 {
			t.Fatalf("first receiver response %d", status)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("first receiver request did not finish")
	}
	if len(outbox.snapshot()) != 1 {
		t.Fatal("failed receiver save drained pending delivery")
	}
	reloaded, err := newRevocationMeshOutbox(file)
	if err != nil {
		t.Fatal(err)
	}
	if len(reloaded.snapshot()) != 1 {
		t.Fatal("pending sender delivery was not persisted")
	}
	reopened := revocation.NewAdmissionRevocations()
	if err := reopened.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	if _, ok := reopened.IsRevoked("target"); ok {
		t.Fatal("injected failed write unexpectedly retained")
	}
	if _, ok := a.IsRevoked("target"); !ok {
		t.Fatal("live receiver did not restrict admission")
	}
	p.mode.Store(0)
	waitUntil(t, 5*time.Second, func() bool { return len(outbox.snapshot()) == 0 }, "fresh automatic retry saves and acknowledges duplicate")
	if p.writes.Load() < 3 || a.ConfigGeneration() != gen+1 {
		t.Fatal("same-value retry did not save or churned generation")
	}
	reopened = revocation.NewAdmissionRevocations()
	if err := reopened.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	if _, ok := reopened.IsRevoked("target"); !ok {
		t.Fatal("receiver restart lost acknowledged block")
	}
	reloaded, err = newRevocationMeshOutbox(file)
	if err != nil {
		t.Fatal(err)
	}
	if len(reloaded.snapshot()) != 0 {
		t.Fatal("ack was not persisted in healthy sender outbox")
	}
}
