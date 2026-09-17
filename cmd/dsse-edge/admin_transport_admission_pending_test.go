package main

import (
	"encoding/json"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

type pendingAdmissionPersister struct {
	entered, release chan struct{}
	err              error
}

func (p *pendingAdmissionPersister) Load() ([]byte, error) { return nil, nil }
func (p *pendingAdmissionPersister) Save([]byte) error     { close(p.entered); <-p.release; return p.err }

func TestAdminTransportAdmissionReadsDuringPendingSave(t *testing.T) {
	for _, action := range []string{"revoke", "restore"} {
		for _, failed := range []bool{false, true} {
			name := action + "/ok"
			if failed {
				name = action + "/failed"
			}
			t.Run(name, func(t *testing.T) {
				h, w, a, _ := transportAuditHandler(t)
				a.Revoke("other-device", "foreign")
				if action == "restore" {
					a.Revoke("owned-device", "prior")
				}
				p := &pendingAdmissionPersister{entered: make(chan struct{}), release: make(chan struct{})}
				if failed {
					p.err = errors.New("private backend error")
				}
				var once sync.Once
				release := func() { once.Do(func() { close(p.release) }) }
				t.Cleanup(release)
				if err := a.SetPersister(p); err != nil {
					t.Fatal(err)
				}
				done := make(chan *httptest.ResponseRecorder, 1)
				go func() { done <- transportAuditRequest(h, action, `{"identity":"owned-device"}`, transportAuditBearer) }()
				select {
				case <-p.entered:
				case <-time.After(2 * time.Second):
					t.Fatal("write did not reach storage")
				}
				// The real authenticated read route must remain usable while this POST is pending.
				reads := make(chan *httptest.ResponseRecorder, 1)
				go func() {
					reads <- admissionStateRequest(h, "GET", "/admin/transport-admission?expected_tenant_id=tenant_lab_001", "")
				}()
				select {
				case r := <-reads:
					if r.Code != 200 {
						t.Fatalf("read %d %s", r.Code, r.Body)
					}
					var b struct {
						Revoked []string `json:"revoked_identities"`
					}
					if err := json.Unmarshal(r.Body.Bytes(), &b); err != nil {
						t.Fatal(err)
					}
					if len(b.Revoked) != 1 || b.Revoked[0] != "owned-device" {
						t.Fatalf("pending block lost or foreign exposed: %+v", b)
					}
				case <-time.After(2 * time.Second):
					t.Fatal("read waited on another request's storage")
				}
				if _, blocked := a.IsRevoked("unblocked-device"); blocked {
					t.Fatal("unrelated identity blocked")
				}
				select {
				case <-done:
					t.Fatal("POST acknowledged before persistence returned")
				default:
				}
				if data, err := os.ReadFile(filepath.Join(w.Dir(), "audit.log.jsonl")); err != nil && !os.IsNotExist(err) {
					t.Fatal(err)
				} else if len(data) > 0 {
					t.Fatal("pending operation was audited as completed")
				}
				release()
				var response *httptest.ResponseRecorder
				select {
				case response = <-done:
				case <-time.After(2 * time.Second):
					t.Fatal("POST did not finish")
				}
				expected := 200
				if failed {
					expected = 503
				}
				if response.Code != expected {
					t.Fatalf("%d %s", response.Code, response.Body)
				}
				if _, blocked := a.IsRevoked("owned-device"); blocked != (action == "revoke" || failed) {
					t.Fatal("wrong completed admission")
				}
				rows := readTransportAudits(t, w)
				if len(rows) != 2 {
					t.Fatalf("audits=%d", len(rows))
				}
				for _, row := range rows {
					want := "success"
					if failed {
						want = "error"
						if row.EventType == "transport_admission_changed" && action == "revoke" {
							want = "partial"
						}
					}
					if stringPtrValue(row.Result) != want {
						t.Fatalf("incorrect audit %+v", row)
					}
				}
			})
		}
	}
}
