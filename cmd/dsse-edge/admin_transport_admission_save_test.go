package main

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/lantern-networks/dsse-core/enrolledinventory"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/revocation"
)

type transportSavePersister struct {
	data   []byte
	err    error
	retain bool
	writes int
}

func (p *transportSavePersister) Load() ([]byte, error) { return bytes.Clone(p.data), nil }
func (p *transportSavePersister) Save(b []byte) error {
	p.writes++
	if p.err == nil || p.retain {
		p.data = bytes.Clone(b)
	}
	return p.err
}

func TestAdminTransportAdmissionSaveOutcome(t *testing.T) {
	for _, mode := range []string{"no_write", "retained_bridge", "lost_wrapped_bridge", "synced_in_place"} {
		for _, action := range []string{"revoke", "restore"} {
			t.Run(mode+"/"+action, func(t *testing.T) {
				h, w, a, _ := transportAuditHandler(t)
				p := &transportSavePersister{}
				a.SetPersister(p)
				a.Revoke("other-device", "foreign block")
				if action == "restore" {
					a.Revoke("owned-device", "prior")
				}
				p.err = errors.New("private storage path")
				p.retain = false
				if mode == "retained_bridge" || mode == "lost_wrapped_bridge" {
					p.err = fmt.Errorf("private storage path: %w", errors.Join(blobstore.ErrSavedWithoutAtomicity, blobstore.ErrDurabilityUnconfirmed))
					p.retain = mode == "retained_bridge"
				}
				if mode == "synced_in_place" {
					p.err = blobstore.ErrSavedWithoutAtomicity
					p.retain = true
				}
				r := transportAuditRequest(h, action, `{"identity":" OWNED-DEVICE ","reason":"incident-42","extra":"private-extra-request-value"}`, transportAuditBearer)
				accepted := mode == "synced_in_place"
				wantCode := 503
				if accepted {
					wantCode = 200
				}
				if r.Code != wantCode {
					t.Fatalf("status %d: %s", r.Code, r.Body.String())
				}
				if strings.Contains(r.Body.String(), "private") {
					t.Fatal("private error escaped")
				}
				_, blocked := a.IsRevoked("owned-device")
				if blocked != (action == "revoke" || !accepted) {
					t.Fatal("incorrect local enforcement")
				}
				domains, commons := 0, 0
				for _, row := range readTransportAudits(t, w) {
					if row.TenantID != "tenant_lab_001" || stringPtrValue(row.ActorUserID) != "transport-admin" {
						t.Fatal("wrong attribution")
					}
					if row.EventType == "transport_admission_changed" {
						domains++
						want := "success"
						if !accepted {
							want = "error"
							if action == "revoke" {
								want = "partial"
							}
						}
						if stringPtrValue(row.Result) != want || stringPtrValue(row.TargetID) != "owned-device" || stringPtrValue(row.Action) != "transport_admission_"+action {
							t.Fatalf("domain: %+v", row)
						}
						if !accepted && (row.Metadata["applied_locally"] != (action == "revoke") || row.Metadata["persistence_confirmed"] != false) {
							t.Fatal("missing partial outcome")
						}
					} else if row.EventType == "admin_config_change" {
						commons++
						want := "error"
						if accepted {
							want = "success"
						}
						if stringPtrValue(row.Result) != want {
							t.Fatal("common false success")
						}
					}
				}
				if domains != 1 || commons != 1 {
					t.Fatalf("audit domain=%d common=%d", domains, commons)
				}
				// Failed authorization must not attempt another save or disturb other tenants.
				writes := p.writes
				if rr := transportAuditRequest(h, action, `{"identity":"other-device"}`, transportAuditBearer); rr.Code != 404 {
					t.Fatal("cross-tenant write accepted")
				}
				if rr := transportAuditRequest(h, action, `{"identity":"owned-device"}`, transportAuditReadBearer); rr.Code != http.StatusForbidden {
					t.Fatal("read-only write accepted")
				}
				if p.writes != writes {
					t.Fatal("denied request touched persistence")
				}
				p.err = nil
				if rr := transportAuditRequest(h, action, `{"identity":"owned-device","reason":"incident-42"}`, transportAuditBearer); rr.Code != 200 {
					t.Fatal("retry failed")
				}
				reopened := revocation.NewAdmissionRevocations()
				reopened.SetPersister(p)
				_, got := reopened.IsRevoked("owned-device")
				if got != (action == "revoke") {
					t.Fatal("retry not saved")
				}
				if why, ok := reopened.IsRevoked("other-device"); !ok || why != "foreign block" {
					t.Fatal("foreign block changed")
				}
			})
		}
	}
}

// The administrator's restrictive action still tears down its registered sessions
// when persistence fails; a failure must not undo the immediate kill switch.
func TestAdminTransportAdmissionFailedSaveStillClosesOwnedSessions(t *testing.T) {
	a := revocation.NewAdmissionRevocations()
	p := &transportSavePersister{}
	a.SetPersister(p)
	ledger := enrolledinventory.NewLedger()
	for id, tenant := range map[string]string{"owned-device": "tenant_lab_001", "other-device": "tenant_other"} {
		if _, err := ledger.Enroll(id, tenant, "", time.Now().UTC().Format(time.RFC3339)); err != nil {
			t.Fatal(err)
		}
	}
	registry := newTransportConnRegistry()
	own, other := &fakeRevocableConn{}, &fakeRevocableConn{}
	registry.register("OWNED-DEVICE", own)
	registry.register("other-device", other)
	auth := seedAdminConnectorAPITokenAuth("transport-admin", transportAuditBearer, []string{"admin.endpoints.write"})
	h := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), AdminAuth: auth, EnrolledLedger: ledger, AdmissionRevocations: a, TransportConnRegistry: registry})
	p.err = errors.New("private storage error")
	r := transportAuditRequest(h, "revoke", `{"identity":" OWNED-DEVICE "}`, transportAuditBearer)
	if r.Code != 503 || own.closeCount() != 1 || other.closeCount() != 0 {
		t.Fatalf("status=%d own=%d other=%d", r.Code, own.closeCount(), other.closeCount())
	}
	if _, ok := a.IsRevoked("owned-device"); !ok {
		t.Fatal("block not enforced")
	}
	if _, ok := a.IsRevoked("other-device"); ok {
		t.Fatal("foreign blocked")
	}
}

func TestAdminEnrolledDeviceAdmissionAuditRecordsActorAndOutbox(t *testing.T) {
	h, w, _, outbox := transportAuditHandler(t)
	for _, action := range []string{"disable", "enable"} {
		req := httptest.NewRequest(http.MethodPost, "/admin/enrolled-devices/owned-device/"+action, nil)
		req.Header.Set("Authorization", "Bearer "+transportAuditBearer)
		r := httptest.NewRecorder()
		h.ServeHTTP(r, req)
		if r.Code != 200 {
			t.Fatalf("status=%d %s", r.Code, r.Body.String())
		}
	}
	domain := 0
	for _, a := range readTransportAudits(t, w) {
		if a.EventType != "enrolled_inventory_updated" {
			continue
		}
		domain++
		if a.TenantID != "tenant_lab_001" || stringPtrValue(a.ActorUserID) != "transport-admin" || stringPtrValue(a.TargetID) != "owned-device" || stringPtrValue(a.Result) != "success" {
			t.Fatalf("missing attribution: %+v", a)
		}
	}
	if domain != 2 || len(outbox.insertedAudits) != 2 || len(outbox.wrapperAudits) != 2 {
		t.Fatalf("domain=%d inserted=%d wrapper=%d", domain, len(outbox.insertedAudits), len(outbox.wrapperAudits))
	}
}
