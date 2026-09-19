package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/revocation"
)

func TestRiskReadRefusesStaleStandbyThroughPromotion(t *testing.T) {
	oldCP, oldE := edgeIsControlPlane, cpLeaderElectorInstance
	defer func() { edgeIsControlPlane = oldCP; cpLeaderElectorInstance = oldE }()
	edgeIsControlPlane = true
	for _, backend := range []string{"postgres", "postgres+import:legacy.json"} {
		for _, initial := range []bool{false, true} {
			t.Run(backend+map[bool]string{false: "/raise", true: "/clear"}[initial], func(t *testing.T) {
				cpLeaderElectorInstance = nil
				h, writer, candidate, out, _, _ := deviceRiskAuditHandler(t)
				p := blobstore.FilePersister{Path: filepath.Join(t.TempDir(), "risk.json")}
				author := revocation.NewHighRiskOverlay()
				if err := author.SetPersister(p); err != nil {
					t.Fatal(err)
				}
				set := func(sev string) {
					t.Helper()
					if _, err := author.SetDeviceRisk("owned-device", sev); err != nil {
						t.Fatal(err)
					}
					if _, err := author.SetUserRisk(revocation.UserRisk{TenantID: "tenant_lab_001", ID: "person", Subjects: []string{"person-subject"}, Severity: sev}); err != nil {
						t.Fatal(err)
					}
				}
				if _, err := author.SetDeviceRisk("other-device", "high"); err != nil {
					t.Fatal(err)
				}
				if _, err := author.SetUserRisk(revocation.UserRisk{TenantID: "tenant_other", ID: "person", Severity: "high"}); err != nil {
					t.Fatal(err)
				}
				if initial {
					set("critical")
				}
				if err := candidate.SetPersister(p); err != nil {
					t.Fatal(err)
				}
				oldDevices, oldUsers := candidate.Snapshot(), candidate.UserSnapshot()
				want := "critical"
				if initial {
					want = ""
					set("none")
				} else {
					set("critical")
				}
				saved, err := p.Load()
				if err != nil {
					t.Fatal(err)
				}
				e := newPromotionModelElector(&promotionLockModel{})
				defer func() { e.release(); e.db.Close() }()
				configureRiskPromotion(e, backend, candidate)
				cpLeaderElectorInstance = e
				refused := func() {
					t.Helper()
					for _, q := range []string{"", "?entity_type=user"} {
						r := promotionRead(h, "/admin/risk-signals"+q)
						if r.Code != 409 || strings.Contains(r.Body.String(), "high_risk") || strings.Contains(r.Body.String(), "person-subject") {
							t.Errorf("standby read must refuse without risk data: %d %s", r.Code, r.Body)
						}
					}
				}
				refused()
				if !reflect.DeepEqual(oldDevices, candidate.Snapshot()) || !reflect.DeepEqual(oldUsers, candidate.UserSnapshot()) {
					t.Fatal("read mutated held state")
				}
				after, _ := p.Load()
				if !bytes.Equal(saved, after) {
					t.Fatal("read changed persistence")
				}
				e.tick()
				if !e.IsLeader() {
					t.Fatal("promotion failed")
				}
				for _, q := range []string{"", "?entity_type=user"} {
					r := promotionRead(h, "/admin/risk-signals"+q)
					var body struct {
						Risk   map[string]string `json:"high_risk"`
						Tenant string            `json:"tenant_id"`
					}
					if err := json.Unmarshal(r.Body.Bytes(), &body); err != nil {
						t.Fatal(err)
					}
					id := "owned-device"
					if q != "" {
						id = "person"
					}
					if r.Code != 200 || body.Tenant != "tenant_lab_001" || body.Risk[id] != want || len(body.Risk) != map[bool]int{true: 0, false: 1}[want == ""] {
						t.Fatalf("promoted response stale/foreign: %d %s", r.Code, r.Body)
					}
				}
				// Loss of leadership closes the reads again even while the held snapshot is healthy.
				e.release()
				refused()
				if candidate.Health() != nil {
					t.Fatal("standby refusal poisoned storage health")
				}
				valid, _ := p.Load()
				if err := os.WriteFile(p.Path, []byte("{broken"), 0600); err != nil {
					t.Fatal(err)
				}
				e.tick()
				if e.IsLeader() || candidate.Health() == nil {
					t.Fatal("failed promotion advertised leadership")
				}
				refused()
				if err := os.WriteFile(p.Path, valid, 0600); err != nil {
					t.Fatal(err)
				}
				e.tick()
				if !e.IsLeader() || candidate.Health() != nil {
					t.Fatal("recovery failed")
				}
				if r := promotionRead(h, "/admin/risk-signals"); r.Code != 200 {
					t.Fatal("read did not recover", r.Code, r.Body)
				}
				if len(out.insertedAudits) != 0 {
					t.Fatal("read/promotion produced change audit")
				}
				if b, err := os.ReadFile(filepath.Join(writer.Dir(), "audit.log.jsonl")); !os.IsNotExist(err) && (err != nil || len(bytes.TrimSpace(b)) > 0) {
					t.Fatal("read produced change audit", err, string(b))
				}
			})
		}
	}
}

func TestRiskReadAuthorityAndAuthenticationBoundaries(t *testing.T) {
	oldCP, oldE := edgeIsControlPlane, cpLeaderElectorInstance
	defer func() { edgeIsControlPlane = oldCP; cpLeaderElectorInstance = oldE }()
	cpLeaderElectorInstance = nil
	h, _, risk, _, _, _ := deviceRiskAuditHandler(t)
	if _, err := risk.SetDeviceRisk("owned-device", "high"); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name                string
		cp, elector, leader bool
		status              int
	}{{"edge", false, true, false, 200}, {"single-cp", true, false, false, 200}, {"leader", true, true, true, 200}, {"standby", true, true, false, 409}} {
		t.Run(tc.name, func(t *testing.T) {
			edgeIsControlPlane = tc.cp
			cpLeaderElectorInstance = nil
			if tc.elector {
				e := &cpLeaderElector{}
				e.isLeader.Store(tc.leader)
				cpLeaderElectorInstance = e
			}
			for _, q := range []string{"", "?entity_type=user"} {
				if r := promotionRead(h, "/admin/risk-signals"+q); r.Code != tc.status {
					t.Fatal(r.Code, r.Body)
				}
			}
			for _, auth := range []struct {
				token  string
				status int
			}{{"", 401}, {transportAuditReadBearer, 403}} {
				r := httptest.NewRequest(http.MethodGet, "/admin/risk-signals", nil)
				if auth.token != "" {
					r.Header.Set("Authorization", "Bearer "+auth.token)
				}
				w := httptest.NewRecorder()
				h.ServeHTTP(w, r)
				if w.Code != auth.status || strings.Contains(w.Body.String(), "owned-device") {
					t.Fatal("authorization lost priority", w.Code, w.Body)
				}
			}
		})
	}
	// Load errors remain 503 on an authority, independent of standby refusal.
	edgeIsControlPlane = true
	cpLeaderElectorInstance = nil
	bad := filepath.Join(t.TempDir(), "broken.json")
	if err := os.WriteFile(bad, []byte("{broken"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := risk.SetStatePath(bad); err == nil {
		t.Fatal("bad file accepted")
	}
	if r := promotionRead(h, "/admin/risk-signals"); r.Code != 503 {
		t.Fatal("load error hidden", r.Code, r.Body)
	}
}
