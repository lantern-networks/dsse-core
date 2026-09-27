package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/humanidentity"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/revocation"
)

type userRiskFlushPersister struct {
	data []byte
	err  error
}

func (p *userRiskFlushPersister) Load() ([]byte, error) { return bytes.Clone(p.data), nil }
func (p *userRiskFlushPersister) Save(b []byte) error   { p.data = bytes.Clone(b); return p.err }

func TestUserRiskHTTPRefusesUnconfirmedFlushAndAllowsExplicitRetry(t *testing.T) {
	for _, mode := range []string{"unconfirmed", "bridge", "synced_in_place"} {
		for _, severity := range []string{"critical", "none"} {
			t.Run(mode+"/"+severity, func(t *testing.T) {
				tenant := "tenant_lab_001"
				directory := humanidentity.NewHumanIdentityDirectoryStore(model.HumanIdentity{TenantID: tenant, ID: "person", Subject: "private-subject"}, model.HumanIdentity{TenantID: "foreign", ID: "person", Subject: "private-subject"})
				p := &userRiskFlushPersister{}
				risk := revocation.NewHighRiskOverlay()
				risk.SetPersister(p)
				for _, owner := range []string{tenant, "foreign"} {
					if _, err := risk.SetUserRisk(revocation.UserRisk{TenantID: owner, ID: "person", Subjects: []string{"private-subject"}, Severity: "high"}); err != nil {
						t.Fatal(err)
					}
				}
				before, generation := risk.UserSnapshot(), risk.ConfigGeneration()
				auth := seedAdminConnectorAPITokenAuth("risk-admin", "private-risk-bearer", []string{"admin.risk.read", "admin.risk.write"})
				writer, err := logs.NewWriter(t.TempDir())
				if err != nil {
					t.Fatal(err)
				}
				h := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), AdminAuth: auth, Writer: writer, HumanIdentities: directory, HighRiskOverlay: risk})
				send := func(method, path, body string) *httptest.ResponseRecorder {
					req := httptest.NewRequest(method, path, strings.NewReader(body))
					req.Header.Set("Authorization", "Bearer private-risk-bearer")
					w := httptest.NewRecorder()
					h.ServeHTTP(w, req)
					return w
				}
				p.err = blobstore.ErrDurabilityUnconfirmed
				if mode == "bridge" {
					p.err = errors.Join(blobstore.ErrSavedWithoutAtomicity, blobstore.ErrDurabilityUnconfirmed)
				}
				if mode == "synced_in_place" {
					p.err = blobstore.ErrSavedWithoutAtomicity
				}
				body := `{"entity_type":"user","entity_id":"person","severity":"` + severity + `","raw_evidence_reference":"private-evidence"}`
				r := send(http.MethodPost, "/admin/risk-signals", body)
				if mode == "synced_in_place" {
					if r.Code != 200 || !strings.Contains(r.Body.String(), `"not_stored_durably"`) {
						t.Fatal("completed weak save lost warning")
					}
				} else {
					if r.Code != 503 {
						t.Fatalf("unconfirmed save status=%d, want 503", r.Code)
					}
					if !reflect.DeepEqual(before, risk.UserSnapshot()) || risk.ConfigGeneration() != generation {
						t.Fatal("refused change published")
					}
					list := send(http.MethodGet, "/admin/risk-signals?entity_type=user", "")
					if list.Code != 200 || !strings.Contains(list.Body.String(), `"person":"high"`) {
						t.Fatal("read lost previous authoritative risk")
					}
				}
				rows, err := writer.ReadJSONL("audit.log.jsonl")
				if err != nil {
					t.Fatal(err)
				}
				domain, common := 0, 0
				for _, a := range rows {
					if a["actor_user_id"] != "risk-admin" || a["tenant_id"] != tenant {
						t.Fatal("wrong audit attribution")
					}
					switch a["event_type"] {
					case "admin_config_change":
						common++
						want := "error"
						if mode == "synced_in_place" {
							want = "success"
						}
						if a["result"] != want || a["target_id"] != "/admin/risk-signals" {
							t.Fatal("wrong route audit")
						}
					case "user_risk_changed":
						domain++
						if mode != "synced_in_place" || a["result"] != "partial" || a["target_id"] != "person" {
							t.Fatal("unconfirmed change audited as applied")
						}
					}
				}
				if common != 1 || (mode == "synced_in_place" && domain != 1) || (mode != "synced_in_place" && domain != 0) {
					t.Fatal("wrong original audit count")
				}
				encoded, _ := json.Marshal(rows)
				for _, secret := range []string{"private-evidence", "private-subject", "private-risk-bearer"} {
					if bytes.Contains(encoded, []byte(secret)) || strings.Contains(r.Body.String(), secret) {
						t.Fatal("private value disclosed")
					}
				}
				p.err = nil
				if r := send(http.MethodPost, "/admin/risk-signals", body); r.Code != 200 {
					t.Fatal("explicit retry refused")
				}
				reopened := revocation.NewHighRiskOverlay()
				reopened.SetPersister(p)
				if !reflect.DeepEqual(risk.UserSnapshot(), reopened.UserSnapshot()) {
					t.Fatal("reapplied state differs after reopen")
				}
				if sev, _ := reopened.UserSeverity("foreign", "private-subject"); sev != "high" {
					t.Fatal("foreign risk changed")
				}
				if _, ok := reopened.IsHighRisk("person"); ok {
					t.Fatal("user risk entered device namespace")
				}
			})
		}
	}
}
