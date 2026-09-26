package main

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/assetcatalog"
	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/eastwestobserve"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/policy"
	"github.com/lantern-networks/dsse-core/policyrule"
)

type adoptionFailurePersister struct {
	blobstore.Persister
	mu            sync.Mutex
	calls, failAt int
}

func (p *adoptionFailurePersister) Save(b []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls++
	if p.calls == p.failAt {
		return fmt.Errorf("private storage diagnostic must not escape")
	}
	return p.Persister.Save(b)
}

func TestObservationAdoptionPartialProgressAndRetry(t *testing.T) {
	for _, stage := range []string{"asset_endpoint", "rule"} {
		t.Run(stage, func(t *testing.T) {
			root := t.TempDir()
			tenant := "tenant_lab_001"
			rp := &adoptionFailurePersister{Persister: blobstore.FilePersister{Path: filepath.Join(root, "rules.json")}}
			ap := &adoptionFailurePersister{Persister: blobstore.FilePersister{Path: filepath.Join(root, "assets.json")}}
			if stage == "rule" {
				rp.failAt = 2
			} else {
				ap.failAt = 2
			}
			rules, assets := policyrule.NewStore(), assetcatalog.NewStore()
			if err := rules.SetPersister(rp); err != nil {
				t.Fatal(err)
			}
			if err := assets.SetPersister(ap); err != nil {
				t.Fatal(err)
			}
			assets.SetBuiltInServices(assetcatalog.BuiltInServices())
			obs := eastwestobserve.NewStore()
			ids := []string{}
			for i := 1; i <= 3; i++ {
				v := obs.Observe(tenant, "*", "", fmt.Sprintf("10.19.0.%d", i), "ssh", 22, time.Now())
				ids = append(ids, v.ObservationID)
			}
			foreign := obs.Observe("foreign", "*", "", "10.19.1.1", "ssh", 22, time.Now())
			auth := newAdminAuthStore()
			auth.UpsertPrincipal(adminPrincipal{ID: "review", TenantID: tenant, Roles: []string{"admin"}, Status: "active"})
			auth.UpsertAPIToken(adminAPIToken{ID: "adopt", TenantID: tenant, TokenHash: adminTokenHash("adopt-fixture"), Roles: []string{"admin"}, Scopes: []string{"*"}, CreatedByAdminPrincipalID: "review", Status: "active", ExpiresAt: time.Now().Add(time.Hour).Format(time.RFC3339)})
			writer, err := logs.NewWriter(filepath.Join(root, "logs"))
			if err != nil {
				t.Fatal(err)
			}
			defer writer.Close()
			policies := policy.NewStore(nil)
			out := &recordingAdminAuditOutboxDeadReader{}
			h := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Writer: writer, AdminAuth: auth, AdminAuditOutbox: out, PolicyStore: policies, RuleStore: rules, AssetStore: assets, EastWestObserveStore: obs})
			send := func(list []string) (int, map[string]any) {
				b, _ := json.Marshal(map[string]any{"observation_ids": list})
				r := httptest.NewRequest("POST", "/admin/east-west/observations/adopt", strings.NewReader(string(b)))
				r.Header.Set("Authorization", "Bearer adopt-fixture")
				w := httptest.NewRecorder()
				h.ServeHTTP(w, r)
				var v map[string]any
				if err := json.Unmarshal(w.Body.Bytes(), &v); err != nil {
					t.Fatal(err)
				}
				return w.Code, v
			}
			status, v := send(ids)
			if status != 500 || v["partial"] != true || v["failed_stage"] != stage || v["failed_observation_id"] != ids[1] {
				t.Fatalf("partial progress absent: %d %+v", status, v)
			}
			if strings.Contains(fmt.Sprint(v), "private storage") {
				t.Fatal("raw storage diagnostic leaked")
			}
			if len(v["created"].([]any)) != 1 || len(v["adopted"].([]any)) != 1 || len(v["unprocessed"].([]any)) != 1 {
				t.Fatalf("wrong progress: %+v", v)
			}
			reload := policyrule.NewStore()
			if err := reload.SetPersister(rp.Persister); err != nil {
				t.Fatal(err)
			}
			if got := reload.List(tenant, policyrule.PlaneEastWest); len(got) != 1 || got[0].ID != v["created"].([]any)[0] {
				t.Fatalf("confirmed rules differ: %+v", got)
			}
			if len(policies.EffectiveEastWestRules(tenant)) != 1 {
				t.Fatal("saved rule not compiled after partial failure")
			}
			status, v = send(append(ids, foreign.ObservationID))
			if status != 200 || len(v["created"].([]any)) != 2 || len(v["skipped_covered"].([]any)) != 1 || len(v["skipped_missing"].([]any)) != 1 {
				t.Fatalf("retry duplicates or loses progress: %d %+v", status, v)
			}
			reload = policyrule.NewStore()
			if err := reload.SetPersister(rp.Persister); err != nil {
				t.Fatal(err)
			}
			if len(reload.List(tenant, policyrule.PlaneEastWest)) != 3 || len(reload.List("foreign", policyrule.PlaneEastWest)) != 0 {
				t.Fatal("restart or tenant mismatch")
			}
			rows := readConnectorManagementAudits(t, writer)
			domain := 0
			for _, a := range rows {
				if a.EventType != "east_west_observations_adopted" {
					continue
				}
				want := "partial"
				if domain == 1 {
					want = "success"
				}
				if stringPtrValue(a.Result) != want || stringPtrValue(a.ActorUserID) != "review" || a.TenantID != tenant {
					t.Fatalf("bad audit: %+v", a)
				}
				if domain == 0 && a.Metadata["failed_stage"] != stage {
					t.Fatal("audit progress missing")
				}
				domain++
			}
			if domain != 2 || len(out.insertedAudits) != 2 {
				t.Fatalf("domain audit absent: file=%d outbox=%d", domain, len(out.insertedAudits))
			}
		})
	}
}

func TestObservationAdoptionRepeatedIDsAndPortCoverage(t *testing.T) {
	tenant := testEvaluator().PolicyBundle.TenantID
	rules, assets := policyrule.NewStore(), assetcatalog.NewStore()
	assets.SetBuiltInServices(assetcatalog.BuiltInServices())
	obs := eastwestobserve.NewStore()
	ssh := obs.Observe(tenant, "*", "", "host.example", "ssh", 22, time.Now())
	other := obs.Observe(tenant, "*", "", "host.example", "ssh", 2222, time.Now())
	h := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), AdminAuth: newAdminAuthStore(), PolicyStore: policy.NewStore(nil), RuleStore: rules, AssetStore: assets, EastWestObserveStore: obs})
	raw, _ := json.Marshal(map[string]any{"observation_ids": []string{ssh.ObservationID, ssh.ObservationID}})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("POST", "/admin/east-west/observations/adopt", strings.NewReader(string(raw))))
	var result struct {
		Created []string `json:"created"`
		Skipped []string `json:"skipped_covered"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil || w.Code != 200 || len(result.Created) != 1 || len(result.Skipped) != 1 {
		t.Fatalf("duplicate batch: %d %s", w.Code, w.Body)
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/admin/east-west/observations", nil))
	var inventory struct {
		Observations []eastwestobserve.FlowObservation `json:"observations"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &inventory); err != nil || w.Code != 200 {
		t.Fatalf("inventory: %d %s", w.Code, w.Body)
	}
	for _, o := range inventory.Observations {
		if o.ObservationID == ssh.ObservationID && !o.Covered {
			t.Fatal("saved SSH rule not reflected")
		}
		if o.ObservationID == other.ObservationID && o.Covered {
			t.Fatal("SSH rule incorrectly covers another port")
		}
	}
}

func TestObservationAdoptionRefusesReadOnlyAndPullingEdge(t *testing.T) {
	for _, edge := range []bool{false, true} {
		t.Run(fmt.Sprint(edge), func(t *testing.T) {
			tenant := testEvaluator().PolicyBundle.TenantID
			rules, assets, obs := policyrule.NewStore(), assetcatalog.NewStore(), eastwestobserve.NewStore()
			item := obs.Observe(tenant, "*", "", "test.example", "ssh", 22, time.Now())
			auth := newAdminAuthStore()
			scope, source, want := "admin.policy.read", "", 403
			if edge {
				scope, source, want = "*", "https://control.example", 409
			}
			auth.UpsertPrincipal(adminPrincipal{ID: "scope-reviewer", TenantID: tenant, Roles: []string{"admin"}, Status: "active"})
			auth.UpsertAPIToken(adminAPIToken{CreatedByAdminPrincipalID: "scope-reviewer", ID: "adopt-scope", TenantID: tenant, TokenHash: adminTokenHash("adopt-scope-fixture"), Roles: []string{"admin"}, Scopes: []string{scope}, Status: "active", ExpiresAt: time.Now().Add(time.Hour).Format(time.RFC3339)})
			h := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), AdminAuth: auth, RuleStore: rules, AssetStore: assets, EastWestObserveStore: obs, ConfigSourceURL: source})
			raw, _ := json.Marshal(map[string]any{"observation_ids": []string{item.ObservationID}})
			r := httptest.NewRequest("POST", "/admin/east-west/observations/adopt", strings.NewReader(string(raw)))
			r.Header.Set("Authorization", "Bearer adopt-scope-fixture")
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != want {
				t.Fatalf("status=%d want=%d body=%s", w.Code, want, w.Body)
			}
			if len(rules.List(tenant, policyrule.PlaneEastWest)) != 0 || len(assets.ListEndpoints(tenant)) != 0 {
				t.Fatal("refused request changed rules or assets")
			}
		})
	}
}
