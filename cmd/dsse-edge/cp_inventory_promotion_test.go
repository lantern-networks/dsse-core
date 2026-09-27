package main

import (
	"encoding/json"
	"errors"
	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/enrolledinventory"
	"github.com/lantern-networks/dsse-core/logs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func inventoryPromotionHandler(ledger *enrolledinventory.Ledger, writers ...*logs.Writer) http.Handler {
	var writer *logs.Writer
	if len(writers) > 0 {
		writer = writers[0]
	}
	auth := newAdminAuthStore()
	auth.UpsertPrincipal(adminPrincipal{ID: "probe", TenantID: "tenant_lab_001", Email: "probe@example.invalid", Roles: []string{"admin"}, Status: "active"})
	auth.UpsertAPIToken(adminAPIToken{ID: "probe", CreatedByAdminPrincipalID: "probe", TenantID: "tenant_lab_001", TokenHash: adminTokenHash("inventory-probe-token"), Roles: []string{"admin"}, Scopes: []string{"*"}, Status: "active", ExpiresAt: time.Now().Add(time.Hour).Format(time.RFC3339)})
	return newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Writer: writer, AdminAuth: auth, EnrolledLedger: ledger})
}
func inventoryPromotionRead(h http.Handler, path string) *httptest.ResponseRecorder {
	q := httptest.NewRequest("GET", path, nil)
	q.Header.Set("Authorization", "Bearer inventory-probe-token")
	r := httptest.NewRecorder()
	h.ServeHTTP(r, q)
	return r
}
func TestInventoryPromotionLoadsLatestAndClosesStandbyReads(t *testing.T) {
	oldCP, oldE := edgeIsControlPlane, cpLeaderElectorInstance
	defer func() { edgeIsControlPlane = oldCP; cpLeaderElectorInstance = oldE }()
	edgeIsControlPlane = true
	for _, backend := range []string{"postgres", "postgres+import:old.json"} {
		for _, initial := range []bool{true, false} {
			t.Run(backend+"/"+map[bool]string{true: "disable", false: "enable"}[initial], func(t *testing.T) {
				p := blobstore.FilePersister{Path: filepath.Join(t.TempDir(), "state.json")}
				author := enrolledinventory.NewLedger()
				author.SetPersister(p)
				author.Enroll("owned-device", "tenant_lab_001", "", "now")
				author.Enroll("foreign-device", "other", "", "now")
				author.SetEnabledChecked("owned-device", initial, "now")
				candidate := enrolledinventory.NewLedger()
				if err := candidate.SetPersisterChecked(p); err != nil {
					t.Fatal(err)
				}
				author.SetEnabledChecked("owned-device", !initial, "later")
				e := newPromotionModelElector(&promotionLockModel{})
				defer func() { e.release(); e.db.Close() }()
				cpLeaderElectorInstance = e
				prepared := 0
				e.prepareLeadership = func() error { prepared++; return nil }
				configureInventoryPromotion(e, backend, candidate)
				h := inventoryPromotionHandler(candidate)
				for _, path := range []string{"/admin/config-bundle", "/admin/enrolled-devices", "/admin/device-groups"} {
					if r := inventoryPromotionRead(h, path); r.Code != 409 || strings.Contains(r.Body.String(), "owned-device") {
						t.Fatalf("standby read %s: %d", path, r.Code)
					}
				}
				e.tick()
				if !e.IsLeader() || prepared != 1 {
					t.Fatal("promotion not prepared")
				}
				r := inventoryPromotionRead(h, "/admin/config-bundle")
				var f configBundlePayload
				json.Unmarshal(r.Body.Bytes(), &f)
				if r.Code != 200 || f.Enrolled == nil || len(f.Enrolled.Entries) != 2 || f.Enrolled.Entries[1].Identity != "owned-device" || f.Enrolled.Entries[1].Enabled == initial || !candidate.IsAdmitted("foreign-device") {
					t.Fatalf("stale promotion %d %+v", r.Code, f.Enrolled)
				}
				gen := candidate.ConfigGeneration()
				e.release()
				e.tick()
				if !e.IsLeader() || candidate.ConfigGeneration() != gen {
					t.Fatal("same state churn")
				}
			})
		}
	}
}
func TestInventoryPromotionLoadFailureReleasesAndRepairs(t *testing.T) {
	for _, bad := range []string{"{}", "null", "{broken", ""} {
		t.Run(bad, func(t *testing.T) {
			p := blobstore.FilePersister{Path: filepath.Join(t.TempDir(), "state.json")}
			l := enrolledinventory.NewLedger()
			l.SetPersister(p)
			l.Enroll("device", "tenant", "", "now")
			valid, _ := p.Load()
			p.Save([]byte(bad))
			e := newPromotionModelElector(&promotionLockModel{})
			defer func() { e.release(); e.db.Close() }()
			configureInventoryPromotion(e, "postgres", l)
			e.tick()
			if e.IsLeader() || e.conn != nil || !l.IsAdmitted("device") {
				t.Fatal("failed load published leader or replaced live state")
			}
			p.Save(valid)
			e.tick()
			if !e.IsLeader() {
				t.Fatal("repair did not promote")
			}
			if _, err := l.SetEnabledChecked("device", false, "later"); err != nil {
				t.Fatal("successful read did not clear write latch")
			}
		})
	}
}

type inventoryHeldLoad struct {
	file           blobstore.FilePersister
	hold           atomic.Bool
	started, allow chan struct{}
	loads          atomic.Int64
}

func (p *inventoryHeldLoad) Load() ([]byte, error) {
	p.loads.Add(1)
	b, err := p.file.Load()
	if p.hold.CompareAndSwap(true, false) {
		close(p.started)
		<-p.allow
	}
	return b, err
}
func (p *inventoryHeldLoad) Save(b []byte) error { return p.file.Save(b) }
func TestInventoryWarmReadCannotCrossPromotion(t *testing.T) {
	p := &inventoryHeldLoad{file: blobstore.FilePersister{Path: filepath.Join(t.TempDir(), "state.json")}, started: make(chan struct{}), allow: make(chan struct{})}
	author := enrolledinventory.NewLedger()
	author.SetPersister(p.file)
	author.Enroll("device", "tenant", "", "now")
	l := enrolledinventory.NewLedger()
	l.SetPersister(p)
	e := newPromotionModelElector(&promotionLockModel{})
	defer func() { e.release(); e.db.Close() }()
	configureInventoryPromotion(e, "postgres", l)
	p.hold.Store(true)
	warm := make(chan error, 1)
	go func() { _, err := e.refreshStandbyInventory(l); warm <- err }()
	<-p.started
	author.SetEnabledChecked("device", false, "later")
	promoted := make(chan struct{})
	go func() { e.tick(); close(promoted) }()
	select {
	case <-promoted:
		t.Fatal("promotion crossed pending warm read")
	case <-time.After(30 * time.Millisecond):
	}
	close(p.allow)
	if err := <-warm; err != nil {
		t.Fatal(err)
	}
	<-promoted
	if !e.IsLeader() || l.IsAdmitted("device") {
		t.Fatal("final preparation did not replace stale warm state")
	}
	loads := p.loads.Load()
	if changed, err := e.refreshStandbyInventory(l); err != nil || changed || p.loads.Load() != loads {
		t.Fatal("leader was reloaded by timer")
	}
}
func TestInventoryPromotionPreservesPreviousFailureAndLocalBoundary(t *testing.T) {
	for _, backend := range []string{"postgres", "postgres+import:old"} {
		e := newPromotionModelElector(&promotionLockModel{})
		prior := errors.New("prior preparation unavailable")
		e.prepareLeadership = func() error { return prior }
		configureInventoryPromotion(e, backend, enrolledinventory.NewLedger())
		if err := e.prepareLeadership(); err != prior {
			t.Fatal("prior preparation lost")
		}
		e.db.Close()
	}
	for _, backend := range []string{"", "local.json", "disabled"} {
		e := newPromotionModelElector(&promotionLockModel{})
		configureInventoryPromotion(e, backend, enrolledinventory.NewLedger())
		if e.prepareLeadership != nil {
			t.Fatal("local store hooked")
		}
		e.db.Close()
	}
	source, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	s := string(source)
	start := strings.Index(s, "cpLeaderElectorInstance.Start()")
	hook := strings.Index(s, "configureInventoryPromotion(cpLeaderElectorInstance, *enrolledInventoryStore, enrolledLedger)")
	load := strings.Index(s, "enrolledLedger.SetPersisterChecked(")
	if load < 0 || hook < load || start < hook || !strings.Contains(s, "cpLeaderElectorInstance.refreshStandbyInventory(l)") || strings.Contains(s, "wasLeader := cpLeaderElectorInstance") {
		t.Fatal("startup or timer bypasses inventory preparation")
	}
}

func TestInventoryGroupAuditRecordsActorAndTarget(t *testing.T) {
	oldCP, oldE := edgeIsControlPlane, cpLeaderElectorInstance
	defer func() { edgeIsControlPlane = oldCP; cpLeaderElectorInstance = oldE }()
	edgeIsControlPlane = true
	cpLeaderElectorInstance = nil
	root := t.TempDir()
	writer, err := logs.NewWriter(root)
	if err != nil {
		t.Fatal(err)
	}
	ledger := enrolledinventory.NewLedger()
	h := inventoryPromotionHandler(ledger, writer)
	request := func(method, path, body string) *httptest.ResponseRecorder {
		q := httptest.NewRequest(method, path, strings.NewReader(body))
		q.Header.Set("Authorization", "Bearer inventory-probe-token")
		q.Header.Set("Content-Type", "application/json")
		r := httptest.NewRecorder()
		h.ServeHTTP(r, q)
		return r
	}
	r := request("POST", "/admin/device-groups", `{"name":"Review","risk":"high"}`)
	if r.Code != 200 {
		t.Fatalf("create %d %s", r.Code, r.Body)
	}
	var reply struct {
		Group enrolledinventory.Group `json:"group"`
	}
	json.Unmarshal(r.Body.Bytes(), &reply)
	path := "/admin/device-groups/" + reply.Group.ID
	for _, step := range []struct{ method, body string }{{"PATCH", `{"name":"Updated","risk":"medium"}`}, {"DELETE", ""}} {
		if r := request(step.method, path, step.body); r.Code != 200 {
			t.Fatalf("%s %d %s", step.method, r.Code, r.Body)
		}
	}
	foreign, _ := ledger.CreateGroup("Foreign", "other", "", "high", "now")
	if r := request("DELETE", "/admin/device-groups/"+foreign.ID, ""); r.Code != 404 {
		t.Fatalf("foreign deletion %d", r.Code)
	}
	if len(ledger.ListGroups()) != 1 {
		t.Fatal("foreign group changed")
	}
	raw, err := os.ReadFile(filepath.Join(root, "audit.log.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) != 7 {
		t.Fatalf("audits=%d", len(lines))
	}
	domain := 0
	for _, line := range lines {
		var a map[string]any
		json.Unmarshal([]byte(line), &a)
		if a["actor_user_id"] != "probe" || a["tenant_id"] != "tenant_lab_001" {
			t.Fatal("audit lost actor/tenant")
		}
		if a["event_type"] == "enrolled_inventory_updated" {
			domain++
			if a["target_type"] != "device_group" || a["target_id"] != reply.Group.ID || a["result"] != "success" {
				t.Fatal("wrong group target")
			}
			if _, exists := a["metadata"].(map[string]any)["enabled"]; exists {
				t.Fatal("group claims device admission")
			}
		}
	}
	if domain != 3 {
		t.Fatal("group domain audit count")
	}
}
