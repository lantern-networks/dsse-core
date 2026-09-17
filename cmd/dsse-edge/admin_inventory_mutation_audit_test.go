package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/enrolledinventory"
	"github.com/lantern-networks/dsse-core/logs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type inventoryMutationStore struct {
	file   blobstore.FilePersister
	fail   atomic.Bool
	retain atomic.Bool
}

func (p *inventoryMutationStore) Load() ([]byte, error) { return p.file.Load() }
func (p *inventoryMutationStore) Save(b []byte) error {
	if p.fail.Load() {
		if p.retain.Load() {
			if err := p.file.Save(b); err != nil {
				return err
			}
		}
		return errors.Join(blobstore.ErrDurabilityUnconfirmed, errors.New("private storage detail"))
	}
	return p.file.Save(b)
}
func inventoryMutationFixture(t *testing.T) (http.Handler, *enrolledinventory.Ledger, *inventoryMutationStore, *recordingAdminAuditOutboxDeadReader, string) {
	t.Helper()
	oldCP, oldE := edgeIsControlPlane, cpLeaderElectorInstance
	t.Cleanup(func() { edgeIsControlPlane = oldCP; cpLeaderElectorInstance = oldE })
	edgeIsControlPlane = true
	cpLeaderElectorInstance = nil
	root := t.TempDir()
	writer, err := logs.NewWriter(filepath.Join(root, "logs"))
	if err != nil {
		t.Fatal(err)
	}
	p := &inventoryMutationStore{file: blobstore.FilePersister{Path: filepath.Join(root, "ledger.json")}}
	l := enrolledinventory.NewLedger()
	if err := l.SetPersisterChecked(p); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"target-device", "failure-device", "foreign-device", "expired-device"} {
		tenant := "tenant_lab_001"
		if id == "foreign-device" {
			tenant = "tenant_other"
		}
		if _, err := l.Enroll(id, tenant, "", "2000-01-01T00:00:00Z"); err != nil {
			t.Fatal(err)
		}
	}
	if !l.Remove("expired-device", "2000-01-01T00:00:00Z") {
		t.Fatal("seed removal failed")
	}
	if _, err := l.CreateGroup("QA", "tenant_lab_001", "", "high", "2000-01-01T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
	auth := newAdminAuthStore()
	auth.UpsertPrincipal(adminPrincipal{ID: "mutation_admin", TenantID: "tenant_lab_001", Email: "probe@example.invalid", Roles: []string{"admin"}, Status: "active"})
	auth.UpsertAPIToken(adminAPIToken{ID: "probe", CreatedByAdminPrincipalID: "mutation_admin", TenantID: "tenant_lab_001", TokenHash: adminTokenHash("inventory-mutation-token"), Roles: []string{"admin"}, Scopes: []string{"*"}, Status: "active", ExpiresAt: time.Now().Add(time.Hour).Format(time.RFC3339)})
	outbox := &recordingAdminAuditOutboxDeadReader{}
	h := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Writer: writer, AdminAuth: auth, EnrolledLedger: l, AdminAuditOutbox: outbox})
	return h, l, p, outbox, root
}
func inventoryMutationRequest(h http.Handler, method, path, body string) *httptest.ResponseRecorder {
	q := httptest.NewRequest(method, path, strings.NewReader(body))
	q.Header.Set("Authorization", "Bearer inventory-mutation-token")
	q.Header.Set("Content-Type", "application/json")
	r := httptest.NewRecorder()
	h.ServeHTTP(r, q)
	return r
}

func inventoryMutationAudits(t *testing.T, root string) []map[string]any {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, "logs", "audit.log.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	var rows []map[string]any
	for _, line := range bytes.Split(bytes.TrimSpace(b), []byte("\n")) {
		var a map[string]any
		if err := json.Unmarshal(line, &a); err != nil {
			t.Fatal(err)
		}
		rows = append(rows, a)
	}
	return rows
}
func TestInventoryMutationAuditOutcomes(t *testing.T) {
	for _, op := range []struct {
		name, method, path, body, id, field string
		want                                any
	}{
		{"enroll", "POST", "/admin/enrolled-devices", `{"identity":" New-Device ","group":" QA "}`, "new-device", "group", "QA"},
		{"assign_group", "POST", "/admin/enrolled-devices/target-device/group", `{"group":" QA "}`, "target-device", "group", "QA"},
		{"assign_group", "POST", "/admin/enrolled-devices/target-device/group", `{"group":""}`, "target-device", "group", ""},
		{"set_kind", "POST", "/admin/enrolled-devices/target-device/kind", `{"kind":" SERVICE "}`, "target-device", "kind", "service"},
		{"set_kind", "POST", "/admin/enrolled-devices/target-device/kind", `{"kind":"endpoint"}`, "target-device", "kind", "endpoint"},
		{"remove", "DELETE", "/admin/enrolled-devices/target-device", "", "target-device", "enabled", false},
	} {
		for _, outcome := range []struct {
			name         string
			fail, retain bool
		}{{"saved", false, false}, {"not_written", true, false}, {"unconfirmed_written", true, true}} {
			t.Run(op.name+"/"+op.body+"/"+outcome.name, func(t *testing.T) {
				h, l, p, outbox, root := inventoryMutationFixture(t)
				before := l.Authoritative()
				savedBefore, _ := p.file.Load()
				gen := l.ConfigGeneration()
				p.fail.Store(outcome.fail)
				p.retain.Store(outcome.retain)
				r := inventoryMutationRequest(h, op.method, op.path, op.body)
				wantStatus := 200
				if outcome.fail {
					wantStatus = 500
				}
				if r.Code != wantStatus {
					t.Fatalf("status %d: %s", r.Code, r.Body.String())
				}
				if strings.Contains(r.Body.String(), "private storage detail") {
					t.Fatal("storage detail exposed")
				}
				rows := inventoryMutationAudits(t, root)
				if len(rows) != 2 {
					t.Fatalf("audits %v", rows)
				}
				a := rows[0]
				result := "success"
				if outcome.fail {
					result = "partial"
					if op.name == "remove" {
						result = "failed"
					}
				}
				if a["result"] != result || a["action"] != "enrolled_inventory_"+op.name || a["target_type"] != "device" || a["target_id"] != op.id {
					t.Fatalf("domain %v", a)
				}
				for _, row := range rows {
					if row["actor_user_id"] != "mutation_admin" || row["tenant_id"] != "tenant_lab_001" {
						t.Fatalf("attribution %v", row)
					}
				}
				meta := a["metadata"].(map[string]any)
				if meta["applied_locally"] != (op.name != "remove" || !outcome.fail) {
					t.Fatalf("application %v", meta)
				}
				if outcome.fail && meta["persistence_error"] != true {
					t.Fatal("missing persistence failure")
				}
				want := op.want
				if op.name == "remove" && outcome.fail {
					want = true
				}
				if meta[op.field] != want {
					t.Fatalf("metadata %v want %v", meta, want)
				}
				outbox.mu.Lock()
				count := len(outbox.insertedAudits)
				var mirrored []byte
				if count == 1 {
					mirrored, _ = json.Marshal(outbox.insertedAudits[0])
				}
				outbox.mu.Unlock()
				var mirror map[string]any
				json.Unmarshal(mirrored, &mirror)
				if count != 1 || !reflect.DeepEqual(a, mirror) {
					t.Fatalf("domain outbox mismatch: %d %s", count, mirrored)
				}
				if op.name == "remove" && outcome.fail {
					if !reflect.DeepEqual(before, l.Authoritative()) || gen != l.ConfigGeneration() {
						t.Fatal("failed removal changed entries, expired tombstones, or generation")
					}
				}
				savedAfter, _ := p.file.Load()
				if outcome.fail && !outcome.retain && !bytes.Equal(savedBefore, savedAfter) {
					t.Fatal("rejected write changed file")
				}
				if outcome.retain && bytes.Equal(savedBefore, savedAfter) {
					t.Fatal("unconfirmed candidate was not retained")
				}
				if outcome.fail && op.name != "remove" && !strings.Contains(r.Body.String(), "active on this node") {
					t.Fatal("partial application not disclosed")
				}
				if outcome.fail {
					p.fail.Store(false)
					r = inventoryMutationRequest(h, op.method, op.path, op.body)
					if r.Code != 200 {
						t.Fatalf("retry %d %s", r.Code, r.Body.String())
					}
				}
				restored := enrolledinventory.NewLedger()
				if err := restored.SetPersisterChecked(p.file); err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(l.Authoritative(), restored.Authoritative()) {
					t.Fatal("confirmed state did not survive reload")
				}
			})
		}
	}
}
func TestInventoryMutationRefusalsDoNotMutateOrMirrorSuccess(t *testing.T) {
	for _, op := range []struct {
		method, path, body string
		status             int
	}{
		{"POST", "/admin/enrolled-devices", `{"identity":"foreign-device"}`, 404},
		{"POST", "/admin/enrolled-devices/foreign-device/group", `{"group":"QA"}`, 404},
		{"POST", "/admin/enrolled-devices/foreign-device/kind", `{"kind":"service"}`, 404},
		{"DELETE", "/admin/enrolled-devices/foreign-device", "", 404},
		{"DELETE", "/admin/enrolled-devices/expired-device", "", 404},
		{"POST", "/admin/enrolled-devices/target-device/kind", `{"kind":"unknown"}`, 400},
		{"POST", "/admin/enrolled-devices", `{"identity":""}`, 400},
	} {
		t.Run(op.method+op.path+op.body, func(t *testing.T) {
			h, l, p, outbox, root := inventoryMutationFixture(t)
			before := l.Authoritative()
			saved, _ := p.file.Load()
			gen := l.ConfigGeneration()
			r := inventoryMutationRequest(h, op.method, op.path, op.body)
			if r.Code != op.status {
				t.Fatalf("status %d %s", r.Code, r.Body.String())
			}
			after, _ := p.file.Load()
			if !reflect.DeepEqual(before, l.Authoritative()) || !bytes.Equal(saved, after) || gen != l.ConfigGeneration() {
				t.Fatal("refusal mutated state")
			}
			rows := inventoryMutationAudits(t, root)
			if len(rows) != 1 || rows[0]["result"] != "error" || rows[0]["actor_user_id"] != "mutation_admin" {
				t.Fatalf("refusal audit %v", rows)
			}
			outbox.mu.Lock()
			defer outbox.mu.Unlock()
			if len(outbox.insertedAudits) != 0 {
				t.Fatal("refusal mirrored domain success")
			}
		})
	}
}
