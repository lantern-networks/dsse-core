package main

import (
	"context"
	"encoding/json"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestOperatorAccessFailedSaveAndRetry(t *testing.T) {
	for _, action := range []string{"delegation", "request", "approve", "end"} {
		t.Run(action, func(t *testing.T) {
			ctx := context.Background()
			dir := t.TempDir()
			path := filepath.Join(dir, "tenants.json")
			store := newOperatorAwareAdminTenantModelStore(model.PolicyBundle{TenantID: "customer"}, time.Now(), path, "operations")
			writer, err := logs.NewWriter(filepath.Join(dir, "logs"))
			if err != nil {
				t.Fatal(err)
			}
			outbox := &recordingAdminAuditOutboxDeadReader{}
			h := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), OperatorTenantID: "operations", AdminAuth: operatorSyncAuth(), TenantModelStore: store, Writer: writer, AdminAuditOutbox: outbox})
			call := func(who, method, url string, body map[string]any, want int) string {
				t.Helper()
				target := ""
				if who == "operator" {
					target = "customer"
				}
				code, raw := operatorEnvelopeCall(t, h, "synthetic-operator-sync-"+who, method, url, target, body)
				if code != want {
					t.Fatalf("%s %s: %d want %d: %s", method, url, code, want, raw)
				}
				return raw
			}
			call("customer-admin", "PUT", "/admin/operator-delegation", map[string]any{"managed": true, "elevation_requires_approval": true}, 200)
			who, method, url, body, want := "customer-admin", "PUT", "/admin/operator-delegation", map[string]any{"managed": false}, 200
			if action == "request" {
				who, method, url, body, want = "operator", "POST", "/admin/operator-elevations", map[string]any{"minutes": 10}, 201
			}
			if action == "approve" || action == "end" {
				raw := call("operator", "POST", "/admin/operator-elevations", map[string]any{"minutes": 10}, 201)
				var created struct {
					Elevation operatorElevation `json:"elevation"`
				}
				if json.Unmarshal([]byte(raw), &created) != nil || created.Elevation.ID == "" {
					t.Fatal(raw)
				}
				url = "/admin/operator-elevations/" + created.Elevation.ID
				body = nil
				if action == "approve" {
					method = "POST"
					url += "/approve"
				} else {
					method = "DELETE"
					call("customer-admin", "POST", url+"/approve", nil, 200)
				}
			}
			before, _ := store.Get(ctx, "customer")
			generation := store.ConfigGeneration()
			if err := os.Rename(path, path+".saved"); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(path, 0700); err != nil {
				t.Fatal(err)
			}
			raw := call(who, method, url, body, 503)
			if strings.Contains(raw, dir) || strings.Contains(raw, "rename") || !strings.Contains(raw, "Reload before retrying") {
				t.Fatalf("unsafe or unactionable response: %s", raw)
			}
			after, _ := store.Get(ctx, "customer")
			if !reflect.DeepEqual(before, after) || store.ConfigGeneration() != generation {
				t.Fatal("failed save changed live authorization")
			}
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(path+".saved", path); err != nil {
				t.Fatal(err)
			}
			call(who, method, url, body, want)
			saved, _ := newOperatorAwareAdminTenantModelStore(model.PolicyBundle{}, time.Now(), path, "operations").Get(ctx, "customer")
			live, _ := store.Get(ctx, "customer")
			if !reflect.DeepEqual(saved, live) || reflect.DeepEqual(saved, before) || store.ConfigGeneration() != generation+1 {
				t.Fatal("retry not durably reflected")
			}
			outbox.mu.Lock()
			defer outbox.mu.Unlock()
			audits := outbox.wrapperAudits
			if len(audits) < 2 {
				t.Fatal("missing audit")
			}
			for i, status := range []int{503, want} {
				a := audits[len(audits)-2+i]
				result := "error"
				if i == 1 {
					result = "success"
				}
				if a.ActorUserID == nil || *a.ActorUserID != who || a.Result == nil || *a.Result != result || a.Metadata["status_code"] != status {
					t.Fatalf("audit %+v", a)
				}
			}
		})
	}
}
