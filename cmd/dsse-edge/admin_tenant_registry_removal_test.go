package main

import (
	"context"
	"errors"
	"github.com/lantern-networks/dsse-core/enrolledinventory"
	"github.com/lantern-networks/dsse-core/logs"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestTenantRegistryRemovalSaveRefusal(t *testing.T) {
	for _, operation := range []string{"delete", "purge-order"} {
		t.Run(operation, func(t *testing.T) {
			ctx := context.Background()
			now := time.Now().UTC()
			path := filepath.Join(t.TempDir(), "tenants.json")
			s := newDurableAdminTenantModelStore(testEvaluator().PolicyBundle, now, path)
			if _, err := s.Put(ctx, adminTenantModel{TenantID: "target", DisplayName: "Target"}, now); err != nil {
				t.Fatal(err)
			}
			before, _ := s.List(ctx)
			generation := s.ConfigGeneration()
			disk, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(path, path+".saved"); err != nil {
				t.Fatal(err)
			}
			for _, p := range []string{path, path + ".tmp"} {
				if err := os.Mkdir(p, 0700); err != nil {
					t.Fatal(err)
				}
			}
			for i := 0; i < 2; i++ {
				var err error
				if operation == "delete" {
					err = s.Delete(ctx, "target")
				} else {
					err = s.OrderPurge("target", now)
				}
				if !errors.Is(err, errAdminTenantSaveUnconfirmed) {
					t.Fatalf("missing persistence error: %v", err)
				}
				after, _ := s.List(ctx)
				if !reflect.DeepEqual(before, after) || len(s.DeletedTenants()) != 0 || len(s.PurgeOrders()) != 0 || s.ConfigGeneration() != generation {
					t.Fatal("unconfirmed removal published live state or generation")
				}
			}
			for _, p := range []string{path, path + ".tmp"} {
				if err := os.Remove(p); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Rename(path+".saved", path); err != nil {
				t.Fatal(err)
			}
			unchanged, _ := os.ReadFile(path)
			if string(unchanged) != string(disk) {
				t.Fatal("refusal changed snapshot")
			}
			for i := 0; i < 2; i++ {
				if operation == "delete" {
					if err := s.Delete(ctx, "target"); err != nil {
						t.Fatal(err)
					}
				} else {
					if err := s.OrderPurge("target", now.Add(time.Duration(i)*time.Hour)); err != nil {
						t.Fatal(err)
					}
				}
			}
			restored := newDurableAdminTenantModelStore(testEvaluator().PolicyBundle, now, path)
			if operation == "delete" {
				if len(restored.DeletedTenants()) != 1 {
					t.Fatal("tombstone not durable")
				}
			} else {
				if len(restored.PurgeOrders()) != 1 || restored.PurgeOrders()[0].OrderedAt != now.Format(time.RFC3339) {
					t.Fatal("first purge order not durable")
				}
			}
			if s.ConfigGeneration() != generation+1 {
				t.Fatal("retry/no-op generation wrong")
			}
		})
	}
}

func TestTenantRegistryRefusalStopsLifecycleHandler(t *testing.T) {
	for _, operation := range []string{"delete", "purge"} {
		t.Run(operation, func(t *testing.T) {
			dir := t.TempDir()
			now := time.Now().UTC()
			path := filepath.Join(dir, "tenants.json")
			store := newOperatorAwareAdminTenantModelStore(testEvaluator().PolicyBundle, now, path, "tenant_lab_001")
			if _, err := store.Put(context.Background(), adminTenantModel{TenantID: "target", DisplayName: "Target"}, now); err != nil {
				t.Fatal(err)
			}
			if operation == "purge" {
				if err := store.Delete(context.Background(), "target"); err != nil {
					t.Fatal(err)
				}
			}
			ledger := enrolledinventory.NewLedger()
			if _, err := ledger.Enroll("kept-device", "target", "", now.Format(time.RFC3339)); err != nil {
				t.Fatal(err)
			}
			auth := newAdminAuthStore()
			auth.UpsertPrincipal(adminPrincipal{ID: "operator", TenantID: "tenant_lab_001", Roles: []string{"owner"}, Status: "active"})
			auth.UpsertAPIToken(adminAPIToken{ID: "token", TenantID: "tenant_lab_001", CreatedByAdminPrincipalID: "operator", Roles: []string{"owner"}, Scopes: []string{"*"}, Status: "active", TokenHash: adminTokenHash("synthetic-registry-removal"), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339)})
			writer, err := logs.NewWriter(filepath.Join(dir, "logs"))
			if err != nil {
				t.Fatal(err)
			}
			handler := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Writer: writer, AdminAuth: auth, TenantModelStore: store, OperatorTenantID: "tenant_lab_001", EnrolledLedger: ledger})
			before := ledger.Authoritative()
			generation := store.ConfigGeneration()
			if err := os.Rename(path, path+".saved"); err != nil {
				t.Fatal(err)
			}
			for _, p := range []string{path, path + ".tmp"} {
				if err := os.Mkdir(p, 0700); err != nil {
					t.Fatal(err)
				}
			}
			send := func() *httptest.ResponseRecorder {
				method, url, body := "DELETE", "/admin/tenants/target", ""
				if operation == "purge" {
					method, url, body = "POST", url+"/purge", `{"confirm_tenant_id":"target"}`
				}
				req := httptest.NewRequest(method, url, strings.NewReader(body))
				req.Header.Set("Authorization", "Bearer synthetic-registry-removal")
				req.Header.Set("Content-Type", "application/json")
				res := httptest.NewRecorder()
				handler.ServeHTTP(res, req)
				return res
			}
			for i := 0; i < 2; i++ {
				res := send()
				if res.Code != 503 {
					t.Fatalf("status %d: %s", res.Code, res.Body)
				}
				if strings.Contains(res.Body.String(), dir) {
					t.Fatal("private path leaked")
				}
			}
			if !reflect.DeepEqual(before, ledger.Authoritative()) || generation != store.ConfigGeneration() {
				t.Fatal("refused lifecycle changed data/generation")
			}
			rows := readTransportAudits(t, writer)
			if len(rows) != 2 {
				t.Fatal("refusal audit count", len(rows))
			}
			for _, a := range rows {
				if a.EventType != "admin_config_change" || stringPtrValue(a.Result) != "error" {
					t.Fatal("false lifecycle success audit", a)
				}
			}
			for _, p := range []string{path, path + ".tmp"} {
				if err := os.Remove(p); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Rename(path+".saved", path); err != nil {
				t.Fatal(err)
			}
			if res := send(); res.Code != 200 {
				t.Fatalf("retry: %d %s", res.Code, res.Body)
			}
			if operation == "purge" {
				if len(ledger.Authoritative()) != 0 {
					t.Fatal("retry did not erase")
				}
			} else {
				if ledger.Authoritative()[0].Enabled {
					t.Fatal("retry did not retire")
				}
			}
		})
	}
}
