package main

import (
	"context"
	"database/sql"
	"errors"
	"github.com/lantern-networks/dsse-core/model"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestTenantRemovalWaitsForConfirmedFileSave(t *testing.T) {
	for _, op := range []string{"delete", "purge"} {
		t.Run(op, func(t *testing.T) {
			ctx := context.Background()
			now := time.Now()
			path := filepath.Join(t.TempDir(), "tenants.json")
			s := newDurableAdminTenantModelStore(testEvaluator().PolicyBundle, now, path)
			before, _ := s.List(ctx)
			gen := s.ConfigGeneration()
			target := before[0].TenantID
			if err := os.Rename(path, path+".saved"); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(path, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(path+".tmp", 0700); err != nil {
				t.Fatal(err)
			}
			if op == "delete" {
				if err := s.Delete(ctx, target); err == nil {
					t.Fatal("delete reported success without saving")
				}
			} else {
				if err := s.OrderPurge(target, now); err == nil {
					t.Fatal("purge reported success without saving")
				}
			}
			after, _ := s.List(ctx)
			if !reflect.DeepEqual(before, after) || s.ConfigGeneration() != gen || len(s.DeletedTenants()) != 0 || len(s.PurgeOrders()) != 0 {
				t.Fatal("failed removal published live state or generation")
			}
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(path + ".tmp"); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(path+".saved", path); err != nil {
				t.Fatal(err)
			}
			if op == "delete" {
				if err := s.Delete(ctx, target); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := s.OrderPurge(target, now); err != nil {
					t.Fatal(err)
				}
			}
			fresh := newDurableAdminTenantModelStore(testEvaluator().PolicyBundle, now, path)
			if op == "delete" {
				found := false
				for _, d := range fresh.DeletedTenants() {
					if d.TenantID == target {
						found = true
					}
				}
				if !found {
					t.Fatal("deletion lost on restart")
				}
			} else if len(fresh.PurgeOrders()) != 1 {
				t.Fatal("purge order lost on restart")
			}
		})
	}
}

// A closed SQL handle tests the save-error boundary without connecting to a DB.
func TestTenantSQLWriteFailureIsUnavailable(t *testing.T) {
	db, err := sql.Open("postgres", "")
	if err != nil {
		t.Fatal(err)
	}
	db.Close()
	store := &postgresAdminTenantModelStore{db: db}
	created := time.Now().UTC().Format(time.RFC3339)
	for _, method := range []string{"put", "update"} {
		tenant := adminTenantModel{TenantID: "customer", DisplayName: "Customer", CreatedAt: &created}
		if method == "put" {
			_, err = store.Put(context.Background(), tenant, time.Now())
		} else {
			_, err = store.Update(context.Background(), tenant, "customer", time.Now())
		}
		if !errors.Is(err, errAdminTenantSaveUnconfirmed) {
			t.Fatalf("%s save not classified: %v", method, err)
		}
		w := httptest.NewRecorder()
		writeAdminTenantSaveError(w, 400, err)
		if w.Code != 503 || strings.Contains(w.Body.String(), "database is closed") {
			t.Fatalf("%s status/detail %d %s", method, w.Code, w.Body)
		}
	}
}

func TestTenantDeleteHTTPFailedSaveAndRetry(t *testing.T) {
	now := time.Now()
	path := filepath.Join(t.TempDir(), "tenants.json")
	tenants := newOperatorAwareAdminTenantModelStore(model.PolicyBundle{TenantID: "customer"}, now, path, "operations")
	for _, id := range []string{"operations", "customer"} {
		if _, err := tenants.Put(context.Background(), adminTenantModel{TenantID: id, DisplayName: id, Status: "active"}, now); err != nil {
			t.Fatal(err)
		}
	}
	auth := newAdminAuthStore()
	auth.UpsertPrincipal(adminPrincipal{ID: "operator", TenantID: "operations", Roles: []string{"super_admin"}, Status: "active"})
	auth.UpsertAPIToken(adminAPIToken{ID: "operator", TenantID: "operations", TokenHash: adminTokenHash("synthetic-removal"), Roles: []string{"super_admin"}, Scopes: []string{"*"}, CreatedByAdminPrincipalID: "operator", Status: "active", ExpiresAt: now.Add(time.Hour).Format(time.RFC3339)})
	h := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), AdminAuth: auth, TenantModelStore: tenants, OperatorTenantID: "operations"})
	if err := os.Rename(path, path+".saved"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	code, raw := operatorEnvelopeCall(t, h, "synthetic-removal", "DELETE", "/admin/tenants/customer", "", nil)
	if code != 503 || strings.Contains(raw, path) {
		t.Fatalf("failed delete: %d %s", code, raw)
	}
	rows, _ := tenants.List(context.Background())
	found := false
	for _, row := range rows {
		if row.TenantID == "customer" {
			found = true
		}
	}
	if !found {
		t.Fatal("failed delete removed tenant")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path+".saved", path); err != nil {
		t.Fatal(err)
	}
	code, raw = operatorEnvelopeCall(t, h, "synthetic-removal", "DELETE", "/admin/tenants/customer", "", nil)
	if code != 200 {
		t.Fatalf("retry: %d %s", code, raw)
	}
	rows, _ = tenants.List(context.Background())
	for _, row := range rows {
		if row.TenantID == "customer" {
			t.Fatal("retry did not remove tenant")
		}
	}
	if len(tenants.DeletedTenants()) != 1 {
		t.Fatal("retry missing tombstone")
	}
}
