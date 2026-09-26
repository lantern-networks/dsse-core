package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/assetcatalog"
	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/humanidentity"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/policy"
	"github.com/lantern-networks/dsse-core/policycandidate"
	"github.com/lantern-networks/dsse-core/revocation"
)

func initialBlobDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("POSTGRES_QUEUE_E2E_DSN")
	if dsn == "" {
		t.Skip("POSTGRES_QUEUE_E2E_DSN not set")
	}
	db, err := newCPStateBlobDB(dsn, filepath.Join("..", "..", "migrations"), true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}
func initialBlob(t *testing.T, db *sql.DB, name string) postgresBlobPersister {
	t.Helper()
	key := fmt.Sprintf("initial_%s_%d", name, time.Now().UnixNano())
	t.Cleanup(func() {
		if _, err := db.Exec("DELETE FROM cp_state_blobs WHERE store_key=$1", key); err != nil {
			t.Error(err)
		}
	})
	return postgresBlobPersister{db: db, key: key}
}

func TestPostgresBlobInitialAndCancelledUpdate(t *testing.T) {
	db := initialBlobDB(t)
	for _, modern := range []bool{false, true} {
		t.Run(fmt.Sprint(modern), func(t *testing.T) {
			p := initialBlob(t, db, "contract")
			update := p.Update
			if modern {
				update = func(edit func([]byte) ([]byte, error)) error {
					return initialBlobContext(t, p, context.Background(), edit)
				}
			}
			if err := update(func(raw []byte) ([]byte, error) {
				if raw != nil {
					return nil, errors.New("absent row was not nil")
				}
				return []byte(`{"value":1}`), nil
			}); err != nil {
				t.Fatal(err)
			}
			if err := p.Save([]byte(`{}`)); err != nil {
				t.Fatal(err)
			}
			if err := update(func(raw []byte) ([]byte, error) {
				if string(raw) != "{}" {
					return nil, errors.New("existing empty object was disguised as absent")
				}
				return raw, nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
	p := initialBlob(t, db, "cancel")
	ctx, cancel := context.WithCancel(context.Background())
	err := initialBlobContext(t, p, ctx, func([]byte) ([]byte, error) { cancel(); return []byte(`{"value":1}`), nil })
	if !errors.Is(err, blobstore.ErrWriteNotCommitted) || !errors.Is(err, context.Canceled) {
		t.Fatalf("rollback classification: %v", err)
	}
	if raw, err := p.Load(); err != nil || raw != nil {
		t.Fatalf("cancelled first write persisted: %q %v", raw, err)
	}
	refusal := errors.New("invalid edit")
	err = p.Update(func([]byte) ([]byte, error) { return nil, refusal })
	if !errors.Is(err, refusal) || !errors.Is(err, blobstore.ErrWriteNotCommitted) || err.Error() != refusal.Error() {
		t.Fatalf("refusal changed: %v", err)
	}
}

// Run on both the base and the reconciled store PRs. This exercises production
// HTTP handlers backed by real PostgreSQL, not a persister mock or GUI fixture.
func TestPostgresBlobInitialAdminWrites(t *testing.T) {
	db := initialBlobDB(t)
	tenant := testEvaluator().PolicyBundle.TenantID
	assets := assetcatalog.NewStore()
	ap := initialBlob(t, db, "assets")
	if err := assets.SetPersister(ap); err != nil {
		t.Fatal(err)
	}
	policies := policy.NewStore(nil)
	pp := initialBlob(t, db, "policy")
	if err := policies.SetRuntimeStatePersister(pp); err != nil {
		t.Fatal(err)
	}
	candidates := policycandidate.NewStore()
	cp := initialBlob(t, db, "candidates")
	if err := candidates.SetPersister(cp); err != nil {
		t.Fatal(err)
	}
	risks := revocation.NewHighRiskOverlay()
	rp := initialBlob(t, db, "risk")
	if err := risks.SetPersister(rp); err != nil {
		t.Fatal(err)
	}
	for _, p := range []postgresBlobPersister{ap, pp, cp, rp} {
		if raw, err := p.Load(); err != nil || raw != nil {
			t.Fatalf("not an empty store before startup: %v", err)
		}
	}
	directory := humanidentity.NewHumanIdentityDirectoryStore(model.HumanIdentity{TenantID: tenant, ID: "fresh-user", Subject: "fresh-user"})
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	h := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), OperatorTenantID: tenant, AdminAuth: newAdminAuthStore(), Writer: writer, AssetStore: assets, PolicyStore: policies, PolicyCandidateStore: candidates, HighRiskOverlay: risks, HumanIdentities: directory})
	cases := []struct {
		name, path, body string
		p                postgresBlobPersister
	}{
		{"assets", "/admin/assets/services", `{"id":"fresh-service","alias":"fresh-service","ports":[{"protocol":"tcp","port":443}]}`, ap},
		{"policy", "/admin/policies", `{"id":"fresh-policy","name":"Fresh policy","status":"active","conditions":{"sni":"example.invalid"},"action":{"decision":"allow"}}`, pp},
		{"candidates", "/admin/policy-candidates", `{"candidate_id":"fresh-candidate","application_id":"fresh-app","service_family":"web","status":"pending"}`, cp},
		{"risk", "/admin/risk-signals", `{"entity_type":"user","entity_id":"fresh-user","severity":"high"}`, rp},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := doAdmin(t, h, http.MethodPost, tc.path, tc.body)
			if rec.Code != http.StatusOK {
				t.Fatalf("initial save: %d %s", rec.Code, rec.Body.String())
			}
			if raw, err := tc.p.Load(); err != nil || len(raw) == 0 {
				t.Fatalf("save not durable: %v", err)
			}
		})
	}
	freshAssets := assetcatalog.NewStore()
	if err := freshAssets.SetPersister(ap); err != nil {
		t.Fatal(err)
	}
	if rows := freshAssets.ListServices(tenant); len(rows) == 0 {
		t.Fatal("service missing after reload")
	}
	freshPolicy := policy.NewStore(nil)
	if err := freshPolicy.SetRuntimeStatePersister(pp); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := freshPolicy.Get(context.Background(), tenant, "fresh-policy"); err != nil || !ok {
		t.Fatal("policy missing after reload")
	}
	freshCandidate := policycandidate.NewStore()
	if err := freshCandidate.SetPersister(cp); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := freshCandidate.Get(context.Background(), tenant, "fresh-candidate"); err != nil || !ok {
		t.Fatal("candidate missing after reload")
	}
	freshRisk := revocation.NewHighRiskOverlay()
	if err := freshRisk.SetPersister(rp); err != nil {
		t.Fatal(err)
	}
	if rows := freshRisk.UserSnapshot(); len(rows) != 1 || rows[0].Severity != "high" {
		t.Fatal("risk missing after reload")
	}
}

func initialBlobContext(t *testing.T, p postgresBlobPersister, ctx context.Context, edit func([]byte) ([]byte, error)) error {
	t.Helper()
	updater, ok := any(p).(interface {
		UpdateContext(context.Context, func([]byte) ([]byte, error)) error
	})
	if !ok {
		t.Fatal("PostgreSQL does not implement the shared context update contract")
	}
	return updater.UpdateContext(ctx, edit)
}
