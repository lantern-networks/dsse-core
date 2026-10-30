package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/dlp"
	"github.com/lantern-networks/dsse-core/model"
)

func dlpErasureFileStores(t *testing.T, dir string) *dlpConfigStores {
	t.Helper()
	s := dlpStoresForTest("test-salt")
	for _, attach := range []struct {
		name string
		set  func(blobstore.Persister) error
	}{
		{"rules", s.rules.SetPersister},
		{"allowlist", s.allowlist.SetPersister},
		{"classifiers", s.classifiers.SetPersister},
		{"fingerprints", s.fingerprints.SetPersister},
		{"policies", s.policies.SetPersister},
	} {
		if err := attach.set(blobstore.FilePersister{Path: filepath.Join(dir, attach.name+".json")}); err != nil {
			t.Fatal(err)
		}
	}
	return s
}

func seedDLPErasureTenant(t *testing.T, s *dlpConfigStores, tenant string) {
	t.Helper()
	ctx := context.Background()
	if err := s.rules.SetRulesContext(ctx, tenant, []model.DLPRule{testDurableDLPRule(tenant)}); err != nil {
		t.Fatal(err)
	}
	if err := s.allowlist.SetValuesContext(ctx, tenant, []string{"synthetic-" + tenant + "@example.invalid"}); err != nil {
		t.Fatal(err)
	}
	if err := s.classifiers.SetSpecsContext(ctx, tenant, []dlp.ClassifierSpec{{Name: "employee_id", Kind: "keyword", Keywords: []string{"EMPLOYEE-" + tenant}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.fingerprints.SetDatasetContext(ctx, tenant, "records", []string{"RECORD-" + tenant + "-123456"}); err != nil {
		t.Fatal(err)
	}
	if err := s.policies.UpsertContext(ctx, model.DLPPolicyObject{ID: "policy", TenantID: tenant, Name: "Synthetic", Identifiers: []string{"email"}, OnMatch: "observe", Status: "active"}); err != nil {
		t.Fatal(err)
	}
}

func TestTenantPurgeErasesEveryDurableDLPStoreAndCompiledCache(t *testing.T) {
	dir := t.TempDir()
	s := dlpErasureFileStores(t, dir)
	// The names differ only by case so a normalized tenant match would destroy
	// another tenant's definitions.
	for _, tenant := range []string{"Gone", "gone"} {
		seedDLPErasureTenant(t, s, tenant)
	}
	extra := adminTenantExtraStores{DLP: s}
	before := countAdminTenantFootprint(context.Background(), "node", "Gone", nil, nil, nil, nil, nil, nil, nil, extra, time.Now())
	for _, row := range extra.dlpErasureRows() {
		if row.store == nil || row.store.CountForTenant("Gone") != 1 || footprintDLPCount(before, row.name) != 1 {
			t.Fatalf("DLP footprint omitted %s before purge", row.name)
		}
	}
	result := purgeAdminTenantData(context.Background(), "node", "Gone", nil, nil, nil, nil, nil, nil, "", nil, nil, extra, nil, time.Now())
	if !result.Complete || len(result.Failures) != 0 || !result.Remaining.Clean() {
		t.Fatalf("DLP erasure did not complete: failures=%v remaining=%+v", result.Failures, result.Remaining.Stores)
	}
	reloaded := dlpErasureFileStores(t, dir)
	for _, row := range (adminTenantExtraStores{DLP: reloaded}).dlpErasureRows() {
		if row.store.CountForTenant("Gone") != 0 || row.store.CountForTenant("gone") != 1 {
			t.Fatalf("%s was not erased on restart or crossed tenant boundary", row.name)
		}
	}
	if s.allowlist.AllowlistForTenant("Gone") != nil || s.classifiers.ClassifierSetForTenant("Gone") != nil || s.fingerprints.FingerprintSetForTenant("Gone") != nil || len(s.rules.RulesForTenant("Gone")) != 0 {
		t.Fatal("live DLP scan cache retained erased tenant")
	}
	if reloaded.allowlist.AllowlistForTenant("Gone") != nil || reloaded.classifiers.ClassifierSetForTenant("Gone") != nil || reloaded.fingerprints.FingerprintSetForTenant("Gone") != nil {
		t.Fatal("reloaded DLP scan cache retained erased tenant")
	}
	if reloaded.allowlist.AllowlistForTenant("gone") == nil || reloaded.classifiers.ClassifierSetForTenant("gone") == nil || reloaded.fingerprints.FingerprintSetForTenant("gone") == nil {
		t.Fatal("other tenant's live DLP scan cache was removed")
	}
	if snapshot := s.Snapshot(); len(snapshot.Allowlists["Gone"])+len(snapshot.Classifiers["Gone"])+len(snapshot.Datasets["Gone"])+len(snapshot.Policies["Gone"])+len(snapshot.Rules["Gone"]) != 0 {
		t.Fatal("signed DLP bundle source retained erased tenant")
	}
}

func footprintDLPCount(f adminTenantFootprint, store string) int64 {
	for _, row := range f.Stores {
		if row.Store == store {
			return row.Count
		}
	}
	return -2
}

func TestTenantPurgeDLPFailedSaveIsIncompleteAndRetryable(t *testing.T) {
	p := &checkedClassifierPersister{}
	s := newDLPAllowlistRuntimeStore("test-salt")
	if err := s.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	if err := s.SetValuesDurable("Gone", []string{"synthetic-Gone@example.invalid"}); err != nil {
		t.Fatal(err)
	}
	p.err = errors.New("storage unavailable")
	extra := adminTenantExtraStores{DLP: &dlpConfigStores{allowlist: s}}
	failed := purgeAdminTenantData(context.Background(), "node", "Gone", nil, nil, nil, nil, nil, nil, "", nil, nil, extra, nil, time.Now())
	if failed.Complete || footprintDLPCount(failed.Remaining, "dlp_allowlist") != 1 || len(failed.Failures) == 0 || s.AllowlistForTenant("Gone") == nil {
		t.Fatal("failed DLP save was reported as a complete tenant erasure")
	}
	p.err = nil
	retry := purgeAdminTenantData(context.Background(), "node", "Gone", nil, nil, nil, nil, nil, nil, "", nil, nil, extra, nil, time.Now())
	if !retry.Complete || len(retry.Failures) != 0 {
		t.Fatalf("confirmed retry failed: %v", retry.Failures)
	}
	reloaded := newDLPAllowlistRuntimeStore("test-salt")
	if err := reloaded.SetPersister(p); err != nil || reloaded.AllowlistForTenant("Gone") != nil {
		t.Fatal("failed-save retry did not survive restart", err)
	}
}

func TestTenantDLPErasureUsesLatestSharedAuthorityAndRejectsFailedCommit(t *testing.T) {
	for name, factory := range dlpPeerFactories() {
		t.Run(name, func(t *testing.T) {
			p := &entitlementReviewPersister{}
			a, b := factory(), factory()
			if err := a.attach(p); err != nil {
				t.Fatal(err)
			}
			if err := b.attach(p); err != nil {
				t.Fatal(err)
			}
			if err := a.write("Gone"); err != nil {
				t.Fatal(err)
			}
			if err := b.write("gone"); err != nil {
				t.Fatal(err)
			}
			// a is stale with respect to the other CP's write. Removal must
			// inspect the shared row, not overwrite it from a local snapshot.
			p.fail = true
			if _, err := a.remove("Gone"); err == nil {
				t.Fatal("failed shared DLP erasure was acknowledged")
			}
			p.fail = false
			if !a.present("Gone") || !b.present("gone") {
				t.Fatal("failed shared erasure changed accepted state")
			}
			if n, err := a.remove("Gone"); err != nil || n != 1 {
				t.Fatalf("shared DLP erasure did not commit: removed=%d err=%v", n, err)
			}
			reloaded := factory()
			if err := reloaded.attach(p); err != nil {
				t.Fatal(err)
			}
			if reloaded.present("Gone") || !reloaded.present("gone") {
				t.Fatal("shared DLP erasure did not survive reload or erased a peer tenant")
			}
		})
	}
}

func TestTenantPurgeHTTPWiresDLPAuthority(t *testing.T) {
	path := filepath.Join(t.TempDir(), "allowlist.json")
	seed := newDLPAllowlistRuntimeStore("dsse-dlp-allowlist-v1")
	if err := seed.SetPersister(blobstore.FilePersister{Path: path}); err != nil {
		t.Fatal(err)
	}
	for _, tenant := range []string{"gone", "peer"} {
		if err := seed.SetValuesDurable(tenant, []string{"synthetic-" + tenant + "@example.invalid"}); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now()
	tenants := newAdminTenantModelStore(model.PolicyBundle{TenantID: "operator"}, now)
	if _, err := tenants.Put(context.Background(), adminTenantModel{TenantID: "gone", Status: "active"}, now); err != nil {
		t.Fatal(err)
	}
	if err := tenants.Delete(context.Background(), "gone"); err != nil {
		t.Fatal(err)
	}
	auth := newAdminAuthStore()
	auth.UpsertPrincipal(adminPrincipal{ID: "operator", TenantID: "operator", Roles: []string{"super_admin"}, Status: "active"})
	auth.UpsertAPIToken(adminAPIToken{ID: "fixture", TenantID: "operator", TokenHash: adminTokenHash("fixture-token"), CreatedByAdminPrincipalID: "operator", Roles: []string{"super_admin"}, Scopes: []string{"*"}, Status: "active", ExpiresAt: now.Add(time.Hour).Format(time.RFC3339)})
	h := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), OperatorTenantID: "operator", AdminAuth: auth, TenantModelStore: tenants, DLPAllowlistStorePath: path})
	req := httptest.NewRequest("POST", "/admin/tenants/gone/purge", strings.NewReader(`{"confirm_tenant_id":"gone"}`))
	req.Header.Set("Authorization", "Bearer fixture-token")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("purge request failed: HTTP %d", rec.Code)
	}
	var result adminTenantPurgeResult
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	reloaded := newDLPAllowlistRuntimeStore("dsse-dlp-allowlist-v1")
	if err := reloaded.SetPersister(blobstore.FilePersister{Path: path}); err != nil {
		t.Fatal(err)
	}
	if !result.Complete || footprintDLPCount(result.Remaining, "dlp_allowlist") != 0 || len(reloaded.ValuesForTenant("gone")) != 0 || len(reloaded.ValuesForTenant("peer")) != 1 {
		t.Fatal("HTTP purge omitted durable tenant DLP state or removed a peer tenant")
	}
}

func TestSignedCarriedTenantPurgeClearsEdgeDLPCache(t *testing.T) {
	dir := t.TempDir()
	stores := dlpErasureFileStores(t, dir)
	seedDLPErasureTenant(t, stores, "gone")
	seedDLPErasureTenant(t, stores, "peer")
	order := configBundlePayload{
		signatureVerified: true,
		Tenants:           &tenantModelBundle{PurgeOrders: []tenantPurgeOrder{{TenantID: "gone"}}},
	}
	applyCarriedTenantPurges(context.Background(), configApplyTargets{dlp: stores}, order, "edge", time.Now())
	for _, row := range (adminTenantExtraStores{DLP: stores}).dlpErasureRows() {
		if row.store.CountForTenant("gone") != 0 || row.store.CountForTenant("peer") != 1 {
			t.Fatalf("signed carried purge left %s active or crossed tenant boundary", row.name)
		}
	}
	if stores.allowlist.AllowlistForTenant("gone") != nil || stores.classifiers.ClassifierSetForTenant("gone") != nil || stores.fingerprints.FingerprintSetForTenant("gone") != nil {
		t.Fatal("signed carried purge left a compiled DLP cache on the Edge")
	}
	reloaded := dlpErasureFileStores(t, dir)
	for _, row := range (adminTenantExtraStores{DLP: reloaded}).dlpErasureRows() {
		if row.store.CountForTenant("gone") != 0 || row.store.CountForTenant("peer") != 1 {
			t.Fatalf("carried purge failed durable reload for %s", row.name)
		}
	}
}
