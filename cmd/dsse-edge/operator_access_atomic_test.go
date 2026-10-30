package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/model"
)

// Block after the first request has loaded its tenant row, before it can save.
// A second request must be able to commit; the first must then decide against
// the latest row rather than writing its stale copy.
type operatorInterleavingStore struct {
	*adminTenantModelStore
	armed   atomic.Bool
	entered chan struct{}
	release chan struct{}
}

type operatorInterleavingPostgresStore struct {
	*postgresAdminTenantModelStore
	armed   atomic.Bool
	entered chan struct{}
	release chan struct{}
}

func (s *operatorInterleavingPostgresStore) Get(ctx context.Context, tenantID string) (adminTenantModel, error) {
	row, err := s.postgresAdminTenantModelStore.Get(ctx, tenantID)
	if err == nil && s.armed.CompareAndSwap(true, false) {
		close(s.entered)
		<-s.release
	}
	return row, err
}

func (s *operatorInterleavingStore) Get(ctx context.Context, tenantID string) (adminTenantModel, error) {
	row, err := s.adminTenantModelStore.Get(ctx, tenantID)
	if err == nil && s.armed.CompareAndSwap(true, false) {
		close(s.entered)
		<-s.release
	}
	return row, err
}

func operatorInterleavingHandler(t *testing.T, initial adminTenantModel) (*operatorInterleavingStore, http.Handler) {
	t.Helper()
	declareOperatorTenantForTest(t, "tenant_operator")
	inner := newAdminTenantModelStore(model.PolicyBundle{TenantID: "tenant_customer"}, time.Now())
	if _, err := inner.Put(context.Background(), initial, time.Now()); err != nil {
		t.Fatal(err)
	}
	store := &operatorInterleavingStore{adminTenantModelStore: inner, entered: make(chan struct{}), release: make(chan struct{})}
	store.armed.Store(true)
	mux := http.NewServeMux()
	registerOperatorAccessRoutes(mux, func(_ string, h http.HandlerFunc) http.HandlerFunc { return h },
		store, "", decision.Evaluator{PolicyBundle: model.PolicyBundle{TenantID: "tenant_operator"}},
		nil, nil, "tenant_operator", nil)
	registerTenantAdminRoutes(mux, func(_ string, h http.HandlerFunc) http.HandlerFunc { return h },
		serverConfig{}, testEvaluator(), nil, store, "tenant_operator", nil, nil, nil, nil,
		adminTenantExtraStores{}, "")
	return store, mux
}

func operatorInterleavingRequest(handler http.Handler, method, path string, caller adminIdentity, selected, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if selected != "" {
		req.Header.Set("X-Operate-Tenant", selected)
	}
	req = req.WithContext(context.WithValue(req.Context(), adminIdentityContextKey{}, caller))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func awaitOperatorInterleaving(t *testing.T, entered <-chan struct{}) {
	t.Helper()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("first operator request did not load its row")
	}
}

func TestOperatorStaleGrantCannotOverwriteCustomerWithdrawal(t *testing.T) {
	store, handler := operatorInterleavingHandler(t, adminTenantModel{TenantID: "tenant_customer", Status: "active", OperatorManaged: true})
	op := adminIdentity{PrincipalID: "operator", TenantID: "tenant_operator", Roles: []string{"super_admin"}, AuthMethod: "admin_session"}
	customer := adminIdentity{PrincipalID: "customer", TenantID: "tenant_customer", Roles: []string{"admin"}, AuthMethod: "admin_session"}
	result := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		result <- operatorInterleavingRequest(handler, http.MethodPut, "/admin/operator-delegation", op, "tenant_customer", `{"managed":true}`)
	}()
	awaitOperatorInterleaving(t, store.entered)
	if rec := operatorInterleavingRequest(handler, http.MethodPut, "/admin/operator-delegation", customer, "", `{"managed":false}`); rec.Code != http.StatusOK {
		t.Fatalf("customer withdrawal failed: %d %s", rec.Code, rec.Body.String())
	}
	close(store.release)
	if rec := <-result; rec.Code != http.StatusForbidden {
		t.Fatalf("stale operator grant returned %d, want 403: %s", rec.Code, rec.Body.String())
	}
	got, err := store.adminTenantModelStore.Get(context.Background(), "tenant_customer")
	if err != nil || got.OperatorManaged || !got.OperatorDelegationWithdrawnByCustomer {
		t.Fatalf("withdrawal lost: row=%+v err=%v", got, err)
	}
}

func TestOperatorElevationUsesCurrentCustomerApprovalRequirement(t *testing.T) {
	store, handler := operatorInterleavingHandler(t, adminTenantModel{TenantID: "tenant_customer", Status: "active", OperatorManaged: true})
	op := adminIdentity{PrincipalID: "operator", TenantID: "tenant_operator", Roles: []string{"super_admin"}, AuthMethod: "admin_session"}
	customer := adminIdentity{PrincipalID: "customer", TenantID: "tenant_customer", Roles: []string{"admin"}, AuthMethod: "admin_session"}
	result := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		result <- operatorInterleavingRequest(handler, http.MethodPost, "/admin/operator-elevations", op, "tenant_customer", `{"minutes":30}`)
	}()
	awaitOperatorInterleaving(t, store.entered)
	if rec := operatorInterleavingRequest(handler, http.MethodPut, "/admin/operator-delegation", customer, "", `{"elevation_requires_approval":true}`); rec.Code != http.StatusOK {
		t.Fatalf("customer approval setting failed: %d %s", rec.Code, rec.Body.String())
	}
	close(store.release)
	if rec := <-result; rec.Code != http.StatusCreated {
		t.Fatalf("elevation grant failed: %d %s", rec.Code, rec.Body.String())
	}
	got, err := store.adminTenantModelStore.Get(context.Background(), "tenant_customer")
	if err != nil || !got.OperatorElevationRequiresApproval || len(got.OperatorElevations) != 1 || !got.OperatorElevations[0].ApprovalRequired || got.OperatorElevations[0].active(time.Now()) {
		t.Fatalf("elevation bypassed current approval setting: row=%+v err=%v", got, err)
	}
}

func TestConcurrentOperatorElevationsPreserveBothHistoryRows(t *testing.T) {
	store, handler := operatorInterleavingHandler(t, adminTenantModel{TenantID: "tenant_customer", Status: "active", OperatorManaged: true})
	op := adminIdentity{PrincipalID: "operator", TenantID: "tenant_operator", Roles: []string{"super_admin"}, AuthMethod: "admin_session"}
	result := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		result <- operatorInterleavingRequest(handler, http.MethodPost, "/admin/operator-elevations", op, "tenant_customer", `{"minutes":30}`)
	}()
	awaitOperatorInterleaving(t, store.entered)
	if rec := operatorInterleavingRequest(handler, http.MethodPost, "/admin/operator-elevations", op, "tenant_customer", `{"minutes":20}`); rec.Code != http.StatusCreated {
		t.Fatalf("second elevation grant failed: %d %s", rec.Code, rec.Body.String())
	}
	close(store.release)
	if rec := <-result; rec.Code != http.StatusCreated {
		t.Fatalf("first elevation grant failed: %d %s", rec.Code, rec.Body.String())
	}
	got, err := store.adminTenantModelStore.Get(context.Background(), "tenant_customer")
	if err != nil || len(got.OperatorElevations) != 2 || got.OperatorElevations[0].ID == got.OperatorElevations[1].ID {
		t.Fatalf("concurrent elevation history was lost: row=%+v err=%v", got, err)
	}
}

func TestSelfTenantSettingsEditCannotRestoreWithdrawnDelegation(t *testing.T) {
	store, handler := operatorInterleavingHandler(t, adminTenantModel{
		TenantID: "tenant_customer", DisplayName: "Old", Status: "active", OperatorManaged: true,
	})
	customer := adminIdentity{PrincipalID: "customer", TenantID: "tenant_customer", Roles: []string{"admin"}, AuthMethod: "admin_session"}
	result := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		result <- operatorInterleavingRequest(handler, http.MethodPost, "/admin/tenant", customer, "", `{"display_name":"New"}`)
	}()
	awaitOperatorInterleaving(t, store.entered)
	if rec := operatorInterleavingRequest(handler, http.MethodPut, "/admin/operator-delegation", customer, "", `{"managed":false}`); rec.Code != http.StatusOK {
		t.Fatalf("customer withdrawal failed: %d %s", rec.Code, rec.Body.String())
	}
	close(store.release)
	if rec := <-result; rec.Code != http.StatusOK {
		t.Fatalf("ordinary tenant edit failed: %d %s", rec.Code, rec.Body.String())
	}
	got, err := store.adminTenantModelStore.Get(context.Background(), "tenant_customer")
	if err != nil || got.OperatorManaged || !got.OperatorDelegationWithdrawnByCustomer || got.DisplayName != "New" {
		t.Fatalf("ordinary edit restored withdrawn delegation: row=%+v err=%v", got, err)
	}
}

func TestOperatorTenantSettingsEditCannotEraseConcurrentElevation(t *testing.T) {
	store, handler := operatorInterleavingHandler(t, adminTenantModel{
		TenantID: "tenant_customer", DisplayName: "Old", Status: "active", OperatorManaged: true,
	})
	op := adminIdentity{PrincipalID: "operator", TenantID: "tenant_operator", Roles: []string{"super_admin"}, AuthMethod: "admin_session"}
	result := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		result <- operatorInterleavingRequest(handler, http.MethodPost, "/admin/tenants", op, "", `{"tenant_id":"tenant_customer","display_name":"New"}`)
	}()
	awaitOperatorInterleaving(t, store.entered)
	if rec := operatorInterleavingRequest(handler, http.MethodPost, "/admin/operator-elevations", op, "tenant_customer", `{"minutes":30}`); rec.Code != http.StatusCreated {
		t.Fatalf("elevation grant failed: %d %s", rec.Code, rec.Body.String())
	}
	close(store.release)
	if rec := <-result; rec.Code != http.StatusOK {
		t.Fatalf("ordinary operator tenant edit failed: %d %s", rec.Code, rec.Body.String())
	}
	got, err := store.adminTenantModelStore.Get(context.Background(), "tenant_customer")
	if err != nil || len(got.OperatorElevations) != 1 || got.DisplayName != "New" {
		t.Fatalf("ordinary edit erased concurrent elevation: row=%+v err=%v", got, err)
	}
}

func TestPostgresOperatorMutationsSerializeAcrossWriters(t *testing.T) {
	db := tenantCaseReviewDB(t)
	applyTenantCaseReviewMigrations(t, db, "023", "024", "038", "039", "040", "041", "044")
	db.SetMaxOpenConns(4)
	first := &postgresAdminTenantModelStore{db: db, operatorTenantID: "tenant_operator"}
	second := &postgresAdminTenantModelStore{db: db, operatorTenantID: "tenant_operator"}
	if _, err := first.Put(context.Background(), adminTenantModel{
		TenantID: "tenant_customer", Status: "active", OperatorManaged: true,
	}, time.Now()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	entered := make(chan struct{})
	release := make(chan struct{})
	secondStarted := make(chan struct{})
	secondEntered := make(chan struct{})
	firstDone := make(chan error, 1)
	secondDone := make(chan error, 1)
	go func() {
		_, err := first.MutateExisting(ctx, "tenant_customer", time.Now(), func(row adminTenantModel) (adminTenantModel, error) {
			close(entered)
			<-release
			row.OperatorElevations = append(row.OperatorElevations, operatorElevation{ID: "first", GrantedTo: "one"})
			return row, nil
		})
		firstDone <- err
	}()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("first PostgreSQL writer did not acquire its row lock")
	}
	go func() {
		close(secondStarted)
		_, err := second.MutateExisting(ctx, "tenant_customer", time.Now(), func(row adminTenantModel) (adminTenantModel, error) {
			close(secondEntered)
			row.OperatorElevations = append(row.OperatorElevations, operatorElevation{ID: "second", GrantedTo: "two"})
			return row, nil
		})
		secondDone <- err
	}()
	<-secondStarted
	enteredBeforeRelease := false
	select {
	case <-secondEntered:
		enteredBeforeRelease = true
	case <-time.After(150 * time.Millisecond):
	}
	close(release)
	if enteredBeforeRelease {
		t.Fatal("second PostgreSQL writer entered its edit before the first row lock was released")
	}
	if err := <-firstDone; err != nil {
		t.Fatalf("first PostgreSQL mutation: %v", err)
	}
	if err := <-secondDone; err != nil {
		t.Fatalf("second PostgreSQL mutation: %v", err)
	}
	got, err := first.Get(ctx, "tenant_customer")
	if err != nil {
		t.Fatal(err)
	}
	if len(got.OperatorElevations) != 2 || got.OperatorElevations[0].ID != "first" || got.OperatorElevations[1].ID != "second" {
		t.Fatalf("concurrent PostgreSQL writers lost an elevation: %+v", got.OperatorElevations)
	}
}

func TestPostgresStaleOperatorGrantCannotUndoOtherControlPlaneWithdrawal(t *testing.T) {
	declareOperatorTenantForTest(t, "tenant_operator")
	db := tenantCaseReviewDB(t)
	applyTenantCaseReviewMigrations(t, db, "023", "024", "038", "039", "040", "041", "044")
	db.SetMaxOpenConns(4)
	first := &postgresAdminTenantModelStore{db: db, operatorTenantID: "tenant_operator"}
	second := &postgresAdminTenantModelStore{db: db, operatorTenantID: "tenant_operator"}
	if _, err := first.Put(context.Background(), adminTenantModel{
		TenantID: "tenant_customer", Status: "active", OperatorManaged: true,
	}, time.Now()); err != nil {
		t.Fatal(err)
	}
	paused := &operatorInterleavingPostgresStore{postgresAdminTenantModelStore: first, entered: make(chan struct{}), release: make(chan struct{})}
	paused.armed.Store(true)
	register := func(store adminTenantModelRuntimeStore) http.Handler {
		mux := http.NewServeMux()
		registerOperatorAccessRoutes(mux, func(_ string, h http.HandlerFunc) http.HandlerFunc { return h },
			store, "", decision.Evaluator{PolicyBundle: model.PolicyBundle{TenantID: "tenant_operator"}},
			nil, nil, "tenant_operator", nil)
		return mux
	}
	op := adminIdentity{PrincipalID: "operator", TenantID: "tenant_operator", Roles: []string{"super_admin"}, AuthMethod: "admin_session"}
	customer := adminIdentity{PrincipalID: "customer", TenantID: "tenant_customer", Roles: []string{"admin"}, AuthMethod: "admin_session"}
	result := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		result <- operatorInterleavingRequest(register(paused), http.MethodPut, "/admin/operator-delegation", op, "tenant_customer", `{"managed":true}`)
	}()
	awaitOperatorInterleaving(t, paused.entered)
	if rec := operatorInterleavingRequest(register(second), http.MethodPut, "/admin/operator-delegation", customer, "", `{"managed":false}`); rec.Code != http.StatusOK {
		t.Fatalf("customer withdrawal failed: %d %s", rec.Code, rec.Body.String())
	}
	close(paused.release)
	if rec := <-result; rec.Code != http.StatusForbidden {
		t.Fatalf("stale PostgreSQL operator grant returned %d: %s", rec.Code, rec.Body.String())
	}
	got, err := second.Get(context.Background(), "tenant_customer")
	if err != nil || got.OperatorManaged || !got.OperatorDelegationWithdrawnByCustomer {
		t.Fatalf("other control plane restored withdrawn delegation: row=%+v err=%v", got, err)
	}
}

func TestPostgresTenantCreationSerializesAndPreservesBothEdits(t *testing.T) {
	db := tenantCaseReviewDB(t)
	applyTenantCaseReviewMigrations(t, db, "023", "024", "038", "039", "040", "041", "044")
	db.SetMaxOpenConns(4)
	first := &postgresAdminTenantModelStore{db: db}
	second := &postgresAdminTenantModelStore{db: db}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	entered := make(chan struct{})
	release := make(chan struct{})
	firstDone := make(chan error, 1)
	secondDone := make(chan error, 1)
	go func() {
		_, err := first.MutateOrCreate(ctx, "tenant_new", time.Now(), func(row adminTenantModel) (adminTenantModel, error) {
			close(entered)
			<-release
			row.DisplayName = "First"
			return row, nil
		})
		firstDone <- err
	}()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("first creator did not enter")
	}
	go func() {
		_, err := second.MutateOrCreate(ctx, "tenant_new", time.Now(), func(row adminTenantModel) (adminTenantModel, error) {
			if row.DisplayName != "First" {
				return row, fmt.Errorf("second creator read stale state: %q", row.DisplayName)
			}
			row.Plan = "Enterprise"
			return row, nil
		})
		secondDone <- err
	}()
	close(release)
	if err := <-firstDone; err != nil {
		t.Fatal(err)
	}
	if err := <-secondDone; err != nil {
		t.Fatal(err)
	}
	got, err := first.Get(ctx, "tenant_new")
	if err != nil || got.DisplayName != "First" || got.Plan != "Enterprise" {
		t.Fatalf("concurrent creation lost an edit: row=%+v err=%v", got, err)
	}
}

func TestTenantSettingsMayCreateOwnMissingRowButNotRestoreDeletedRow(t *testing.T) {
	store := newAdminTenantModelStore(model.PolicyBundle{TenantID: "tenant_operator"}, time.Now())
	mux := http.NewServeMux()
	registerTenantAdminRoutes(mux, func(_ string, h http.HandlerFunc) http.HandlerFunc { return h },
		serverConfig{}, testEvaluator(), nil, store, "", nil, nil, nil, nil,
		adminTenantExtraStores{}, "")
	admin := adminIdentity{PrincipalID: "customer", TenantID: "tenant_customer", Roles: []string{"admin"}, AuthMethod: "admin_session"}
	if rec := operatorInterleavingRequest(mux, http.MethodPost, "/admin/tenant", admin, "", `{"display_name":"Customer"}`); rec.Code != http.StatusOK {
		t.Fatalf("first self profile failed: %d %s", rec.Code, rec.Body.String())
	}
	if err := store.Delete(context.Background(), "tenant_customer"); err != nil {
		t.Fatal(err)
	}
	if rec := operatorInterleavingRequest(mux, http.MethodPost, "/admin/tenant", admin, "", `{"display_name":"Revived"}`); rec.Code != http.StatusNotFound {
		t.Fatalf("deleted organization self-recreated: %d %s", rec.Code, rec.Body.String())
	}
	if rows, err := store.List(context.Background()); err != nil {
		t.Fatal(err)
	} else {
		for _, row := range rows {
			if row.TenantID == "tenant_customer" {
				t.Fatal("deleted organization was restored by self profile update")
			}
		}
	}
}

func TestPostgresSelfProfileCannotRestoreDeletedTenant(t *testing.T) {
	db := tenantCaseReviewDB(t)
	applyTenantCaseReviewMigrations(t, db, "023", "024", "038", "039", "040", "041", "044")
	store := &postgresAdminTenantModelStore{db: db}
	if _, err := store.Put(context.Background(), adminTenantModel{TenantID: "tenant_customer", Status: "active"}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := store.Delete(context.Background(), "tenant_customer"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.MutateOrCreate(context.Background(), "tenant_customer", time.Now(), func(row adminTenantModel) (adminTenantModel, error) {
		row.DisplayName = "Revived"
		return row, nil
	}); !errors.Is(err, errAdminTenantModelMissing) {
		t.Fatalf("deleted organization was self-created: %v", err)
	}
	var count int
	if err := db.QueryRow(`SELECT count(*) FROM admin_tenant_models WHERE tenant_id='tenant_customer'`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("deleted organization row reappeared: count=%d err=%v", count, err)
	}
}

func TestPostgresTenantUpsertRollsBackWhenTombstoneRetirementFails(t *testing.T) {
	db := tenantCaseReviewDB(t)
	applyTenantCaseReviewMigrations(t, db, "023", "024", "038", "039", "040", "041", "044")
	store := &postgresAdminTenantModelStore{db: db}
	ctx := context.Background()
	if _, err := store.Put(ctx, adminTenantModel{TenantID: "tenant_customer", DisplayName: "Old", Status: "active"}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO admin_tenant_model_deletions(tenant_id,deleted_at) VALUES ('tenant_customer',now())`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE FUNCTION refuse_tombstone_retirement() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'blocked retirement'; END$$`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TRIGGER refuse_tombstone_retirement BEFORE DELETE ON admin_tenant_model_deletions FOR EACH ROW EXECUTE FUNCTION refuse_tombstone_retirement()`); err != nil {
		t.Fatal(err)
	}
	beforeGeneration := store.ConfigGeneration()
	if _, err := store.Put(ctx, adminTenantModel{TenantID: "tenant_customer", DisplayName: "New", Status: "active"}, time.Now()); err == nil {
		t.Fatal("upsert succeeded even though tombstone retirement failed")
	}
	var name string
	if err := db.QueryRow(`SELECT display_name FROM admin_tenant_models WHERE tenant_id='tenant_customer'`).Scan(&name); err != nil || name != "Old" {
		t.Fatalf("failed upsert published a new row: name=%q err=%v", name, err)
	}
	if store.ConfigGeneration() != beforeGeneration {
		t.Fatal("failed upsert advanced config generation")
	}
	var count int
	if err := db.QueryRow(`SELECT count(*) FROM admin_tenant_model_deletions WHERE tenant_id='tenant_customer'`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("failed upsert retired the tombstone: count=%d err=%v", count, err)
	}
}
