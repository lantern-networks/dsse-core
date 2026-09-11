package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/logs"
)

func TestAdminTenantModelOpenAPIContract(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "openapi", "admin_api.yaml"))
	if err != nil {
		t.Fatalf("read admin OpenAPI contract: %v", err)
	}
	contract := string(data)
	for _, want := range []string{
		"    TenantModel:",
		"    TenantModelList:",
		"  /admin/tenant:",
		"  /admin/tenants:",
		"  /admin/tenants/{tenant_id}:",
		"admin.tenant.read",
		"admin.tenant.write",
		"admin.tenant.admin",
		"is_operator:",
		`$ref: "#/components/schemas/TenantModel"`,
		`$ref: "#/components/schemas/TenantModelList"`,
	} {
		if !strings.Contains(contract, want) {
			t.Fatalf("admin OpenAPI contract missing %q", want)
		}
	}
}

func TestAdminTenantModelAPIReadsSeededTenant(t *testing.T) {
	handler := newServerWithConfig(serverConfig{
		Evaluator: testEvaluator(),
		Registry:  connector.NewRegistry(),
		AdminAuth: newAdminAuthStore(),
	})
	req := httptest.NewRequest(http.MethodGet, "/admin/tenant", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var tenant adminTenantModel
	if err := json.Unmarshal(rec.Body.Bytes(), &tenant); err != nil {
		t.Fatalf("decode tenant model: %v", err)
	}
	if tenant.TenantID != "tenant_lab_001" || tenant.DisplayName != "tenant_lab_001" || tenant.Status != "active" || tenant.PolicyBundleID != "pb_lab_20260522_001" {
		t.Fatalf("seeded tenant = %#v, want policy-bundle tenant profile", tenant)
	}
	if tenant.CreatedAt == nil || tenant.UpdatedAt == nil {
		t.Fatalf("seeded tenant timestamps = %#v/%#v, want created/updated", tenant.CreatedAt, tenant.UpdatedAt)
	}
}

func TestAdminTenantModelAPIUpdateThenRead(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	outbox := &recordingAdminAuditOutboxDeadReader{}
	handler := newServerWithConfig(serverConfig{
		Evaluator:        testEvaluator(),
		Writer:           writer,
		Registry:         connector.NewRegistry(),
		AdminAuth:        newAdminAuthStore(),
		AdminAuditOutbox: outbox,
	})
	// ★ data_residency IS NO LONGER ACCEPTED (2026-08-19, operator decision). It was stored, normalised and
	// consulted by nothing, and its name is a compliance promise — so setting it is now a 400 naming
	// home_region / allowed_regions, which are what actually place an organization. A record that already
	// carries a value still stores, so distribution is unaffected; see TestSettingDataResidencyIsRefused.
	body := `{
		"tenant_id":"tenant_lab_001",
		"display_name":"Lab Tenant",
		"region":"jp",
		"plan":"phase3",
		"status":"active",
		"policy_bundle_id":"pb_lab_20260522_001",
		"policy_bundle_version":"2026.05.22.001",
		"metadata_key_count":2
	}`
	req := httptest.NewRequest(http.MethodPost, "/admin/tenant", strings.NewReader(body))
	req.Header.Set("content-type", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var updated adminTenantModel
	if err := json.Unmarshal(rec.Body.Bytes(), &updated); err != nil {
		t.Fatalf("decode updated tenant model: %v", err)
	}
	if updated.DisplayName != "Lab Tenant" || updated.Region != "jp" || updated.Plan != "phase3" || updated.UpdatedAt == nil {
		t.Fatalf("updated tenant = %#v, want tenant metadata update", updated)
	}

	readReq := httptest.NewRequest(http.MethodGet, "/admin/tenant", nil)
	readRec := httptest.NewRecorder()
	handler.ServeHTTP(readRec, readReq)
	if readRec.Code != http.StatusOK {
		t.Fatalf("read status = %d, want %d, body=%s", readRec.Code, http.StatusOK, readRec.Body.String())
	}
	var read adminTenantModel
	if err := json.Unmarshal(readRec.Body.Bytes(), &read); err != nil {
		t.Fatalf("decode read tenant model: %v", err)
	}
	if read.DisplayName != updated.DisplayName || read.MetadataKeyCount != 2 {
		t.Fatalf("read tenant = %#v, want updated tenant %#v", read, updated)
	}
	if len(outbox.insertedAudits) != 1 || outbox.insertedAudits[0].EventType != "admin_tenant_model_updated" {
		t.Fatalf("outbox inserted audits = %#v, want tenant model update", outbox.insertedAudits)
	}
	audit := outbox.insertedAudits[0]
	if audit.SourceIP != nil || audit.ActorUserID != nil {
		t.Fatalf("tenant audit included raw source/user fields: %#v", audit)
	}
	if audit.Metadata["tenant_metadata_recorded_scope"] != "none" || audit.Metadata["runtime_hot_reload"] != false {
		t.Fatalf("tenant audit metadata = %#v, want non-secret admin boundary", audit.Metadata)
	}
}

func TestAdminTenantModelAPIRejectsTenantMismatch(t *testing.T) {
	handler := newServerWithConfig(serverConfig{
		Evaluator: testEvaluator(),
		AdminAuth: newAdminAuthStore(),
	})
	req := httptest.NewRequest(http.MethodPost, "/admin/tenant", strings.NewReader(`{"tenant_id":"tenant_other_001","status":"active"}`))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "tenant_id") {
		t.Fatalf("status = %d body=%s, want tenant mismatch bad request", rec.Code, rec.Body.String())
	}
}

// TestAdminTenantsSuperAdminListCreateDelete exercises the cross-tenant (super-admin) surface: create a tenant
// OTHER than the authenticated one (which the self-scoped /admin/tenant would reject), list all tenants, then
// delete it. The default lab-bypass principal is "owner" (the super-admin role), so admin.tenant.admin is held.
func TestAdminTenantsSuperAdminListCreateDelete(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	outbox := &recordingAdminAuditOutboxDeadReader{}
	handler := newServerWithConfig(serverConfig{
		Evaluator:        testEvaluator(),
		Writer:           writer,
		Registry:         connector.NewRegistry(),
		AdminAuth:        newAdminAuthStore(),
		AdminAuditOutbox: outbox,
		// ★ The caller below is the node's own organization acting across organizations, which is what this
		// test is about. Since 2026-08-21 that requires BELONGING to the operator organization, not merely
		// holding the role — see operator_is_an_organization_not_a_role.go.
		OperatorTenantID: "tenant_lab_001",
	})

	// Create a DIFFERENT tenant than the authenticated tenant_lab_001 — only possible cross-tenant.
	//
	// ★ AND WITHOUT NAMING IT (2026-08-21). The id is issued by this route, not chosen by the caller — see
	// organization_id_is_not_a_name.go. The display name is the part a person picks.
	createBody := `{"display_name":"Acme","status":"suspended","plan":"enterprise"}`
	createReq := httptest.NewRequest(http.MethodPost, "/admin/tenants", strings.NewReader(createBody))
	createReq.Header.Set("content-type", "application/json")
	createRec := httptest.NewRecorder()
	handler.ServeHTTP(createRec, createReq)
	if createRec.Code != http.StatusOK {
		t.Fatalf("create status = %d, want %d, body=%s", createRec.Code, http.StatusOK, createRec.Body.String())
	}
	var created adminTenantModel
	if err := json.Unmarshal(createRec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode created tenant: %v", err)
	}
	if created.Status != "suspended" || created.Plan != "enterprise" {
		t.Fatalf("created tenant = %#v, want cross-tenant create with lifecycle status", created)
	}
	if !strings.HasPrefix(created.TenantID, "tenant_") || len(created.TenantID) < 24 {
		t.Fatalf("the created organization was given %q — the id must be issued and unguessable, since it is "+
			"offered on the transport port by name", created.TenantID)
	}
	if strings.Contains(strings.ToLower(created.TenantID), "acme") {
		t.Fatalf("the id %q was derived from the display name, which is exactly what a stranger guesses",
			created.TenantID)
	}

	// List returns both the seeded tenant and the created one.
	listReq := httptest.NewRequest(http.MethodGet, "/admin/tenants", nil)
	listRec := httptest.NewRecorder()
	handler.ServeHTTP(listRec, listReq)
	if listRec.Code != http.StatusOK {
		t.Fatalf("list status = %d, want %d, body=%s", listRec.Code, http.StatusOK, listRec.Body.String())
	}
	var listResp struct {
		Tenants []adminTenantModel `json:"tenants"`
	}
	if err := json.Unmarshal(listRec.Body.Bytes(), &listResp); err != nil {
		t.Fatalf("decode tenant list: %v", err)
	}
	ids := map[string]bool{}
	for _, tenant := range listResp.Tenants {
		ids[tenant.TenantID] = true
	}
	if !ids["tenant_lab_001"] || !ids[created.TenantID] {
		t.Fatalf("tenant list = %#v, want both tenant_lab_001 and the organization just created", listResp.Tenants)
	}

	// Delete the created tenant.
	delReq := httptest.NewRequest(http.MethodDelete, "/admin/tenants/"+created.TenantID, nil)
	delRec := httptest.NewRecorder()
	handler.ServeHTTP(delRec, delReq)
	if delRec.Code != http.StatusOK {
		t.Fatalf("delete status = %d, want %d, body=%s", delRec.Code, http.StatusOK, delRec.Body.String())
	}

	// List again: the deleted tenant is gone, the seeded one remains.
	listRec2 := httptest.NewRecorder()
	handler.ServeHTTP(listRec2, httptest.NewRequest(http.MethodGet, "/admin/tenants", nil))
	var listResp2 struct {
		Tenants []adminTenantModel `json:"tenants"`
	}
	if err := json.Unmarshal(listRec2.Body.Bytes(), &listResp2); err != nil {
		t.Fatalf("decode tenant list after delete: %v", err)
	}
	for _, tenant := range listResp2.Tenants {
		if tenant.TenantID == created.TenantID {
			t.Fatalf("the created organization is still present after delete: %#v", listResp2.Tenants)
		}
	}

	// Audit: a create and a delete lifecycle event were recorded, both within the non-secret boundary.
	var sawCreate, sawDelete bool
	for _, audit := range outbox.insertedAudits {
		switch audit.EventType {
		case "admin_tenant_model_created":
			sawCreate = true
		case "admin_tenant_model_deleted":
			sawDelete = true
		}
		if audit.SourceIP != nil || audit.ActorUserID != nil {
			t.Fatalf("cross-tenant audit leaked raw source/user fields: %#v", audit)
		}
	}
	if !sawCreate || !sawDelete {
		t.Fatalf("audits = %#v, want create+delete lifecycle events", outbox.insertedAudits)
	}
}

// TestAdminTenantsCrossTenantRequiresSuperAdminScope confirms the cross-tenant surface is gated on
// admin.tenant.admin: a token holding only the self-scoped admin.tenant.write cannot list across tenants.
func TestAdminTenantsCrossTenantRequiresSuperAdminScope(t *testing.T) {
	adminAuth := newAdminAuthStore()
	adminAuth.UpsertPrincipal(adminPrincipal{
		ID:        "admin_tenant_writer_001",
		TenantID:  "tenant_lab_001",
		Subject:   "sub_tenant_writer_001",
		Email:     "tenant-writer@example.test",
		Roles:     []string{"admin"},
		IDPID:     "keycloak_lab",
		Status:    "active",
		CreatedAt: time.Now().UTC().Add(-time.Hour).Format(time.RFC3339),
	})
	adminAuth.UpsertAPIToken(adminAPIToken{
		ID:                        "admin_token_tenant_writer_001",
		TenantID:                  "tenant_lab_001",
		Name:                      "tenant-writer-token",
		TokenHash:                 adminTokenHash("raw-tenant-writer-token"),
		Roles:                     []string{"admin"},
		Scopes:                    []string{"admin.tenant.read", "admin.tenant.write"},
		CreatedByAdminPrincipalID: "admin_tenant_writer_001",
		CreatedAt:                 time.Now().UTC().Add(-time.Hour).Format(time.RFC3339),
		ExpiresAt:                 time.Now().UTC().Add(time.Hour).Format(time.RFC3339),
		Status:                    "active",
	})
	handler := newServerWithConfig(serverConfig{
		Evaluator: testEvaluator(),
		Registry:  connector.NewRegistry(),
		AdminAuth: adminAuth,
	})
	req := httptest.NewRequest(http.MethodGet, "/admin/tenants", nil)
	req.Header.Set("authorization", "Bearer raw-tenant-writer-token")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "admin.tenant.admin") {
		t.Fatalf("status = %d body=%s, want admin.tenant.admin super-admin denial", rec.Code, rec.Body.String())
	}
}

// TestAdminTenantModelDurablePersistence confirms the file-backed store survives a restart: a tenant put into a
// store with a snapshot path is present when a fresh store is constructed from the same path.
func TestAdminTenantModelDurablePersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tenant_model.json")
	bundle := testEvaluator().PolicyBundle
	now := time.Now().UTC()

	store := newDurableAdminTenantModelStore(bundle, now, path)
	if _, err := store.Put(context.Background(), adminTenantModel{TenantID: "tenant_acme_001", DisplayName: "Acme", Status: "suspended"}, now); err != nil {
		t.Fatalf("put: %v", err)
	}

	reloaded := newDurableAdminTenantModelStore(bundle, now, path)
	list, err := reloaded.List(context.Background())
	if err != nil {
		t.Fatalf("list after reload: %v", err)
	}
	found := map[string]string{}
	for _, tenant := range list {
		found[tenant.TenantID] = tenant.Status
	}
	if found["tenant_acme_001"] != "suspended" {
		t.Fatalf("reloaded tenants = %#v, want tenant_acme_001 suspended to survive restart", list)
	}
	if _, ok := found["tenant_lab_001"]; !ok {
		t.Fatalf("reloaded tenants = %#v, want seeded tenant_lab_001 preserved", list)
	}
}

// TestAdminTenantsOperatorTenantSeededAndUndeletable covers the multi-tenant Admin Console Q5 operator-tenant
// feature: with -operator-tenant-id set, the operator tenant is seeded (display "Operator", active), flagged
// is_operator in GET /admin/tenants while customer tenants stay is_operator=false, and DELETE refuses to remove
// it (409 lockout protection) so it survives the attempt.
func TestAdminTenantsOperatorTenantSeededAndUndeletable(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	const operatorID = "tenant_operator_001"
	store := newOperatorAwareAdminTenantModelStore(testEvaluator().PolicyBundle, time.Now().UTC(), "", operatorID)
	// ★ READ BY SOMEBODY WHO BELONGS TO THE OPERATOR ORGANIZATION (2026-08-21). The deployment view is the
	// operator's; a customer administrator is now shown only their own organization, so this test needs a
	// credential seated where the operator actually is.
	const operatorTenantListBearer = "raw-operator-tenant-list"
	operatorAuth := newAdminAuthStore()
	operatorNow := time.Now().UTC()
	operatorAuth.UpsertPrincipal(adminPrincipal{ID: "adm_op_list", TenantID: operatorID, Subject: "sub_op_list",
		Email: "operator@example.invalid", Roles: []string{"admin", "super_admin"}, IDPID: "keycloak_lab",
		Status: "active", CreatedAt: operatorNow.Add(-time.Hour).Format(time.RFC3339)})
	operatorAuth.UpsertAPIToken(adminAPIToken{ID: "tok_op_list", TenantID: operatorID, Name: "operator",
		TokenHash: adminTokenHash(operatorTenantListBearer), Roles: []string{"admin", "super_admin"},
		Scopes: []string{"*"}, CreatedByAdminPrincipalID: "adm_op_list",
		CreatedAt: operatorNow.Add(-time.Hour).Format(time.RFC3339),
		ExpiresAt: operatorNow.Add(time.Hour).Format(time.RFC3339), Status: "active"})
	handler := newServerWithConfig(serverConfig{
		Evaluator:        testEvaluator(),
		Writer:           writer,
		Registry:         connector.NewRegistry(),
		AdminAuth:        operatorAuth,
		AdminAuditOutbox: &recordingAdminAuditOutboxDeadReader{},
		TenantModelStore: store,
		OperatorTenantID: operatorID,
	})

	listRec := httptest.NewRecorder()
	listReq := httptest.NewRequest(http.MethodGet, "/admin/tenants", nil)
	listReq.Header.Set("authorization", "Bearer "+operatorTenantListBearer)
	handler.ServeHTTP(listRec, listReq)
	if listRec.Code != http.StatusOK {
		t.Fatalf("list status = %d, want %d, body=%s", listRec.Code, http.StatusOK, listRec.Body.String())
	}
	var listResp struct {
		Tenants []adminTenantModel `json:"tenants"`
	}
	if err := json.Unmarshal(listRec.Body.Bytes(), &listResp); err != nil {
		t.Fatalf("decode tenant list: %v", err)
	}
	var operator *adminTenantModel
	for i := range listResp.Tenants {
		switch listResp.Tenants[i].TenantID {
		case operatorID:
			operator = &listResp.Tenants[i]
		case "tenant_lab_001":
			if listResp.Tenants[i].IsOperator {
				t.Fatalf("customer tenant tenant_lab_001 flagged is_operator: %#v", listResp.Tenants[i])
			}
		}
	}
	if operator == nil {
		t.Fatalf("operator tenant %q not seeded into list: %#v", operatorID, listResp.Tenants)
	}
	if !operator.IsOperator || operator.DisplayName != "Operator" || operator.Status != "active" {
		t.Fatalf("operator tenant = %#v, want is_operator/Operator/active", *operator)
	}

	delRec := httptest.NewRecorder()
	// ★ AS THE OPERATOR. Deleting an organization is an operator act (2026-08-22 — a customer administrator
	// was measured deleting an unrelated organization), so an unauthenticated delete now stops one gate
	// earlier and would never reach the operator-tenant refusal this asserts.
	delReq := httptest.NewRequest(http.MethodDelete, "/admin/tenants/"+operatorID, nil)
	delReq.Header.Set("authorization", "Bearer "+operatorTenantListBearer)
	handler.ServeHTTP(delRec, delReq)
	if delRec.Code != http.StatusConflict || !strings.Contains(delRec.Body.String(), "operator tenant") {
		t.Fatalf("delete operator status = %d body=%s, want 409 operator-tenant refusal", delRec.Code, delRec.Body.String())
	}

	// The operator tenant survives the rejected delete.
	afterRec := httptest.NewRecorder()
	afterReq := httptest.NewRequest(http.MethodGet, "/admin/tenants", nil)
	afterReq.Header.Set("authorization", "Bearer "+operatorTenantListBearer)
	handler.ServeHTTP(afterRec, afterReq)
	if !strings.Contains(afterRec.Body.String(), operatorID) {
		t.Fatalf("operator tenant gone after rejected delete: %s", afterRec.Body.String())
	}
}

// TestAdminTenantsOperatorFeatureOffUnchanged pins the lab default: with -operator-tenant-id unset, no tenant is
// flagged is_operator and any tenant (including the seeded one) is deletable — behavior is unchanged.
func TestAdminTenantsOperatorFeatureOffUnchanged(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	handler := newServerWithConfig(serverConfig{
		Evaluator:        testEvaluator(),
		Writer:           writer,
		Registry:         connector.NewRegistry(),
		AdminAuth:        newAdminAuthStore(),
		AdminAuditOutbox: &recordingAdminAuditOutboxDeadReader{},
	})

	listRec := httptest.NewRecorder()
	handler.ServeHTTP(listRec, httptest.NewRequest(http.MethodGet, "/admin/tenants", nil))
	if listRec.Code != http.StatusOK {
		t.Fatalf("list status = %d, want %d, body=%s", listRec.Code, http.StatusOK, listRec.Body.String())
	}
	var listResp struct {
		Tenants []adminTenantModel `json:"tenants"`
	}
	if err := json.Unmarshal(listRec.Body.Bytes(), &listResp); err != nil {
		t.Fatalf("decode tenant list: %v", err)
	}
	if len(listResp.Tenants) == 0 {
		t.Fatalf("expected the seeded tenant in the list")
	}
	for _, tenant := range listResp.Tenants {
		if tenant.IsOperator {
			t.Fatalf("tenant %q flagged is_operator with the feature off: %#v", tenant.TenantID, tenant)
		}
	}

	// The seeded tenant is deletable when the operator feature is off (no 409 lockout).
	delRec := httptest.NewRecorder()
	handler.ServeHTTP(delRec, httptest.NewRequest(http.MethodDelete, "/admin/tenants/tenant_lab_001", nil))
	if delRec.Code != http.StatusOK {
		t.Fatalf("delete status = %d body=%s, want 200 (no lockout when feature off)", delRec.Code, delRec.Body.String())
	}
}

func TestAdminTenantModelAPIRequiresWriteScopeForAPIToken(t *testing.T) {
	adminAuth := newAdminAuthStore()
	adminAuth.UpsertPrincipal(adminPrincipal{
		ID:        "admin_tenant_reader_001",
		TenantID:  "tenant_lab_001",
		Subject:   "sub_tenant_reader_001",
		Email:     "tenant-reader@example.test",
		Roles:     []string{"admin"},
		IDPID:     "keycloak_lab",
		Status:    "active",
		CreatedAt: time.Now().UTC().Add(-time.Hour).Format(time.RFC3339),
	})
	adminAuth.UpsertAPIToken(adminAPIToken{
		ID:                        "admin_token_tenant_reader_001",
		TenantID:                  "tenant_lab_001",
		Name:                      "tenant-reader-token",
		TokenHash:                 adminTokenHash("raw-tenant-reader-token"),
		Roles:                     []string{"admin"},
		Scopes:                    []string{"admin.tenant.read"},
		CreatedByAdminPrincipalID: "admin_tenant_reader_001",
		CreatedAt:                 time.Now().UTC().Add(-time.Hour).Format(time.RFC3339),
		ExpiresAt:                 time.Now().UTC().Add(time.Hour).Format(time.RFC3339),
		Status:                    "active",
	})
	handler := newServerWithConfig(serverConfig{
		Evaluator: testEvaluator(),
		Registry:  connector.NewRegistry(),
		AdminAuth: adminAuth,
	})
	req := httptest.NewRequest(http.MethodPost, "/admin/tenant", strings.NewReader(`{"tenant_id":"tenant_lab_001","status":"active"}`))
	req.Header.Set("authorization", "Bearer raw-tenant-reader-token")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "admin api token scope admin.tenant.write is required") {
		t.Fatalf("status = %d body=%s, want write scope denial", rec.Code, rec.Body.String())
	}
}

// A tenant's timezone is PER TENANT because an MSSP runs tenants whose main regions differ; one clock cannot
// suit all of them. These check the two things that decide whether the setting is trustworthy: that a typo is
// refused while the operator can still see it, and that an unset value means UTC rather than "whatever zone
// the Edge happens to be running in".
func TestTenantTimezoneMustBeARealIANAZone(t *testing.T) {
	for _, zone := range []string{"Asia/Tokyo", "Europe/Berlin", "America/New_York", "UTC", ""} {
		tenant := adminTenantModel{TenantID: "tenant_tz", DisplayName: "TZ", Timezone: zone}
		if _, err := normalizeAdminTenantModel(tenant, "tenant_tz", time.Now()); err != nil {
			t.Fatalf("timezone %q was rejected: %v", zone, err)
		}
	}

	// A character-class check would accept every one of these. Only consulting the real database catches them,
	// and the mistake would otherwise surface much later as reports covering the wrong day.
	// NOT included: a wrong-case name like "Asia/tokyo". Whether that resolves depends on where the zone data
	// comes from — macOS reads a case-INSENSITIVE filesystem, while the scratch-based runtime image has only
	// the embedded database, which is case-sensitive. Asserting either way would encode a platform difference
	// as a product rule. The strict behaviour is the one production has, and it errs toward refusing, so an
	// operator sees the mistake instead of living with it.
	for _, zone := range []string{"Asia/Tokyoo", "Mars/Olympus", "JST", "+09:00"} {
		tenant := adminTenantModel{TenantID: "tenant_tz", DisplayName: "TZ", Timezone: zone}
		if _, err := normalizeAdminTenantModel(tenant, "tenant_tz", time.Now()); err == nil {
			t.Fatalf("timezone %q was accepted but is not a real IANA zone — the error would only appear later, "+
				"as a report covering the wrong day", zone)
		}
	}
}

// The IANA database must be available to the RUNNING BINARY, not just to the developer's machine. The runtime
// image is FROM scratch and carries no /usr/share/zoneinfo, so without the embedded database LoadLocation
// fails for every zone and the operator sees their own correct input rejected.
func TestTimezoneDatabaseIsCompiledIn(t *testing.T) {
	for _, zone := range []string{"Asia/Tokyo", "Europe/Berlin", "America/Sao_Paulo"} {
		if _, err := time.LoadLocation(zone); err != nil {
			t.Fatalf("%q is unavailable to this binary (%v) — on the scratch-based runtime image every zone "+
				"would be refused, and it would look like the operator mistyped it", zone, err)
		}
	}
}

// Unset falls back to UTC, never to the host's local zone. The host is wherever the Edge happens to run —
// for an MSSP, not any tenant's region — so adopting it would make the same log read differently depending on
// which node served the request.
func TestUnsetTenantTimezoneIsUTCNotHostLocal(t *testing.T) {
	if got := tenantLocation(adminTenantModel{}); got != time.UTC {
		t.Fatalf("an unset tenant timezone resolved to %v, want UTC", got)
	}
	// An unreadable value must also fall back rather than adopt the host's zone.
	if got := tenantLocation(adminTenantModel{Timezone: "Mars/Olympus"}); got != time.UTC {
		t.Fatalf("an unknown zone resolved to %v, want UTC", got)
	}
	tokyo := tenantLocation(adminTenantModel{Timezone: "Asia/Tokyo"})
	if tokyo == time.UTC {
		t.Fatal("a configured zone was ignored")
	}
	// The point of storing a ZONE rather than an offset: the offset has to change with daylight saving, and
	// "yesterday" must mean the operator's yesterday all year round.
	berlin := tenantLocation(adminTenantModel{Timezone: "Europe/Berlin"})
	_, winter := time.Date(2026, 1, 15, 12, 0, 0, 0, berlin).Zone()
	_, summer := time.Date(2026, 7, 15, 12, 0, 0, 0, berlin).Zone()
	if winter == summer {
		t.Fatal("the stored zone does not track daylight saving — an offset would have been enough, and it is not")
	}
}
