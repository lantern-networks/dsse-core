package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
)

func TestInterceptionImportsAuditSavedFingerprintAndTarget(t *testing.T) {
	now := time.Now().UTC()
	tenant := testEvaluator().PolicyBundle.TenantID
	auth := newAdminAuthStore()
	auth.UpsertPrincipal(adminPrincipal{ID: "import_admin", TenantID: tenant, Roles: []string{"admin", "super_admin"}, Status: "active"})
	auth.UpsertAPIToken(adminAPIToken{ID: "import_token", TenantID: tenant, TokenHash: adminTokenHash(testTenantCABearer), Roles: []string{"admin", "super_admin"}, Scopes: []string{"*"}, CreatedByAdminPrincipalID: "import_admin", ExpiresAt: now.Add(time.Hour).Format(time.RFC3339), Status: "active"})
	dir := t.TempDir()
	writer, err := logs.NewWriter(dir)
	if err != nil {
		t.Fatal(err)
	}
	refused := false
	authority := newTenantInterceptionAuthority(nil, func([]byte) error {
		if refused {
			return errors.New("save refused")
		}
		return nil
	}, nil)
	tenants := newOperatorAwareAdminTenantModelStore(testEvaluator().PolicyBundle, now, "", tenant)
	handler := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Writer: writer, AdminAuth: auth, OperatorTenantID: tenant, TenantModelStore: tenants, TenantInterceptionAuthority: authority})
	var roots, issuers, keys []string
	for _, name := range []string{"Initial", "Incoming"} {
		r, c, k, e := mintTenantInterceptionAuthority(tenant, name, now)
		if e != nil {
			t.Fatal(e)
		}
		roots = append(roots, r)
		issuers = append(issuers, c)
		keys = append(keys, k)
	}
	send := func(i int, want int) {
		t.Helper()
		res := doTenantCARequest(t, handler, http.MethodPost, "/admin/tenant-interception-authority", map[string]string{"root_pem": roots[i], "issuing_cert_pem": issuers[i], "issuing_key_pem": keys[i]})
		if res.Code != want {
			t.Fatalf("import status=%d want=%d", res.Code, want)
		}
	}
	send(0, 200)
	refused = true
	send(1, 400)
	refused = false
	send(1, 200)
	raw, err := os.ReadFile(filepath.Join(dir, "audit.log.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range keys {
		if strings.Contains(string(raw), strings.TrimSpace(key)) {
			t.Fatal("private key in audit")
		}
	}
	var found []model.AuditLog
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		var a model.AuditLog
		if e := json.Unmarshal([]byte(line), &a); e != nil {
			t.Fatal(e)
		}
		if a.EventType == "pki_material_changed" {
			found = append(found, a)
		}
	}
	if len(found) != 2 {
		t.Fatalf("domain audits=%d want 2 saved operations only", len(found))
	}
	for i, a := range found {
		root, _ := summarizeCertificatePEM(roots[i])
		issuer, _ := summarizeCertificatePEM(issuers[i])
		if a.TenantID != tenant || a.TargetID == nil || *a.TargetID != tenant || a.Metadata["principal_id"] != "import_admin" || a.Metadata["root_sha256"] != root.SHA256 || a.Metadata["issuing_sha256"] != issuer.SHA256 || a.Metadata["staged"] != (i == 1) {
			t.Fatalf("wrong public audit attribution: %+v", a)
		}
		action := []string{"interception_authority_imported", "interception_authority_staged"}[i]
		if a.Action == nil || *a.Action != action {
			t.Fatalf("wrong action for import %d", i)
		}
	}
}
