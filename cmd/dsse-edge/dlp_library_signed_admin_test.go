package main

import (
	"context"
	"encoding/json"
	"github.com/lantern-networks/dsse-core/agentpolicy"
	"github.com/lantern-networks/dsse-core/dlp"
	"github.com/lantern-networks/dsse-core/logs"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLibrarySignedAdminCRUDAndAudit(t *testing.T) {
	prev := operatorTenantConfigured()
	t.Cleanup(func() { operatorTenantAuthority.Store(prev) })
	auth := newAdminAuthStore()
	for _, tenant := range []string{"operator", "customer"} {
		auth.UpsertPrincipal(adminPrincipal{ID: tenant, TenantID: tenant, Roles: []string{"admin"}, Status: "active"})
		auth.UpsertAPIToken(adminAPIToken{ID: tenant, TenantID: tenant, TokenHash: adminTokenHash("token-" + tenant), Roles: []string{"admin"}, Scopes: []string{"*"}, CreatedByAdminPrincipalID: tenant, Status: "active", ExpiresAt: time.Now().Add(time.Hour).Format(time.RFC3339)})
	}
	auth.UpsertAPIToken(adminAPIToken{ID: "reader", TenantID: "customer", TokenHash: adminTokenHash("token-reader"), Roles: []string{"admin"}, Scopes: []string{"admin.dlp.read"}, CreatedByAdminPrincipalID: "customer", Status: "active", ExpiresAt: time.Now().Add(time.Hour).Format(time.RFC3339)})
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	signer, err := agentpolicy.LoadOrGenerateSigner("", true)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	server := httptest.NewServer(newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Writer: writer, AdminAuth: auth, OperatorTenantID: "operator", DLPClassifierStorePath: filepath.Join(dir, "classifiers.json"), DLPFingerprintStorePath: filepath.Join(dir, "fingerprints.json"), AgentPolicySigner: signer}))
	defer server.Close()
	send := func(token, method, path, body string, want int) string {
		t.Helper()
		req, _ := http.NewRequest(method, server.URL+path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer token-"+token)
		r, err := server.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer r.Body.Close()
		b, _ := io.ReadAll(r.Body)
		if r.StatusCode != want {
			t.Fatalf("%s %s status=%d want=%d body=%s", method, path, r.StatusCode, want, b)
		}
		return string(b)
	}
	send("reader", "POST", "/admin/dlp-classifiers", `{"classifiers":[]}`, 403)
	send("customer", "POST", "/admin/dlp-classifiers", `{"classifiers":[],"expected_tenant_id":"other"}`, 409)
	send("customer", "DELETE", "/admin/dlp-fingerprints?name=employees&expected_tenant_id=other", "", 409)
	send("operator", "POST", "/admin/dlp-classifiers", `{"classifiers":[{"name":"foreign_id","kind":"keyword","keywords":["FOREIGN"]}]}`, 200)
	src := configBundleSource{url: server.URL, client: server.Client(), token: "token-customer", tenantID: "customer", verifyPubKeyHex: signer.PublicKeyHex(), requireSigned: true}
	before, err := src.fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	edge := dlpStoresForTest("receiver")
	for _, value := range []string{"EMPLOYEE123", "UPDATED123", ""} {
		if value != "" {
			body, _ := json.Marshal(map[string]any{"classifiers": []dlp.ClassifierSpec{{Name: "employee_id", Kind: "keyword", Keywords: []string{value}}}})
			send("customer", "POST", "/admin/dlp-classifiers", string(body), 200)
			body, _ = json.Marshal(map[string]any{"name": "employees", "values": []string{value}})
			send("customer", "POST", "/admin/dlp-fingerprints", string(body), 200)
		} else {
			send("customer", "POST", "/admin/dlp-classifiers", `{"classifiers":[]}`, 200)
			send("customer", "DELETE", "/admin/dlp-fingerprints?name=employees", "", 200)
		}
		got := send("reader", "GET", "/admin/dlp-classifiers", "", 200)
		if value != "" && !strings.Contains(got, value) {
			t.Fatal("saved classifier missing")
		}
		got = send("reader", "GET", "/admin/dlp-fingerprints", "", 200)
		if strings.Contains(got, "EMPLOYEE123") || strings.Contains(got, "UPDATED123") {
			t.Fatal("source dataset value returned")
		}
		bundle, err := src.fetch(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if bundle.Generation <= before.Generation || bundle.DLP == nil {
			t.Fatal("edit did not advance distributed generation")
		}
		if _, ok := bundle.DLP.Classifiers["operator"]; ok {
			t.Fatal("foreign definition exposed")
		}
		if err := edge.Apply(bundle.DLP); err != nil {
			t.Fatal(err)
		}
		for _, candidate := range []string{"EMPLOYEE123", "UPDATED123"} {
			hits := dlp.DetectWithOptions([]byte(candidate), "text/plain", dlp.Options{Classifiers: edge.classifiers.ClassifierSetForTenant("customer"), Fingerprints: edge.fingerprints.FingerprintSetForTenant("customer")})
			want := 0
			if candidate == value {
				want = 2
			}
			if len(hits) != want {
				t.Fatalf("received scan=%v want=%d", hits, want)
			}
		}
		before = bundle
	}
	count := 0
	for _, row := range readConnectorManagementAudits(t, writer) {
		if row.EventType != "admin_config_change" || row.TenantID != "customer" || stringPtrValue(row.Result) != "success" {
			continue
		}
		path := row.Metadata["path"]
		if path != "/admin/dlp-classifiers" && path != "/admin/dlp-fingerprints" {
			continue
		}
		count++
		if stringPtrValue(row.ActorUserID) != "customer" {
			t.Fatal("audit actor missing")
		}
		b, _ := json.Marshal(row)
		if strings.Contains(string(b), "EMPLOYEE123") || strings.Contains(string(b), "UPDATED123") {
			t.Fatal("raw definition entered audit")
		}
	}
	if count != 6 {
		t.Fatalf("successful edit audit count=%d", count)
	}
}
