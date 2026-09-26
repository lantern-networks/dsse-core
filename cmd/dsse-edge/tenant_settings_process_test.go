package main

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/lantern-networks/dsse-core/agentpolicy"
	"github.com/lantern-networks/dsse-core/appcatalog"
	"github.com/lantern-networks/dsse-core/assetcatalog"
	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/policy"
	"github.com/lantern-networks/dsse-core/policyrule"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func tenantSettingsSyncAuth() *adminAuthStore {
	auth := newAdminAuthStore()
	for _, a := range []struct{ id, tenant, role string }{{"operator", "operations", "super_admin"}, {"customer-admin", "customer", "admin"}} {
		auth.UpsertPrincipal(adminPrincipal{ID: a.id, TenantID: a.tenant, Roles: []string{a.role, "admin"}, Status: "active"})
		auth.UpsertAPIToken(adminAPIToken{ID: a.id, TenantID: a.tenant, TokenHash: adminTokenHash("synthetic-tenant-sync-" + a.id), Roles: []string{a.role, "admin"}, Scopes: []string{"*"}, CreatedByAdminPrincipalID: a.id, Status: "active", ExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339)})
	}
	return auth
}

func TestTenantSettingsCPChild(t *testing.T) {
	dir := os.Getenv("DSSE_TENANT_SETTINGS_CP_CHILD")
	if dir == "" {
		t.Skip("helper process")
	}
	signer, err := agentpolicy.LoadOrGenerateSigner("", true)
	if err != nil {
		t.Fatal(err)
	}
	tenants := newOperatorAwareAdminTenantModelStore(model.PolicyBundle{TenantID: "customer"}, time.Now(), filepath.Join(dir, "cp-tenants.json"), "operations")
	writer, err := logs.NewWriter(filepath.Join(dir, "logs"))
	if err != nil {
		t.Fatal(err)
	}
	outbox := &recordingAdminAuditOutboxDeadReader{}
	cp := httptest.NewServer(newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Registry: connector.NewRegistry(), OperatorTenantID: "operations", AdminAuth: tenantSettingsSyncAuth(), TenantModelStore: tenants, AgentPolicySigner: signer, Writer: writer, AdminAuditOutbox: outbox}))
	defer cp.Close()
	raw, _ := json.Marshal(map[string]string{"url": cp.URL, "public_key": signer.PublicKeyHex()})
	if err := os.WriteFile(filepath.Join(dir, "ready.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(35 * time.Second)
	for {
		if _, err := os.Stat(filepath.Join(dir, "stop")); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("parent did not finish")
		}
		time.Sleep(10 * time.Millisecond)
	}
	outbox.mu.Lock()
	defer outbox.mu.Unlock()
	if len(outbox.wrapperAudits) != 6 {
		t.Fatalf("audits=%d want 6", len(outbox.wrapperAudits))
	}
	for _, a := range outbox.wrapperAudits {
		if a.ActorUserID == nil || (*a.ActorUserID != "operator" && *a.ActorUserID != "customer-admin") || a.Result == nil || *a.Result != "success" || a.Metadata["status_code"] != 200 {
			t.Fatalf("audit=%+v", a)
		}
	}
}

func TestTenantSettingsAcrossCPAndEdgeProcesses(t *testing.T) {
	dir := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestTenantSettingsCPChild$", "-test.v")
	child.Env = append(os.Environ(), "DSSE_TENANT_SETTINGS_CP_CHILD="+dir)
	var output bytes.Buffer
	child.Stdout = &output
	child.Stderr = &output
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if child.ProcessState == nil {
			_ = child.Process.Kill()
			_ = child.Wait()
		}
	}()
	var ready struct {
		URL       string `json:"url"`
		PublicKey string `json:"public_key"`
	}
	for {
		raw, err := os.ReadFile(filepath.Join(dir, "ready.json"))
		if err == nil && json.Unmarshal(raw, &ready) == nil && ready.URL != "" {
			break
		}
		if ctx.Err() != nil {
			t.Fatal("CP startup timeout")
		}
		time.Sleep(10 * time.Millisecond)
	}
	call := func(who, method, path, body string) []byte {
		t.Helper()
		r, err := http.NewRequestWithContext(ctx, method, ready.URL+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("Authorization", "Bearer synthetic-tenant-sync-"+who)
		resp, err := http.DefaultClient.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		raw, err := io.ReadAll(resp.Body)
		if err != nil || resp.StatusCode != 200 {
			t.Fatalf("%s %s: %d %s %v", method, path, resp.StatusCode, raw, err)
		}
		return raw
	}
	edgePath := filepath.Join(dir, "edge-tenants.json")
	edgeTenants := newOperatorAwareAdminTenantModelStore(model.PolicyBundle{TenantID: "customer"}, time.Now(), edgePath, "operations")
	status := &configBundleSyncStatus{source: ready.URL, interval: 20 * time.Millisecond}
	source := configBundleSource{url: ready.URL, client: http.DefaultClient, token: "synthetic-tenant-sync-operator", tenantID: "operations", verifyPubKeyHex: ready.PublicKey, requireSigned: true, status: status, interval: 20 * time.Millisecond}
	pollCtx, stop := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		source.run(pollCtx, configApplyTargets{tenantModels: edgeTenants, applications: appcatalog.NewStore(), assets: assetcatalog.NewStore(), rules: policyrule.NewStore(), policyStore: policy.NewStore(nil), dlp: dlpStoresForTest("tenant-settings-sync")})
	}()
	defer func() { stop(); <-done }()
	edge := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), AdminAuth: tenantSettingsSyncAuth(), TenantModelStore: edgeTenants, OperatorTenantID: "operations", ConfigSourceURL: ready.URL})
	temporaryID := ""
	check := func(name, zone string, regions []string, extra bool) {
		t.Helper()
		bundle, err := source.fetch(ctx)
		if err != nil || !bundle.signatureVerified {
			t.Fatalf("signed bundle: %v", err)
		}
		deadline := time.Now().Add(5 * time.Second)
		for {
			snap := status.snapshot()
			if snap["have_applied"] == true && snap["last_applied_generation"].(uint64) >= bundle.Generation {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("Edge did not apply generation: %v", snap)
			}
			time.Sleep(10 * time.Millisecond)
		}
		for label, store := range map[string]*adminTenantModelStore{"Edge": edgeTenants, "saved Edge": newOperatorAwareAdminTenantModelStore(model.PolicyBundle{}, time.Now(), edgePath, "operations"), "saved CP": newOperatorAwareAdminTenantModelStore(model.PolicyBundle{}, time.Now(), filepath.Join(dir, "cp-tenants.json"), "operations")} {
			row, err := store.Get(ctx, "customer")
			if err != nil || row.DisplayName != name || row.Timezone != zone || !reflect.DeepEqual(row.AllowedRegions, regions) {
				t.Fatalf("%s row=%+v err=%v", label, row, err)
			}
			rows, err := store.List(ctx)
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, r := range rows {
				if r.TenantID == temporaryID {
					found = true
				}
			}
			if found != extra {
				t.Fatalf("%s temporary=%v want %v", label, found, extra)
			}
		}
		code, raw := operatorEnvelopeCall(t, edge, "synthetic-tenant-sync-customer-admin", "GET", "/admin/session", "", nil)
		var session map[string]any
		if code != 200 || json.Unmarshal([]byte(raw), &session) != nil || session["timezone"] != zone {
			t.Fatalf("session %d %s", code, raw)
		}
		code, raw = operatorEnvelopeCall(t, edge, "synthetic-tenant-sync-customer-admin", "GET", "/admin/tenant", "", nil)
		var row adminTenantModel
		if code != 200 || json.Unmarshal([]byte(raw), &row) != nil || row.DisplayName != name || row.Timezone != zone {
			t.Fatalf("tenant GET %d %s", code, raw)
		}
	}
	call("customer-admin", "POST", "/admin/tenant", `{"timezone":"Asia/Tokyo"}`)
	check("customer", "Asia/Tokyo", nil, false)
	call("operator", "POST", "/admin/tenants", `{"tenant_id":"customer","display_name":"Renamed customer"}`)
	check("Renamed customer", "Asia/Tokyo", nil, false)
	call("customer-admin", "POST", "/admin/tenant", `{"allowed_regions":["region-a"]}`)
	check("Renamed customer", "Asia/Tokyo", []string{"region-a"}, false)
	call("customer-admin", "POST", "/admin/tenant", `{"allowed_regions":[]}`)
	check("Renamed customer", "Asia/Tokyo", nil, false)
	created := call("operator", "POST", "/admin/tenants", `{"display_name":"Temporary"}`)
	var newTenant adminTenantModel
	if err := json.Unmarshal(created, &newTenant); err != nil || newTenant.TenantID == "" {
		t.Fatalf("create: %s %v", created, err)
	}
	temporaryID = newTenant.TenantID
	check("Renamed customer", "Asia/Tokyo", nil, true)
	call("operator", "DELETE", "/admin/tenants/"+temporaryID, ``)
	check("Renamed customer", "Asia/Tokyo", nil, false)
	code, _ := operatorEnvelopeCall(t, edge, "synthetic-tenant-sync-customer-admin", "POST", "/admin/tenant", "", map[string]any{"timezone": "UTC"})
	if code != 409 {
		t.Fatalf("sourced Edge edit=%d want 409", code)
	}
	if err := os.WriteFile(filepath.Join(dir, "stop"), []byte("done"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := child.Wait(); err != nil {
		t.Fatalf("CP: %v %s", err, output.String())
	}
}
