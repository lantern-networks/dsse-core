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
	"strings"
	"testing"
	"time"
)

func operatorSyncAuth() *adminAuthStore {
	auth := newAdminAuthStore()
	for _, a := range []struct{ id, tenant, role string }{{"operator", "operations", "super_admin"}, {"customer-admin", "customer", "admin"}} {
		auth.UpsertPrincipal(adminPrincipal{ID: a.id, TenantID: a.tenant, Roles: []string{a.role, "admin"}, Status: "active"})
		auth.UpsertAPIToken(adminAPIToken{ID: a.id, TenantID: a.tenant, TokenHash: adminTokenHash("synthetic-operator-sync-" + a.id), Roles: []string{a.role, "admin"}, Scopes: []string{"*"}, CreatedByAdminPrincipalID: a.id, Status: "active", ExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339)})
	}
	return auth
}

func TestOperatorAccessCPChild(t *testing.T) {
	dir := os.Getenv("DSSE_OPERATOR_ACCESS_CP_CHILD")
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
	cp := httptest.NewServer(newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Registry: connector.NewRegistry(), OperatorTenantID: "operations", AdminAuth: operatorSyncAuth(), TenantModelStore: tenants, AgentPolicySigner: signer, Writer: writer, AdminAuditOutbox: outbox}))
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
	var successful int
	for _, a := range outbox.wrapperAudits {
		if a.Result != nil && *a.Result == "success" && (a.Metadata["status_code"] == 200 || a.Metadata["status_code"] == 201) {
			if a.ActorUserID == nil || (*a.ActorUserID != "operator" && *a.ActorUserID != "customer-admin") {
				t.Fatalf("missing actor: %+v", a)
			}
			successful++
		}
	}
	if successful != 6 {
		t.Fatalf("successful mutation audits=%d want 6", successful)
	}

}

func TestOperatorAccessAcrossCPAndEdgeProcesses(t *testing.T) {
	dir := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestOperatorAccessCPChild$", "-test.v")
	child.Env = append(os.Environ(), "DSSE_OPERATOR_ACCESS_CP_CHILD="+dir)
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
	call := func(who, method, path, body string, want int) []byte {
		t.Helper()
		r, err := http.NewRequestWithContext(ctx, method, ready.URL+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("Authorization", "Bearer synthetic-operator-sync-"+who)
		if who == "operator" {
			r.Header.Set("X-Operate-Tenant", "customer")
		}
		resp, err := http.DefaultClient.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		raw, err := io.ReadAll(resp.Body)
		if err != nil || resp.StatusCode != want {
			t.Fatalf("%s %s: %d %s %v", method, path, resp.StatusCode, raw, err)
		}
		return raw
	}
	edgePath := filepath.Join(dir, "edge-tenants.json")
	edgeTenants := newOperatorAwareAdminTenantModelStore(model.PolicyBundle{TenantID: "customer"}, time.Now(), edgePath, "operations")
	status := &configBundleSyncStatus{source: ready.URL, interval: 20 * time.Millisecond}
	source := configBundleSource{url: ready.URL, client: http.DefaultClient, token: "synthetic-operator-sync-operator", tenantID: "operations", verifyPubKeyHex: ready.PublicKey, requireSigned: true, status: status, interval: 20 * time.Millisecond}
	pollCtx, stop := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		source.run(pollCtx, configApplyTargets{tenantModels: edgeTenants, applications: appcatalog.NewStore(), assets: assetcatalog.NewStore(), rules: policyrule.NewStore(), policyStore: policy.NewStore(nil), dlp: dlpStoresForTest("tenant-settings-sync")})
	}()
	defer func() { stop(); <-done }()
	edge := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), AdminAuth: operatorSyncAuth(), TenantModelStore: edgeTenants, OperatorTenantID: "operations", ConfigSourceURL: ready.URL})
	check := func(managed bool, elevationState string) {
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
			if err != nil || row.OperatorManaged != managed || !row.OperatorElevationRequiresApproval {
				t.Fatalf("%s delegation=%+v err=%v", label, row, err)
			}
			if elevationState != "" && (len(row.OperatorElevations) != 1 || row.OperatorElevations[0].state(time.Now()) != elevationState) {
				t.Fatalf("%s elevation=%+v", label, row.OperatorElevations)
			}
		}
		code, raw := operatorEnvelopeCall(t, edge, "synthetic-operator-sync-customer-admin", "GET", "/admin/operator-access", "", nil)
		var record struct {
			Managed    bool `json:"managed"`
			Elevations []struct {
				State string `json:"state"`
			} `json:"elevations"`
		}
		if code != 200 || json.Unmarshal([]byte(raw), &record) != nil || record.Managed != managed || (elevationState != "" && (len(record.Elevations) != 1 || record.Elevations[0].State != elevationState)) {
			t.Fatalf("access record %d %s", code, raw)
		}
		want := 403
		if managed {
			want = 200
		}
		code, raw = operatorEnvelopeCall(t, edge, "synthetic-operator-sync-operator", "GET", "/admin/tenant", "customer", nil)
		if code != want {
			t.Fatalf("delegated read %d want %d: %s", code, want, raw)
		}
		// Check the real elevated endpoint's authorization. A sourced Edge rejects
		// an authorized write with 409; no actual device is revoked by this probe.
		want = 403
		if managed && elevationState == "active" {
			want = 409
		}
		code, raw = operatorEnvelopeCall(t, edge, "synthetic-operator-sync-operator", "POST", "/admin/transport-admission/revoke", "customer", map[string]any{"identity": "synthetic-device"})
		if code != want {
			t.Fatalf("elevated endpoint %d want %d: %s", code, want, raw)
		}
	}
	call("customer-admin", "PUT", "/admin/operator-delegation", `{"managed":true,"elevation_requires_approval":true}`, 200)
	check(true, "")
	raw := call("operator", "POST", "/admin/operator-elevations", `{"minutes":10}`, 201)
	var created struct {
		Elevation operatorElevation `json:"elevation"`
	}
	if json.Unmarshal(raw, &created) != nil || created.Elevation.ID == "" {
		t.Fatalf("create %s", raw)
	}
	path := "/admin/operator-elevations/" + created.Elevation.ID
	check(true, "pending_approval")
	call("customer-admin", "POST", path+"/approve", `{}`, 200)
	check(true, "active")
	call("customer-admin", "DELETE", path, ``, 200)
	check(true, "ended")
	call("customer-admin", "PUT", "/admin/operator-delegation", `{"managed":false}`, 200)
	check(false, "ended")
	call("operator", "PUT", "/admin/operator-delegation", `{"managed":true}`, 403)
	call("customer-admin", "PUT", "/admin/operator-delegation", `{"managed":true}`, 200)
	check(true, "ended")
	if err := os.WriteFile(filepath.Join(dir, "stop"), []byte("done"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := child.Wait(); err != nil {
		t.Fatalf("CP: %v %s", err, output.String())
	}
}
