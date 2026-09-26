package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/agentpolicy"
	"github.com/lantern-networks/dsse-core/appcatalog"
	"github.com/lantern-networks/dsse-core/assetcatalog"
	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/policy"
	"github.com/lantern-networks/dsse-core/policyrule"
)

func TestIncomingWithdrawalCPChild(t *testing.T) {
	dir := os.Getenv("DSSE_INCOMING_WITHDRAWAL_CP_CHILD")
	if dir == "" {
		t.Skip("helper process")
	}
	signer, err := agentpolicy.LoadOrGenerateSigner("", true)
	if err != nil {
		t.Fatal(err)
	}
	writer, err := logs.NewWriter(filepath.Join(dir, "logs"))
	if err != nil {
		t.Fatal(err)
	}
	outbox := &recordingAdminAuditOutboxDeadReader{}
	cpAssets := incomingWithdrawalAssets(t, filepath.Join(dir, "cp-assets.json"))
	cpRules := policyrule.NewStore()
	if err := cpRules.SetStatePath(filepath.Join(dir, "cp-rules.json")); err != nil {
		t.Fatal(err)
	}
	cpPolicy := policy.NewStore(nil)
	if err := cpPolicy.SetRuntimeStatePath(filepath.Join(dir, "cp-policy.json")); err != nil {
		t.Fatal(err)
	}
	cp := httptest.NewServer(newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Registry: connector.NewRegistry(),
		OperatorTenantID: incomingWithdrawalTenant, AdminAuth: incomingWithdrawalAuth(),
		ApplicationCatalogStore: incomingWithdrawalApps(t, filepath.Join(dir, "cp-apps.json")),
		AssetStore:              cpAssets,
		RuleStore:               cpRules,
		PolicyStore:             cpPolicy,
		AgentPolicySigner:       signer, Writer: writer, AdminAuditOutbox: outbox}))
	defer cp.Close()
	raw, err := json.Marshal(incomingWithdrawalReady{URL: cp.URL, PublicKey: signer.PublicKeyHex()})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ready.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(25 * time.Second)
	for {
		if _, err := os.Stat(filepath.Join(dir, "stop")); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("Edge did not finish before the deadline")
		}
		time.Sleep(10 * time.Millisecond)
	}
	outbox.mu.Lock()
	defer outbox.mu.Unlock()
	if len(outbox.wrapperAudits) != 5 {
		t.Fatalf("audits=%d want 5", len(outbox.wrapperAudits))
	}
	paths := []string{"/admin/legacy-exceptions", "/admin/server-initiated", "/admin/legacy-exceptions/startup", "/admin/server-initiated", "/admin/server-initiated"}
	for i, a := range outbox.wrapperAudits {
		method := "POST"
		if i == 2 {
			method = "DELETE"
		}
		if a.TenantID != incomingWithdrawalTenant || a.ActorUserID == nil || *a.ActorUserID != "operator" || a.TargetID == nil || *a.TargetID != paths[i] || a.Action == nil || *a.Action != method || a.Result == nil || *a.Result != "success" || a.Metadata["status_code"] != 200 {
			t.Fatalf("audit %d=%+v", i, a)
		}
	}
}

// Mutations go to a separate CP process; Edge consumes signed bundles through
// the product poller and evaluates requests with the original startup settings.
func TestIncomingWithdrawalAcrossCPAndEdgeProcesses(t *testing.T) {
	dir := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestIncomingWithdrawalCPChild$", "-test.v")
	child.Env = append(os.Environ(), "DSSE_INCOMING_WITHDRAWAL_CP_CHILD="+dir)
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
	var ready incomingWithdrawalReady
	for {
		raw, err := os.ReadFile(filepath.Join(dir, "ready.json"))
		if err == nil && json.Unmarshal(raw, &ready) == nil && ready.URL != "" {
			break
		}
		if ctx.Err() != nil {
			t.Fatal("CP startup timed out")
		}
		time.Sleep(10 * time.Millisecond)
	}
	call := func(method, path, body string) {
		t.Helper()
		r, err := http.NewRequestWithContext(ctx, method, ready.URL+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("Authorization", "Bearer "+incomingWithdrawalToken)
		r.Header.Set("X-Operate-Tenant", incomingWithdrawalTenant)
		r.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		raw, err := io.ReadAll(resp.Body)
		if err != nil || resp.StatusCode != 200 {
			t.Fatalf("%s %s: %d %s %v", method, path, resp.StatusCode, raw, err)
		}
	}
	edgePolicy := policy.NewStore(nil)
	status := &configBundleSyncStatus{source: ready.URL, interval: 20 * time.Millisecond}
	source := configBundleSource{url: ready.URL, client: http.DefaultClient, token: incomingWithdrawalToken, tenantID: incomingWithdrawalTenant, verifyPubKeyHex: ready.PublicKey, requireSigned: true, status: status, interval: 20 * time.Millisecond}
	pollCtx, stop := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		source.run(pollCtx, configApplyTargets{applications: appcatalog.NewStore(), assets: assetcatalog.NewStore(), rules: policyrule.NewStore(), policyStore: edgePolicy, dlp: dlpStoresForTest("incoming-withdrawal")})
	}()
	defer func() { stop(); <-done }()
	base := decision.Evaluator{PolicyBundle: model.PolicyBundle{TenantID: incomingWithdrawalTenant}, ServerInitiatedEnabled: true, LegacyExceptions: []decision.LegacyException{{ID: "startup", SourceServer: "patchsrv", ServiceFamily: "smb", Port: 445, Mode: "allow", Active: true, ExpiresAt: time.Now().Add(time.Hour)}}}
	req := model.DecisionRequest{TenantID: incomingWithdrawalTenant, ActorType: "human", ConnectionInitiator: "server", SourceServer: "patchsrv", ServiceFamily: "smb", DestinationPort: 445, Protocol: "tcp"}
	check := func(enabled bool, exceptions int) {
		t.Helper()
		bundle, err := source.fetch(ctx)
		if err != nil || !bundle.signatureVerified {
			t.Fatalf("signed bundle: %v", err)
		}
		deadline := time.Now().Add(4 * time.Second)
		applied := false
		for time.Now().Before(deadline) {
			snap := status.snapshot()
			if snap["have_applied"] == true && snap["last_applied_generation"].(uint64) >= bundle.Generation {
				applied = true
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		if !applied {
			t.Fatal("Edge did not apply generation")
		}
		fresh := policy.NewStore(nil)
		if err := fresh.SetRuntimeStatePath(filepath.Join(dir, "cp-policy.json")); err != nil {
			t.Fatal(err)
		}
		for name, store := range map[string]*policy.Store{"Edge": edgePolicy, "CP fresh read": fresh} {
			cfg := store.SnapshotTenantConfig(incomingWithdrawalTenant)
			if cfg.ServerInitiatedEnabled != enabled || len(cfg.LegacyExceptions) != exceptions {
				t.Fatalf("%s saved/distributed state differs", name)
			}
			ev := store.RuntimeEvaluator(base)
			if ev.ServerInitiatedEnabled != enabled || len(ev.LegacyExceptions) != exceptions {
				t.Fatalf("%s resurrected startup state", name)
			}
			if enabled {
				want := "deny"
				if exceptions > 0 {
					want = "allow"
				}
				if got := ev.Evaluate(req); got.Decision != want {
					t.Fatalf("%s decision=%+v want %s", name, got, want)
				}
			} else {
				for _, code := range ev.Evaluate(req).ReasonCodes {
					if strings.HasPrefix(code, "server_initiated_") {
						t.Fatalf("%s disabled gate still evaluates incoming access: %s", name, code)
					}
				}
			}
		}
		other := base
		other.PolicyBundle.TenantID = "other"
		ev := edgePolicy.RuntimeEvaluator(other)
		if !ev.ServerInitiatedEnabled || len(ev.LegacyExceptions) != 1 {
			t.Fatal("unconfigured tenant changed")
		}
	}
	ex := model.LegacyException{ID: "startup", BusinessOwner: "secops", SourceServer: "patchsrv", ServiceFamily: "smb", Protocol: "tcp", Port: 445, Mode: "allow", Status: "active", ExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339)}
	raw, err := json.Marshal(ex)
	if err != nil {
		t.Fatal(err)
	}
	call("POST", "/admin/legacy-exceptions", string(raw))
	call("POST", "/admin/server-initiated", `{"enabled":true}`)
	check(true, 1)
	call("DELETE", "/admin/legacy-exceptions/startup", "")
	check(true, 0)
	call("POST", "/admin/server-initiated", `{"enabled":false}`)
	check(false, 0)
	call("POST", "/admin/server-initiated", `{"enabled":true}`)
	check(true, 0)
	stop()
	<-done
	if err := os.WriteFile(filepath.Join(dir, "stop"), []byte("done"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := child.Wait(); err != nil {
		t.Fatalf("CP audit: %v %s", err, output.String())
	}
}

func incomingWithdrawalAuth() *adminAuthStore {
	auth := newAdminAuthStore()
	auth.UpsertPrincipal(adminPrincipal{ID: "operator", TenantID: incomingWithdrawalTenant, Roles: []string{"admin"}, Status: "active"})
	auth.UpsertAPIToken(adminAPIToken{ID: "operator", TenantID: incomingWithdrawalTenant, TokenHash: adminTokenHash(incomingWithdrawalToken), Roles: []string{"admin"}, Scopes: []string{"admin.policy.read", "admin.serverinitiated.read", "admin.serverinitiated.write"}, CreatedByAdminPrincipalID: "operator", Status: "active", ExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339)})
	return auth
}

const incomingWithdrawalTenant = "tenant_lab_001"
const incomingWithdrawalToken = "synthetic-incoming-withdrawal-token"

type incomingWithdrawalReady struct {
	URL       string `json:"url"`
	PublicKey string `json:"public_key"`
}

func incomingWithdrawalAssets(t *testing.T, path string) *assetcatalog.Store {
	t.Helper()
	s := assetcatalog.NewStore()
	if err := s.SetStatePath(path); err != nil {
		t.Fatal(err)
	}
	return s
}
func incomingWithdrawalApps(t *testing.T, path string) *appcatalog.Store {
	t.Helper()
	s := appcatalog.NewStore()
	if err := s.SetStatePath(path); err != nil {
		t.Fatal(err)
	}
	return s
}
