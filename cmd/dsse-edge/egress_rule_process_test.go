package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/agentpolicy"
	"github.com/lantern-networks/dsse-core/appcatalog"
	"github.com/lantern-networks/dsse-core/assetcatalog"
	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/edgeplane"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/policy"
	"github.com/lantern-networks/dsse-core/policyrule"
)

func egressProcessBasePolicies() []model.Policy {
	return []model.Policy{{ID: "fallback", Name: "fallback", TenantID: "customer", Status: "active", Priority: 1000, Conditions: map[string]any{"protocol": "tcp"}, Action: model.PolicyAction{Decision: "allow"}}}
}

func TestEgressRuleCPChild(t *testing.T) {
	dir := os.Getenv("DSSE_EGRESS_RULE_CP_CHILD")
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
	defer writer.Close()
	outbox := &recordingAdminAuditOutboxDeadReader{}
	assets := assetcatalog.NewStore()
	if err := assets.SetStatePath(filepath.Join(dir, "cp-assets.json")); err != nil {
		t.Fatal(err)
	}
	rules := policyrule.NewStore()
	if err := rules.SetStatePath(filepath.Join(dir, "cp-rules.json")); err != nil {
		t.Fatal(err)
	}
	cp := httptest.NewServer(newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Registry: connector.NewRegistry(), OperatorTenantID: "operations", AdminAuth: operatorSyncAuth(), TenantModelStore: tenants, AgentPolicySigner: signer, Writer: writer, AdminAuditOutbox: outbox, AssetStore: assets, RuleStore: rules, PolicyStore: policy.NewStore(egressProcessBasePolicies())}))
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
		if strings.HasPrefix(fmt.Sprint(a.Metadata["path"]), "/admin/rules") && a.Result != nil && *a.Result == "success" && (a.Metadata["status_code"] == 200 || a.Metadata["status_code"] == 201) {
			if a.ActorUserID == nil || (*a.ActorUserID != "operator" && *a.ActorUserID != "customer-admin") {
				t.Fatalf("missing actor: %+v", a)
			}
			successful++
		}
	}
	if successful != 5 {
		t.Fatalf("successful mutation audits=%d want 5", successful)
	}

}

func TestEgressRuleAcrossCPAndEdgeProcesses(t *testing.T) {
	dir := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestEgressRuleCPChild$", "-test.v")
	child.Env = append(os.Environ(), "DSSE_EGRESS_RULE_CP_CHILD="+dir)
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
	edgeAssets := assetcatalog.NewStore()
	edgeRules := policyrule.NewStore()
	edgePolicy := policy.NewStore(nil)
	status := &configBundleSyncStatus{source: ready.URL, interval: 20 * time.Millisecond}
	source := configBundleSource{url: ready.URL, client: http.DefaultClient, token: "synthetic-operator-sync-operator", tenantID: "operations", verifyPubKeyHex: ready.PublicKey, requireSigned: true, status: status, interval: 20 * time.Millisecond}
	pollCtx, stop := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		source.run(pollCtx, configApplyTargets{applications: appcatalog.NewStore(), assets: edgeAssets, rules: edgeRules, policyStore: edgePolicy, dlp: dlpStoresForTest("egress-rule-sync"), onRulesApplied: func() {
			edgePolicy.SetCompiledPolicies("customer", policyrule.CompileEgressPolicies("customer", edgeRules.List("customer", policyrule.PlaneEgress), edgeAssets))
		}})
	}()
	defer func() { stop(); <-done }()
	var reached atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached.Add(1); w.WriteHeader(204) }))
	defer upstream.Close()
	upstreamURL, _ := url.Parse(upstream.URL)
	// Synthetic in-process device identity and a loopback upstream; no deployed TLS claim.
	ev := decision.Evaluator{PolicyBundle: model.PolicyBundle{TenantID: "customer"}, Policies: egressProcessBasePolicies()}
	edgeWriter, err := logs.NewWriter(filepath.Join(dir, "edge-logs"))
	if err != nil {
		t.Fatal(err)
	}
	defer edgeWriter.Close()
	egress := newEdgeSWGHTTPEgressHandler(edgeSWGHTTPEgressHandlerConfig{Evaluator: ev, PolicyStore: edgePolicy, Writer: edgeWriter, DecisionStore: newAccessDecisionStore(), InspectionEvents: newInspectionEventStore(), Registry: connector.NewRegistry(), ProxyClient: &http.Client{Transport: redirectAllToServer{host: upstreamURL.Host, rt: http.DefaultTransport}}, DeviceAuthenticatedInProcess: true})
	edgeServer := httptest.NewServer(egress)
	defer edgeServer.Close()
	check := func(dest string, disabled, deleted bool) {
		t.Helper()
		bundle, err := source.fetch(ctx)
		if err != nil || !bundle.signatureVerified {
			t.Fatalf("signed bundle %v", err)
		}
		deadline := time.Now().Add(5 * time.Second)
		for {
			snap := status.snapshot()
			if snap["have_applied"] == true && snap["last_applied_generation"].(uint64) >= bundle.Generation {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("Edge sync timeout")
			}
			time.Sleep(10 * time.Millisecond)
		}
		fresh := policyrule.NewStore()
		if err := fresh.SetStatePath(filepath.Join(dir, "cp-rules.json")); err != nil {
			t.Fatal(err)
		}
		for label, store := range map[string]*policyrule.Store{"Edge": edgeRules, "CP saved": fresh} {
			rows := store.List("customer", policyrule.PlaneEgress)
			if deleted {
				if len(rows) != 0 {
					t.Fatalf("%s retained deleted rule", label)
				}
			} else if len(rows) != 1 || (rows[0].Status == policyrule.StatusDisabled) != disabled || len(rows[0].Destination) != 1 || rows[0].Destination[0] != dest {
				t.Fatalf("%s rule=%+v", label, rows)
			}
		}
		for _, host := range []string{"a.example.test", "b.example.test"} {
			req, err := http.NewRequestWithContext(ctx, "GET", edgeServer.URL+edgeplane.EdgeSWGHTTPEgressPath, nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set(edgeplane.EdgeSWGHTTPEgressTargetURLHeader, "http://"+host+"/")
			before := reached.Load()
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			raw, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				t.Fatal(err)
			}
			blocked := !deleted && !disabled && ((dest == "dest-a" && host == "a.example.test") || (dest == "dest-b" && host == "b.example.test"))
			if blocked {
				if resp.StatusCode != 403 || reached.Load() != before {
					t.Fatalf("blocked %s: %d %s", host, resp.StatusCode, string(raw))
				}
			} else if resp.StatusCode != 204 || reached.Load() != before+1 {
				t.Fatalf("allowed %s: %d %s", host, resp.StatusCode, string(raw))
			}
		}
	}
	for _, x := range []struct{ id, host string }{{"dest-a", "a.example.test"}, {"dest-b", "b.example.test"}} {
		call("customer-admin", "POST", "/admin/assets/endpoints", fmt.Sprintf(`{"id":%q,"kind":"network","alias":%q,"address":%q}`, x.id, x.id, x.host), 200)
	}
	save := func(dest string, disabled bool) {
		state := "active"
		if disabled {
			state = "disabled"
		}
		call("customer-admin", "POST", "/admin/rules", fmt.Sprintf(`{"id":"egress-rule","plane":"egress","priority":10,"status":%q,"source":["*"],"destination":[%q],"action":{"access":"deny"}}`, state, dest), 200)
		check(dest, disabled, false)
	}
	save("dest-a", false)
	save("dest-b", false)
	save("dest-b", true)
	save("dest-b", false)
	call("customer-admin", "DELETE", "/admin/rules/egress-rule", ``, 200)
	check("", false, true)
	if err := os.WriteFile(filepath.Join(dir, "stop"), []byte("done"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := child.Wait(); err != nil {
		t.Fatalf("CP: %v %s", err, output.String())
	}
}
