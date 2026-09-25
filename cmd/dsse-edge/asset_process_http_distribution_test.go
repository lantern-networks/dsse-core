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

	"github.com/lantern-networks/dsse-core/appcatalog"
	"github.com/lantern-networks/dsse-core/assetcatalog"
	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/policy"
	"github.com/lantern-networks/dsse-core/policyrule"
)

// This covers ordinary asset mutation across two OS processes and the signed
// automatic CP-to-Edge feed. It does not stand in for deployed fleet traffic.
func TestAssetRuleDistributionAcrossCPAndEdgeProcesses(t *testing.T) {
	dir := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestApplicationDistributionCPChild$", "-test.v")
	child.Env = append(os.Environ(), "DSSE_DISTRIBUTION_CP_CHILD="+dir, "DSSE_DISTRIBUTION_CP_MODE=assets")
	var childOutput bytes.Buffer
	child.Stdout, child.Stderr = &childOutput, &childOutput
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if child.ProcessState == nil {
			_ = child.Process.Kill()
			_ = child.Wait()
		}
	}()
	var ready processDistributionReady
	for {
		raw, err := os.ReadFile(filepath.Join(dir, "ready.json"))
		if err == nil && json.Unmarshal(raw, &ready) == nil && ready.URL != "" {
			break
		}
		if ctx.Err() != nil {
			t.Fatal("CP process did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	request := func(method, base, path, body string) []byte {
		t.Helper()
		req, err := http.NewRequest(method, base+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+processDistributionToken)
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		raw, err := io.ReadAll(resp.Body)
		if err != nil || resp.StatusCode != http.StatusOK {
			t.Fatalf("%s %s: status=%d read=%v body=%s", method, path, resp.StatusCode, err, raw)
		}
		return raw
	}
	edgeAssetPath := filepath.Join(dir, "edge-assets.json")
	edgeAssets := processDistributionAssets(t, edgeAssetPath)
	edgeRules := policyrule.NewStore()
	edgePolicy := policy.NewStore(nil)
	edge := httptest.NewServer(newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Registry: connector.NewRegistry(),
		OperatorTenantID: processDistributionTenant, AdminAuth: processDistributionAuth(), AssetStore: edgeAssets,
		RuleStore: edgeRules, PolicyStore: edgePolicy, ConfigSourceURL: ready.URL}))
	defer edge.Close()
	status := &configBundleSyncStatus{source: ready.URL, interval: 20 * time.Millisecond}
	source := configBundleSource{url: ready.URL, client: http.DefaultClient, token: processDistributionToken,
		tenantID: processDistributionTenant, verifyPubKeyHex: ready.PublicKey, requireSigned: true,
		status: status, interval: 20 * time.Millisecond}
	targets := configApplyTargets{applications: appcatalog.NewStore(), assets: edgeAssets, rules: edgeRules, policyStore: edgePolicy,
		dlp: dlpStoresForTest("asset-process-http"),
		onRulesApplied: func() {
			edgePolicy.SetCompiledPolicies(processDistributionTenant,
				policyrule.CompileEgressPolicies(processDistributionTenant, edgeRules.List(processDistributionTenant, policyrule.PlaneEgress), edgeAssets))
		}}
	pollCtx, stopPoll := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { defer close(done); source.run(pollCtx, targets) }()
	defer func() { stopPoll(); <-done }()
	check := func(wantAddress string) {
		t.Helper()
		bundle, err := source.fetch(ctx)
		if err != nil || !bundle.signatureVerified {
			t.Fatalf("signed CP bundle: verified=%v err=%v", bundle.signatureVerified, err)
		}
		deadline := time.Now().Add(4 * time.Second)
		for time.Now().Before(deadline) {
			snap := status.snapshot()
			if snap["have_applied"] == true && snap["last_applied_generation"].(uint64) >= bundle.Generation {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		snap := status.snapshot()
		if snap["have_applied"] != true || snap["last_applied_generation"].(uint64) < bundle.Generation {
			t.Fatalf("Edge did not apply generation %d: %+v", bundle.Generation, snap)
		}
		var listed []assetcatalog.Endpoint
		if err := json.Unmarshal(request(http.MethodGet, edge.URL, "/admin/assets/endpoints", ""), &listed); err != nil {
			t.Fatal(err)
		}
		found := false
		for _, ep := range listed {
			if ep.ID == "ep-a" && ep.Address == wantAddress {
				found = true
			}
		}
		if found != (wantAddress != "") {
			t.Fatalf("Edge HTTP endpoint=%+v, want address %q", listed, wantAddress)
		}
		savedEndpoint, saved := processDistributionAssets(t, edgeAssetPath).GetEndpoint(processDistributionTenant, "ep-a")
		if saved != (wantAddress != "") || (saved && savedEndpoint.Address != wantAddress) {
			t.Fatalf("Edge durable endpoint present=%v address=%q, want address %q", saved, savedEndpoint.Address, wantAddress)
		}
		var rules []policyrule.Rule
		if err := json.Unmarshal(request(http.MethodGet, edge.URL, "/admin/rules?plane=egress", ""), &rules); err != nil {
			t.Fatal(err)
		}
		if len(rules) != 1 || rules[0].ID != "rule-a" {
			t.Fatalf("Edge HTTP rules=%+v", rules)
		}
		eval := edgePolicy.RuntimeEvaluator(decision.Evaluator{PolicyBundle: model.PolicyBundle{TenantID: processDistributionTenant}})
		var denyHosts []string
		for _, p := range eval.Policies {
			if p.Action.Decision == "deny" {
				if host, ok := p.Conditions["fqdn"].(string); ok {
					denyHosts = append(denyHosts, host)
				}
			}
		}
		if (wantAddress == "" && (len(denyHosts) != 1 || denyHosts[0] != "\x00no-such-destination")) ||
			(wantAddress != "" && (len(denyHosts) != 1 || denyHosts[0] != wantAddress)) {
			t.Fatalf("Edge compiled deny hosts=%v, want address %q", denyHosts, wantAddress)
		}
	}
	request(http.MethodPost, ready.URL, "/admin/assets/endpoints", `{"id":"ep-a","kind":"network","alias":"example-a","address":"a.example.test"}`)
	request(http.MethodPost, ready.URL, "/admin/rules", `{"id":"rule-a","plane":"egress","priority":10,"source":["*"],"destination":["ep-a"],"action":{"access":"deny"}}`)
	check("a.example.test")
	request(http.MethodPost, ready.URL, "/admin/assets/endpoints", `{"id":"ep-a","kind":"network","alias":"example-a","address":"b.example.test"}`)
	check("b.example.test")
	request(http.MethodDelete, ready.URL, "/admin/assets/endpoints/ep-a", "")
	check("")
	stopPoll()
	<-done
	if err := os.WriteFile(filepath.Join(dir, "stop"), []byte("done"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := child.Wait(); err != nil {
		t.Fatalf("CP audit verification: %v; output=%s", err, childOutput.String())
	}
}
