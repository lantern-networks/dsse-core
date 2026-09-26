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
	"sync/atomic"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/appcatalog"
	"github.com/lantern-networks/dsse-core/assetcatalog"
	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/policy"
	"github.com/lantern-networks/dsse-core/policyrule"
)

type changingEastWestPolicyStore struct {
	*policy.Store
	changeAfterSnapshot atomic.Bool
}

func (store *changingEastWestPolicyStore) SnapshotTenantConfig(tenant string) policy.TenantConfigBundle {
	cfg := store.Store.SnapshotTenantConfig(tenant)
	if store.changeAfterSnapshot.CompareAndSwap(true, false) {
		store.Store.SetEastWestAllowUnmatched(tenant, true)
	}
	return cfg
}

func TestConfigBundleRefusesEastWestPostureChangedDuringSnapshot(t *testing.T) {
	store := &changingEastWestPolicyStore{Store: policy.NewStore(nil)}
	store.SetEastWestEnabled(processDistributionTenant, true)
	store.SetEastWestAllowUnmatched(processDistributionTenant, false)
	cp := httptest.NewServer(newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Registry: connector.NewRegistry(),
		OperatorTenantID: processDistributionTenant, AdminAuth: processDistributionAuth(),
		ApplicationCatalogStore: appcatalog.NewStore(), PolicyStore: store}))
	defer cp.Close()
	get := func() (int, []byte) {
		t.Helper()
		req, err := http.NewRequest(http.MethodGet, cp.URL+"/admin/config-bundle", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+processDistributionToken)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		return resp.StatusCode, body
	}
	store.changeAfterSnapshot.Store(true)
	if status, body := get(); status != http.StatusServiceUnavailable || !strings.Contains(string(body), "retry") {
		t.Fatalf("mixed-generation bundle status=%d body=%s; want retryable 503", status, body)
	}
	status, body := get()
	if status != http.StatusOK {
		t.Fatalf("stable bundle status=%d body=%s", status, body)
	}
	var bundle configBundlePayload
	if err := json.Unmarshal(body, &bundle); err != nil {
		t.Fatal(err)
	}
	if bundle.TenantConfig == nil || !bundle.TenantConfig.EastWestEnabled || !bundle.TenantConfig.EastWestAllowUnmatched {
		t.Fatalf("stable bundle lost partial posture: %+v", bundle.TenantConfig)
	}
}

// Covers the ordinary Connector Access posture and rule lifecycle through a
// product CP in another OS process and the signed automatic Edge poller.
func TestEastWestDistributionAcrossCPAndEdgeProcesses(t *testing.T) {
	testEastWestDistributionAcrossCPAndEdgeProcesses(t, "")
}

func testEastWestDistributionAcrossCPAndEdgeProcesses(t *testing.T, connectorBinary string) {
	dir := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestApplicationDistributionCPChild$", "-test.v")
	child.Env = append(os.Environ(), "DSSE_DISTRIBUTION_CP_CHILD="+dir, "DSSE_DISTRIBUTION_CP_MODE=eastwest")
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
			t.Fatalf("CP process did not start: %s", childOutput.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
	request := func(method, base, body string) []byte {
		t.Helper()
		req, err := http.NewRequest(method, base+"/admin/east-west", strings.NewReader(body))
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
			t.Fatalf("%s /admin/east-west: status=%d read=%v body=%s", method, resp.StatusCode, err, raw)
		}
		return raw
	}
	edgePolicy := policy.NewStore(nil)
	var edge *httptest.Server
	destination := "internal.example.test"
	var traffic func(int, string)
	if connectorBinary == "" {
		edge = httptest.NewServer(newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Registry: connector.NewRegistry(),
			OperatorTenantID: processDistributionTenant, AdminAuth: processDistributionAuth(), PolicyStore: edgePolicy, ConfigSourceURL: ready.URL}))
	} else {
		edge, destination, traffic = startEastWestTrafficConnector(t, ctx, connectorBinary, dir, ready.URL, edgePolicy)
	}
	defer edge.Close()
	status := &configBundleSyncStatus{source: ready.URL, interval: 20 * time.Millisecond}
	source := configBundleSource{url: ready.URL, client: http.DefaultClient, token: processDistributionToken,
		tenantID: processDistributionTenant, verifyPubKeyHex: ready.PublicKey, requireSigned: true,
		status: status, interval: 20 * time.Millisecond}
	pollCtx, stopPoll := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		source.run(pollCtx, configApplyTargets{applications: appcatalog.NewStore(), assets: assetcatalog.NewStore(),
			rules: policyrule.NewStore(), policyStore: edgePolicy, dlp: dlpStoresForTest("eastwest-process-http")})
	}()
	defer func() { stopPoll(); <-done }()
	check := func(wantMode, wantRuleMode string) {
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
		var got struct {
			Mode  string `json:"mode"`
			Rules []struct {
				ID   string `json:"id"`
				Mode string `json:"mode"`
			} `json:"rules"`
		}
		if err := json.Unmarshal(request(http.MethodGet, edge.URL, ""), &got); err != nil {
			t.Fatal(err)
		}
		if got.Mode != wantMode || len(got.Rules) != boolToInt(wantRuleMode != "") ||
			(wantRuleMode != "" && (got.Rules[0].ID != "rule-ew" || got.Rules[0].Mode != wantRuleMode)) {
			t.Fatalf("Edge HTTP state=%+v, CP=%s bundle=%+v, want posture=%q rule=%q", got,
				request(http.MethodGet, ready.URL, ""), bundle.TenantConfig, wantMode, wantRuleMode)
		}
		for label, store := range map[string]*policy.Store{"Edge live": edgePolicy, "CP durable": func() *policy.Store {
			restored := policy.NewStore(nil)
			if err := restored.SetRuntimeStatePath(filepath.Join(dir, "cp-policy.json")); err != nil {
				t.Fatal(err)
			}
			return restored
		}()} {
			enabled, allow := store.EastWestIsEnabled(processDistributionTenant), store.EastWestAllowsUnmatched(processDistributionTenant)
			rules := store.EastWestRulesFor(processDistributionTenant)
			if enabled != (wantMode != "observe") || (wantMode != "observe" && allow != (wantMode == "partial")) ||
				len(rules) != boolToInt(wantRuleMode != "") ||
				(wantRuleMode != "" && (rules[0].ID != "rule-ew" || rules[0].Mode != wantRuleMode || len(rules[0].Protocols) != 1 || rules[0].Protocols[0] != "ssh")) {
				t.Fatalf("%s state: enabled=%v allow=%v rules=%+v", label, enabled, allow, rules)
			}
		}
	}
	if traffic != nil {
		save := func(body, mode, rule string, code int) {
			request(http.MethodPost, ready.URL, strings.ReplaceAll(body, "internal.example.test", destination))
			check(mode, rule)
			reason := ""
			if code == 403 {
				reason = "east_west_policy_deny"
				if rule == "" {
					reason = "east_west_default_deny"
				}
			}
			traffic(code, reason)
		}
		save(`{"mode":"partial","rules":[{"id":"rule-ew","mode":"deny","destinations":["internal.example.test"],"protocols":["ssh"]}]}`, "partial", "deny", 403)
		save(`{"mode":"observe"}`, "observe", "deny", 200)
		save(`{"mode":"partial"}`, "partial", "deny", 403)
		save(`{"mode":"full","rules":[{"id":"rule-ew","mode":"allow","destinations":["internal.example.test"],"protocols":["ssh"]}]}`, "full", "allow", 200)
		save(`{"rules":[]}`, "full", "", 403)
		save(`{"mode":"observe"}`, "observe", "", 200)
	} else {

		request(http.MethodPost, ready.URL, `{"mode":"partial","rules":[{"id":"rule-ew","mode":"deny","destinations":["internal.example.test"],"protocols":["ssh"]}]}`)
		check("partial", "deny")
		request(http.MethodPost, ready.URL, `{"mode":"full","rules":[{"id":"rule-ew","mode":"allow","destinations":["internal.example.test"],"protocols":["ssh"]}]}`)
		check("full", "allow")
		request(http.MethodPost, ready.URL, `{"mode":"observe"}`)
		check("observe", "allow")
		request(http.MethodPost, ready.URL, `{"mode":"partial"}`)
		check("partial", "allow")
		request(http.MethodPost, ready.URL, `{"rules":[]}`)
		check("partial", "")
		request(http.MethodPost, ready.URL, `{"mode":"observe"}`)
		check("observe", "")
	}
	stopPoll()
	<-done
	if err := os.WriteFile(filepath.Join(dir, "stop"), []byte("done"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := child.Wait(); err != nil {
		t.Fatalf("CP audit verification: %v; output=%s", err, childOutput.String())
	}
}

func boolToInt(v bool) int {
	if v {
		return 1
	}
	return 0
}
