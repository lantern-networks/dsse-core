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
	"reflect"
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
	"github.com/lantern-networks/dsse-core/swg"
	"github.com/lantern-networks/dsse-core/swghttprewrite"
	"github.com/lantern-networks/dsse-core/tenantrestriction"
)

func TestSaaSDistributionAcrossCPAndEdgeProcesses(t *testing.T) {
	dir := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestApplicationDistributionCPChild$", "-test.v")
	child.Env = append(os.Environ(), "DSSE_DISTRIBUTION_CP_CHILD="+dir, "DSSE_DISTRIBUTION_CP_MODE=saas")
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
		req, err := http.NewRequest(method, base+"/admin/swg/tenant-restriction", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+processDistributionToken)
		req.Header.Set("X-Operate-Tenant", processDistributionTenant)
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
			t.Fatalf("%s /admin/swg/tenant-restriction: status=%d read=%v body=%s", method, resp.StatusCode, err, raw)
		}
		return raw
	}
	edgePolicy := policy.NewStore(nil)
	edge := httptest.NewServer(newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Registry: connector.NewRegistry(),
		OperatorTenantID: processDistributionTenant, AdminAuth: processDistributionAuth(),
		PolicyStore: edgePolicy, ConfigSourceURL: ready.URL}))
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
			rules: policyrule.NewStore(), policyStore: edgePolicy, dlp: dlpStoresForTest("saas-process-http")})
	}()
	defer func() { stopPoll(); <-done }()
	rawFixture, err := os.ReadFile(filepath.Join("..", "..", "swghttprewrite", "testdata", "swg_saas_tenant_enforcement_preflight.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		PolicyBundle model.PolicyBundle `json:"policy_bundle"`
		Fixtures     []struct {
			Request model.DecisionRequest `json:"request"`
		} `json:"fixtures"`
	}
	if err := json.Unmarshal(rawFixture, &fixture); err != nil {
		t.Fatal(err)
	}
	fixture.PolicyBundle.SaaSCatalog = nil
	fixture.PolicyBundle.SWGTenantRestrictionRules = nil
	fixture.PolicyBundle.SWGTLSBypassRules = nil
	expected := map[string]tenantrestriction.Setting{}
	capture := make(chan http.Header, 1)
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { capture <- r.Header.Clone(); w.WriteHeader(204) }))
	defer upstream.Close()
	for _, provider := range tenantrestriction.Providers() {
		first, second := "one.example", "two.example"
		switch provider.ID {
		case "anthropic_claude":
			first = "11111111-1111-4111-8111-111111111111"
			second = "33333333-3333-4333-8333-333333333333"
		case "openai_chatgpt":
			first = "wsp_Example123"
			second = "wsp_Example456"
		}
		for step := 0; step < 4; step++ {
			enabled := step != 2
			value := second
			if step == 0 {
				value = first
			}
			patch := map[string]any{"provider": provider.ID, "enabled": enabled}
			if step < 2 {
				patch["allowed_value"] = value
				if provider.ID == "microsoft_365" {
					patch["context_tenant_id"] = "22222222-2222-4222-8222-222222222222"
				}
			}
			setting := tenantrestriction.Setting{AllowedValue: value, Enabled: enabled}
			if provider.ID == "microsoft_365" {
				setting.ContextTenantID = "22222222-2222-4222-8222-222222222222"
			}
			expected[provider.ID] = setting
			body, _ := json.Marshal(patch)
			request(http.MethodPost, ready.URL, string(body))
			bundle, err := source.fetch(ctx)
			if err != nil || !bundle.signatureVerified {
				t.Fatalf("signed bundle: %v", err)
			}
			deadline := time.Now().Add(4 * time.Second)
			for time.Now().Before(deadline) {
				snap := status.snapshot()
				if snap["have_applied"] == true && snap["last_applied_generation"].(uint64) >= bundle.Generation {
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			if !reflect.DeepEqual(edgePolicy.SnapshotTenantConfig(processDistributionTenant).SaaSTenantRestrictions, expected) {
				t.Fatalf("%s step%d Edge state differs", provider.ID, step)
			}
			fresh := policy.NewStore(nil)
			if err := fresh.SetRuntimeStatePath(filepath.Join(dir, "cp-policy.json")); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(fresh.SnapshotTenantConfig(processDistributionTenant).SaaSTenantRestrictions, expected) {
				t.Fatal("CP fresh file read differs")
			}
			for _, base := range []string{ready.URL, edge.URL} {
				var got struct {
					Rules []struct {
						Provider string
						Active   bool
					}
				}
				response := request(http.MethodGet, base, "")
				if err := json.Unmarshal(response, &got); err != nil {
					t.Fatal(err)
				}
				found := false
				for _, r := range got.Rules {
					if r.Provider == provider.ID {
						found = true
						if r.Active != enabled {
							t.Fatalf("%s step%d status active=%v", provider.ID, step, r.Active)
						}
					}
				}
				if !found {
					t.Fatal("provider status absent")
				}
				if bytes.Contains(response, []byte(value)) {
					t.Fatal("public status exposed allowed value")
				}
			}
			ev := edgePolicy.RuntimeEvaluator(decision.Evaluator{PolicyBundle: fixture.PolicyBundle})
			req := fixture.Fixtures[0].Request
			req.TenantID = processDistributionTenant
			req.FQDN = provider.Hosts[0]
			req.SNI = provider.Hosts[0]
			req.Destination = provider.Hosts[0]
			dec := ev.Evaluate(req)
			if dec.Decision != "allow" {
				t.Fatalf("%s step%d decision=%s", provider.ID, step, dec.Decision)
			}
			httpReq, _ := http.NewRequest("GET", upstream.URL, nil)
			rewritten, result, err := rewriteEdgeSWGHTTPRequest(httpReq, dec, swg.RuntimeConfig{}, swghttprewrite.HeaderValueMap(ev.TenantRestrictionHeaderValues))
			if err != nil || result.HeaderApplied != enabled {
				t.Fatalf("%s step%d rewrite=%v err=%v", provider.ID, step, result, err)
			}
			resp, err := upstream.Client().Do(rewritten)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			headers := <-capture
			want := ""
			if enabled {
				want = value
			}
			if headers.Get(provider.Header) != want {
				t.Fatalf("%s step%d header mismatch", provider.ID, step)
			}
			if provider.ID == "microsoft_365" {
				wantContext := ""
				if enabled {
					wantContext = setting.ContextTenantID
				}
				if headers.Get("Restrict-Access-Context") != wantContext {
					t.Fatal("M365 context differs")
				}
			}
			if len(edgePolicy.SnapshotTenantConfig("other").SaaSTenantRestrictions) != 0 {
				t.Fatal("another tenant inherited settings")
			}
		}
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
