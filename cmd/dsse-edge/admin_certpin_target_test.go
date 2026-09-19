package main

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/assetcatalog"
	"github.com/lantern-networks/dsse-core/edgeplane"
	"github.com/lantern-networks/dsse-core/inspectionposture"
	"github.com/lantern-networks/dsse-core/knownbypass"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/policycandidate"
	"github.com/lantern-networks/dsse-core/policyrule"
)

func TestCertPinRuleRefusesUnsupportedIPv6BeforeSaving(t *testing.T) {
	for _, host := range []string{"2001:0db8::1", "::ffff:192.0.2.1"} {
		t.Run(host, func(t *testing.T) {
			assets := assetcatalog.NewStore()
			rules := policyrule.NewStore()
			c := policycandidate.Candidate{CandidateID: "observed-ip", TenantID: "own", Source: policycandidate.SourceCertPinningDetection, Host: host}
			if err := emitCertPinBypassRule(assets, rules, c); err == nil {
				t.Fatal("unsupported IPv6-only target accepted")
			}
			if len(assets.ListEndpoints("own")) != 0 || len(rules.Snapshot()) != 0 {
				t.Fatal("unsupported target changed dependent state")
			}
		})
	}
}

func TestAdminCertPinTargetsKeepExactScopeAndAuditRisk(t *testing.T) {
	ctx := context.Background()
	tenant := testEvaluator().PolicyBundle.TenantID
	now := time.Now()
	s := policycandidate.NewStore()
	ids := map[string]string{}
	for _, x := range []struct{ host, sni string }{{"203.0.113.7", "sni.example"}, {"198.51.100.10", ""}, {"*.example", ""}, {"2001:0db8::1", ""}, {"::ffff:192.0.2.1", ""}} {
		c, e := s.ObserveCertPinFailure(ctx, tenant, x.host, x.sni, 443, "pin", now)
		if e != nil {
			t.Fatal(e)
		}
		c.Status = "approved"
		c.Confidence = "high"
		c.SuggestedAction = "review"
		c.AttributionSource = "dns_tunnel_correlation"
		s.Upsert(ctx, c, tenant, now)
		ids[x.host] = c.CandidateID
	}
	auth := newAdminAuthStore()
	auth.UpsertPrincipal(adminPrincipal{ID: "actor", TenantID: tenant, Roles: []string{"admin"}, Status: "active"})
	auth.UpsertAPIToken(adminAPIToken{ID: "token", TenantID: tenant, TokenHash: adminTokenHash("target-fixture-token"), Roles: []string{"admin"}, Scopes: []string{"*"}, CreatedByAdminPrincipalID: "actor", Status: "active", ExpiresAt: now.Add(time.Hour).Format(time.RFC3339)})
	writer, e := logs.NewWriter(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	defer writer.Close()
	assets := assetcatalog.NewStore()
	rules := policyrule.NewStore()
	engine := edgeplane.NewNetworkExtensionLabTLSInterceptionMatchOnly([]string{"*"})
	apply := newTenantInspectionApplier(engine, inspectionposture.NewStore(), rules, assets, knownbypass.NewOverrideStore(), func() []knownbypass.Group { return nil }, []string{"*"}, nil)
	apply("")
	h := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Writer: writer, AdminAuth: auth, PolicyCandidateStore: s, AssetStore: assets, RuleStore: rules, NetworkExtensionLabTLS: engine, ApplyMaterializedCertPinBypass: apply})
	statuses := []int{}
	call := func(method, path, body string, status int) map[string]any {
		t.Helper()
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer target-fixture-token")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != status {
			t.Fatalf("%s: %d %s", path, w.Code, w.Body)
		}
		if method == "POST" {
			statuses = append(statuses, status)
		}
		var out map[string]any
		if e := json.Unmarshal(w.Body.Bytes(), &out); e != nil {
			t.Fatal(e)
		}
		return out
	}
	list := call("GET", "/admin/policy-candidates", "", 200)
	for _, row := range list["candidates"].([]any) {
		c := row.(map[string]any)
		if c["host"] == "203.0.113.7" {
			if c["registration_host"] != "sni.example" {
				t.Fatal("SNI projection", c)
			}
		} else if _, ok := c["registration_host"]; ok {
			t.Fatal("unsafe projection", c)
		}
	}
	before, _ := s.List(ctx, tenant, policycandidate.ListOptions{})
	for _, host := range []string{"*", "*.example", "https://named.example", "198.51.100.0/24", "198.51.100.10"} {
		b, _ := json.Marshal(map[string]any{"host": host, "allow_high_risk": true})
		call("POST", "/admin/cert-pin-bypass", string(b), 400)
	}
	after, _ := s.List(ctx, tenant, policycandidate.ListOptions{})
	if !reflect.DeepEqual(before, after) || len(rules.Snapshot()) != 0 || len(assets.ListEndpoints(tenant)) != 0 {
		t.Fatal("invalid registration changed stores")
	}
	materialize := func(host, body string, status int) {
		call("POST", "/admin/policy-candidates/"+ids[host]+"/materialize", body, status)
	}
	materialize("*.example", `{"allow_high_risk":true}`, 400)
	materialize("2001:0db8::1", `{"allow_high_risk":true}`, 400)
	materialize("::ffff:192.0.2.1", `{"allow_high_risk":true}`, 400)
	materialize("198.51.100.10", `{}`, 400)
	after, _ = s.List(ctx, tenant, policycandidate.ListOptions{})
	if !reflect.DeepEqual(before, after) {
		t.Fatal("risk refusal published candidate")
	}
	materialize("203.0.113.7", `{}`, 200)
	for host, want := range map[string]bool{"sni.example": false, "203.0.113.7": true, "child.sni.example": true, "control.invalid": true} {
		if engine.Matches(edgeplane.NetworkExtensionRuntimeCopyTCPRoute{TenantID: tenant, Host: host, Port: 443}) != want {
			t.Fatalf("wrong exact-name scope %s", host)
		}
	}
	materialize("198.51.100.10", `{"allow_high_risk":true}`, 200)
	for host, want := range map[string]bool{"198.51.100.10": false, "198.51.100.11": true} {
		if engine.Matches(edgeplane.NetworkExtensionRuntimeCopyTCPRoute{TenantID: tenant, Host: host, Port: 443}) != want {
			t.Fatalf("wrong exact-IP scope %s", host)
		}
	}
	if !engine.Matches(edgeplane.NetworkExtensionRuntimeCopyTCPRoute{TenantID: "other", Host: "sni.example", Port: 443}) {
		t.Fatal("bypass leaked to other tenant")
	}
	result := call("POST", "/admin/cert-pin-bypass", `{"host":"\u4f8b\u3048.\u30c6\u30b9\u30c8"}`, 200)
	if result["host"] != "xn--r8jz45g.xn--zckzah" {
		t.Fatal("IDNA acknowledgement", result)
	}
	audits := readTransportAudits(t, writer)
	common, domain := 0, 0
	for _, a := range audits {
		if a.TenantID != tenant || stringPtrValue(a.ActorUserID) != "actor" {
			t.Fatal("wrong audit actor", a)
		}
		if a.EventType == "admin_config_change" {
			want := "success"
			if statuses[common] >= 400 {
				want = "error"
			}
			if stringPtrValue(a.Result) != want {
				t.Fatal("wrong common result", a)
			}
			common++
		} else {
			domain++
			if stringPtrValue(a.Result) != "success" {
				t.Fatal(a)
			}
			ip := stringPtrValue(a.TargetID) == ids["198.51.100.10"]
			if a.Metadata["high_risk_override_used"] != ip {
				t.Fatal("risk audit mismatch", a)
			}
		}
	}
	if common != 12 || domain != 3 {
		t.Fatalf("audits common=%d domain=%d", common, domain)
	}
	raw, _ := json.Marshal(audits)
	for _, v := range []string{"target-fixture-token", "198.51.100.10", "sni.example"} {
		if strings.Contains(string(raw), v) {
			t.Fatal("audit disclosed private observation", v)
		}
	}
}
