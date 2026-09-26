package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/lantern-networks/dsse-core/dnsresolver"
	"github.com/lantern-networks/dsse-core/policy"
)

func TestDNSPolicyRejectedSaveKeepsLiveAndRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dns.json")
	store := newDNSPolicyStore(path)
	resolver := dnsresolver.NewWithUpstream("tenant", nil, nil)
	mux := http.NewServeMux()
	registerDNSPolicyRoutes(mux, func(_ string, h http.HandlerFunc) http.HandlerFunc { return h }, resolver, store, "")
	put := func(body string) *httptest.ResponseRecorder {
		r := httptest.NewRecorder()
		mux.ServeHTTP(r, httptest.NewRequest("PUT", "/admin/dns-policy", strings.NewReader(body)))
		return r
	}
	if r := put(`{"deny":["blocked.example.test"]}`); r.Code != 200 {
		t.Fatal(r.Code, r.Body.String())
	}
	before := dnsresolver.PolicyToDTO(resolver.CurrentPolicy())
	gen := resolver.ConfigGeneration()
	// A directory at the staging-file path deterministically rejects writes without OS permission assumptions.
	if err := os.Mkdir(path+".tmp", 0700); err != nil {
		t.Fatal(err)
	}
	r := put(`{"stub_ipv4":{"wiki.example.test":"192.0.2.25"}}`)
	if r.Code != 503 {
		t.Fatalf("rejected save returned %d: %s", r.Code, r.Body.String())
	}
	if strings.Contains(r.Body.String(), path) {
		t.Fatal("storage path exposed")
	}
	if !reflect.DeepEqual(before, dnsresolver.PolicyToDTO(resolver.CurrentPolicy())) || gen != resolver.ConfigGeneration() {
		t.Fatal("rejected save changed DNS or generation")
	}
	fresh := dnsresolver.NewWithUpstream("tenant", nil, nil)
	restoreDNSPolicy(newDNSPolicyStore(path), fresh)
	if !reflect.DeepEqual(before, dnsresolver.PolicyToDTO(fresh.CurrentPolicy())) {
		t.Fatal("restart lost prior DNS")
	}
	if err := os.Remove(path + ".tmp"); err != nil {
		t.Fatal(err)
	}
	if r := put(`{"stub_ipv4":{"wiki.example.test":"192.0.2.25"}}`); r.Code != 200 {
		t.Fatal(r.Code, r.Body.String())
	}
	restoreDNSPolicy(newDNSPolicyStore(path), fresh)
	if !reflect.DeepEqual(dnsresolver.PolicyToDTO(resolver.CurrentPolicy()), dnsresolver.PolicyToDTO(fresh.CurrentPolicy())) {
		t.Fatal("retry not saved")
	}
}

func TestDNSPolicyExplicitEmptyReplacesButLegacyEmptyDoesNot(t *testing.T) {
	for _, authoritative := range []bool{false, true} {
		r := dnsresolver.NewWithUpstream("tenant", nil, nil)
		p, _ := dnsresolver.PolicyFromDTO(dnsresolver.PolicyDTO{Deny: []string{"blocked.example.test"}})
		r.SetPolicy(p)
		raw, _ := json.Marshal(map[string]any{"dns_policy": map[string]any{}, "dns_policy_authoritative": authoritative})
		var payload configBundlePayload
		if err := json.Unmarshal(raw, &payload); err != nil {
			t.Fatal(err)
		}
		_, err := (configBundleSource{tenantID: "tenant"}).apply(payload, configApplyTargets{resolver: r, policyStore: policy.NewStore(nil)})
		if err != nil {
			t.Fatal(err)
		}
		if r.CurrentPolicy().IsEmpty() != authoritative {
			t.Fatalf("explicit empty=%v did not apply correctly", authoritative)
		}
	}
}

func TestAdminDNSPolicyConcurrentDurableReplacement(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dns.json")
	handler := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), AdminAuth: newAdminAuthStore(), DNSPolicyStorePath: path})
	var wg sync.WaitGroup
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			name := fmt.Sprintf("blocked-%d.example", i)
			req := httptest.NewRequest("PUT", "/admin/dns-policy", strings.NewReader(fmt.Sprintf(`{"deny":["%s"]}`, name)))
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != 200 {
				t.Errorf("write %d: %d", i, rec.Code)
				return
			}
			var dto struct {
				Deny []string `json:"deny"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &dto); err != nil || !reflect.DeepEqual(dto.Deny, []string{name}) {
				t.Errorf("response does not acknowledge its own request: %s", rec.Body.String())
			}
		}(i)
	}
	wg.Wait()
	saved, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest("GET", "/admin/dns-policy", nil))
	var disk, live dnsresolver.PolicyDTO
	if err := json.Unmarshal(saved, &disk); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &live); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(disk, live) {
		t.Fatal("last saved and live policies diverged")
	}
}
