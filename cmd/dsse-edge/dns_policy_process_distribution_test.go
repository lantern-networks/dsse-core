package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
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
	"github.com/lantern-networks/dsse-core/dns"
	"github.com/lantern-networks/dsse-core/dnsresolver"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/policy"
	"github.com/lantern-networks/dsse-core/policyrule"
	"golang.org/x/net/dns/dnsmessage"
)

func TestDNSDistributionCPChild(t *testing.T) {
	dir := os.Getenv("DSSE_DNS_CP_CHILD")
	if dir == "" {
		t.Skip("helper process")
	}
	auth := processDistributionAuth()
	auth.UpsertPrincipal(adminPrincipal{ID: "operator", TenantID: processDistributionTenant, Roles: []string{"admin", "super_admin"}, Status: "active"})
	auth.UpsertAPIToken(adminAPIToken{ID: "operator", TenantID: processDistributionTenant, TokenHash: adminTokenHash(processDistributionToken), Roles: []string{"admin", "super_admin"}, Scopes: []string{"admin.policy.read", "admin.dns.read", "admin.dns.write"}, CreatedByAdminPrincipalID: "operator", Status: "active", ExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339)})
	signer, err := agentpolicy.LoadOrGenerateSigner("", true)
	if err != nil {
		t.Fatal(err)
	}
	writer, err := logs.NewWriter(filepath.Join(dir, "logs"))
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	cp := httptest.NewServer(newServerWithConfig(serverConfig{Evaluator: testEvaluator(), OperatorTenantID: processDistributionTenant, AdminAuth: auth, AgentPolicySigner: signer, Writer: writer, DNSPolicyStorePath: filepath.Join(dir, "dns.json")}))
	defer cp.Close()
	raw, _ := json.Marshal(processDistributionReady{URL: cp.URL, PublicKey: signer.PublicKeyHex()})
	if err := os.WriteFile(filepath.Join(dir, "ready.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(40 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(filepath.Join(dir, "stop")); err == nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("parent did not finish")
}

type dnsDistributionUpstream struct{}

func (dnsDistributionUpstream) Resolve(raw []byte) ([]byte, error) {
	var q dnsmessage.Message
	if err := q.Unpack(raw); err != nil {
		return nil, err
	}
	q.Response = true
	q.RecursionAvailable = true
	q.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: q.Questions[0].Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60}, Body: &dnsmessage.AResource{A: [4]byte{198, 51, 100, 8}}}}
	return q.Pack()
}

func TestDNSAdminChangesReachSeparateEdgeUDP(t *testing.T) {
	dir := t.TempDir()
	logFile, err := os.Create(filepath.Join(dir, "cp.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer logFile.Close()
	cmd := exec.Command(os.Args[0], "-test.run=^TestDNSDistributionCPChild$", "-test.count=1")
	cmd.Env = append(os.Environ(), "DSSE_DNS_CP_CHILD="+dir)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		os.WriteFile(filepath.Join(dir, "stop"), nil, 0600)
		if err := cmd.Wait(); err != nil {
			raw, _ := os.ReadFile(filepath.Join(dir, "cp.log"))
			t.Errorf("CP: %v %s", err, raw)
		}
	}()
	var ready processDistributionReady
	deadline := time.Now().Add(10 * time.Second)
	for ready.URL == "" && time.Now().Before(deadline) {
		raw, _ := os.ReadFile(filepath.Join(dir, "ready.json"))
		_ = json.Unmarshal(raw, &ready)
		time.Sleep(10 * time.Millisecond)
	}
	if ready.URL == "" {
		t.Fatal("CP did not become ready")
	}
	edge := dnsresolver.NewWithUpstream(processDistributionTenant, dnsDistributionUpstream{}, dns.NewConntrackStore())
	conn, err := dnsresolver.StartUDP("127.0.0.1:0", edge)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	source := configBundleSource{url: ready.URL, client: http.DefaultClient, token: processDistributionToken, tenantID: processDistributionTenant, verifyPubKeyHex: ready.PublicKey, requireSigned: true, interval: 20 * time.Millisecond}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		source.run(ctx, configApplyTargets{resolver: edge, policyStore: policy.NewStore(nil), applications: appcatalog.NewStore(), assets: assetcatalog.NewStore(), rules: policyrule.NewStore(), dlp: dlpStoresForTest("dns-process")})
	}()
	defer func() { cancel(); <-done }()
	request := func(method, path, body string) []byte {
		t.Helper()
		req, _ := http.NewRequest(method, ready.URL+path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+processDistributionToken)
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != 200 {
			t.Fatalf("%s %d %s", path, resp.StatusCode, raw)
		}
		return raw
	}
	udpAnswer := func() (string, error) {
		c, err := net.Dial("udp", conn.LocalAddr().String())
		if err != nil {
			return "", err
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(time.Second))
		msg := dnsmessage.Message{Header: dnsmessage.Header{ID: 42, RecursionDesired: true}, Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName("wiki.example.test."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}}
		raw, _ := msg.Pack()
		if _, err := c.Write(raw); err != nil {
			return "", err
		}
		buf := make([]byte, 2048)
		n, err := c.Read(buf)
		if err != nil {
			return "", err
		}
		var reply dnsmessage.Message
		if err := reply.Unpack(buf[:n]); err != nil {
			return "", err
		}
		if reply.RCode == dnsmessage.RCodeNameError {
			return "blocked", nil
		}
		for _, rr := range reply.Answers {
			if a, ok := rr.Body.(*dnsmessage.AResource); ok {
				return net.IP(a.A[:]).String(), nil
			}
		}
		return "", fmt.Errorf("no A answer")
	}
	for _, step := range []struct{ name, body, want string }{
		{"register", `{"stub_ipv4":{"wiki.example.test":"192.0.2.10"}}`, "192.0.2.10"},
		{"edit", `{"stub_ipv4":{"wiki.example.test":"192.0.2.20"}}`, "192.0.2.20"},
		{"block", `{"deny":["wiki.example.test"]}`, "blocked"},
		{"remove-last-rule", `{}`, "198.51.100.8"},
	} {
		request("PUT", "/admin/dns-policy", step.body)
		bundle, err := source.fetch(ctx)
		if err != nil || !bundle.signatureVerified {
			t.Fatalf("signed bundle: %v", err)
		}
		deadline := time.Now().Add(4 * time.Second)
		got := ""
		for time.Now().Before(deadline) {
			got, err = udpAnswer()
			if err == nil && got == step.want {
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
		if got != step.want {
			t.Fatalf("%s DNS=%s want=%s error=%v", step.name, got, step.want, err)
		}
		var displayed dnsresolver.PolicyDTO
		if err := json.Unmarshal(request("GET", "/admin/dns-policy", ""), &displayed); err != nil {
			t.Fatal(err)
		}
		saved, ok := newDNSPolicyStore(filepath.Join(dir, "dns.json")).load()
		if !ok {
			t.Fatal("saved DNS unavailable")
		}
		a, _ := json.Marshal(saved)
		b, _ := json.Marshal(displayed)
		if string(a) != string(b) {
			t.Fatal("CP display differs from saved DNS")
		}
	}
	freshStore := newDNSPolicyStore(filepath.Join(dir, "dns.json"))
	freshResolver := dnsresolver.NewWithUpstream(processDistributionTenant, nil, nil)
	restoreDNSPolicy(freshStore, freshResolver)
	_, authored := freshStore.snapshot(freshResolver)
	if !authored || !freshResolver.CurrentPolicy().IsEmpty() {
		t.Fatal("explicit empty marker did not survive store reload")
	}
}
