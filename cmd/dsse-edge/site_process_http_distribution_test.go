package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
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
	"github.com/lantern-networks/dsse-core/logs"
)

const siteProcessTenant = "tenant_site_fixture"
const siteProcessToken = "synthetic-site-process-token"

func siteProcessAuth() *adminAuthStore {
	auth := newAdminAuthStore()
	auth.UpsertPrincipal(adminPrincipal{ID: "site-admin", TenantID: siteProcessTenant, Roles: []string{"admin"}, Status: "active"})
	auth.UpsertAPIToken(adminAPIToken{ID: "site-admin", TenantID: siteProcessTenant, TokenHash: adminTokenHash(siteProcessToken),
		Roles: []string{"admin"}, Scopes: []string{"admin.policy.read", "admin.connectors.read", "admin.connectors.write"},
		CreatedByAdminPrincipalID: "site-admin", Status: "active", ExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339)})
	return auth
}

// The child owns its HTTP server, Site store, and signed-bundle poller.
func TestSiteDistributionEdgeChild(t *testing.T) {
	dir := os.Getenv("DSSE_SITE_EDGE_CHILD")
	if dir == "" {
		t.Skip("helper process")
	}
	raw, err := os.ReadFile(filepath.Join(dir, "boot.json"))
	if err != nil {
		t.Fatal(err)
	}
	var boot networkProcessBoot
	if err := json.Unmarshal(raw, &boot); err != nil {
		t.Fatal(err)
	}
	source := &configBundleSource{url: boot.ControlPlaneURL, client: http.DefaultClient, token: siteProcessToken,
		tenantID: siteProcessTenant, interval: 20 * time.Millisecond, verifyPubKeyHex: boot.PublicKey,
		requireSigned: true, status: &configBundleSyncStatus{source: boot.ControlPlaneURL, interval: 20 * time.Millisecond}}
	edge := httptest.NewServer(newServerWithConfig(serverConfig{Evaluator: testEvaluator(), AdminAuth: siteProcessAuth(),
		SiteStore:               newDurableAdminSiteStore(filepath.Join(dir, "edge-sites.json")),
		ApplicationCatalogStore: networkProcessApps(t, filepath.Join(dir, "edge-apps.json")),
		ConfigSourceURL:         boot.ControlPlaneURL, ConfigBundleSource: source}))
	defer edge.Close()
	if err := os.WriteFile(filepath.Join(dir, "ready"), []byte(edge.URL), 0o600); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(25 * time.Second)
	for {
		if _, err := os.Stat(filepath.Join(dir, "stop")); err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("parent did not complete before deadline")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestSiteDistributionAcrossControlPlaneAndEdgeProcesses(t *testing.T) {
	dir := t.TempDir()
	cpPath := filepath.Join(dir, "cp-sites.json")
	writer, err := logs.NewWriter(filepath.Join(dir, "logs"))
	if err != nil {
		t.Fatal(err)
	}
	outbox := &recordingAdminAuditOutboxDeadReader{}
	signer, err := agentpolicy.LoadOrGenerateSigner("", true)
	if err != nil {
		t.Fatal(err)
	}
	cp := httptest.NewServer(newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Writer: writer,
		AdminAuth: siteProcessAuth(), AdminAuditOutbox: outbox, OperatorTenantID: siteProcessTenant, AgentPolicySigner: signer,
		SiteStore:               newDurableAdminSiteStore(cpPath),
		ApplicationCatalogStore: networkProcessApps(t, filepath.Join(dir, "cp-apps.json"))}))
	defer cp.Close()
	boot, err := json.Marshal(networkProcessBoot{ControlPlaneURL: cp.URL, PublicKey: signer.PublicKeyHex()})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "boot.json"), boot, 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestSiteDistributionEdgeChild$", "-test.v")
	child.Env = append(os.Environ(), "DSSE_SITE_EDGE_CHILD="+dir)
	var output bytes.Buffer
	child.Stdout, child.Stderr = &output, &output
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if child.ProcessState == nil {
			_ = child.Process.Kill()
			_ = child.Wait()
		}
	}()
	var edgeURL string
	for edgeURL == "" {
		raw, err := os.ReadFile(filepath.Join(dir, "ready"))
		if err == nil {
			edgeURL = string(raw)
		}
		if ctx.Err() != nil {
			t.Fatalf("Edge did not start: %v; output: %s", ctx.Err(), output.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
	request := func(method, base, path, body string) []byte {
		t.Helper()
		req, err := http.NewRequestWithContext(ctx, method, base+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+siteProcessToken)
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
			t.Fatalf("%s %s returned %d (%v): %s", method, path, resp.StatusCode, err, raw)
		}
		return raw
	}
	sites := func(base string) []adminSite {
		t.Helper()
		var result struct {
			Sites []adminSite `json:"sites"`
		}
		if err := json.Unmarshal(request(http.MethodGet, base, "/admin/sites", ""), &result); err != nil {
			t.Fatal(err)
		}
		return result.Sites
	}
	waitEdge := func(name string, count, want int) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for {
			got := sites(edgeURL)
			if len(got) == want && (want == 0 || got[0].Name == name && got[0].ExpectedConnectorCount == count) {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("Edge did not apply Site change: %+v; child output: %s", got, output.String())
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	for _, change := range []struct {
		name  string
		count int
	}{{"First", 2}, {"Edited", 3}} {
		body := fmt.Sprintf(`{"site_id":"site-one","name":%q,"expected_connector_count":%d}`, change.name, change.count)
		request(http.MethodPost, cp.URL, "/admin/sites", body)
		if got := sites(cp.URL); len(got) != 1 || got[0].Name != change.name || got[0].ExpectedConnectorCount != change.count {
			t.Fatalf("CP save/readback failed: %+v", got)
		}
		waitEdge(change.name, change.count, 1)
		for _, path := range []string{cpPath, filepath.Join(dir, "edge-sites.json")} {
			fresh, err := newDurableAdminSiteStore(path).List(context.Background(), siteProcessTenant)
			if err != nil || len(fresh) != 1 || fresh[0].Name != change.name || fresh[0].ExpectedConnectorCount != change.count {
				t.Fatalf("saved Site differs on fresh reload of %s: %+v (%v)", path, fresh, err)
			}
		}
	}
	request(http.MethodDelete, cp.URL, "/admin/sites/site-one", "")
	if got := sites(cp.URL); len(got) != 0 {
		t.Fatalf("CP last deletion not visible: %+v", got)
	}
	waitEdge("", 0, 0)
	if err := os.WriteFile(filepath.Join(dir, "stop"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := child.Wait(); err != nil {
		t.Fatalf("Edge process failed: %v; output: %s", err, output.String())
	}
	for _, path := range []string{cpPath, filepath.Join(dir, "edge-sites.json")} {
		fresh, err := newDurableAdminSiteStore(path).List(context.Background(), siteProcessTenant)
		if err != nil || len(fresh) != 0 {
			t.Fatalf("last deletion was not durable in %s: %+v (%v)", path, fresh, err)
		}
	}
	outbox.mu.Lock()
	defer outbox.mu.Unlock()
	if len(outbox.wrapperAudits) != 3 {
		t.Fatalf("CP mutation audit count = %d, want 3", len(outbox.wrapperAudits))
	}
	for i, audit := range outbox.wrapperAudits {
		if audit.EventType != "admin_config_change" || audit.TenantID != siteProcessTenant || audit.Metadata["status_code"] != http.StatusOK {
			t.Fatalf("CP mutation audit %d is incomplete: %+v", i, audit)
		}
	}
}
