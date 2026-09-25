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
	"github.com/lantern-networks/dsse-core/appcatalog"
	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/vlan"
)

const networkProcessTenant = "tenant_network_fixture"
const networkProcessToken = "synthetic-network-process-token"

func networkProcessAuth() *adminAuthStore {
	auth := newAdminAuthStore()
	auth.UpsertPrincipal(adminPrincipal{ID: "network-admin", TenantID: networkProcessTenant, Roles: []string{"admin"}, Status: "active"})
	auth.UpsertAPIToken(adminAPIToken{ID: "network-admin", TenantID: networkProcessTenant, TokenHash: adminTokenHash(networkProcessToken),
		Roles: []string{"admin"}, Scopes: []string{"admin.policy.read", "admin.vlan.read", "admin.vlan.write"},
		CreatedByAdminPrincipalID: "network-admin", Status: "active", ExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339)})
	return auth
}

type networkProcessBoot struct {
	ControlPlaneURL string `json:"control_plane_url"`
	PublicKey       string `json:"public_key"`
}

func networkProcessApps(t *testing.T, path string) *appcatalog.Store {
	t.Helper()
	store := appcatalog.NewStore()
	if err := store.SetStatePath(path); err != nil {
		t.Fatal(err)
	}
	return store
}

// This helper runs the product Edge HTTP server and its own background bundle poller in a separate process.
func TestNetworkDistributionEdgeChild(t *testing.T) {
	dir := os.Getenv("DSSE_NETWORK_EDGE_CHILD")
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
	source := &configBundleSource{url: boot.ControlPlaneURL, client: http.DefaultClient, token: networkProcessToken,
		tenantID: networkProcessTenant, interval: 20 * time.Millisecond, verifyPubKeyHex: boot.PublicKey,
		requireSigned: true, status: &configBundleSyncStatus{source: boot.ControlPlaneURL, interval: 20 * time.Millisecond}}
	edge := httptest.NewServer(newServerWithConfig(serverConfig{Evaluator: testEvaluator(), AdminAuth: networkProcessAuth(),
		ApplicationCatalogStore: networkProcessApps(t, filepath.Join(dir, "edge-apps.json")),
		VLANObjectStorePath:     filepath.Join(dir, "edge-vlan.json"), ConfigSourceURL: boot.ControlPlaneURL, ConfigBundleSource: source}))
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

func TestNetworkDistributionAcrossControlPlaneAndEdgeProcesses(t *testing.T) {
	dir := t.TempDir()
	cpPath := filepath.Join(dir, "cp-vlan.json")
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
		AdminAuth: networkProcessAuth(), AdminAuditOutbox: outbox, OperatorTenantID: networkProcessTenant, AgentPolicySigner: signer, VLANObjectStorePath: cpPath,
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
	child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestNetworkDistributionEdgeChild$", "-test.v")
	child.Env = append(os.Environ(), "DSSE_NETWORK_EDGE_CHILD="+dir)
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
		req.Header.Set("Authorization", "Bearer "+networkProcessToken)
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
	objects := func(base string) []model.VLANObject {
		t.Helper()
		var result struct {
			Objects []model.VLANObject `json:"objects"`
		}
		if err := json.Unmarshal(request(http.MethodGet, base, "/admin/vlan-objects", ""), &result); err != nil {
			t.Fatal(err)
		}
		return result.Objects
	}
	waitEdge := func(name, cidr string, want int) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for {
			got := objects(edgeURL)
			if len(got) == want && (want == 0 || got[0].Name == name && len(got[0].CIDRs) == 1 && got[0].CIDRs[0] == cidr) {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("Edge did not apply Network change: %+v; child output: %s", got, output.String())
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	for _, change := range []struct{ name, cidr string }{{"First", "10.81.1.0/24"}, {"Edited", "10.81.2.0/24"}} {
		body := fmt.Sprintf(`{"id":"network-one","name":%q,"class":"server","cidrs":[%q]}`, change.name, change.cidr)
		request(http.MethodPost, cp.URL, "/admin/vlan-objects", body)
		if got := objects(cp.URL); len(got) != 1 || got[0].Name != change.name {
			t.Fatalf("CP save/readback failed: %+v", got)
		}
		waitEdge(change.name, change.cidr, 1)
		for _, path := range []string{cpPath, filepath.Join(dir, "edge-vlan.json")} {
			fresh := vlan.NewStore()
			if err := fresh.SetPersister(blobstore.FilePersister{Path: path}); err != nil {
				t.Fatalf("fresh reload of %s: %v", path, err)
			}
			if got := fresh.ListObjects(); len(got) != 1 || got[0].Name != change.name || len(got[0].CIDRs) != 1 || got[0].CIDRs[0] != change.cidr {
				t.Fatalf("saved Network differs on fresh reload of %s: %+v", path, got)
			}
		}
	}
	request(http.MethodDelete, cp.URL, "/admin/vlan-objects/network-one", "")
	if got := objects(cp.URL); len(got) != 0 {
		t.Fatalf("CP last deletion not visible: %+v", got)
	}
	waitEdge("", "", 0)
	if err := os.WriteFile(filepath.Join(dir, "stop"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := child.Wait(); err != nil {
		t.Fatalf("Edge process failed: %v; output: %s", err, output.String())
	}
	for _, path := range []string{cpPath, filepath.Join(dir, "edge-vlan.json")} {
		fresh := vlan.NewStore()
		if err := fresh.SetPersister(blobstore.FilePersister{Path: path}); err != nil {
			t.Fatalf("fresh reload of %s: %v", path, err)
		}
		if got := fresh.ListObjects(); len(got) != 0 {
			t.Fatalf("last deletion was not durable in %s: %+v", path, got)
		}
	}
	outbox.mu.Lock()
	defer outbox.mu.Unlock()
	if len(outbox.wrapperAudits) != 3 {
		t.Fatalf("CP mutation audit count = %d, want 3", len(outbox.wrapperAudits))
	}
	for i, audit := range outbox.wrapperAudits {
		if audit.EventType != "admin_config_change" || audit.TenantID != networkProcessTenant || audit.Metadata["status_code"] != http.StatusOK {
			t.Fatalf("CP mutation audit %d is incomplete: %+v", i, audit)
		}
	}
}
