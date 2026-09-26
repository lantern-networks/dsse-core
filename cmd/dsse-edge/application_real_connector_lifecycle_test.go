package main

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/tunnel"
)

// Opt-in: build ./cmd/dsse-connector and set DSSE_TEST_CONNECTOR_BIN to its
// absolute path. This exercises the product Connector, not a frame mock.
func TestApplicationLifecycleThroughRealConnector(t *testing.T) {
	binary := os.Getenv("DSSE_TEST_CONNECTOR_BIN")
	if binary == "" {
		t.Skip("set DSSE_TEST_CONNECTOR_BIN to a built product Connector")
	}
	previous := connectorMTLSPresentationRelaxed
	t.Log(setConnectorMTLSPresentationRelaxed(false, true))
	t.Cleanup(func() { connectorMTLSPresentationRelaxed = previous })
	testApplicationDistributionAcrossCPAndEdgeProcesses(t, false, binary)
}

func startApplicationTrafficConnector(t *testing.T, ctx context.Context, binary, dir, edgeURL string, manager *tunnel.Manager) (string, int, func(bool)) {
	t.Helper()
	var hits atomic.Int64
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = io.WriteString(w, "application-through-product-connector")
	}))
	t.Cleanup(backend.Close)
	host, _, err := net.SplitHostPort(backend.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port := backend.Listener.Addr().(*net.TCPAddr).Port
	raw, err := json.Marshal(map[string]any{"applications": []map[string]any{{"application_id": "wiki", "fqdn": host, "destination_port": port}}})
	if err != nil {
		t.Fatal(err)
	}
	routeFile := filepath.Join(dir, "connector-routes.json")
	if err := os.WriteFile(routeFile, raw, 0600); err != nil {
		t.Fatal(err)
	}
	output, err := os.Create(filepath.Join(dir, "connector-process.log"))
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(ctx, binary, "--dev-mode", "--listen", "127.0.0.1:0", "--edge-url", edgeURL, "--connector-id", "conn-test", "--connector-group-id", "site", "--tenant-id", processDistributionTenant, "--connector-secret", "synthetic-application-traffic", "--protected-app-map", routeFile)
	cmd.Stdout, cmd.Stderr = output, output
	if err := cmd.Start(); err != nil {
		output.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait(); _ = output.Close() })
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, ok := manager.Get("conn-test"); ok {
			break
		}
		if time.Now().After(deadline) {
			raw, _ := os.ReadFile(filepath.Join(dir, "connector-process.log"))
			t.Fatalf("product Connector did not establish its tunnel: %s", raw)
		}
		time.Sleep(10 * time.Millisecond)
	}
	client := &http.Client{Timeout: 5 * time.Second}
	check := func(allowed bool) {
		t.Helper()
		for _, query := range []string{"", "?connector_id=conn-test"} {
			before := hits.Load()
			resp, err := client.Get(edgeURL + "/apps/wiki" + query)
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				t.Fatal(err)
			}
			if allowed {
				if resp.StatusCode != http.StatusOK || string(body) != "application-through-product-connector" || hits.Load() != before+1 {
					t.Fatalf("allowed request: status=%d body=%q hits=%d", resp.StatusCode, body, hits.Load()-before)
				}
			} else if resp.StatusCode != http.StatusNotFound || hits.Load() != before {
				t.Fatalf("stopped request: status=%d body=%q backend hits=%d", resp.StatusCode, body, hits.Load()-before)
			}
		}
	}
	return host, port, check
}
