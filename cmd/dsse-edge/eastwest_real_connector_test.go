package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/appcatalog"
	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/edgeplane"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/policy"
	"github.com/lantern-networks/dsse-core/tunnel"
)

// Tests SSH-classified TCP authorization with an HTTP byte probe, not an SSH
// login or deployed mTLS. The Connector is a separately built product process.
func TestEastWestLifecycleThroughRealConnector(t *testing.T) {
	binary := os.Getenv("DSSE_TEST_CONNECTOR_BIN")
	if binary == "" {
		t.Skip("set DSSE_TEST_CONNECTOR_BIN to a built product Connector")
	}
	previous := connectorMTLSPresentationRelaxed
	t.Log(setConnectorMTLSPresentationRelaxed(false, true))
	t.Cleanup(func() { connectorMTLSPresentationRelaxed = previous })
	testEastWestDistributionAcrossCPAndEdgeProcesses(t, binary)
}

func startEastWestTrafficConnector(t *testing.T, ctx context.Context, binary, dir, cpURL string, policies *policy.Store) (*httptest.Server, string, func(int, string)) {
	t.Helper()
	var hits, connections atomic.Int64
	backend := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		io.WriteString(w, "eastwest-through-product-connector")
	}))
	backend.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			connections.Add(1)
		}
	}
	backend.Start()
	t.Cleanup(backend.Close)
	host, _, err := net.SplitHostPort(backend.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port := backend.Listener.Addr().(*net.TCPAddr).Port
	manager := tunnel.NewManagerWithRequestTimeout(3 * time.Second)
	writer, err := logs.NewWriter(filepath.Join(dir, "edge-traffic-logs"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { writer.Close() })
	apps := appcatalog.NewStore()
	if _, err := apps.Upsert(ctx, appcatalog.Entry{
		ApplicationID: "wiki", TenantID: processDistributionTenant, Name: "TCP probe", ApplicationType: "private_app",
		ServiceFamily: "ssh", Protocol: "tcp", DestinationRole: "ssh_server", ApplicationSensitivity: "low",
		Destination: host, DestinationPort: port, PublishProtocol: "tcp", ConnectorGroupID: "site", Published: true, Status: "active",
	}, processDistributionTenant, time.Now()); err != nil {
		t.Fatal(err)
	}
	labMode := true
	edge := httptest.NewServer(newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Registry: connector.NewRegistry(), LabMode: &labMode,
		OperatorTenantID: processDistributionTenant, AdminAuth: processDistributionAuth(), PolicyStore: policies, ConfigSourceURL: cpURL,
		ApplicationCatalogStore: apps, TunnelManager: manager, Writer: writer, ConnectorSecret: "synthetic-eastwest-traffic",
		RouteProfiles: map[string]edgeplane.ApplicationRouteProfile{"wiki": {Destination: host, DestinationPort: port, Protocol: "tcp", ServiceFamily: "ssh", DestinationRole: "ssh_server", ApplicationSensitivity: "low"}}}))
	routes, _ := json.Marshal(map[string]any{"applications": []map[string]any{{"application_id": "wiki", "fqdn": host, "destination_port": port}}})
	routePath := filepath.Join(dir, "connector-routes.json")
	if err := os.WriteFile(routePath, routes, 0600); err != nil {
		t.Fatal(err)
	}
	output, err := os.Create(filepath.Join(dir, "connector-traffic.log"))
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(ctx, binary, "--dev-mode", "--listen", "127.0.0.1:0", "--edge-url", edge.URL, "--connector-id", "conn-test", "--connector-group-id", "site", "--tenant-id", processDistributionTenant, "--connector-secret", "synthetic-eastwest-traffic", "--protected-app-map", routePath)
	cmd.Stdout, cmd.Stderr = output, output
	if err := cmd.Start(); err != nil {
		output.Close()
		edge.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait(); output.Close() })
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, ok := manager.Get("conn-test"); ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("Connector tunnel startup timeout")
		}
		time.Sleep(10 * time.Millisecond)
	}
	target, _ := url.Parse(edge.URL)
	check := func(want int, reason string) {
		t.Helper()
		beforeHits, beforeConnections := hits.Load(), connections.Load()
		conn, err := net.DialTimeout("tcp", target.Host, 3*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		fmt.Fprintf(conn, "CONNECT /apps/wiki HTTP/1.1\r\nHost: %s\r\n\r\n", backend.Listener.Addr().String())
		reader := bufio.NewReader(conn)
		resp, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != want {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("CONNECT status=%d want=%d body=%s", resp.StatusCode, want, raw)
		}
		if want != 200 {
			var decision struct {
				ReasonCodes []string `json:"reason_codes"`
			}
			err := json.NewDecoder(resp.Body).Decode(&decision)
			resp.Body.Close()
			if err != nil || !slices.Contains(decision.ReasonCodes, reason) {
				t.Fatalf("denial reasons=%v want=%s error=%v", decision.ReasonCodes, reason, err)
			}
			if hits.Load() != beforeHits || connections.Load() != beforeConnections {
				t.Fatal("denied flow reached backend")
			}
			return
		}
		fmt.Fprint(conn, "GET /probe HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
		app, err := http.ReadResponse(reader, &http.Request{Method: http.MethodGet})
		if err != nil {
			t.Fatal(err)
		}
		raw, err := io.ReadAll(app.Body)
		app.Body.Close()
		if err != nil || app.StatusCode != 200 || string(raw) != "eastwest-through-product-connector" || hits.Load() != beforeHits+1 || connections.Load() != beforeConnections+1 {
			t.Fatalf("TCP probe status=%d body=%q hits=%d connections=%d error=%v", app.StatusCode, raw, hits.Load()-beforeHits, connections.Load()-beforeConnections, err)
		}
	}
	return edge, host, check
}
