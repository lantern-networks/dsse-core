package main

import (
	"encoding/csv"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Read the effective fall/rise values from a running copy of each generated
// doorway. A backend default-server line can inherit values from defaults, so
// testing for directive text alone does not establish its effective settings.
func checkThreeNodeHAProxyHealthThresholds(t *testing.T, checker, config string, edgeCounts ...int) {
	t.Helper()
	localAddress := func() string {
		t.Helper()
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		address := listener.Addr().String()
		listener.Close()
		return address
	}
	front, stats := localAddress(), localAddress()
	// Bind only loopback test ports and keep all fictional Node health probes
	// local. Backend directives and their thresholds remain as generated.
	config = strings.Replace(config, "    bind :443\n", "    bind "+front+"\n", 1)
	config = strings.NewReplacer("10.20.0.1", "127.0.0.1", "10.20.0.2", "127.0.0.1", "10.20.0.3", "127.0.0.1").Replace(config)
	config += fmt.Sprintf("\nlisten test_health_stats\n    bind %s\n    mode http\n    stats enable\n    stats uri /stats\n", stats)
	path := filepath.Join(t.TempDir(), "haproxy-thresholds.cfg")
	if err := os.WriteFile(path, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(checker, "-db", "-f", path)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() })
	client := &http.Client{Timeout: time.Second}
	defer client.CloseIdleConnections()
	var response *http.Response
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		var err error
		response, err = client.Get("http://" + stats + "/stats;csv")
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if response == nil {
		t.Fatal("generated HAProxy did not expose test statistics")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("HAProxy statistics status = %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		t.Fatal(err)
	}
	reader := csv.NewReader(strings.NewReader(strings.TrimPrefix(string(body), "# ")))
	rows, err := reader.ReadAll()
	if err != nil || len(rows) < 2 {
		t.Fatalf("invalid HAProxy statistics CSV: %v", err)
	}
	column := func(name string) int {
		t.Helper()
		for i, header := range rows[0] {
			if header == name {
				return i
			}
		}
		t.Fatalf("HAProxy statistics lack %q", name)
		return -1
	}
	backend, server, fall, rise := column("pxname"), column("svname"), column("check_fall"), column("check_rise")
	seen := map[string]int{}
	for _, row := range rows[1:] {
		if row[server] == "BACKEND" || row[server] == "FRONTEND" {
			continue
		}
		wantFall, wantRise := "2", "1"
		switch row[backend] {
		case "cp_admin_plane", "cp_data_plane", "console_plane":
		case "edge_fleet":
			wantFall, wantRise = "2", "2"
		default:
			continue
		}
		seen[row[backend]]++
		if row[fall] != wantFall || row[rise] != wantRise {
			t.Errorf("%s/%s effective fall/rise = %s/%s, want %s/%s", row[backend], row[server], row[fall], row[rise], wantFall, wantRise)
		}
	}
	for _, name := range []string{"cp_admin_plane", "cp_data_plane", "console_plane", "edge_fleet"} {
		want := 3
		if name == "edge_fleet" && len(edgeCounts) > 0 {
			want = edgeCounts[0]
		}
		if name != "edge_fleet" && len(edgeCounts) > 1 {
			want = edgeCounts[1]
		}
		if seen[name] != want {
			t.Errorf("checked %d servers for %s, want %d", seen[name], name, want)
		}
	}
}

func TestRegionDoorKeepsLegacyManagementHealthThresholds(t *testing.T) {
	dir := t.TempDir()
	if err := writeRegionFrontDoorConfig(dir, planeNamesFor("example.test")); err != nil {
		t.Fatal(err)
	}
	config := deploymentFileContents(t, dir, "haproxy-edge.cfg")
	if !strings.Contains(config, "    default-server inter 5s fall 3 rise 2\n") {
		t.Fatal("legacy Region doorway lost its default health thresholds")
	}
	for _, name := range []string{"cp_admin_plane", "cp_data_plane", "console_plane"} {
		if strings.Contains(backendBlock(config, name), "inter 2s") {
			t.Fatalf("three-Node management thresholds leaked into legacy %s", name)
		}
		if strings.Contains(backendBlock(config, name), "balance first") || strings.Contains(backendBlock(config, name), "balance roundrobin") {
			t.Errorf("three-Node management balancing leaked into legacy %s", name)
		}
	}
}
