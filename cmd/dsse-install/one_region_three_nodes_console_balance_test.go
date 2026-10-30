package main

import (
	"encoding/csv"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestOneRegionThreeNodesConsoleOrderIsStable(t *testing.T) {
	ordered, err := oneRegionThreeNodesConsoleBackends("10.20.0.1:19544,10.20.0.2:19544,10.20.0.3:19544", "console.example.test")
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{
		"10.20.0.3:19544,10.20.0.1:19544,10.20.0.2:19544",
		"10.20.0.2:19544,10.20.0.3:19544,10.20.0.1:19544",
	} {
		got, err := oneRegionThreeNodesConsoleBackends(raw, "console.example.test")
		if err != nil || got != ordered {
			t.Errorf("Console candidates depend on input order: %v\n%s", err, got)
		}
	}
}

// Model two eligible Consoles during health-check overlap. Use the generated
// backend, real TLS listeners and fresh connections through a running HAProxy.
// Speed up only the health interval; this tests selection, not deployed RTO.
func TestOneRegionThreeNodesConsoleSelectsOneCandidateDuringOverlap(t *testing.T) {
	checker := threeNodeHAProxyChecker(t)
	var ready [3]atomic.Bool
	ready[0].Store(true)
	ready[1].Store(true)
	var consoles [3]*httptest.Server
	for i := range consoles {
		name := fmt.Sprintf("console-%d", i+1)
		consoles[i] = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/ready" {
				if ready[i].Load() {
					w.WriteHeader(http.StatusOK)
				} else {
					w.WriteHeader(http.StatusServiceUnavailable)
				}
				return
			}
			fmt.Fprint(w, name)
		}))
		t.Cleanup(consoles[i].Close)
	}
	backend, err := oneRegionThreeNodesConsoleBackends("10.20.0.1:19544,10.20.0.2:19544,10.20.0.3:19544", "console.example.test")
	if err != nil {
		t.Fatal(err)
	}
	for i, server := range consoles {
		backend = strings.ReplaceAll(backend, fmt.Sprintf("10.20.0.%d:19544", i+1), strings.TrimPrefix(server.URL, "https://"))
	}
	backend = strings.Replace(backend, "inter 2s", "inter 100ms", 1)
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
	config := fmt.Sprintf(`global
    maxconn 32
defaults
    mode tcp
    timeout connect 1s
    timeout check 1s
    timeout client 2s
    timeout server 2s
frontend console
    bind %s
    default_backend console_plane
backend console_plane
%s
listen test_console_stats
    bind %s
    mode http
    stats enable
    stats uri /stats
`, front, backend, stats)
	path := filepath.Join(t.TempDir(), "haproxy-console-balance.cfg")
	if err := os.WriteFile(path, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command(checker, "-c", "-f", path).CombinedOutput(); err != nil {
		t.Fatalf("HAProxy rejected the generated Console backend: %v\n%s", err, output)
	}
	cmd := exec.Command(checker, "-db", "-f", path)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() })
	statsClient := &http.Client{Timeout: time.Second}
	defer statsClient.CloseIdleConnections()
	statuses := func() map[string]string {
		response, err := statsClient.Get("http://" + stats + "/stats;csv")
		if err != nil {
			return nil // The process may still be starting.
		}
		defer response.Body.Close()
		rows, err := csv.NewReader(response.Body).ReadAll()
		if err != nil || len(rows) < 2 {
			t.Fatalf("invalid Console statistics CSV: %v", err)
		}
		statusColumn := -1
		for i, header := range rows[0] {
			if header == "status" {
				statusColumn = i
			}
		}
		if statusColumn == -1 {
			t.Fatal("HAProxy statistics lack health status")
		}
		result := map[string]string{}
		for _, row := range rows[1:] {
			if row[0] == "console_plane" {
				result[row[1]] = row[statusColumn]
			}
		}
		return result
	}
	waitFor := func(first string) {
		t.Helper()
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			state := statuses()
			if state["console-1"] == first && state["console-2"] == "UP" && state["console-3"] == "DOWN" {
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Fatalf("Console candidates did not reach %s/UP/DOWN: %v", first, statuses())
	}
	client := consoles[0].Client()
	transport := client.Transport.(*http.Transport).Clone()
	transport.DisableKeepAlives = true
	defer transport.CloseIdleConnections()
	client = &http.Client{Transport: transport, Timeout: time.Second}
	checkConnections := func(want string) {
		t.Helper()
		for i := range 8 {
			response, err := client.Get("https://" + front + "/")
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(response.Body)
			response.Body.Close()
			if err != nil || string(body) != want {
				t.Fatalf("fresh connection %d reached %q, want only %s: %v", i+1, body, want, err)
			}
		}
	}
	waitFor("UP") // Both first and second are UP, as during a transition.
	checkConnections("console-1")
	ready[0].Store(false)
	waitFor("DOWN")
	checkConnections("console-2")
	ready[0].Store(true)
	waitFor("UP")
	checkConnections("console-1")
}
