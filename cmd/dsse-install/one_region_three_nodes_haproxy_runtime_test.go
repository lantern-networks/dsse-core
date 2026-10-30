package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
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

// With an installed HAProxy, exercise the generated two-listener health rule
// against real TLS sockets. A syntax-only check cannot show whether the second
// connect actually probes the data port or silently repeats the admin probe.
func TestOneRegionThreeNodesCPDataHealthFollowsBothPorts(t *testing.T) {
	checker := threeNodeHAProxyChecker(t)
	work := t.TempDir()
	planPath := filepath.Join(work, "plan.json")
	planBody, err := json.Marshal(threeNodesOneRegionPlan())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(planPath, planBody, 0o600); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(work, "deployment")
	installFromPlan(t, planPath, dir)
	cert, err := tls.LoadX509KeyPair(filepath.Join(dir, "management.crt"), filepath.Join(dir, "management.key"))
	if err != nil {
		t.Fatal(err)
	}
	anchor, err := os.ReadFile(filepath.Join(dir, "deployment-anchor.pem"))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(anchor) {
		t.Fatal("generated anchor is not a certificate")
	}
	newTLSServer := func(handler http.Handler) *httptest.Server {
		srv := httptest.NewUnstartedServer(handler)
		srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
		srv.StartTLS()
		t.Cleanup(srv.Close)
		return srv
	}
	var adminReady atomic.Bool
	adminReady.Store(true)
	admin := newTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/leader" {
			if adminReady.Load() {
				w.WriteHeader(http.StatusOK)
			} else {
				w.WriteHeader(http.StatusServiceUnavailable)
			}
			return
		}
		http.NotFound(w, r)
	}))
	var dataReady atomic.Bool
	dataReady.Store(true)
	data := newTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" {
			http.NotFound(w, r)
			return
		}
		if !dataReady.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	_, adminPort, err := net.SplitHostPort(admin.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_, dataPort, err := net.SplitHostPort(data.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	front, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	frontAddr := front.Addr().String()
	front.Close()
	name := "admin.kiri.example.test"
	check := strings.Replace(oneRegionThreeNodesCPDataHealth(name), "port 19543", "port "+adminPort, 1)
	config := fmt.Sprintf(`global
    maxconn 32
defaults
    mode tcp
    timeout connect 1s
    timeout check 1s
    timeout client 2s
    timeout server 2s
frontend authority
    bind %s
    default_backend cp_data_plane
backend cp_data_plane
%s    default-server inter 100ms fall 1 rise 1
    server cp-a 127.0.0.1:%s check check-ssl check-sni %s verify required ca-file %s verifyhost %s
`, frontAddr, check, dataPort, name, filepath.Join(dir, "deployment-anchor.pem"), name)
	configPath := filepath.Join(work, "haproxy-runtime.cfg")
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(checker, "-db", "-f", configPath)
	if output, err := exec.Command(checker, "-c", "-f", configPath).CombinedOutput(); err != nil {
		t.Fatalf("runtime test HAProxy config: %v: %s", err, output)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() })
	transport := &http.Transport{
		TLSClientConfig:   &tls.Config{RootCAs: roots, ServerName: name},
		DisableKeepAlives: true,
		DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
			return net.DialTimeout("tcp", frontAddr, time.Second)
		},
	}
	t.Cleanup(transport.CloseIdleConnections)
	client := &http.Client{Transport: transport, Timeout: time.Second}
	probe := func() int {
		resp, err := client.Get("https://" + name + "/healthz")
		if err != nil {
			// A backend taken out of service has no TLS server to relay to.
			// A TLS 503 from the data server is not sufficient for this test.
			return 0
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	waitFor := func(want int) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			if probe() == want {
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
		t.Fatalf("authority backend probe did not become status %d (0 = no TLS backend)", want)
	}
	waitFor(http.StatusOK)
	dataReady.Store(false)
	waitFor(0)
	dataReady.Store(true)
	waitFor(http.StatusOK)
	adminReady.Store(false)
	waitFor(0)
	adminReady.Store(true)
	waitFor(http.StatusOK)
}
