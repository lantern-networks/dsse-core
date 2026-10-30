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
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestOneRegionThreeNodesAdminTLSReturns503WhenNoCPAccepts(t *testing.T) {
	checker := threeNodeHAProxyChecker(t)
	work := t.TempDir()
	plan, _ := json.Marshal(threeNodesOneRegionPlan())
	planPath := filepath.Join(work, "plan.json")
	if err := os.WriteFile(planPath, plan, 0600); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(work, "deployment")
	installFromPlan(t, planPath, dir)
	pair, err := tls.LoadX509KeyPair(filepath.Join(dir, "management.crt"), filepath.Join(dir, "management.key"))
	if err != nil {
		t.Fatal(err)
	}
	anchor, _ := os.ReadFile(filepath.Join(dir, "deployment-anchor.pem"))
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(anchor) {
		t.Fatal("invalid anchor")
	}
	server := func(handler http.Handler) *httptest.Server {
		s := httptest.NewUnstartedServer(handler)
		s.TLS = &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}
		s.StartTLS()
		t.Cleanup(s.Close)
		return s
	}
	var ready [3]atomic.Bool
	ready[0].Store(true)
	addresses := []string{}
	for i := range ready {
		i := i
		s := server(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !ready[i].Load() {
				w.WriteHeader(503)
				return
			}
			w.WriteHeader(200)
		}))
		addresses = append(addresses, s.Listener.Addr().String())
	}
	unavailable := server(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Header().Set("Retry-After", "1"); w.WriteHeader(503) }))
	b, err := os.ReadFile(filepath.Join(dir, "haproxy-edge.cfg"))
	if err != nil {
		t.Fatal(err)
	}
	generated := string(b)
	admin := backendBlock(generated, "cp_admin_plane")
	i := 0
	admin = regexp.MustCompile(`(?m)(    server \S+ )\S+( check)`).ReplaceAllStringFunc(admin, func(line string) string {
		parts := strings.Fields(line)
		out := strings.Replace(line, parts[2], addresses[i], 1)
		i++
		return out
	})
	if i != 3 {
		t.Fatalf("expected three real CPs, got %d", i)
	}
	fallback := backendBlock(generated, "cp_admin_unavailable")
	fallback = strings.ReplaceAll(fallback, "dsse-cp-unavailable:9443", unavailable.Listener.Addr().String())
	fallback = strings.ReplaceAll(fallback, " resolvers containers init-addr last,libc,none resolve-prefer ipv4", "")
	var route string
	for _, line := range strings.Split(generated, "\n") {
		if strings.HasPrefix(line, "    use_backend cp_admin_unavailable if ") {
			route = line
		}
	}
	if route == "" {
		t.Fatal("missing generated refusal route")
	}
	front, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := front.Addr().String()
	front.Close()
	cfg := fmt.Sprintf("global\n    maxconn 32\ndefaults\n    mode tcp\n    timeout connect 1s\n    timeout check 3s\n    timeout client 3s\n    timeout server 3s\nfrontend region\n    bind %s\n    tcp-request inspect-delay 1s\n    tcp-request content accept if { req_ssl_hello_type 1 }\n%s\n    default_backend cp_admin_plane\n%s\n%s\n", addr, route, admin, fallback)
	cfg = strings.ReplaceAll(cfg, "/deployment/deployment-anchor.pem", filepath.Join(dir, "deployment-anchor.pem"))
	path := filepath.Join(work, "runtime.cfg")
	if err = os.WriteFile(path, []byte(cfg), 0600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(checker, "-c", "-f", path).CombinedOutput(); err != nil {
		t.Fatalf("invalid generated refusal route: %v %s", err, out)
	}
	cmd := exec.Command(checker, "-db", "-f", path)
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Process.Wait() })
	name := "admin.kiri.example.test"
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: name}, DisableKeepAlives: true, DialContext: func(context.Context, string, string) (net.Conn, error) {
		return net.DialTimeout("tcp", addr, time.Second)
	}}
	t.Cleanup(transport.CloseIdleConnections)
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	wait := func(want int) {
		t.Helper()
		deadline := time.Now().Add(12 * time.Second)
		for time.Now().Before(deadline) {
			r, err := client.Post("https://"+name+"/admin/vlan-objects", "application/json", strings.NewReader(`{}`))
			if err == nil {
				r.Body.Close()
				if r.StatusCode == want {
					if want == 503 && r.Header.Get("Retry-After") != "1" {
						// A CP's own check is already failing while HAProxy's
						// configured fall window still has it UP. Wait for the
						// actual refusal backend, not that in-progress sample.
						time.Sleep(100 * time.Millisecond)
						continue
					}
					return
				}
			}
			time.Sleep(100 * time.Millisecond)
		}
		t.Fatalf("verified admin TLS did not return %d", want)
	}
	wait(200)
	ready[0].Store(false)
	wait(503)
	ready[1].Store(true)
	wait(200)
}
