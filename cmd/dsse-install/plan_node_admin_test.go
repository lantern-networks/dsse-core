package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
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
	"sync/atomic"
	"testing"
	"time"
)

func TestThreeNodeAdminNamesRejectOverlongLabelsAndNameCollisions(t *testing.T) {
	p := threeNodesOneRegionPlan()
	p.Regions[0].ID = strings.Repeat("r", 50)
	if err := p.Validate(); err == nil || !strings.Contains(err.Error(), "admin name") {
		t.Fatalf("invalid wildcard label accepted: %v", err)
	}
	p = threeNodesOneRegionPlan()
	p.Regions[0].Machines[1].Portal = "kiri-node-a-edge-a.admin.example.test"
	if err := p.Validate(); err == nil {
		t.Fatal("portal may shadow another Node's admin SNI")
	}
}

func TestThreeNodeAdminOwnersCannotBeForgedBySixAliases(t *testing.T) {
	p := threeNodesOneRegionPlan()
	env, _ := p.MachineEnvironment("node-a")
	var wrongOwner atomic.Bool
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, target := range p.nodeAdminTargets() {
			if r.Host == target.Label+".admin.example.test" {
				machine := target.Machine
				if wrongOwner.Load() {
					machine = "node-a"
				}
				json.NewEncoder(w).Encode(map[string]string{"machine": machine, "role": target.Role, "status": "ok"})
				return
			}
		}
		w.WriteHeader(404)
	}))
	defer s.Close()
	transport := s.Client().Transport.(*http.Transport).Clone()
	transport.TLSClientConfig.ServerName = s.Certificate().DNSNames[0]
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, strings.TrimPrefix(s.URL, "https://"))
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: time.Second}
	var edges, cps []string
	for _, target := range p.nodeAdminTargets() {
		u := "https://" + target.Label + ".admin.example.test"
		if target.Role == "edge" {
			edges = append(edges, u)
		} else {
			cps = append(cps, u)
		}
	}
	if result := verifyNodeAdminOwners(client, env, p.Deployment, edges, strings.Join(cps, ",")); !result.ok {
		t.Fatal(result.note)
	}
	wrongOwner.Store(true)
	if result := verifyNodeAdminOwners(client, env, p.Deployment, edges, strings.Join(cps, ",")); result.ok {
		t.Fatal("six aliases of one machine passed")
	}
	wrongOwner.Store(false)
	for _, invalid := range [][]string{edges[:2], {edges[0], edges[0], edges[2]}, {"https://admin.example.test", edges[1], edges[2]}} {
		if result := verifyNodeAdminOwners(client, env, p.Deployment, invalid, strings.Join(cps, ",")); result.ok {
			t.Fatal("incomplete or shared admin URLs passed")
		}
	}
}

// Exercise the rendered SNI routes, real TLS and real HAProxy on all three
// doors. Replacing private addresses and the bind port is the only lab shim.
func TestThreeNodeAdminAllEighteenRoutesAndOwnerLoss(t *testing.T) {
	checker := threeNodeHAProxyChecker(t)
	p := threeNodesOneRegionPlan()
	work := t.TempDir()
	planPath := filepath.Join(work, "plan.json")
	b, _ := json.Marshal(p)
	if err := os.WriteFile(planPath, b, 0600); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(work, "source")
	installFromPlan(t, planPath, source)
	pair, err := tls.LoadX509KeyPair(filepath.Join(source, "management.crt"), filepath.Join(source, "management.key"))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(beforeFile(t, source, "deployment-anchor.pem"))
	targets := p.nodeAdminTargets()
	servers := map[string]*httptest.Server{}
	for _, target := range targets {
		s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, target.Machine+"/"+target.Role)
		}))
		s.TLS = &tls.Config{Certificates: []tls.Certificate{pair}}
		s.StartTLS()
		t.Cleanup(s.Close)
		servers[target.Label] = s
	}
	var doors []string
	for _, machine := range p.Regions[0].Machines {
		dir := filepath.Join(work, machine.Name)
		os.MkdirAll(dir, 0700)
		env, _ := p.MachineEnvironment(machine.Name)
		os.WriteFile(filepath.Join(dir, "deployment.env"), []byte(PlanEnvironmentFor("", env)), 0600)
		names := planeNamesFor(p.Deployment)
		backends := perNodeAdminBackends(dir, names)
		for _, target := range targets {
			backends = strings.ReplaceAll(backends, target.Address, strings.TrimPrefix(servers[target.Label].URL, "https://"))
		}
		backends = strings.ReplaceAll(backends, "/deployment/deployment-anchor.pem", filepath.Join(source, "deployment-anchor.pem"))
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		front := listener.Addr().String()
		listener.Close()
		doors = append(doors, front)
		config := fmt.Sprintf("global\n    maxconn 64\ndefaults\n    mode tcp\n    timeout connect 300ms\n    timeout check 300ms\n    timeout client 1s\n    timeout server 1s\nfrontend door\n    bind %s\n    tcp-request inspect-delay 1s\n    tcp-request content accept if { req.ssl_hello_type 1 }\n%s%s", front, perNodeAdminRouting(dir, names), backends)
		path := filepath.Join(dir, "test.cfg")
		os.WriteFile(path, []byte(config), 0600)
		if output, err := exec.Command(checker, "-c", "-f", path).CombinedOutput(); err != nil {
			t.Fatalf("invalid config: %v\n%s", err, output)
		}
		cmd := exec.Command(checker, "-db", "-f", path)
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	}
	probe := func(door string, target planNodeAdminTarget) (string, error) {
		transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}, DisableKeepAlives: true,
			DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, door)
			}}
		defer transport.CloseIdleConnections()
		r, err := (&http.Client{Transport: transport, Timeout: 2 * time.Second}).Get("https://" + target.Label + ".admin.example.test/healthz")
		if err != nil {
			return "", err
		}
		defer r.Body.Close()
		b, err := io.ReadAll(r.Body)
		return string(b), err
	}
	for _, door := range doors {
		for _, target := range targets {
			deadline := time.Now().Add(3 * time.Second)
			for {
				body, err := probe(door, target)
				if err == nil && body == target.Machine+"/"+target.Role {
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("%s via %s: %q %v", target.Label, door, body, err)
				}
				time.Sleep(20 * time.Millisecond)
			}
		}
	}
	// Both admin services on one host disappear; its names must never fall
	// back to a surviving host, while the other twelve paths keep working.
	for _, target := range targets {
		if target.Machine == "node-b" {
			servers[target.Label].Close()
		}
	}
	for _, door := range doors {
		for _, target := range targets {
			body, err := probe(door, target)
			if target.Machine == "node-b" {
				if err == nil {
					t.Fatalf("lost owner answered via %s: %q", door, body)
				}
			} else if err != nil || body != target.Machine+"/"+target.Role {
				t.Fatalf("surviving owner failed: %q %v", body, err)
			}
		}
	}
}
