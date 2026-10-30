package main

import (
	"bufio"
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

// Real TLS streams through each Region's generated backend retain PROXY client
// metadata. Only local Edges share the load; unhealthy local Edges lose new
// connections without killing live streams.
func TestThreeRegionsMultiEdgeDistributesConnectionsAndWithdrawsFailedEdge(t *testing.T) {
	p := threeRegionsMultiEdgePlan()
	for regionIndex, region := range p.Regions {
		for _, backend := range []string{"edge_fleet", "edge_region_portal"} {
			t.Run(region.ID+"/"+backend, func(t *testing.T) { exerciseDedicatedEdgeDistribution(t, p, regionIndex, backend) })
		}
	}
}

func TestOneRegionMultiEdgeRuntimeDistribution(t *testing.T) {
	for _, backend := range []string{"edge_fleet", "edge_region_portal"} {
		t.Run(backend, func(t *testing.T) { exerciseDedicatedEdgeDistribution(t, oneRegionMultiEdgePlan(), 0, backend) })
	}
}

func exerciseDedicatedEdgeDistribution(t *testing.T, p *Plan, regionIndex int, backend string) {
	checker := threeNodeHAProxyChecker(t)
	work := t.TempDir()
	planPath := filepath.Join(work, "plan.json")
	raw, _ := json.Marshal(p)
	if err := os.WriteFile(planPath, raw, 0600); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(work, "deployment")
	installFromPlan(t, planPath, dir)
	issuerDir := dir
	if regionIndex > 0 {
		cp := p.Regions[regionIndex].controlPlane()
		archive := filepath.Join(work, cp.Name+".tar.gz")
		if err := carryPlanMachine(p, dir, archive, cp.Name); err != nil {
			t.Fatal(err)
		}
		dir = unpackCarry(t, archive)
		if err := applyPlanToThisMachine(p, dir, cp.Name); err != nil {
			t.Fatal(err)
		}
	}
	// Health probes authenticate the transport identity, while browser Portal
	// streams use their separately provisioned browser leaf. In a three-Region
	// plan the transport fallback deliberately covers no Portal name.
	transportPair, err := tls.LoadX509KeyPair(filepath.Join(issuerDir, "transport.crt"), filepath.Join(issuerDir, "transport.key"))
	if err != nil {
		t.Fatal(err)
	}
	ca, err := os.ReadFile(filepath.Join(dir, "deployment-anchor.pem"))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		t.Fatal("invalid anchor")
	}
	dataPair := transportPair
	if backend == "edge_region_portal" {
		portalNames := p.BrowserPortalNames()
		if p.Profile == "three-regions-multi-edge" {
			portalNames = []string{p.regionPortalName(p.Regions[regionIndex].ID)}
		}
		browserCert, browserKey, browserRoot := installerPortalPair(t, portalNames, false)
		dataPair, err = tls.X509KeyPair(browserCert, browserKey)
		if err != nil || !roots.AppendCertsFromPEM(browserRoot) {
			t.Fatal("invalid browser certificate fixture:", err)
		}
	}
	edges := []PlanMachine{}
	for _, m := range p.Regions[regionIndex].Machines {
		if m.Holds.has("edges") {
			edges = append(edges, m)
		}
	}
	if len(edges) < 2 {
		t.Fatal("Region must have at least two Edges")
	}
	ready := make([]atomic.Bool, len(edges))
	health := make([]*httptest.Server, len(edges))
	data := make([]net.Listener, len(edges))
	var proxyErrors atomic.Int32
	var dials atomic.Uint64
	block := backendBlock(deploymentFileContents(t, dir, "haproxy-edge.cfg"), backend)
	if got := strings.Count(block, "    server "); got != len(edges) {
		t.Fatalf("%s backend has %d targets; Region %s has %d local Edges", backend, got, p.Regions[regionIndex].ID, len(edges))
	}
	for i, other := range p.Regions {
		if i == regionIndex {
			continue
		}
		for _, edge := range other.Machines {
			if edge.Holds.has("edges") && strings.Contains(block, edge.reachableAt()+":8443") {
				t.Fatalf("%s backend forwards across Regions to %s", backend, edge.Name)
			}
		}
	}
	for i := range data {
		ready[i].Store(true)
		health[i] = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/healthz" || !ready[i].Load() {
				w.WriteHeader(503)
				return
			}
			w.WriteHeader(200)
		}))
		health[i].TLS = &tls.Config{Certificates: []tls.Certificate{transportPair}}
		health[i].StartTLS()
		t.Cleanup(health[i].Close)
		data[i], err = net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { data[i].Close() })
		go func(i int) {
			for {
				conn, err := data[i].Accept()
				if err != nil {
					return
				}
				go func() {
					defer conn.Close()
					conn.SetDeadline(time.Now().Add(10 * time.Second))
					reader := bufio.NewReader(conn)
					line, err := reader.ReadString('\n')
					if err != nil || !strings.HasPrefix(line, "PROXY TCP4 ") {
						proxyErrors.Add(1)
						return
					}
					secure := tls.Server(&bufferedMultiEdgeTestConn{Conn: conn, reader: reader}, &tls.Config{Certificates: []tls.Certificate{dataPair}, MinVersion: tls.VersionTLS12})
					defer secure.Close()
					if err := secure.Handshake(); err != nil {
						return
					}
					fmt.Fprintf(secure, "edge-%d\n", i)
					io.Copy(secure, secure)
				}()
			}
		}(i)
		_, port, _ := net.SplitHostPort(health[i].Listener.Addr().String())
		original := edges[i].reachableAt() + ":8443"
		if p.oneRegionThreeNodes() && i == 0 {
			original = "dsse-edge-a:8443"
		}
		lines := strings.Split(block, "\n")
		for j, line := range lines {
			if strings.Contains(line, original) {
				lines[j] = strings.Replace(strings.Replace(line, original, data[i].Addr().String(), 1), "port 9443", "port "+port, 1)
			}
		}
		block = strings.Join(lines, "\n")
	}
	// Shorten health polling only; this is selection evidence, not deployed RTO.
	block = strings.ReplaceAll(block, "inter 1s", "inter 100ms")
	block = strings.ReplaceAll(block, "/deployment/deployment-anchor.pem", filepath.Join(dir, "deployment-anchor.pem"))
	block = strings.ReplaceAll(block, " resolvers containers init-addr last,libc,none resolve-prefer ipv4", "")
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	listener.Close()
	config := fmt.Sprintf("global\n    maxconn 64\ndefaults\n    mode tcp\n    timeout connect 1s\n    timeout client 10s\n    timeout server 10s\nfrontend test\n    bind %s\n    default_backend %s\n%s\n", address, backend, block)
	path := filepath.Join(work, "runtime.cfg")
	if err := os.WriteFile(path, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(checker, "-c", "-f", path).CombinedOutput(); err != nil {
		t.Fatalf("HAProxy syntax: %v %s", err, out)
	}
	proc := exec.Command(checker, "-db", "-f", path)
	if err := proc.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { proc.Process.Kill(); proc.Wait() })
	dial := func() (net.Conn, string, error) {
		c, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", address, &tls.Config{RootCAs: roots, ServerName: func() string {
			if backend == "edge_region_portal" {
				return p.edgePortalName(edges[int(dials.Add(1)-1)%len(edges)])
			}
			return p.PlaneNamesFor(p.Regions[regionIndex].ID)["agents"]
		}(), MinVersion: tls.VersionTLS12})
		if err != nil {
			return nil, "", err
		}
		c.SetDeadline(time.Now().Add(2 * time.Second))
		name, err := bufio.NewReader(c).ReadString('\n')
		if err != nil {
			c.Close()
			return nil, "", err
		}
		return c, strings.TrimSpace(name), nil
	}
	counts := map[string]int{}
	var held []net.Conn
	t.Cleanup(func() {
		for _, c := range held {
			c.Close()
		}
	})
	deadline := time.Now().Add(4 * time.Second)
	for len(held) < 3*len(edges) && time.Now().Before(deadline) {
		c, name, err := dial()
		if err != nil {
			time.Sleep(50 * time.Millisecond)
			continue
		}
		held = append(held, c)
		counts[name]++
	}
	if len(held) != 3*len(edges) || len(counts) != len(edges) {
		t.Fatalf("connections not distributed: %v", counts)
	}
	ready[0].Store(false)
	deadline = time.Now().Add(3 * time.Second)
	successes := 0
	for time.Now().Before(deadline) && successes < 8 {
		c, name, err := dial()
		if c != nil {
			c.Close()
		}
		if err == nil && name != "edge-0" {
			successes++
		} else {
			successes = 0
		}
		time.Sleep(50 * time.Millisecond)
	}
	if successes != 8 {
		t.Fatal("new connections still reach the failed Edge")
	}
	for _, c := range held {
		c.SetDeadline(time.Now().Add(time.Second))
		if _, err := c.Write([]byte("x")); err != nil {
			t.Fatal(err)
		}
		b := []byte{0}
		if _, err := io.ReadFull(c, b); err != nil || b[0] != 'x' {
			t.Fatalf("existing stream lost: %v", err)
		}
	}
	if proxyErrors.Load() != 0 {
		t.Fatal("PROXY client metadata missing")
	}
}

type bufferedMultiEdgeTestConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedMultiEdgeTestConn) Read(b []byte) (int, error) { return c.reader.Read(b) }

func TestOneRegionThreeNodesSharedPortalRuntime(t *testing.T) {
	for _, backend := range []string{"edge_fleet", "edge_region_portal"} {
		t.Run(backend, func(t *testing.T) { exerciseDedicatedEdgeDistribution(t, threeNodesOneRegionPlan(), 0, backend) })
	}
}
