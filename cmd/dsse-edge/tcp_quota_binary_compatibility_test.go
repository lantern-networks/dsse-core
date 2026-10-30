package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/tunnel"
)

// Opt-in, real retained v0.3.1 and current executable interoperability. All
// destinations are loopback. Server TLS is pinned; no InsecureSkipVerify. Lab
// registration/HMAC is used here, so this is not a production mTLS acceptance test.
func TestTCPQuotaReleasedAndCurrentExecutables(t *testing.T) {
	oldConnector, newConnector := os.Getenv("DSSE_TCP_RELEASED_CONNECTOR"), os.Getenv("DSSE_TCP_CURRENT_CONNECTOR")
	oldEdge, newEdge := os.Getenv("DSSE_TCP_RELEASED_EDGE"), os.Getenv("DSSE_TCP_CURRENT_EDGE")
	if oldConnector == "" || newConnector == "" || oldEdge == "" || newEdge == "" {
		t.Skip("requires four retained/current product executable paths")
	}
	for _, p := range []string{oldConnector, newConnector, oldEdge, newEdge} {
		if !filepath.IsAbs(p) {
			t.Fatal("absolute executable paths required")
		}
	}
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if out := os.Getenv("DSSE_TCP_BINARY_OUTPUT"); out != "" {
		dir, err = os.MkdirTemp(out, "tcp-run-")
		if err != nil {
			t.Fatal(err)
		}
	}
	policyPath, bundlePath := filepath.Join(dir, "policy.json"), filepath.Join(dir, "bundle.json")
	for _, item := range []struct{ sample, target string }{{"policy_lab_https_allow.json", policyPath}, {"policy_bundle_standard.json", bundlePath}} {
		raw, e := os.ReadFile(filepath.Join(root, "samples/phase1", item.sample))
		if e != nil {
			t.Fatal(e)
		}
		var value map[string]any
		if e = json.Unmarshal(raw, &value); e != nil {
			t.Fatal(e)
		}
		value["tenant_id"] = "tenant"
		binaryJSON(t, item.target, value)
	}

	// The httptest fixture certificate is valid for 127.0.0.1 and signed by itself.
	fixture := httptest.NewTLSServer(http.NotFoundHandler())
	pair := fixture.TLS.Certificates[0]
	fixture.Close()
	certPath, keyPath := filepath.Join(dir, "tls.pem"), filepath.Join(dir, "tls.key")
	binaryWrite(t, certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: pair.Certificate[0]}))
	key, err := x509.MarshalPKCS8PrivateKey(pair.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	binaryWrite(t, keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}))
	pool := x509.NewCertPool()
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	pool.AddCert(leaf)
	tlsConfig := &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	backend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	go func() {
		for {
			c, e := backend.Accept()
			if e != nil {
				return
			}
			go func() { defer c.Close(); c.SetDeadline(time.Now().Add(30 * time.Second)); io.Copy(c, c) }()
		}
	}()
	port := backend.Addr().(*net.TCPAddr).Port
	routePath := filepath.Join(dir, "routes.json")
	binaryJSON(t, routePath, map[string]any{"applications": []map[string]any{{"application_id": "ssh", "fqdn": "127.0.0.1", "destination_port": port}}})
	start := func(label, bin string, args ...string) func() {
		t.Helper()
		log, e := os.Create(filepath.Join(dir, label+".log"))
		if e != nil {
			t.Fatal(e)
		}
		cmd := exec.Command(bin, args...)
		cmd.Dir = root
		cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + dir, "TMPDIR=" + os.TempDir()}
		cmd.Stdout, cmd.Stderr = log, log
		if e = cmd.Start(); e != nil {
			log.Close()
			t.Fatal(e)
		}
		stopped := false
		stop := func() {
			if !stopped {
				stopped = true
				cmd.Process.Kill()
				cmd.Wait()
				log.Close()
			}
		}
		t.Cleanup(stop)
		return stop
	}
	frame := func(id string, large bool) tunnel.Frame {
		f := tunnel.Frame{Type: tunnel.FrameTCPOpen, RequestID: id, ApplicationID: "ssh", TenantID: "tenant", Host: "127.0.0.1", Port: port, ConnectTimeoutMillis: 5000, ConcurrentConnectionCap: 1024}
		if large {
			f.ByteCap = 8 << 30
			f.MaxConnectionLifetimeMillis = 8 * 3600000
			f.IdleTimeoutMillis = 3600000
		}
		return f
	}
	exchange := func(s *tunnel.Session, f tunnel.Frame) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		ch, release, res, e := s.OpenTCP(ctx, f)
		if e != nil || res.Error != "" {
			t.Fatalf("actual receiver refused open: %v %s", e, res.Error)
		}
		defer release()
		proof := "quota-wire-proof"
		if e = s.WriteTCPStreamFrame(tunnel.Frame{Type: tunnel.FrameTCPData, RequestID: f.RequestID, Direction: tunnel.TCPDirectionUp, Data: base64.StdEncoding.EncodeToString([]byte(proof))}); e != nil {
			t.Fatal(e)
		}
		select {
		case got := <-ch:
			raw, e := base64.StdEncoding.DecodeString(got.Data)
			if e != nil || string(raw) != proof {
				t.Fatalf("backend echo did not return: type=%s error=%s", got.Type, got.Error)
			}
		case <-ctx.Done():
			t.Fatal("backend echo timed out")
		}
		_ = s.WriteTCPStreamFrame(tunnel.Frame{Type: tunnel.FrameTCPClose, RequestID: f.RequestID, Direction: tunnel.TCPDirectionLocal, CloseReason: tunnel.TCPCloseReasonEOF})
	}
	// Edge sender -> actual old/new Connector. The server advertises only its
	// actual capability; old Connector does not advertise, and receives old bounds.
	for _, version := range []struct {
		name, bin string
		modern    bool
	}{{"released", oldConnector, false}, {"current", newConnector, true}} {
		t.Run("connector-"+version.name, func(t *testing.T) {
			sessions := make(chan *tunnel.Session, 2)
			srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.HasSuffix(r.URL.Path, "/tunnel") {
					c, e := tunnel.UpgradeWithHeaders(w, r, http.Header{tunnel.TCPQuotaCapabilityHeader: []string{tunnel.TCPQuotaCapabilityV1}})
					if e != nil {
						return
					}
					s, _ := tunnel.NewManager().Register("connector", "tunnel", c)
					sessions <- s
					_ = s.Run()
					return
				}
				if strings.HasSuffix(r.URL.Path, "/effective-routes") {
					w.Header().Set("Content-Type", "application/json")
					json.NewEncoder(w).Encode(map[string]any{"cidrs": []string{"127.0.0.1/32"}})
					return
				}
				w.WriteHeader(http.StatusNoContent)
			}))
			srv.TLS = &tls.Config{Certificates: []tls.Certificate{pair}}
			srv.StartTLS()
			defer srv.Close()
			stop := start("connector-"+version.name, version.bin, "-dev-mode", "-listen", "127.0.0.1:0", "-edge-url", srv.URL, "-edge-transport-ca", certPath, "-connector-id", "fixture", "-tenant-id", "tenant", "-connector-secret", "synthetic-quotas", "-protected-app-map", routePath)
			defer stop()
			var s *tunnel.Session
			select {
			case s = <-sessions:
			case <-time.After(15 * time.Second):
				t.Fatal("Connector upgrade timed out")
			}
			defer s.Close()
			f := s.PrepareTCPOpenFrame(frame("default", false))
			if (f.ByteCap == 0) != version.modern {
				t.Fatal("incorrect real Connector capability")
			}
			exchange(s, f)
			exchange(s, frame("explicit-large", true))
		})
	}
	// Actual old/new Edge receiver -> actual old/new Connector -> loopback echo. The
	// sending session uses the real authenticated upgrade response to choose wire.
	for _, version := range []struct {
		name, bin, connector string
		modern               bool
	}{{"released-released", oldEdge, oldConnector, false}, {"released-current", oldEdge, newConnector, false}, {"current-released", newEdge, oldConnector, true}, {"current-current", newEdge, newConnector, true}} {
		t.Run("mesh-"+version.name, func(t *testing.T) {
			addr := binaryAddress(t)
			stopEdge := start("edge-"+version.name, version.bin, "-lab-mode", "-no-control-plane", "-operator-tenant-id", "tenant", "-policy", policyPath, "-bundle", bundlePath, "-schema-dir", filepath.Join(root, "schemas"), "-listen", addr, "-tls-cert", certPath, "-tls-key", keyPath, "-connector-secret", "synthetic-quotas", "-mesh-secret", "synthetic-mesh-quotas", "-log-dir", filepath.Join(dir, "edge-"+version.name), "-drain-period", "50ms")
			defer stopEdge()
			client := &http.Client{Timeout: time.Second, Transport: &http.Transport{TLSClientConfig: tlsConfig.Clone()}}
			defer client.CloseIdleConnections()
			binaryEventually(t, "actual Edge TLS health", func() bool {
				r, e := client.Get("https://" + addr + "/healthz")
				if e != nil {
					return false
				}
				defer r.Body.Close()
				return r.StatusCode == 200
			})
			stopConnector := start("mesh-connector-"+version.name, version.connector, "-dev-mode", "-listen", "127.0.0.1:0", "-edge-url", "https://"+addr, "-edge-transport-ca", certPath, "-connector-id", "fixture", "-tenant-id", "tenant", "-connector-secret", "synthetic-quotas", "-protected-app-map", routePath)
			defer stopConnector()
			// Read this fixture process's own startup record: registration can
			// complete before its WebSocket. No admin authorization is relaxed.
			binaryEventually(t, "real Connector attached", func() bool {
				b, e := os.ReadFile(filepath.Join(dir, "mesh-connector-"+version.name+".log"))
				return e == nil && strings.Contains(string(b), "connector tunnel connected")
			})
			h := http.Header{"x-mesh-secret": []string{"synthetic-mesh-quotas"}, tunnel.TCPQuotaCapabilityHeader: []string{tunnel.TCPQuotaCapabilityV1}}
			signMeshRequest(h, "synthetic-mesh-quotas", nil, time.Now())
			c, e := tunnel.DialTLS(context.Background(), "wss://"+addr+"/mesh/ingress/tunnel", h, tlsConfig.Clone())
			if e != nil {
				t.Fatal(e)
			}
			defer c.Close()
			s, _ := tunnel.NewManager().Register("edge", "mesh", c)
			go s.Run()
			defer s.Close()
			f := s.PrepareTCPOpenFrame(frame("mesh-default", false))
			if (f.ByteCap == 0) != version.modern {
				t.Fatal("incorrect real Edge capability")
			}
			exchange(s, f)
			exchange(s, frame("mesh-explicit-large", true))
		})
	}
}
