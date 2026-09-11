package edgeplane

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

// Exercise the actual interception listener, including tickets and HTTP reuse.
// Leaf-only verification cannot establish that a client holding an old session
// recovers when the issuing certificate expires during a rotation.
func TestInterceptionRotationPreservesHTTPAndRenewsExpiredClientSession(t *testing.T) {
	for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		for _, h2 := range []bool{false, true} {
			name := tls.VersionName(version) + "/http1"
			if h2 {
				name = tls.VersionName(version) + "/http2"
			}
			t.Run(name, func(t *testing.T) {
				start := time.Now().UTC().Truncate(time.Second)
				var clock atomic.Int64
				clock.Store(start.UnixNano())
				now := func() time.Time { return time.Unix(0, clock.Load()).UTC() }
				eng, err := NewNetworkExtensionLabTLSInterception([]string{"*"}, now)
				if err != nil {
					t.Fatal(err)
				}
				root, rk := boundedInterceptionCA(t, "rotation root", nil, nil, start.Add(-time.Hour), start.Add(24*time.Hour))
				old, oldKey := boundedInterceptionCA(t, "issuing CA", root, rk, start.Add(-time.Minute), start.Add(6*time.Minute))
				if _, err := eng.LoadOfflineTenantIntermediate("rotation_tenant", pemOf(root), pemOf(old), ecKeyPEM(t, oldKey)); err != nil {
					t.Fatal(err)
				}
				var handled atomic.Int64
				eng.httpHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					handled.Add(1)
					_, _ = io.WriteString(w, "inspected")
				})
				ln, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = ln.Close() })
				go func() {
					for {
						conn, err := ln.Accept()
						if err != nil {
							return
						}
						go eng.serve(conn, NetworkExtensionRuntimeCopyTCPRoute{TenantID: "rotation_tenant", Host: "rotation.example.com", Port: 443}, nil)
					}
				}()
				roots := x509.NewCertPool()
				roots.AddCert(root)
				tr := &http.Transport{ForceAttemptHTTP2: h2, TLSClientConfig: &tls.Config{
					RootCAs: roots, ServerName: "rotation.example.com", Time: now,
					MinVersion: version, MaxVersion: version, ClientSessionCache: tls.NewLRUClientSessionCache(4),
				}}
				t.Cleanup(tr.CloseIdleConnections)
				client := &http.Client{Transport: tr, Timeout: 5 * time.Second}
				request := func() *tls.ConnectionState {
					t.Helper()
					resp, err := client.Get("https://" + ln.Addr().String() + "/rotation-check")
					if err != nil {
						t.Fatal(err)
					}
					body, err := io.ReadAll(resp.Body)
					_ = resp.Body.Close()
					if err != nil || resp.StatusCode != 200 || string(body) != "inspected" {
						t.Fatalf("interception handler response: status=%d body=%q err=%v", resp.StatusCode, body, err)
					}
					if (resp.ProtoMajor == 2) != h2 {
						t.Fatalf("wrong HTTP protocol: %s", resp.Proto)
					}
					return resp.TLS
				}
				first := request()
				if first.DidResume {
					t.Fatal("initial handshake resumed")
				}
				tr.CloseIdleConnections()
				if !request().DidResume {
					t.Fatal("control connection did not resume before rotation")
				}
				clock.Store(start.Add(3 * time.Minute).UnixNano())
				next, nextKey := boundedInterceptionCA(t, "issuing CA", root, rk, now().Add(-time.Minute), start.Add(13*time.Minute))
				if _, err := eng.LoadOfflineTenantIntermediate("rotation_tenant", pemOf(root), pemOf(next), ecKeyPEM(t, nextKey)); err != nil {
					t.Fatal(err)
				}
				request() // Existing HTTP connection remains usable during the material swap.
				clock.Store(start.Add(7 * time.Minute).UnixNano())
				tr.CloseIdleConnections()
				last := request()
				if last.DidResume {
					t.Fatal("client reused its expired cached leaf session")
				}
				if len(last.PeerCertificates) < 2 || !bytes.Equal(last.PeerCertificates[1].Raw, next.Raw) {
					t.Fatal("fresh handshake did not receive replacement issuer")
				}
				if handled.Load() != 4 {
					t.Fatalf("requests left interception HTTP handler: %d", handled.Load())
				}
			})
		}
	}
}
