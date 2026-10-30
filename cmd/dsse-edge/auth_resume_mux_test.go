package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/decision"
	devicestore "github.com/lantern-networks/dsse-core/device"
	"github.com/lantern-networks/dsse-core/grantstore"
	"github.com/lantern-networks/dsse-core/idpregistry"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/policy"
)

// This drives CONNECT /steer-mux on the production server. No substitute decision
// callback: initial enrichment, the wait, fresh enrichment and forwarding all run.
func TestAuthResumeProductionMux(t *testing.T) {
	for _, mode := range []string{"missing inventory", "full trust differs", "posture worsens", "policy denies", "upstream dial fails", "single request", "ordinary inventory failure", "remote Edge C via A", "remote Edge C via B"} {
		t.Run(mode, func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			go func() {
				c, e := ln.Accept()
				if e == nil {
					defer c.Close()
					c.Write([]byte("ok"))
				}
			}()
			_, portString, _ := net.SplitHostPort(ln.Addr().String())
			port, _ := strconv.Atoi(portString)
			tenant, device := "auth-resume-test", "resume-device"
			bundle := model.PolicyBundle{TenantID: tenant}
			policies := []model.Policy{{ID: "need-auth", TenantID: tenant, Status: "active", Priority: 1, Conditions: map[string]any{"destination_port": port, "device_trust_level": "managed"}, Action: model.PolicyAction{Decision: "require_reauthentication"}}}
			if mode == "single request" {
				policies[0].Metadata = map[string]any{"max_age_seconds": 0, "grant_ttl_seconds": 15}
			}
			ps := policy.NewStore(policies)
			devices := devicestore.NewStore()
			if mode != "missing inventory" {
				_, err = devices.Register(model.Device{ID: device, TenantID: tenant, DeviceTrustLevel: "noncompliant"}, bundle, time.Now())
				if err != nil {
					t.Fatal(err)
				}
			}
			var deviceSource deviceRuntimeStore = devices
			if mode == "ordinary inventory failure" {
				deviceSource = &authCountingDeviceStore{deviceRuntimeStore: devices, err: errors.New("inventory unavailable")}
				policies[0].Action.Decision = "allow"
				if _, e := ps.Upsert(context.Background(), policies[0], tenant, time.Now()); e != nil {
					t.Fatal(e)
				}
			}
			writer, err := logs.NewWriter(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			cfg := serverConfig{Writer: writer, Evaluator: decision.Evaluator{PolicyBundle: bundle, Policies: policies}, PolicyStore: ps, DeviceStore: deviceSource, ClientlessBaseURL: "https://portal.example", StepUpBindingSecret: "local-test-secret"}
			ingress := ""
			if mode == "remote Edge C via A" || mode == "remote Edge C via B" {
				ingress = "a"
				if mode == "remote Edge C via B" {
					ingress = "b"
				}
				cfg.ClientlessBaseURL = "https://portal-c.example"
				cfg.StepUpPortalOrigins = "https://portal-a.example,https://portal-b.example,https://portal-c.example"
				cfg.EntrancePortalOrigins = `{"agents-a.example":"https://portal-a.example","agents-b.example":"https://portal-b.example","agents-c.example":"https://portal-c.example"}`
			}
			handler := newServerWithConfig(cfg)
			registry := theIdPRegistry.Load()
			provider, err := registry.Upsert(idpregistry.Connection{IdPID: "corp", TenantID: tenant, Type: "oidc", Issuer: "https://idp.example", AuthorizationEndpoint: "https://idp.example/auth", ClientID: "client", VerifiedDomains: []string{"example"}})
			if err != nil {
				t.Fatal(err)
			}
			provider = authTestAssign(t, registry, tenant, device, "user", "corp")
			req := httptest.NewRequest(http.MethodConnect, "/steer-mux", nil)
			cert := leafWithCN(t, device)
			req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}, VerifiedChains: [][]*x509.Certificate{{cert}}}
			if ingress != "" {
				req.TLS.ServerName = "agents-" + ingress + ".example"
			}
			req.Header.Set(postureHeaderEncryption, "true")
			req.Header.Set(postureHeaderFirewall, "true")
			w := newHijackableCONNECTResponseWriter()
			defer w.close()
			done := make(chan struct{})
			go func() { defer close(done); handler.ServeHTTP(w, req) }()
			defer func() {
				w.close()
				select {
				case <-done:
				case <-time.After(time.Second):
					t.Error("mux did not finish")
				}
			}()
			w.clientConn.SetDeadline(time.Now().Add(5 * time.Second))
			reader := bufio.NewReader(w.clientConn)
			response, err := http.ReadResponse(reader, req)
			if err != nil {
				t.Fatal(err)
			}
			if response.StatusCode != 200 {
				t.Fatal(response.StatusCode)
			}
			if err = authTestFrame(w.clientConn, 1, 0, []byte(ln.Addr().String()+"\x00u=alice a=local-test op="+testAuthPrincipal+" ls="+testAuthSession)); err != nil {
				t.Fatal(err)
			}
			readFrame := func() (byte, []byte) {
				t.Helper()
				h := make([]byte, 9)
				if _, e := io.ReadFull(reader, h); e != nil {
					t.Fatal(e)
				}
				n := binary.BigEndian.Uint32(h[5:])
				if n > 16384 {
					t.Fatal("oversize")
				}
				b := make([]byte, n)
				if _, e := io.ReadFull(reader, b); e != nil {
					t.Fatal(e)
				}
				return h[4], b
			}
			if mode == "ordinary inventory failure" {
				// The mux stays reachable, but the flow must not reach the upstream
				// while device risk/posture cannot be read. The flow may end with
				// a CLOSE frame or a closed virtual connection.
				_ = w.clientConn.SetReadDeadline(time.Now().Add(time.Second))
				header := make([]byte, 9)
				if _, readErr := io.ReadFull(reader, header); readErr == nil && header[4] == 1 {
					t.Fatal("ordinary flow reached upstream during inventory outage")
				}
				return
			}
			kind, startData := readFrame()
			if kind != 3 {
				t.Fatalf("expected STEPUP, got %d", kind)
			}
			if ingress != "" {
				start, e := url.Parse(string(startData))
				if e != nil || start.Host != "portal-"+ingress+".example" || start.Query().Get("portal_origin") != "https://portal-"+ingress+".example:443" {
					t.Fatal("remote Edge selected its own stopped entrance instead of the actual ingress")
				}
			}
			if mode == "upstream dial fails" {
				_ = ln.Close()
			}
			if mode == "posture worsens" {
				no := false
				deviceRuntime.ingestFromReport(device, tenant, "", &no, &no, "test", "", time.Now().Add(time.Second))
			}
			if mode == "policy denies" {
				policies[0].Action.Decision = "deny"
				if _, e := ps.Upsert(context.Background(), policies[0], tenant, time.Now()); e != nil {
					t.Fatal(e)
				}
			}
			candidate := grantstore.Grant{GrantID: "resume-grant", TenantID: tenant, UserID: "user", DeviceID: device, IdPID: provider.IdPID, Issuer: provider.Issuer, OSPrincipal: testAuthPrincipal, OSSession: testAuthSession, ProviderConfigSHA256: authEvidenceForOwner(provider, device, testAuthPrincipal, testAuthSession), Scope: ln.Addr().String()}
			if mode == "single request" {
				start, _ := url.Parse(string(startData))
				if start.Query().Get("grant_ttl") != "15" {
					t.Fatal("production mux lost the policy lifetime cap")
				}
				candidate.AuthenticationRequestID = start.Query().Get("request_id")
				candidate.AuthTime = time.Now().UTC().Format(time.RFC3339)
				candidate.ReauthenticationStartedAt = candidate.AuthTime
			}
			_, err = theGrantStore.Load().Mint(candidate, time.Minute, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			wantResult := "resumed"
			if mode == "posture worsens" || mode == "policy denies" || mode == "upstream dial fails" {
				wantResult = "not_resumed"
			}
			var outcome struct {
				RequestID string `json:"request_id"`
				Result    string `json:"result"`
			}
			start, _ := url.Parse(string(startData))
			var sawResult, sawData, sawClose bool
			for i := 0; i < 4 && !(sawResult && (wantResult == "resumed" && sawData || wantResult == "not_resumed" && sawClose)); i++ {
				kind, data := readFrame()
				switch kind {
				case 5:
					if sawResult || json.Unmarshal(data, &outcome) != nil || outcome.RequestID != start.Query().Get("request_id") || outcome.Result != wantResult {
						t.Fatalf("unexpected authenticated-flow result: %+v", outcome)
					}
					sawResult = true
				case 1:
					if wantResult != "resumed" || string(data) != "ok" {
						t.Fatalf("invalid held flow data: %q", data)
					}
					sawData = true
				case 2:
					sawClose = true
				default:
					t.Fatalf("unexpected held flow frame: kind=%d", kind)
				}
			}
			if !sawResult || wantResult == "resumed" && !sawData || wantResult == "not_resumed" && !sawClose {
				t.Fatalf("incomplete held flow: result=%v data=%v close=%v", sawResult, sawData, sawClose)
			}
			if mode == "single request" {
				saved, ok := theGrantStore.Load().Get("resume-grant")
				if !ok || !saved.Revoked {
					t.Fatal("production forwarding did not consume grant")
				}
				if err = authTestFrame(w.clientConn, 2, 0, []byte(ln.Addr().String()+"\x00u=alice a=local-test op="+testAuthPrincipal+" ls="+testAuthSession)); err != nil {
					t.Fatal(err)
				}
				kind, _ = readFrame()
				if kind == 2 {
					kind, _ = readFrame()
				} // closure of first flow may precede notification
				if kind != 3 {
					t.Fatal("second flow reused authentication", kind)
				}
			}

		})
	}
}
