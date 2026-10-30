package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestSharedFleetVerifierMeasuresEveryEntranceOriginAndRefusesBadTLS(t *testing.T) {
	plan := threeNodesOneRegionPlan()
	names := []string{"portal-a.example.test", "portal-b.example.test", "portal-c.example.test"}
	cert, key, ca := installerPortalPair(t, names, false)
	pair, err := tls.X509KeyPair(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		t.Fatal("fixture CA")
	}
	addresses := map[string]string{}
	var handshakes atomic.Int64
	for _, m := range plan.machines() {
		server := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
		server.Config.ErrorLog = log.New(io.Discard, "", 0)
		server.TLS = &tls.Config{Certificates: []tls.Certificate{pair}, GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			if !strings.HasPrefix(hello.ServerName, "portal-") {
				t.Error("probe did not send the planned browser SNI")
			}
			handshakes.Add(1)
			return nil, nil
		}}
		server.StartTLS()
		t.Cleanup(server.Close)
		addresses[net.JoinHostPort(m.reachableAt(), "443")] = server.Listener.Addr().String()
	}
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		target, ok := addresses[address]
		if !ok {
			return nil, errors.New("unplanned target")
		}
		return (&net.Dialer{}).DialContext(ctx, network, target)
	}
	env := map[string]string{"DSSE_STEPUP_PORTAL_ORIGINS": "https://portal-a.example.test,https://portal-b.example.test,https://portal-c.example.test"}
	if result := verifySharedFleetPortalTLS(plan, env, roots, dial); !result.ok || result.skipped || handshakes.Load() != 9 {
		t.Fatalf("did not measure all nine pairs: %+v handshakes=%d", result, handshakes.Load())
	}
	if result := verifySharedFleetPortalTLS(plan, env, x509.NewCertPool(), dial); result.ok || result.skipped {
		t.Fatal("untrusted actual TLS was not a failure")
	}
	plan.Regions[0].Machines[2].Portal = "portal-d.example.test"
	missingSAN := map[string]string{"DSSE_STEPUP_PORTAL_ORIGINS": "https://portal-a.example.test,https://portal-b.example.test,https://portal-d.example.test"}
	if result := verifySharedFleetPortalTLS(plan, missingSAN, roots, dial); result.ok || result.skipped {
		t.Fatal("a browser certificate missing a declared Portal SAN was accepted")
	}
	plan.Regions[0].Machines[2].Portal = "portal-c.example.test"
	badEnv := map[string]string{"DSSE_STEPUP_PORTAL_ORIGINS": "https://portal-a.example.test"}
	if result := verifySharedFleetPortalTLS(plan, badEnv, roots, dial); result.ok || result.skipped {
		t.Fatal("partial Portal set was accepted")
	}
	delete(addresses, net.JoinHostPort(plan.machines()[2].reachableAt(), "443"))
	if result := verifySharedFleetPortalTLS(plan, env, roots, dial); result.ok || result.skipped {
		t.Fatal("missing entrance was not a failure")
	}
	if result := unmeasuredSharedFleetAcceptance(); result.ok || !result.skipped || !strings.Contains(result.note, "mandatory before device admission and release") {
		t.Fatal("unmeasured browser/fault acceptance was promoted to PASS")
	}
}

func TestThreeRegionVerifierChecksOwnPortalAndRejectsForeignOrigins(t *testing.T) {
	plan := threeRegionsMultiEdgePlan()
	roots := x509.NewCertPool()
	addresses := map[string]string{}
	var handshakes atomic.Int64
	for _, region := range plan.Regions {
		cert, key, ca := installerPortalPair(t, []string{plan.regionPortalName(region.ID)}, false)
		pair, err := tls.X509KeyPair(cert, key)
		if err != nil || !roots.AppendCertsFromPEM(ca) {
			t.Fatal("regional certificate fixture:", err)
		}
		server := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
		server.Config.ErrorLog = log.New(io.Discard, "", 0)
		server.TLS = &tls.Config{Certificates: []tls.Certificate{pair}, GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			if !strings.HasPrefix(hello.ServerName, "portal.region-") {
				return nil, errors.New("unplanned Portal SNI")
			}
			handshakes.Add(1)
			return nil, nil
		}}
		server.StartTLS()
		t.Cleanup(server.Close)
		addresses[net.JoinHostPort(region.controlPlane().reachableAt(), "443")] = server.Listener.Addr().String()
	}
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		target, ok := addresses[address]
		if !ok {
			return nil, errors.New("unplanned entrance")
		}
		return (&net.Dialer{}).DialContext(ctx, network, target)
	}
	env := map[string]string{"DSSE_STEPUP_PORTAL_ORIGINS": "https://portal.region-a.dsse.example,https://portal.region-b.dsse.example,https://portal.region-c.dsse.example"}
	if result := verifySharedFleetPortalTLS(plan, env, roots, dial); !result.ok || result.skipped || !strings.Contains(result.note, "3 serving entrance/Portal pairs and refusal on 6 foreign-Region pairs") || handshakes.Load() != 9 {
		t.Fatalf("did not verify local TLS and foreign refusal: %+v handshakes=%d", result, handshakes.Load())
	}
	all := []string{plan.regionPortalName("region-a"), plan.regionPortalName("region-b"), plan.regionPortalName("region-c")}
	cert, key, ca := installerPortalPair(t, all, false)
	pair, err := tls.X509KeyPair(cert, key)
	if err != nil || !roots.AppendCertsFromPEM(ca) {
		t.Fatal("cross-region certificate fixture:", err)
	}
	rogue := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	rogue.Config.ErrorLog = log.New(io.Discard, "", 0)
	rogue.TLS = &tls.Config{Certificates: []tls.Certificate{pair}}
	rogue.StartTLS()
	t.Cleanup(rogue.Close)
	first := net.JoinHostPort(plan.Regions[0].controlPlane().reachableAt(), "443")
	addresses[first] = rogue.Listener.Addr().String()
	if result := verifySharedFleetPortalTLS(plan, env, roots, dial); result.ok || result.skipped {
		t.Fatal("cross-region Portal serving was accepted")
	}
	delete(addresses, net.JoinHostPort(plan.Regions[1].controlPlane().reachableAt(), "443"))
	if result := verifySharedFleetPortalTLS(plan, env, roots, dial); result.ok || result.skipped {
		t.Fatal("missing Region entrance was accepted")
	}
}

func TestInstallerStateJoinPreconditionDoesNotRequireAFencedCP(t *testing.T) {
	p := threeNodesOneRegionPlan()
	steps := p.InstallOrder("/opt/dsse", "plan.json")
	for _, s := range steps {
		if s.Machine == "node-b" && strings.Contains(s.Do, "-start-node") && (!strings.Contains(s.Needs, "CP availability is not required") || strings.Contains(s.Needs, "founding control plane, running")) {
			t.Fatal("join requires a CP that is intentionally fenced until three voters exist")
		}
	}
	if !strings.Contains(steps[3].Why, "until all three planned voting store members join") {
		t.Fatal("bootstrap closure does not explain quorum fencing")
	}
}
