package edgeplane

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/tunnel"
)

// Exercise admission with both production open-frame builders. Short, completed
// requests would not expose a limit that incorrectly rejects the 33rd live flow.
func TestProductionConnectorOpensDoNotImposeLegacyConcurrencyLimit(t *testing.T) {
	for name, limits := range map[string]EdgeTCPConnectLimits{
		"published application": defaultEdgeTCPConnectLimits(),
		"steered and relayed":   InteractiveEastWestEdgeTCPConnectLimits(),
	} {
		t.Run(name, func(t *testing.T) {
			registry := tunnel.NewTCPConnectionRegistry()
			now := time.Now()
			makeFrame := func(index int) tunnel.Frame {
				t.Helper()
				frame, err := EdgeTCPOpenFrameForTarget(fmt.Sprintf("held-%d", index), EdgeTCPConnectTarget{ApplicationID: "app", Host: "private.internal", Port: 443}, limits)
				if err != nil {
					t.Fatal(err)
				}
				return frame
			}
			const simultaneous = 2048
			for i := 0; i < simultaneous; i++ {
				if err := registry.Open(makeFrame(i), now); err != nil {
					t.Fatalf("stream %d hit an implicit capacity limit: %v", i+1, err)
				}
			}
			if registry.Count() != simultaneous {
				t.Fatal("not all streams were held together")
			}
			if _, err := registry.Close("held-0", tunnel.TCPDirectionLocal, tunnel.TCPCloseReasonEOF, now); err != nil {
				t.Fatal(err)
			}
			if err := registry.Open(makeFrame(simultaneous), now); err != nil {
				t.Fatalf("closed slot was not reusable: %v", err)
			}
		})
	}
}

func TestConnectorStreamBudgetsRequireExplicitOperatorConfiguration(t *testing.T) {
	for _, name := range []string{"DSSE_TCP_STREAM_MAX_BYTES", "DSSE_TCP_STREAM_MAX_LIFETIME_SECONDS", "DSSE_TCP_STREAM_IDLE_TIMEOUT_SECONDS"} {
		t.Setenv(name, "")
	}
	limits := InteractiveEastWestEdgeTCPConnectLimits()
	if limits.ByteCap != 0 || limits.IdleTimeoutMillis != 0 || limits.MaxConnectionLifetimeMillis != 0 {
		t.Fatal("default stream quotas must be disabled")
	}
	t.Setenv("DSSE_TCP_STREAM_MAX_BYTES", "8589934592")
	t.Setenv("DSSE_TCP_STREAM_MAX_LIFETIME_SECONDS", "86400")
	t.Setenv("DSSE_TCP_STREAM_IDLE_TIMEOUT_SECONDS", "7200")
	limits = InteractiveEastWestEdgeTCPConnectLimits()
	if limits.ByteCap != 8<<30 || limits.MaxConnectionLifetimeMillis != 86400000 || limits.IdleTimeoutMillis != 7200000 {
		t.Fatal("explicit operator values were clamped")
	}
	if _, err := EdgeTCPOpenFrameForTarget("operator", EdgeTCPConnectTarget{ApplicationID: "app", Host: "private.internal", Port: 443}, limits); err != nil {
		t.Fatal(err)
	}
}

func TestEdgeTCPOpenFrameForTargetRejectsMissingLimits(t *testing.T) {
	limits := validEdgeTCPConnectLimits()
	limits.ByteCap = -1
	_, err := EdgeTCPOpenFrameForTarget("req_tcp_001", EdgeTCPConnectTarget{
		ApplicationID: "app_dummy_https",
		Host:          "route-profile.internal",
		Port:          8443,
		ServiceFamily: "https",
	}, limits)
	if err == nil {
		t.Fatal("EdgeTCPOpenFrameForTarget returned nil error")
	}
	if !strings.Contains(err.Error(), "byte_cap") {
		t.Fatalf("error = %q, want byte_cap", err.Error())
	}
}

func TestEdgeTCPConnectOpenFrameForRequestUsesConnectAuthority(t *testing.T) {
	routeProfiles := map[string]ApplicationRouteProfile{
		"app_dummy_https": {
			Destination:     "route-profile.internal",
			DestinationPort: 8443,
			ServiceFamily:   "https",
		},
	}
	req := httptest.NewRequest(http.MethodConnect, "/apps/app_dummy_https", nil)
	req.Host = "route-profile.internal:8443"
	req.RequestURI = "route-profile.internal:8443"

	frame, err := edgeTCPConnectOpenFrameForRequest(req, "app_dummy_https", routeProfiles)
	if err != nil {
		t.Fatalf("edgeTCPConnectOpenFrameForRequest returned error: %v", err)
	}
	if frame.Type != tunnel.FrameTCPOpen || frame.ApplicationID != "app_dummy_https" || frame.Host != "route-profile.internal" || frame.Port != 8443 {
		t.Fatalf("frame = %+v, want route-profile.internal:8443 tcp_open", frame)
	}
	if frame.RequestID == "" || !strings.HasPrefix(frame.RequestID, "req_tcp_") {
		t.Fatalf("request_id = %q, want req_tcp_ prefix", frame.RequestID)
	}
}

func TestEdgeTCPConnectOpenFrameForRequestUsesForwardedConnectAuthorityHeader(t *testing.T) {
	routeProfiles := map[string]ApplicationRouteProfile{
		"app_dummy_https": {
			Destination:     "route-profile.internal",
			DestinationPort: 8443,
			ServiceFamily:   "https",
		},
	}
	req := httptest.NewRequest(http.MethodConnect, "/apps/app_dummy_https", nil)
	req.Host = "edge.local"
	req.RequestURI = "/apps/app_dummy_https?connector_id=conn_lab_001"
	req.Header.Set(ConnectAuthorityHeader, "route-profile.internal:8443")

	frame, err := edgeTCPConnectOpenFrameForRequest(req, "app_dummy_https", routeProfiles)
	if err != nil {
		t.Fatalf("edgeTCPConnectOpenFrameForRequest returned error: %v", err)
	}
	if frame.Host != "route-profile.internal" || frame.Port != 8443 || frame.ApplicationID != "app_dummy_https" {
		t.Fatalf("frame = %+v, want forwarded CONNECT authority route target", frame)
	}
}

func TestEdgeTCPConnectOpenFrameForRequestRejectsAuthorityMismatch(t *testing.T) {
	routeProfiles := map[string]ApplicationRouteProfile{
		"app_dummy_https": {
			Destination:     "route-profile.internal",
			DestinationPort: 8443,
			ServiceFamily:   "https",
		},
	}
	req := httptest.NewRequest(http.MethodConnect, "/apps/app_dummy_https", nil)
	req.Host = "evil.internal:8443"
	req.RequestURI = "evil.internal:8443"

	_, err := edgeTCPConnectOpenFrameForRequest(req, "app_dummy_https", routeProfiles)
	if err == nil {
		t.Fatal("edgeTCPConnectOpenFrameForRequest returned nil error")
	}
	if !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("error = %q, want does not match", err.Error())
	}
}

func validEdgeTCPConnectLimits() EdgeTCPConnectLimits {
	return EdgeTCPConnectLimits{
		ConnectTimeoutMillis:        int((5 * time.Second) / time.Millisecond),
		MaxConnectionLifetimeMillis: int((5 * time.Minute) / time.Millisecond),
		IdleTimeoutMillis:           int((30 * time.Second) / time.Millisecond),
		ByteCap:                     64 << 20,
		ConcurrentConnectionCap:     32,
	}
}
