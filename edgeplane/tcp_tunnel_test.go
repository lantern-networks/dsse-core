package edgeplane

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/tunnel"
)

func TestEdgeTCPOpenFrameForTargetRejectsMissingLimits(t *testing.T) {
	limits := validEdgeTCPConnectLimits()
	limits.ByteCap = 0
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
