package main

import (
	"strings"
	"testing"
)

func TestGeneratedFrontDoorHasOnlyExplicitOperatorQuotas(t *testing.T) {
	t.Setenv("DSSE_HAPROXY_MAX_CONNECTIONS", "")
	t.Setenv("DSSE_HAPROXY_SESSION_IDLE_TIMEOUT_SECONDS", "")
	body := "global\n__DSSE_HAPROXY_CONNECTION_QUOTA__\ndefaults\n    mode tcp\n    timeout client  24h\n    timeout server  24h\n    timeout tunnel  24h\n"
	unconfigured := frontDoorResourceSettings(body)
	if strings.Contains(unconfigured, "maxconn ") || strings.Count(unconfigured, "0ms") != 3 {
		t.Fatal("generated fixed connection or session-time quota remains")
	}
	if !strings.Contains(unconfigured, "option clitcpka") || !strings.Contains(unconfigured, "option srvtcpka") || !strings.Contains(unconfigured, "stats socket /tmp/dsse-haproxy.cfg.sock mode 600") {
		t.Fatal("unlimited healthy idle lost liveness or runtime observability")
	}
	t.Setenv("DSSE_HAPROXY_MAX_CONNECTIONS", "1000000")
	t.Setenv("DSSE_HAPROXY_SESSION_IDLE_TIMEOUT_SECONDS", "172800")
	configured := frontDoorResourceSettings(body)
	if !strings.Contains(configured, "maxconn 1000000") || strings.Count(configured, "172800000ms") != 3 {
		t.Fatal("operator front-door budgets were clamped")
	}
}
