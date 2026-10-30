package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInspectionCRLDoorHasSeparateLoopbackPublishedHTTPPort(t *testing.T) {
	dir := t.TempDir()
	if err := writeRegionFrontDoorConfig(dir, planeNamesFor("agents.example.test")); err != nil {
		t.Fatal(err)
	}
	front, err := os.ReadFile(filepath.Join(dir, "haproxy-edge.cfg"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(front), "frontend inspection_crl\n    bind :8088\n    default_backend inspection_crl_local") ||
		!strings.Contains(string(front), "server cp-a dsse-control-plane-a:8088 check") {
		t.Fatal("signed CRL listener is not routed to the local CP")
	}
	compose, err := composeBodyFor(dir, foundingShape)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(compose, "${DSSE_CRL_PUBLISH_BIND:-127.0.0.1:18080}:8088") {
		t.Fatal("CRL doorway is not loopback-only by default")
	}
	if !strings.Contains(string(front), "frontend region\n    bind :443") {
		t.Fatal("agent/console TLS entrance changed")
	}
}
