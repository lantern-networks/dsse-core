package main

import (
	"errors"
	"strings"
	"testing"
)

// Acceptance C (2026-11-07): preflight answered "local image 1" and "local image 7" and nothing about which
// images those were. The detail now names the reference and the reason.
func TestPreflightNamesTheImageItCouldNotFind(t *testing.T) {
	const ref = "clickhouse/clickhouse-server:26.8.36.3-alpine@sha256:f5443f9ffa48f0154cdd50cab39fed732201762574a27f04f1f564bbba81832d"
	missing := preflightImageDetail(ref, errors.New("No such image"), "", "", "amd64")
	if !strings.Contains(missing, ref) || !strings.Contains(missing, "not on this host") || !strings.Contains(missing, "config --images") {
		t.Fatalf("a missing image is not named with what to do: %q", missing)
	}
	wrong := preflightImageDetail(ref, nil, "linux", "arm64", "amd64")
	if !strings.Contains(wrong, ref) || !strings.Contains(wrong, "linux/arm64") || !strings.Contains(wrong, "linux/amd64") {
		t.Fatalf("an image for another architecture is not named with both platforms: %q", wrong)
	}
	if ok := preflightImageDetail(ref, nil, "linux", "amd64", "amd64"); !strings.Contains(ok, ref) {
		t.Fatalf("a present image is not named: %q", ok)
	}
}
