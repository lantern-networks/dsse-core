package main

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// ★ AN ARTIFACT NOBODY IS SERVING TRAFFIC WITH MUST NOT BE ABLE TO STOP THE NODE (2026-08-16).
//
// The agent-configuration snapshot publisher writes a file. It carries no traffic, enforces nothing, and every
// device on the node keeps working without it. Both its construction and its first publish were log.Fatalf, so
// enabling it with one flag missing (-network-extension-config-publish-dir set,
// -network-extension-runtime-copy-edge-url not) put the reference Edge into a crash loop — enforcement,
// interception and every tunnel gone, with a real Mac steering through it. Measured by doing exactly that.
//
// Refusing to start is right for material the node cannot serve traffic WITHOUT: the control plane, the
// signing key, a state store whose absence would silently disarm enforcement. It is wrong for something whose
// absence costs an artifact. This gate keeps the two apart, because the difference is invisible at the call
// site — log.Fatalf reads as diligence in both.
func TestTheSnapshotPublisherCannotKillTheEdge(t *testing.T) {
	source, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	text := string(source)

	// Every line that ends the process, with the publisher named on it.
	fatal := regexp.MustCompile(`(?m)^.*log\.Fatalf\(.*$`)
	for _, line := range fatal.FindAllString(text, -1) {
		lower := strings.ToLower(line)
		if !strings.Contains(lower, "snapshot publisher") && !strings.Contains(lower, "policy snapshot") {
			continue
		}
		t.Errorf("this line stops the Edge over an artifact:\n  %s\n"+
			"The agent-configuration snapshot is a file. Losing it costs a file; refusing to start costs every "+
			"device on the node. Warn and continue.", strings.TrimSpace(line))
	}
}
