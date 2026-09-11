package main

import (
	"strings"
	"testing"
)

// ★★★ THE CONSOLE COULD NOT SIGN ANYONE IN WHEN LEADERSHIP MOVED (2026-08-27, measured the first time it
// landed in another region).
//
// Its three upstreams named https://dsse-control-plane:9443 — the door in front of THIS MACHINE's control
// planes, which health-checks GET /leader and therefore has no backend at all while the leader is elsewhere.
// The Console logged `proxy error: EOF` and the screen said
//
//	Invalid credentials.
//
// for a password that was correct: asked of the leader directly, the same email and password answered 200
// with a challenge token. That is the worst wrong answer this screen can give — it sends an administrator to
// reset a credential that is fine, on a deployment whose authority is simply somewhere else.
//
// The region doorway already routes admin.<host> to whichever control plane holds leadership, in any region.
// The Edges' door learned that; the Console's own upstream had not.
func TestTheConsoleReachesTheAuthorityWhereverItIs(t *testing.T) {
	dir := t.TempDir()
	if err := run(dir, "dsse.example", "Test Deployment", 10, false); err != nil {
		t.Fatalf("install: %v", err)
	}
	compose := composeForShape(t, dir, machineShape{holds: regionShapeStateBearing, edges: true})

	planes := planeNamesFor("dsse.example")
	for _, key := range []string{"ADMIN_API_UPSTREAM", "CONTROL_API_UPSTREAM", "AUTH_API_UPSTREAM"} {
		line := lineContaining(compose, key+":")
		if line == "" {
			t.Fatalf("the Console is given no %s", key)
		}
		if strings.Contains(line, "dsse-control-plane:9443") {
			t.Errorf("%s points at THIS MACHINE's control planes: %s — when leadership is in another region "+
				"that door has no backend, and the Console reports a correct password as invalid", key, strings.TrimSpace(line))
		}
		if !strings.Contains(line, planes.Admin) {
			t.Errorf("%s does not go through the deployment's admin plane (%s): %s", key, planes.Admin, strings.TrimSpace(line))
		}
	}
}

// ★ AND A DEPLOYMENT THAT ANSWERS ON AN ADDRESS KEEPS THE SHORT PATH. There is no admin plane to route
// through when the planes are not separated by name, and the compose service beside it is both correct and
// one hop shorter. Without this the fix above would be a change for every deployment rather than for the
// shape that needed it.
func TestADeploymentOnAnAddressKeepsTheLocalUpstream(t *testing.T) {
	dir := t.TempDir()
	if err := run(dir, "203.0.113.10", "Test Deployment", 10, false); err != nil {
		t.Fatalf("install: %v", err)
	}
	compose := composeForShape(t, dir, machineShape{holds: regionShapeStateBearing, edges: true})
	if !strings.Contains(compose, "dsse-control-plane-a:9443") {
		t.Fatal("a deployment that answers on an address lost the local upstream it has no replacement for")
	}
}

func lineContaining(body, want string) string {
	for _, l := range strings.Split(body, "\n") {
		if strings.Contains(l, want) {
			return l
		}
	}
	return ""
}
