package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ★★★ THE ADMIN PLANE'S DOOR LEARNED TO CROSS A REGION AND THE AUTHORITY'S DID NOT (2026-08-27, measured on a
// two-region deployment whose leader was in the other one).
//
// Both backends front the same nodes and both check GET /leader, so when leadership moves, the LOCAL pair
// fails that check in both. The admin plane had been given the other regions' control planes; the data plane
// had not. The Edges here could then read nothing and write nothing to the authority:
//
//	FAIL what this Edge records is reaching the authority — shipping to authority.<host>/audit-ingest failing
//	FAIL blocking a device stops it steering — could not be blocked: 404
//
// which is word for word what frontdoor.go's own note says the authority's name exists to prevent.
func TestBothDoorsCanReachTheAuthorityInAnotherRegion(t *testing.T) {
	dir := t.TempDir()
	if err := run(dir, "dsse.example", "Test Deployment", 10, false); err != nil {
		t.Fatalf("install: %v", err)
	}
	// Name another region's control planes, the way an operator does once a second region exists.
	appendEnv(t, dir, "DSSE_CP_PEERS", "https://cp-b.dsse.example:37543,https://cp-b.dsse.example:37544")
	appendEnv(t, dir, "DSSE_CP_DATA_PEERS", "cp-b.dsse.example:37545:37543,cp-b.dsse.example:37546:37544")
	_ = "the explicit per-node form, which an operator who published those ports may still use"
	if err := os.Remove(filepath.Join(dir, "haproxy-edge.cfg")); err != nil {
		t.Fatal(err)
	}
	if err := writeRegionFrontDoorConfig(dir, planeNamesFor("dsse.example")); err != nil {
		t.Fatal(err)
	}
	body := readFileForTest(t, filepath.Join(dir, "haproxy-edge.cfg"))

	admin := backendBlock(body, "cp_admin_plane")
	data := backendBlock(body, "cp_data_plane")
	if !strings.Contains(admin, "cp-peer-1") {
		t.Error("the admin plane's door does not reach the other region's control planes")
	}
	if !strings.Contains(data, "cp-data-peer-1") {
		t.Error("the AUTHORITY's door does not reach the other region's control planes — an Edge here cannot " +
			"ship what it recorded or report an enrolment whenever leadership is elsewhere")
	}
	// ★ AND THE HEALTH CHECK ASKS THE ADMIN PORT WHILE TRAFFIC GOES TO THE DATA ONE, exactly as the local pair
	// does. Across machines the two are published separately, so neither can be derived from the other.
	if !strings.Contains(data, "cp-b.dsse.example:37545 check check-ssl verify none port 37543") {
		t.Errorf("the authority's peer does not send traffic to the data surface and check the admin one:\n%s", data)
	}
	// ★★ NO resolvers ON EITHER SET. haproxy will not hand the same address to two servers in one backend when
	// a resolvers section is in play, and another region's two nodes share a name.
	for _, line := range strings.Split(admin+data, "\n") {
		if strings.Contains(line, "peer-") && strings.Contains(line, "resolvers") {
			t.Errorf("a peer carries resolvers, so its twin will sit at \"No IP for server\": %s", strings.TrimSpace(line))
		}
	}
}

// ★ AND ONE REGION SAYS SO RATHER THAN LOOKING UNFINISHED. Empty is the ordinary case, and a reader should not
// have to wonder whether something is missing.
func TestOneRegionSaysItHoldsItsAuthorityInOnePlace(t *testing.T) {
	dir := t.TempDir()
	if err := run(dir, "dsse.example", "Test Deployment", 10, false); err != nil {
		t.Fatalf("install: %v", err)
	}
	body := readFileForTest(t, filepath.Join(dir, "haproxy-edge.cfg"))
	if n := strings.Count(body, "this deployment holds its authority in one region"); n < 2 {
		t.Errorf("only %d of the two doors say why they name no peers", n)
	}
}

func appendEnv(t *testing.T, dir, key, value string) {
	t.Helper()
	p := filepath.Join(dir, "deployment.env")
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, append(b, []byte("\n"+key+"='"+value+"'\n")...), 0o600); err != nil {
		t.Fatal(err)
	}
}

func readFileForTest(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// backendBlock returns one haproxy backend's lines, so an assertion about the authority's door cannot be
// satisfied by the admin plane's.
func backendBlock(body, name string) string {
	i := strings.Index(body, "\nbackend "+name)
	if i < 0 {
		return ""
	}
	rest := body[i+1:]
	if j := strings.Index(rest[len("backend "+name):], "\nbackend "); j >= 0 {
		return rest[:len("backend "+name)+j]
	}
	return rest
}
