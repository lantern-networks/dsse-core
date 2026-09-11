package main

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ★★★ THE BYTES cmd/dsse-edge ACTUALLY ISSUES. The two commands live in trees that cannot import each other,
// so the profile's field names are a contract nothing in the compiler checks. This is the document the
// Console downloads, written out here exactly as buildConnectorInstallProfile marshals it; its mirror is
// TestTheDownloadedProfileCarriesWhatTheInstallerReads in cmd/dsse-edge. A rename on either side fails one of
// the two, which is the only way this stays true.
const profileTheConsoleHandsOut = `{
  "kind": "dsse_connector_install_profile.v1",
  "issued_at": "2026-08-26T00:00:00Z",
  "tenant_id": "t1",
  "site": "tokyo-dc",
  "edge_endpoints": [
    "region-a=https://a.example:443",
    "region-b=https://b.example:443"
  ],
  "edge_ca": "-----BEGIN CERTIFICATE-----\nX\n-----END CERTIFICATE-----",
  "state_dir": "/var/lib/dsse-connector",
  "token": "%TOKEN%",
  "note": "This file is a credential until the connector it installs has run once. tried in this order; a connector that loses one door moves to the next, so the estate behind it survives losing a region"
}
`

func profileFile(t *testing.T, dir, body string) string {
	t.Helper()
	path := filepath.Join(dir, "dsse-connector-tokyo-dc.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestTheProfileTheConsoleHandsOutIsReadable(t *testing.T) {
	dir := t.TempDir()
	token := base64.RawURLEncoding.EncodeToString([]byte(`{"v":1,"site":"tokyo-dc","tenant_id":"t1","edge_url":"https://a.example:443"}`))
	path := profileFile(t, dir, strings.ReplaceAll(profileTheConsoleHandsOut, "%TOKEN%", token))

	gotToken, gotStateDir, err := readInstallProfile(path)
	if err != nil {
		t.Fatalf("the installer cannot read what the Console hands out: %v", err)
	}
	if gotToken != token {
		t.Fatalf("token: %q", gotToken)
	}
	if gotStateDir != "/var/lib/dsse-connector" {
		t.Fatalf("state dir: %q", gotStateDir)
	}
	// And the doors in it reach the connector: the profile is the durable half, so a profile whose door list
	// this installer cannot see produces a connector with one region and no report of it.
	parsed, err := readToken(gotToken)
	if err != nil {
		t.Fatalf("the token inside the profile: %v", err)
	}
	if parsed.Site != "tokyo-dc" {
		t.Fatalf("site: %q", parsed.Site)
	}
}

// ★ THE WRONG FILE IS THE LIKELY MISTAKE. A deployment hands out several JSON documents and they land in one
// downloads folder. The agent's install profile also carries tenant_id and endpoints, and applying it here
// would enrol nothing while reporting no reason.
func TestAnotherOfThisDeploymentsFilesIsRefusedByName(t *testing.T) {
	dir := t.TempDir()
	agentProfile := `{"kind":"dsse_install_profile.v1","tenant_id":"t1","transport_url":"https://a.example"}`
	_, _, err := readInstallProfile(profileFile(t, dir, agentProfile))
	if err == nil || !strings.Contains(err.Error(), "not a connector install profile") {
		t.Fatalf("got %v", err)
	}
	// Control: the same read, on the right kind, succeeds — so the refusal above is about the kind and not
	// about the way this test writes files.
	token := base64.RawURLEncoding.EncodeToString([]byte(`{"v":1,"site":"s","edge_url":"https://a.example"}`))
	good := strings.ReplaceAll(profileTheConsoleHandsOut, "%TOKEN%", token)
	if _, _, cerr := readInstallProfile(profileFile(t, t.TempDir(), good)); cerr != nil {
		t.Fatalf("the control must pass: %v", cerr)
	}
}

func TestAProfileWithNoTokenInstallsNothing(t *testing.T) {
	dir := t.TempDir()
	var p map[string]any
	if err := json.Unmarshal([]byte(strings.ReplaceAll(profileTheConsoleHandsOut, "%TOKEN%", "x")), &p); err != nil {
		t.Fatal(err)
	}
	delete(p, "token")
	body, _ := json.Marshal(p)
	_, _, err := readInstallProfile(profileFile(t, dir, string(body)))
	if err == nil || !strings.Contains(err.Error(), "no enrolment token") {
		t.Fatalf("got %v", err)
	}
}
