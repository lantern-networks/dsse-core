package main

import (
	"encoding/base64"
	"encoding/json"
	"github.com/lantern-networks/dsse-core/internal/posixperm"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func tokenFor(t *testing.T, payload map[string]any) string {
	t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}

// ★★★ REFUSE RATHER THAN INSTALL SOMETHING THAT CANNOT WORK. A connector with no address to dial is a service
// that starts, retries for ever and fronts nothing — and the machine it is on looks configured.
func TestATokenThatNamesNoAddressInstallsNothing(t *testing.T) {
	dir := t.TempDir()
	err := run(tokenFor(t, map[string]any{"v": 1, "site": "tokyo-dc", "tenant_id": "t1"}),
		filepath.Join(dir, "state"), "/usr/local/bin/dsse-connector", "dsse-connector", true)
	if err == nil {
		t.Fatal("a token with no address must be refused")
	}
	if !strings.Contains(err.Error(), "could never connect") {
		t.Fatalf("the refusal must say why: %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(dir, "state")); statErr == nil {
		t.Fatal("nothing may be written when the install is refused")
	}
}

// A token with no site leaves an operator nothing to author routes against.
func TestATokenThatNamesNoSiteInstallsNothing(t *testing.T) {
	dir := t.TempDir()
	err := run(tokenFor(t, map[string]any{"v": 1, "edge_url": "https://a.example", "tenant_id": "t1"}),
		filepath.Join(dir, "state"), "/usr/local/bin/dsse-connector", "dsse-connector", true)
	if err == nil || !strings.Contains(err.Error(), "no site") {
		t.Fatalf("a token with no site must be refused: %v", err)
	}
}

// Something that is not a token at all says so in the words of the person holding it.
func TestSomethingThatIsNotATokenSaysSo(t *testing.T) {
	dir := t.TempDir()
	err := run("this is not a token", filepath.Join(dir, "state"), "/bin/true", "dsse-connector", true)
	if err == nil || !strings.Contains(err.Error(), "does not look like an enrolment token") {
		t.Fatalf("got %v", err)
	}
	err = run("", filepath.Join(dir, "state"), "/bin/true", "dsse-connector", true)
	if err == nil || !strings.Contains(err.Error(), "-token is required") {
		t.Fatalf("got %v", err)
	}
}

// ★ THE STATE DIRECTORY IS THIS CONNECTOR'S IDENTITY, so it is created for this machine alone, and the start
// script that holds a live credential is not readable by everything on the box.
func TestWhatIsWrittenIsNotReadableByEverything(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "state")
	token := tokenFor(t, map[string]any{
		"v": 1, "site": "tokyo-dc", "tenant_id": "t1",
		"edge_endpoints": "region-a=https://a.example;region-b=https://b.example",
	})
	if err := run(token, state, aConnectorProgram(t, dir, "dsse-connector"), "dsse-connector", true); err != nil {
		t.Fatalf("install: %v", err)
	}
	info, err := os.Stat(state)
	if err != nil {
		t.Fatalf("state dir: %v", err)
	}
	script := filepath.Join(state, "start-connector.sh")
	si, err := os.Stat(script)
	if err != nil {
		t.Fatalf("start script: %v", err)
	}
	// ★ THE MODE BITS ARE CHECKED WHERE THEY EXIST. This installer writes a "#!/bin/sh" start script, so the
	// machine it runs on is a POSIX one and 0700 is the real guarantee there. Windows has no POSIX permission
	// bits at all -- os.MkdirAll(dir, 0700) produces a directory Stat reports as drwxrwxrwx -- so asserting
	// 0700 there tests the operating system, not this code, and turns the Windows development box red while
	// every CI runner stays green. That split is how a genuine break hides (2026-08-14).
	//
	// It is a SKIP and not a relaxation: the property is unverified on Windows, and saying so is the honest
	// report. Delivering it there means an ACL, which this installer does not write because it does not run
	// there.
	if !posixperm.Meaningful() {
		t.Log("permission assertions skipped: " + posixperm.SkipReason)
	} else {
		if info.Mode().Perm() != 0o700 {
			t.Fatalf("the directory holding this connector's identity is %v", info.Mode().Perm())
		}
		if si.Mode().Perm() != 0o700 {
			t.Fatalf("the script carrying a live one-time credential is %v", si.Mode().Perm())
		}
	}
	body, err := os.ReadFile(script)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !strings.Contains(string(body), "--state-dir '"+state+"'") {
		t.Fatalf("the script does not persist into the directory that was prepared:\n%s", body)
	}
}

// ★ A VALUE CARRYING A SHELL METACHARACTER WOULD BE RUN. The deployment's own env file carries a warning
// about exactly this, arrived at by every node of a deployment exiting 127 at once.
func TestAValueWithAQuoteInItCannotEscapeTheScript(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "state")
	token := tokenFor(t, map[string]any{
		"v": 1, "site": "tokyo-dc", "tenant_id": "t1", "edge_url": "https://a.example",
	})
	// The metacharacter arrives on a path that REALLY EXISTS, because that is the only way it reaches the
	// generated script: the installer refuses a program that is not on the machine before writing anything.
	// A single quote is a legal character in a Unix filename, so this is a path a machine can actually have.
	hostile := aConnectorProgram(t, dir, "dsse-connector'; touch pwned; echo '")
	if err := run(token, state, hostile, "dsse-connector", true); err != nil {
		t.Fatalf("install: %v", err)
	}
	body, err := os.ReadFile(filepath.Join(state, "start-connector.sh"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if strings.Contains(string(body), "; touch pwned; echo ") && !strings.Contains(string(body), `'\''`) {
		t.Fatalf("a value escaped its quotes:\n%s", body)
	}
}

// The doors are read the way the connector reads them, and one is reported as one.
func TestTheDoorsAreReadFromTheToken(t *testing.T) {
	both := enrolmentToken{EdgeEndpoints: "region-a=https://a.example;region-b=https://b.example"}
	if got := doorsOf(both); len(got) != 2 || got[0].display() != "region-a=https://a.example" {
		t.Fatalf("doors: %v", got)
	}
	// ★ THE SEPARATOR THE CONNECTOR ACCEPTS AND THIS DID NOT. A comma-separated pair printed as one door
	// under the "★ one address" warning while the connector failed over between two.
	if got := doorsOf(enrolmentToken{EdgeEndpoints: "region-a=https://a.example,region-b=https://b.example"}); len(got) != 2 {
		t.Fatalf("a comma-separated pair is two doors to the connector, so it is two here: %v", got)
	}
	if !strings.Contains(doorsNote(2), "does not take this location off the network") {
		t.Fatalf("note: %q", doorsNote(2))
	}
	one := enrolmentToken{EdgeURL: "https://only.example"}
	if got := doorsOf(one); len(got) != 1 || got[0].display() != "https://only.example" {
		t.Fatalf("a token with a single address must still name it: %v", got)
	}
	if !strings.Contains(doorsNote(1), "unreachable until it comes back") {
		t.Fatalf("one door has a consequence: %q", doorsNote(1))
	}
}

// aConnectorProgram puts an executable at name inside dir and returns its path, so a test can install against
// a machine that really has the program the service would start.
func aConnectorProgram(t *testing.T, dir, name string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("place a connector program: %v", err)
	}
	return path
}

// ★★★ A SERVICE POINTING AT NOTHING IS THE SAME DEFECT AS A TOKEN POINTING AT NOWHERE. Measured on
// 2026-08-26: the installer wrote a start script and a unit naming /usr/local/bin/dsse-connector on a machine
// that had no such file, said nothing about it, and exited 0.
func TestAProgramThatIsNotOnThisMachineInstallsNothing(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "state")
	token := tokenFor(t, map[string]any{
		"v": 1, "site": "tokyo-dc", "tenant_id": "t1", "edge_url": "https://a.example",
	})
	err := run(token, state, filepath.Join(dir, "not-here"), "dsse-connector", true)
	if err == nil || !strings.Contains(err.Error(), "no connector program at") {
		t.Fatalf("got %v", err)
	}
	if _, serr := os.Stat(state); serr == nil {
		t.Fatalf("a refusal wrote %s anyway", state)
	}
}
