package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// ★★★ THE OUT-OF-BAND STEP-UP HAS AN ADDRESS (2026-09-02, measured on a live deployment with a real device).
//
// An egress rule with access=authenticate compiles, reaches the Edge and enforces. A steered Mac asking for a
// destination under one was answered
//
//	HTTP/2 401     {"decision":"require_reauthentication","actions":[{"type":"prompt_reauthentication"}]}
//
// and that was the whole ceremony: no step-up URL in the body, no X-Dsse-Stepup-Url header, and a browser
// Accept got the same bare 401 rather than the redirect the Edge is written to send. isAuthRedirectCase
// returns false when brokerBaseURL is empty, and nothing this installer generated ever set
// -clientless-base-url — so the broker, the grant store, the device binding, the mux STEPUP frame, the macOS
// agent that opens the URL and the Windows agent that reads the header were all implemented and none of them
// could fire.
//
// A control that holds a flow and cannot say where to go is a control that only denies.
func TestTheEdgeIsToldWhereItsStepUpPortalIs(t *testing.T) {
	dir := t.TempDir()
	if err := writeEnvironment(dir, []string{"edge.example.test"}, nil); err != nil {
		t.Fatalf("render the environment: %v", err)
	}
	if err := writeLaunchScripts(dir); err != nil {
		t.Fatalf("render the launch scripts: %v", err)
	}
	body, err := os.ReadFile(filepath.Join(dir, "start-edge.sh"))
	if err != nil {
		t.Fatal(err)
	}
	script := string(body)
	if !strings.Contains(script, "-clientless-base-url=") {
		t.Fatal("the Edge is started without -clientless-base-url, so an authenticate decision can only 401: " +
			"the step-up portal has no address and no agent is ever told where to send the user")
	}
	// ★ AND IT IS PASSED, NOT MERELY COMPUTED. A variable set and left out of the exec line is the same
	// outage with a comment above it.
	exec := script[strings.Index(script, "exec \"$DSSE_EDGE_BINARY\""):]
	if !strings.Contains(exec, "$CLIENTLESS") {
		t.Error("the step-up portal's address is computed and never passed to the Edge")
	}
	// The address a USER'S BROWSER has to resolve is the region's agent plane — the door the device already
	// uses — not a container name, and not the admin plane.
	if !strings.Contains(script, "DSSE_AGENT_PLANE_NAME") {
		t.Error("the step-up portal's address is not derived from the agent plane the device can reach")
	}
}

// ★★★ AND EVERY EDGE SIGNS THE STEP-UP WITH THE SAME KEY (2026-09-02).
//
// The step-up URL names the deployment's agent plane; the region's front door hands that connection to
// whichever Edge it likes; and the Edge that RECEIVES it is usually not the one that issued it. A key each
// process invents means the signature does not verify — and that does not fail loudly, because an
// unverifiable device is read as "no device identity", which mints an organization-wide grant in place of a
// device-bound one, with nothing said anywhere.
func TestEveryEdgeSignsTheStepUpWithTheDeploymentsKey(t *testing.T) {
	dir := t.TempDir()
	if err := writeEnvironment(dir, []string{"edge.example.test"}, nil); err != nil {
		t.Fatalf("render the environment: %v", err)
	}
	if err := writeLaunchScripts(dir); err != nil {
		t.Fatalf("render the launch scripts: %v", err)
	}
	env, err := os.ReadFile(filepath.Join(dir, "deployment.env"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(env), "STEPUP_BINDING_SECRET=") {
		t.Error("the deployment generates no step-up binding secret, so every Edge signs with a key of its " +
			"own and a ceremony that crosses a node loses its device binding")
	}
	script, err := os.ReadFile(filepath.Join(dir, "start-edge.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(script), "-step-up-binding-secret=") {
		t.Error("the secret is generated and never given to the Edge")
	}
	// ★ AND A DEPLOYMENT BUILT BEFORE THE SECRET EXISTED STILL GETS A SHARED KEY. A repair does not add
	// secrets, and inventing one per machine would give every Edge a different key while each believed it
	// had a shared one — the same outage, now silent.
	if !strings.Contains(string(script), "${STEPUP_BINDING_SECRET:-$CONNECTOR_SECRET}") {
		t.Error("an existing deployment has no STEPUP_BINDING_SECRET and no fallback to a secret its Edges " +
			"already share, so each signs with a key of its own")
	}
}

// ★★★ AND THE ADDRESS IS THE DEVICE'S OWN REGION'S DOOR (2026-09-02, measured on three regions).
//
// Every region rendered the same deployment-wide name, which resolves to ONE region. A flow held in osaka
// sent the user to tokyo-east's Edge, which ran the ceremony and minted the grant in its own memory — an
// Edge is zero-DB — while the Edge holding the flow looked in its own and found none: the user authenticates
// successfully and is held again, with nothing broken. And when the region behind that one name is the one
// that fails, every region's step-up points at a dead address, including the regions the devices correctly
// failed over to.
//
// The test runs the shell the installer writes, because the first version of this derivation dropped the
// LAST region in the map — read returns non-zero on a final line with no trailing separator — so exactly one
// region silently had no portal.
func TestTheStepUpPortalIsThisRegionsOwnDoor(t *testing.T) {
	dir := t.TempDir()
	if err := writeEnvironment(dir, []string{"edge.example.test"}, nil); err != nil {
		t.Fatalf("render the environment: %v", err)
	}
	if err := writeLaunchScripts(dir); err != nil {
		t.Fatalf("render the launch scripts: %v", err)
	}
	body, err := os.ReadFile(filepath.Join(dir, "start-edge.sh"))
	if err != nil {
		t.Fatal(err)
	}
	// Take the derivation out of the script and run it for every position in a three-region map.
	script := string(body)
	start := strings.Index(script, "DSSE_CLIENTLESS_REGION_URL=")
	if start < 0 {
		t.Fatal("the Edge does not derive its own region's portal address")
	}
	end := strings.Index(script[start:], "\nif [ -n \"$DSSE_CLIENTLESS_REGION_URL\" ]")
	if end < 0 {
		t.Fatal("could not find the end of the derivation")
	}
	derivation := script[start : start+end]
	const endpoints = "osaka=https://agents.osaka.example;tokyo-east=https://agents.tokyo-east.example;" +
		"tokyo-west=https://agents.tokyo-west.example"
	for _, region := range []string{"osaka", "tokyo-east", "tokyo-west"} {
		// ★★★ UNDER set -eu, THE WAY THE SCRIPT RUNS IT (2026-09-02). Without it this gate passed while the
		// real start-edge.sh died: the derivation's loop ended non-zero for every region except the one last
		// in the map, and set -e killed the script before it logged anything. Two of three Edges exited 1
		// with empty logs and their region's door served a backend that was not there.
		out, err := exec.Command("/bin/sh", "-c",
			"set -eu\n"+
				"DSSE_REGION_ENDPOINTS='"+endpoints+"' DSSE_EDGE_REGION='"+region+"'\n"+
				"export DSSE_REGION_ENDPOINTS DSSE_EDGE_REGION\n"+derivation+
				"\nprintf '%s' \"$DSSE_CLIENTLESS_REGION_URL\"").CombinedOutput()
		if err != nil {
			t.Fatalf("%s: run the derivation: %v\n%s", region, err, out)
		}
		if want := "https://agents." + region + ".example"; string(out) != want {
			t.Errorf("region %s derives %q, want %q — a region with no portal falls back to the "+
				"deployment-wide name, which is another region's door", region, out, want)
		}
	}
}

// ★★★ AND THE OPERATOR CAN GIVE THE PORTAL ITS OWN CERTIFICATE (2026-09-02).
//
// A browser is sent to the portal and has no reason to trust what this deployment mints. The identity
// provider is not part of this product — it is the customer's Okta or Entra ID, reached over a publicly
// trusted certificate — so the hop in between is a browser-facing page whose certificate is provided for it.
// Dropping the pair beside the launch script is the whole act; without one the portal keeps the agent
// plane's certificate, which is a visible browser warning rather than a quiet trust decision.
func TestTheOperatorCanGiveTheStepUpPortalItsOwnCertificate(t *testing.T) {
	dir := t.TempDir()
	if err := writeEnvironment(dir, []string{"edge.example.test"}, nil); err != nil {
		t.Fatalf("render the environment: %v", err)
	}
	if err := writeLaunchScripts(dir); err != nil {
		t.Fatalf("render the launch scripts: %v", err)
	}
	body, err := os.ReadFile(filepath.Join(dir, "start-edge.sh"))
	if err != nil {
		t.Fatal(err)
	}
	script := string(body)
	for _, needs := range []string{"clientless/tls.crt", "clientless/tls.key", "-clientless-tls-cert=", "-clientless-tls-key="} {
		if !strings.Contains(script, needs) {
			t.Errorf("the Edge is never told about %s, so an operator who provides a portal certificate "+
				"cannot get it served", needs)
		}
	}
	// ★ AND IT IS CONDITIONAL. Passing a flag for a file that is not there is how an Edge refuses to start
	// on every deployment that has not been given one — which is every deployment, on the day this landed.
	if !strings.Contains(script, "[ -f \"$here/clientless/tls.crt\" ]") {
		t.Error("the certificate flags are passed unconditionally, so a deployment without one is broken by " +
			"the presence of the feature")
	}
}
