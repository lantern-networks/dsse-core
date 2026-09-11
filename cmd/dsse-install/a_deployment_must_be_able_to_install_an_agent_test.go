package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ★★★ A DEPLOYMENT THIS PROGRAM PRODUCES COULD NOT INSTALL THE ENDPOINT AGENT (2026-08-27, measured by
// building the real signed, notarised .pkg and running its own preinstall against the configuration this
// deployment hands a Mac).
//
//	REFUSING TO INSTALL: the agent configuration has no usable update_signing_keys, so this Mac could
//	never be updated. Each entry must be a 64-character hex Ed25519 public key.
//
// That gate is right and exists because the fleet once shipped exactly that — a security agent that can never
// be patched. The configuration is published by the control plane, which emits update_signing_keys only when
// it HAS one; the key is named by -agent-update-pin; and this installer names none. So the two halves of the
// product — the thing that installs the deployment and the thing that installs the agent — refuse each other,
// and every macOS install against a freshly installed deployment stops at that line.
//
// ★ THE PRIVATE KEY IS NOT WHAT IS MISSING. Releases can be published by PUTting an envelope signed
// elsewhere, and there is deliberately no on-disk fallback for the signing key: it belongs in a token. What a
// deployment must have is the PUBLIC key it accepts — a pin. That is what makes a configuration installable,
// and it is public by nature.
func TestADeploymentNamesTheKeyThatMayUpdateItsAgents(t *testing.T) {
	dir := t.TempDir()
	if err := run(dir, "dsse.example", "Test Deployment", 10, false); err != nil {
		t.Fatalf("install: %v", err)
	}
	body, err := os.ReadFile(filepath.Join(dir, "start-control-plane.sh"))
	if err != nil {
		t.Fatal(err)
	}
	script := string(body)
	if !strings.Contains(script, "-agent-update-pin=") {
		t.Error("this deployment names no update-signing key, so the configuration it publishes carries no " +
			"update_signing_keys and the endpoint installer refuses every install against it — the deployment " +
			"comes up healthy and no device can ever join it")
	}
	// ★★ AND IT MUST NOT BE THE AGENT-POLICY KEY. The update key says WHAT code runs; the policy key says
	// WHEN, and carries the halt. One key for both means the party a freeze exists to stop is the party who
	// signs the freeze — the Edge refuses to start on that pairing, so naming it here would be an installer
	// that produces a deployment that cannot boot.
	pin := valueOfFlag(script, "-agent-update-pin=")
	policy := deploymentFileContents(t, dir, "agent-policy-signing.pub")
	if pin != "" && strings.EqualFold(pin, policy) {
		t.Error("the update-signing pin is the agent-policy key; every control plane refuses that pairing at " +
			"startup, so this deployment would not come up at all")
	}
	// ★★★ AND THE PRIVATE HALF IS NOT IN THE DEPLOYMENT DIRECTORY. There is no on-disk fallback for this key
	// by design: an Edge holding it would mean a compromised node can authorise running code on every device.
	// A pin is public; a key beside it would quietly become the thing operators use.
	for _, name := range []string{"agent-update-signing.key", "agent-update.key"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err == nil {
			t.Errorf("%s is in the deployment directory — the key that authorises running code on every device "+
				"must not sit beside the nodes that run it", name)
		}
	}
}

func valueOfFlag(script, flag string) string {
	i := strings.Index(script, flag)
	if i < 0 {
		return ""
	}
	rest := script[i+len(flag):]
	rest = strings.TrimPrefix(rest, "\"")
	if j := strings.IndexAny(rest, "\" \n\\"); j >= 0 {
		rest = rest[:j]
	}
	return strings.TrimSpace(rest)
}

func deploymentFileContents(t *testing.T, dir, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// ★★★ RE-RUNNING THE INSTALLER LEFT A DEPLOYMENT WORSE THAN BEFORE (2026-08-27, measured on a copy of a
// running lab).
//
// An operator with an existing deployment re-runs this program to pick up what a new version needs. It
// correctly refuses to replace authorities — "Replacing them is a rotation, not an install: it orphans every
// anchor already distributed" — and then rewrites the generated files:
//
//	rewrote this deployment's generated files from the current installer:
//	  the launch scripts
//	  docker-compose.yml
//	Nothing changes until the deployment is restarted, and no secret or authority was touched.
//
// The launch script now READS agent-update-signing.pub and the compose file MOUNTS it, and nothing minted it.
// So the control plane starts, finds nothing, pins an empty list, and publishes a configuration every
// endpoint installer refuses — on a deployment whose installer just reported success and reassured the
// operator that nothing was touched.
//
// ★ MINTING WHAT IS ABSENT IS NOT A ROTATION. The refusal above protects anchors devices have adopted; a key
// that does not exist has been adopted by nobody, and there is nothing to orphan. This is the same rule
// writeAgentPolicySigningKey already states: mint if this directory has none, never touch one that exists.
func TestReRunningTheInstallerMintsWhatItsNewScriptsRead(t *testing.T) {
	dir := t.TempDir()
	if err := run(dir, "dsse.example", "Test Deployment", 10, false); err != nil {
		t.Fatalf("install: %v", err)
	}
	// The state an operator upgrading is in: authorities already here, this one not yet.
	if err := os.Remove(filepath.Join(dir, agentUpdateSigningPublicFile)); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, authorityDirName, agentUpdateSigningKeyFile)); err != nil {
		t.Fatal(err)
	}
	if err := run(dir, "dsse.example", "Test Deployment", 10, false); err != nil {
		t.Fatalf("re-run: %v", err)
	}

	pin := deploymentFileContents(t, dir, agentUpdateSigningPublicFile)
	if pin == "" {
		script := deploymentFileContents(t, dir, "start-control-plane.sh")
		if strings.Contains(script, agentUpdateSigningPublicFile) {
			t.Fatalf("the re-run rewrote the launch script to read %s and did not mint it — the control plane "+
				"will start, find nothing, pin an empty list, and publish a configuration every endpoint "+
				"installer refuses, on a deployment the installer just reported success for",
				agentUpdateSigningPublicFile)
		}
		t.Fatalf("%s was not minted on a re-run", agentUpdateSigningPublicFile)
	}
	// ★★ AND AN EXISTING ONE IS NEVER REPLACED. Every device installed from this deployment pins the public
	// half; replacing it orphans all of them, which is the thing the refusal beside this exists to prevent.
	if err := run(dir, "dsse.example", "Test Deployment", 10, false); err != nil {
		t.Fatalf("third run: %v", err)
	}
	if again := deploymentFileContents(t, dir, agentUpdateSigningPublicFile); again != pin {
		t.Errorf("re-running the installer replaced the update-signing key (%s -> %s) — every device installed "+
			"from this deployment pins the public half and would stop accepting updates", pin[:16], again[:16])
	}
}

// ★★★ THE INSTRUCTION NAMED A VARIABLE THE FILE DID NOT CONTAIN (2026-08-28, found standing up two real
// sites). Every install ends by printing "set DSSE_REGION_ENDPOINTS to the same value in every region's
// deployment.env" — and only a region created with -region had the line. In the region that FOUNDED the
// deployment the variable did not exist, so an operator following the product's own closing instruction went
// looking in the file the product had just written for them and did not find it.
//
// ★ AND EMPTY IS THE RIGHT VALUE UNTIL EVERY REGION EXISTS. The point is not to fill it in here; it is that
// the answer has somewhere to be written, with what leaving it empty costs beside it.
func TestTheFoundingRegionCarriesTheMapOfItsDeploymentsRegions(t *testing.T) {
	dir := t.TempDir()
	if err := run(dir, "dsse.example", "Test Deployment", 10, false); err != nil {
		t.Fatalf("install: %v", err)
	}
	env := deploymentFileContents(t, dir, "deployment.env")
	if !strings.Contains(env, "DSSE_REGION_ENDPOINTS=") {
		t.Error("the founding region's deployment.env names no DSSE_REGION_ENDPOINTS, and every install ends " +
			"by telling the operator to set it — so the instruction points at a line their own configuration " +
			"does not have")
	}
	if !strings.Contains(env, "never fails over there") {
		t.Error("the variable is there with nothing saying what leaving it empty costs — an Edge holding a " +
			"shorter map is healthy, and the devices it serves simply never fail over")
	}
}

// ★★★ AND THE DEPLOYMENT MUST HAVE A WAY TO PUBLISH ONE (2026-08-28, measured by walking the Console's install
// lane on a deployment this program built). Every field an endpoint installer demands was present and -verify
// passed 64 of 64 — while the Console's Agent Releases screen said "nothing can be published from here" and
// every platform read "Nothing published". A fleet that installs and can then never be handed a new version is
// the shape of the defect this file already carries one instance of.
//
// One of two answers is enough, and they are different postures rather than better and worse: a token the
// control plane signs with, or the private half kept in the authority directory and signed away from every node.
func TestADeploymentCanPublishAReleaseAtAll(t *testing.T) {
	dir := t.TempDir()
	if err := run(dir, "dsse.example", "Test Deployment", 10, false); err != nil {
		t.Fatalf("install: %v", err)
	}
	// The publisher is the operator's answer and is deliberately not invented by the installer; set it so this
	// test is about the publish route and nothing else.
	envPath := filepath.Join(dir, "deployment.env")
	env, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(envPath, append(env, []byte("\nDSSE_AGENT_PUBLISHER='TEAMID1234'\n")...), 0o600); err != nil {
		t.Fatal(err)
	}

	results := verifyAnEndpointCanBeInstalled(dir)
	if len(results) != 1 || !results[0].ok {
		t.Fatalf("a freshly installed deployment cannot publish a release: %+v", results)
	}

	// Take the key away — the state a deployment is in if the authority directory is moved off the machine
	// without a token replacing it — and the check must say so rather than passing.
	if err := os.Remove(authorityPath(dir, agentUpdateSigningKeyFile)); err != nil {
		t.Fatalf("remove the signing key: %v", err)
	}
	results = verifyAnEndpointCanBeInstalled(dir)
	if len(results) != 1 || results[0].ok {
		t.Fatal("with no token and no key, nothing can sign a manifest — a deployment that reports this as " +
			"healthy is one whose devices stay on their installed version for ever")
	}
	if !strings.Contains(results[0].note, "no way to publish a release") {
		t.Errorf("the reason does not name what is wrong: %q", results[0].note)
	}
}

// ★★★ AND AN ORGANIZATION MUST BE ABLE TO GET ITS OWN DOOR NAME (2026-08-28, measured by pressing the button).
//
// The name an organization's agents send is minted from its issued id under this deployment's DNS suffix, so
// that nobody has to invent one and nothing derived from the customer's real name is offered on a transport
// port where SNI is plaintext. The control plane mints it, and it had no suffix — the installer set the flag on
// nothing — so the derived name came out empty and the act was refused with:
//
//	the name this organization's agents will send must be given when its authority is created
//
// on a Console that deliberately does not ask for one, for exactly the reason above. The source file for that
// flag already records this being measured on 2026-08-21, on the OTHER node: "deriving it from
// -renewal-recovery-sni left the control plane with an empty suffix". The flag was added and nothing passed it.
func TestTheControlPlaneCanMintAnOrganizationsOwnName(t *testing.T) {
	dir := t.TempDir()
	if err := run(dir, "dsse.example", "Test Deployment", 10, false); err != nil {
		t.Fatalf("install: %v", err)
	}
	body, err := os.ReadFile(filepath.Join(dir, "start-control-plane.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "-deployment-name-suffix=") {
		t.Fatal("the control plane is given no name suffix, so every organization's transport name is minted " +
			"empty and creating one is refused — asking the operator to type a name is the one answer this " +
			"design rules out, because the customer's own name on a plaintext SNI is what it exists to prevent")
	}
}

// ★★★ AND A SECOND ORGANIZATION'S RECORDS MUST BE ABLE TO REACH THE AUTHORITY (2026-08-28, measured by putting
// one on the lab).
//
// The audit-ingest authority map says which organizations an Edge may ship records for. It named ONE — the
// operator's own — and every Edge this installer generates ships under the same identity, CN=dsse-edge-fleet.
// So the certificate the receiver checks proves which DEPLOYMENT is shipping and cannot tell one organization
// from another: the per-organization value stopped no hostile Edge and refused every legitimate second
// customer, with
//
//	shipping to …/audit-ingest has been failing (audit ingest returned HTTP 403)
//
// and nothing anywhere saying an organization had to be added to a file. It stayed invisible for longer still,
// because until flows were attributed to the organization their device's certificate proves, every record was
// stamped with the operator's organization and the map was accidentally true.
func TestASecondOrganizationsRecordsCanReachTheAuthority(t *testing.T) {
	dir := t.TempDir()
	if err := run(dir, "dsse.example", "Test Deployment", 10, false); err != nil {
		t.Fatalf("install: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "audit-ingest-authority.json"))
	if err != nil {
		t.Fatal(err)
	}
	var byEdge map[string][]string
	if err := json.Unmarshal(raw, &byEdge); err != nil {
		t.Fatalf("decode: %v (%s)", err, raw)
	}
	allowed, named := byEdge["dsse-edge-fleet"]
	if !named {
		t.Fatalf("the fleet identity this installer ships under is not in the map: %v", byEdge)
	}
	admits := func(tenant string) bool {
		for _, a := range allowed {
			if a == "*" || a == tenant {
				return true
			}
		}
		return false
	}
	if !admits("tenant_default") {
		t.Error("the deployment's own organization cannot ship its records")
	}
	if !admits("tenant_some_customer_created_later") {
		t.Error("an organization created after installation cannot ship a single record, and the only sign of " +
			"it is a 403 in a check nobody has run yet")
	}
}

// ★★★ AND THE PACKAGE MUST HAVE SOMEWHERE TO LAND (2026-08-28, measured by publishing a real signed, notarised
// .pkg through the Console's own release screen).
//
// The manifest published — 200, "Mac (Apple silicon) 0.3.0" — and the artifact upload came back 502 in the
// browser. The 502 was the Console's proxy reporting a closed connection; the control plane's own answer,
// visible only with curl, was
//
//	this process has no artifact directory (-agent-update-manifest-dir), so it has nowhere to put the bytes
//
// The installer never passed the flag. So a deployment could publish a release and never deliver one: the
// screen said "Waiting for the package" for ever, and nothing on it says which flag is missing. This is the
// same shape as the update-signing key: the release lane existed at every layer and the deployment was not
// given the one place the bytes live.
func TestAPublishedReleaseHasSomewhereToLand(t *testing.T) {
	dir := t.TempDir()
	if err := run(dir, "dsse.example", "Test Deployment", 10, false); err != nil {
		t.Fatalf("install: %v", err)
	}
	body, err := os.ReadFile(filepath.Join(dir, "start-control-plane.sh"))
	if err != nil {
		t.Fatal(err)
	}
	script := string(body)
	if !strings.Contains(script, "-agent-update-manifest-dir=") {
		t.Fatal("the control plane is given no artifact directory, so a release can be published and its " +
			"package refused with 412 — the fleet waits for a file that has nowhere to go, and the screen " +
			"says only 'Waiting for the package'")
	}
	// ★ AND IT LIVES WITH THE REST OF THE CONTROL PLANE'S DURABLE STATE, not beside the binary: an artifact
	// directory that is not on the state volume is emptied by the next container recreate, which turns every
	// published release into one the fleet can no longer download.
	dirFlag := valueOfFlag(script, "-agent-update-manifest-dir=")
	stateFlag := valueOfFlag(script, "-state-dir=")
	if dirFlag == "" || stateFlag == "" || !strings.HasPrefix(dirFlag, stateFlag) {
		t.Errorf("the artifact directory %q is not under the control plane's state directory %q, so a recreate "+
			"loses every published package", dirFlag, stateFlag)
	}
}

// ★★★ AND AN EDGE MUST BE TOLD WHERE RELEASES COME FROM (2026-08-28, measured by publishing a real notarised
// package and asking a device for it).
//
// The control plane held the release. Every Edge this installer generates was given NO agent-update flags at
// all — no pin, no source URL, nowhere to keep what it pulls — so it pulled nothing and answered every device
//
//	no agent updates are published by this edge
//
// which is also what a deployment that has published nothing says. The two are indistinguishable from the
// device, and nothing on either side named the missing flag.
func TestAnEdgeIsToldWhereReleasesComeFrom(t *testing.T) {
	dir := t.TempDir()
	if err := run(dir, "dsse.example", "Test Deployment", 10, false); err != nil {
		t.Fatalf("install: %v", err)
	}
	body, err := os.ReadFile(filepath.Join(dir, "start-edge.sh"))
	if err != nil {
		t.Fatal(err)
	}
	script := string(body)
	for _, want := range []struct{ flag, why string }{
		{"-agent-update-source-url=", "the Edge never asks the control plane what is published, so every device is told nothing is"},
		{"-agent-update-pin=", "the Edge has no key to judge a release by, and refuses to relay one at all"},
		{"-agent-update-manifest-dir=", "the Edge has nowhere to keep what it pulled, so nothing survives to be served"},
		// ★ THE HALT AND THE VERSION COME DOWN THE SAME WAY. Without this the Edge never reads any
		// organization's rollout plan: a freeze an administrator authored reaches no device, and the version an
		// organization says it runs reaches none either. Both are answered 200 on the screen that set them.
		{"-agent-rollout-source-url=", "the Edge never reads a rollout plan, so a freeze reaches no device and neither does the version an organization runs"},
	} {
		if !strings.Contains(script, want.flag) {
			t.Errorf("start-edge.sh names no %s — %s", want.flag, want.why)
		}
	}
	// ★ AND THE PIN IS THE DEPLOYMENT'S OWN, read from the file this installer wrote.
	//
	// ★★ ASSERTED AGAINST THE SOURCE, NOT THE FLAG. valueOfFlag on a shell substitution returns the first
	// fragment of the substitution and is never empty, so "the pin is not empty" passes for a deployment whose
	// pin is empty — the shape of test this repository spent the morning removing.
	if !strings.Contains(script, `-agent-update-pin="$(cat "$here/`+agentUpdateSigningPublicFile+`"`) {
		t.Error("the Edge's update-signing pin does not come from this deployment's own published key, so it " +
			"would relay whatever the control plane handed it — the one thing keeping the update key off the " +
			"traffic nodes exists to prevent")
	}
}
