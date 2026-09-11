package main

// verify_an_endpoint_can_be_installed.go — whether any device can join this deployment at all.
//
// ★★★ A DEPLOYMENT THIS PROGRAM PRODUCED COULD NOT INSTALL AN ENDPOINT (2026-08-27, found by asking whether
// the manual steps in a lab walk were the standard install, then building the real signed and notarised macOS
// package and running its own preinstall against the configuration this deployment publishes):
//
//	REFUSING TO INSTALL: the agent configuration has no usable update_signing_keys, so this Mac could
//	never be updated.
//	REFUSING TO INSTALL: the agent configuration names no update_publisher_team_id. Without it this Mac
//	installs whatever a signed manifest points at, as root, without checking who built it.
//
// Both gates are right. The deployment was healthy, every screen was green, -verify passed 20 of 31 checks,
// and no endpoint could ever have joined it — because the two halves of this product, the thing that installs
// the DEPLOYMENT and the thing that installs the AGENT, are built and tested apart and nothing asked them
// about each other.
//
// ★ SO THIS ASKS THE QUESTION AT THE DEPLOYMENT, where it can still be fixed, rather than leaving it to be
// discovered by whoever first tries a device. It reads the same fields the endpoint installer refuses without.

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// verifyAnEndpointCanBeInstalled reads the deployment's own configuration for the values an endpoint
// installer requires before it will install anything.
func verifyAnEndpointCanBeInstalled(dir string) []verifyResult {
	const name = "an endpoint can be installed against this deployment"
	env := readDeploymentEnv(dir)

	missing := []string{}
	if strings.TrimSpace(deploymentFileValue(dir, agentUpdateSigningPublicFile)) == "" {
		missing = append(missing, "no update-signing key is named ("+agentUpdateSigningPublicFile+" is absent "+
			"or empty), so the published configuration carries no update_signing_keys and a device would be "+
			"installing a security agent nobody can ever patch")
	}
	if strings.TrimSpace(env["DSSE_AGENT_PUBLISHER"]) == "" {
		missing = append(missing, "DSSE_AGENT_PUBLISHER is empty, so the published configuration names no "+
			"publisher and a device would install, as root, whatever a signed manifest points at — the "+
			"manifest signature says a trusted party CHOSE the package, not that the package is theirs. Set it "+
			"to the identity that signs the agent packages you distribute (macOS: codesign -dv <app> 2>&1 | "+
			"grep TeamIdentifier)")
	}
	// ★★★ AND WHETHER A RELEASE CAN EVER BE PUBLISHED AT ALL (2026-08-28, measured by walking the Console's
	// install lane on a deployment this program built). The two fields above make the CONFIGURATION installable.
	// They say nothing about whether this deployment can hand a device a package: the update-signing key has no
	// on-disk fallback by design, so a control plane without a token cannot sign, and the Console's Agent
	// Releases screen showed "nothing can be published from here" with every platform reading "Nothing
	// published". The route that does exist is to sign the manifest away from the nodes and publish the
	// envelope — which needs the private half to be somewhere the operator can reach.
	//
	// So this asks for ONE of the two, and names both: a token the control plane can sign with, or the key in
	// the authority directory that nothing at runtime mounts.
	hasAuthorityKey := deploymentFileValue(filepath.Join(dir, authorityDirName), agentUpdateSigningKeyFile) != ""
	hasToken := strings.Contains(deploymentFileValue(dir, "start-control-plane.sh"), "-agent-update-hsm-agent-socket=/")
	if !hasAuthorityKey && !hasToken {
		missing = append(missing, "there is no way to publish a release: this control plane has no signing token "+
			"(-agent-update-hsm-agent-socket) and the update-signing key is not in the "+authorityDirName+" "+
			"directory either, so nothing can sign a manifest and the Console's release screen has nothing to "+
			"offer. Devices install and then stay on whatever they were installed with, for ever")
	}
	if len(missing) > 0 {
		return []verifyResult{{name: name, note: fmt.Sprintf(
			"%d thing(s) an endpoint installer refuses without: %s. This deployment comes up healthy and no "+
				"device can join it; the refusal happens on the device, where it reads as a broken installer",
			len(missing), strings.Join(missing, "; "))}}
	}
	how := "the key kept in the " + authorityDirName + " directory, signed away from every node"
	if hasToken {
		how = "a signing token the control plane holds a handle to"
	}
	return []verifyResult{{ok: true, name: name, note: fmt.Sprintf(
		"this deployment names an update-signing key and the publisher %q, which are what an endpoint "+
			"installer refuses without, and a release can be published with %s. It does NOT say the agent "+
			"package itself is signed by that publisher — that is a property of the artifact and is checked "+
			"where it is built",
		strings.TrimSpace(env["DSSE_AGENT_PUBLISHER"]), how)}}
}

// deploymentFileValue reads one small file from the deployment directory, or "" if it is not there.
func deploymentFileValue(dir, name string) string {
	body, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(body))
}
