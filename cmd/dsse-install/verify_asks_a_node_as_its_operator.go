package main

// verify_asks_a_node_as_its_operator.go — the walk asks each node what it is with a credential, because a node
// tells only its operator.
//
// ★★★ /healthz USED TO TELL ANYBODY (2026-11-09). Every mouth of a deployment is 443 and 443 is open to the
// internet, so the build, the machine names, the regions, the control channel and the database's replica set
// went to whoever asked — 184 sources in twelve and a half hours on one lab. A node now answers the status to
// everybody and the rest only to a caller its administrator authentication resolves to the operator's
// organization (the Edge's a_node_tells_only_its_operator_what_it_is.go). Half of this walk reads those fields,
// so it presents the narrowest credential it holds:
//
//	authority/installation-state-read-token   admin.state.read and nothing else, held by the machine that ran
//	                                          -bootstrap-admin and never carried
//	EDGE_CP_TOKEN, after -bootstrap-admin     the fleet's own named token, which every machine holds
//	ADMIN_TOKEN, before it                    the break-glass credential, which is armed until then
//
// The choice between the last two is the one the start script and the break-glass check already make, on the
// same marker, so the three cannot disagree about whether the deployment is closed.

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// nodeDetailBearer is what the walk presents when it reads a node's /healthz. Set by deploymentClient.
var nodeDetailBearer string

// nodeDetailCredentialKind names which credential nodeDetailBearer is, for the walk's own output. Never the value.
var nodeDetailCredentialKind string

func nodeDetailCredential(dir string) (token, kind string) {
	if t, err := readOperatorToken(privateInstallReadTokenDestination(dir)); err == nil && strings.TrimSpace(t) != "" {
		return strings.TrimSpace(t), "the installation's read-only token"
	}
	env, err := readEnvFile(filepath.Join(dir, "deployment.env"))
	if err != nil {
		return "", ""
	}
	if _, err := os.Stat(runtimePath(dir, adminBootstrappedMarker)); err == nil {
		if t := strings.TrimSpace(env["EDGE_CP_TOKEN"]); t != "" {
			return t, "the fleet's token (EDGE_CP_TOKEN)"
		}
		return "", ""
	}
	if t := strings.TrimSpace(env["ADMIN_TOKEN"]); t != "" {
		return t, "the break-glass credential (before -bootstrap-admin)"
	}
	return "", ""
}

// getNodeHealth reads a node's /healthz as the operator.
//
// The credential goes only to a server that proved this deployment's anchor over TLS (review HEALTH-R3,
// 2026-11-09: the client followed a 302/307 from the verified HTTPS node to a plain-HTTP address on the same
// host and sent the bearer there in clear). So: HTTPS or the credential is not sent at all, and no redirect is
// followed — a health answer is one round trip, and whoever answers a redirect has not proved the anchor.
func getNodeHealth(client *http.Client, url string) (int, []byte, error) {
	if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(url)), "https://") {
		return 0, nil, fmt.Errorf("refusing to send the walk's credential over %q: a node is asked over https only", url)
	}
	oneHop := *client
	oneHop.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return get(&oneHop, url, nodeDetailBearer)
}

// verifyTheWalkCanAskANodeWhatItIs says, before any check that reads a field, whether those checks can be
// answered at all — so a machine without the credential reads as that, and not as a dozen nodes that "did not
// say".
func verifyTheWalkCanAskANodeWhatItIs() verifyResult {
	if nodeDetailBearer == "" {
		return verifyResult{name: "this walk can ask a node what it is", ok: false,
			note: "this machine holds none of the deployment's credentials (authority/installation-state-read-token, " +
				"or deployment.env), so every node answers it only whether it takes traffic. Run -verify on the " +
				"machine that ran -bootstrap-admin"}
	}
	return verifyResult{name: "this walk can ask a node what it is", ok: true,
		note: "asking as the operator with " + nodeDetailCredentialKind}
}
